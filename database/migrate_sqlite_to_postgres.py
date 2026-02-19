#!/usr/bin/env python3
"""
Migration script to migrate data from SQLite to PostgreSQL.
"""

import argparse
import asyncio
import json
import logging
import os
import sqlite3
import sys
import uuid
from datetime import datetime
from typing import Any, Dict, List

# Add the project root to the path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

try:
    from database.postgres_client import PostgresClient

    HAS_POSTGRES = True
except ImportError:
    print("Error: PostgreSQL client not available")
    sys.exit(1)

logger = logging.getLogger(__name__)


def get_sqlite_scans(sqlite_db_path: str) -> List[Dict[str, Any]]:
    """
    Extract all scans from SQLite database.

    Args:
        sqlite_db_path: Path to SQLite database file

    Returns:
        List of scan dictionaries
    """
    try:
        conn = sqlite3.connect(sqlite_db_path)
        conn.row_factory = sqlite3.Row  # Enable column access by name
        cursor = conn.cursor()

        # Fetch all scans
        cursor.execute(
            """
            SELECT id, timestamp, target, ip, command, output
            FROM scans
            ORDER BY id
        """
        )

        rows = cursor.fetchall()
        scans = []

        for row in rows:
            scan = {
                "id": row["id"],
                "timestamp": row["timestamp"],
                "target": row["target"],
                "ip": row["ip"],
                "command": row["command"],
                "output": row["output"],
            }
            scans.append(scan)

        conn.close()
        return scans

    except Exception as e:
        print(f"Error reading SQLite database: {e}")
        return []


def parse_scan_output(output: str) -> List[Dict[str, Any]]:
    """
    Parse scan output to extract port information.

    Args:
        output: Raw scan output string

    Returns:
        List of port result dictionaries
    """
    results = []

    # This is a simplified parser - in a real implementation,
    # you would need to parse the actual scan output format
    # For now, we'll create some sample data
    try:
        # Try to parse as JSON if it's in that format
        if output.strip().startswith("{") or output.strip().startswith("["):
            data = json.loads(output)
            if isinstance(data, dict) and "open_ports" in data:
                results = data["open_ports"]
            elif isinstance(data, list):
                results = data
    except json.JSONDecodeError:
        # If not JSON, create some sample data for demonstration
        # In a real implementation, you'd parse the actual output format
        pass

    return results


async def migrate_scans(
    sqlite_scans: List[Dict[str, Any]],
    postgres_client: PostgresClient,
    dry_run: bool = False,
) -> int:
    """
    Migrate scans from SQLite to PostgreSQL.

    Args:
        sqlite_scans: List of scans from SQLite
        postgres_client: PostgreSQL client instance
        dry_run: If True, only show what would be migrated without actually doing it

    Returns:
        Number of scans migrated
    """
    if not sqlite_scans:
        print("No scans to migrate")
        return 0

    migrated_count = 0
    batch_size = 500
    scan_batch = []
    result_batch = []

    print(f"Migrating {len(sqlite_scans)} scans in batches of {batch_size}...")

    for i, scan in enumerate(sqlite_scans):
        try:
            if not dry_run:
                # Parse output to get results
                results = parse_scan_output(scan["output"])
                
                # Parse timestamp with error handling
                raw_ts = scan.get("timestamp", "")
                try:
                    completed_at = datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
                except (ValueError, TypeError):
                    logger.warning(f"Bad timestamp {raw_ts!r}, using UTC now")
                    completed_at = datetime.utcnow()

                scan_id = str(uuid.uuid4())
                scan_batch.append(
                    (
                        scan_id,
                        scan["target"],
                        json.dumps({"command": scan["command"], "ip": scan["ip"]}),
                        "completed",
                        completed_at,
                    )
                )

                for result in results or []:
                    result_batch.append(
                        (
                            str(uuid.uuid4()),
                            scan_id,
                            result.get("port"),
                            result.get("state"),
                            result.get("service"),
                            result.get("version"),
                            result.get("banner"),
                            result.get("risk"),
                            json.dumps(result.get("metadata", {})),
                        )
                    )

                # Process batch when it reaches batch_size
                if len(scan_batch) >= batch_size:
                    await _process_batch(postgres_client, scan_batch, result_batch)
                    migrated_count += len(scan_batch)
                    print(f"Progress: {i+1}/{len(sqlite_scans)} scans migrated")
                    scan_batch.clear()
                    result_batch.clear()

        except Exception as e:
            print(f"Error migrating scan {scan['id']}: {e}")
            # Continue with other scans

    # Process remaining items in batch
    if scan_batch and not dry_run:
        await _process_batch(postgres_client, scan_batch, result_batch)
        migrated_count += len(scan_batch)

    return migrated_count


async def _process_batch(postgres_client, scan_batch, result_batch):
    """Process a batch of scans with transaction rollback on failure."""
    try:
        if not postgres_client.enabled or not postgres_client.pool:
            raise RuntimeError("PostgreSQL pool not initialized")

        async with postgres_client.pool.acquire() as conn:
            async with conn.transaction():
                await conn.executemany(
                    """
                    INSERT INTO scans (id, target, config, status, completed_at)
                    VALUES ($1, $2, $3, $4, $5)
                    """,
                    scan_batch,
                )
                if result_batch:
                    await conn.executemany(
                        """
                        INSERT INTO scan_results
                        (id, scan_id, port, state, service, version, banner, risk_level, metadata)
                        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                        """,
                        result_batch,
                    )
    except Exception as e:
        print(f"Error processing batch: {e}")
        # Rollback is handled by individual scan error handling above
        raise


async def main():
    """Main migration function."""
    parser = argparse.ArgumentParser(description="Migrate SQLite data to PostgreSQL")
    parser.add_argument(
        "--sqlite-db", default="./reports/scans.db", help="Path to SQLite database file"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be migrated without actually doing it",
    )
    parser.add_argument(
        "--verbose", action="store_true", help="Show detailed migration information"
    )

    args = parser.parse_args()

    print("SQLite to PostgreSQL Migration Tool")
    print("=" * 50)

    if args.dry_run:
        print("DRY RUN MODE - No data will be actually migrated")
        print()

    # Check if SQLite database exists
    if not os.path.exists(args.sqlite_db):
        print(f"Error: SQLite database not found at {args.sqlite_db}")
        return 1

    # Initialize PostgreSQL client
    postgres_client = PostgresClient()
    try:
        initialized = await postgres_client.initialize()
        if not initialized:
            print("Error: Failed to initialize PostgreSQL connection")
            return 1
    except Exception as e:
        print(f"Error initializing PostgreSQL: {e}")
        return 1

    # Extract data from SQLite
    print(f"Reading scans from SQLite database: {args.sqlite_db}")
    sqlite_scans = get_sqlite_scans(args.sqlite_db)
    print(f"Found {len(sqlite_scans)} scans to migrate")

    if args.verbose and sqlite_scans:
        print("\nSample scan data:")
        for i, scan in enumerate(sqlite_scans[:3]):  # Show first 3 scans
            print(f"  Scan {scan['id']}: {scan['target']} at {scan['timestamp']}")

    # Perform migration
    try:
        migrated_count = await migrate_scans(
            sqlite_scans, postgres_client, args.dry_run
        )
        print(f"\nMigration completed: {migrated_count} scans processed")

        if not args.dry_run:
            print("Data migration successful!")
        else:
            print("Dry run completed - no data was actually migrated")

    except Exception as e:
        print(f"Migration failed: {e}")
        return 1
    finally:
        await postgres_client.close()

    return 0


if __name__ == "__main__":
    asyncio.run(main())
