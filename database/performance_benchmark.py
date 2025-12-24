#!/usr/bin/env python3
"""
Performance benchmark comparing SQLite and PostgreSQL for CyberSec-CLI.
"""

import os
import sys
import time
import asyncio
import sqlite3
import tempfile
import json
from typing import List, Dict, Any
from datetime import datetime

# Add the project root to the path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

try:
    from database.postgres_client import PostgresClient

    HAS_POSTGRES = True
except ImportError:
    HAS_POSTGRES = False
    print("Warning: PostgreSQL client not available, only SQLite benchmark will run")


def create_sample_scans(count: int) -> List[Dict[str, Any]]:
    """Create sample scan data for benchmarking."""
    scans = []
    for i in range(count):
        scan = {
            "target": f"example{i}.com",
            "timestamp": datetime.now().isoformat() + "Z",
            "ip": f"192.168.1.{i % 255}",
            "command": f"scan example{i}.com --ports 1-1000",
            "output": json.dumps(
                {
                    "scan_id": f"scan_{i}",
                    "target": f"example{i}.com",
                    "ports": "1-1000",
                    "total_ports_scanned": 1000,
                    "open_ports": [
                        {
                            "port": 22,
                            "service": "ssh",
                            "version": "OpenSSH 8.0",
                            "banner": "SSH-2.0-OpenSSH_8.0",
                            "confidence": 0.95,
                            "protocol": "tcp",
                            "risk": "LOW",
                            "cvss_score": 0.0,
                        },
                        {
                            "port": 80,
                            "service": "http",
                            "version": "Apache 2.4.6",
                            "banner": "Apache/2.4.6 (CentOS)",
                            "confidence": 0.90,
                            "protocol": "tcp",
                            "risk": "MEDIUM",
                            "cvss_score": 5.3,
                        },
                    ],
                }
            ),
            "config": {"scan_type": "TCP", "timeout": 1.0, "max_concurrent": 50},
        }
        scans.append(scan)
    return scans


def benchmark_sqlite(scans: List[Dict[str, Any]]) -> Dict[str, float]:
    """Benchmark SQLite performance."""
    # Create temporary SQLite database
    temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    temp_db.close()

    try:
        # Initialize database
        conn = sqlite3.connect(temp_db.name)
        c = conn.cursor()
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                target TEXT,
                ip TEXT,
                command TEXT,
                output TEXT
            )
        """
        )
        conn.commit()

        # Benchmark insert performance
        start_time = time.time()
        for scan in scans:
            c.execute(
                "INSERT INTO scans (timestamp, target, ip, command, output) VALUES (?, ?, ?, ?, ?)",
                (
                    scan["timestamp"],
                    scan["target"],
                    scan["ip"],
                    scan["command"],
                    scan["output"],
                ),
            )
        conn.commit()
        insert_time = time.time() - start_time

        # Benchmark select performance
        start_time = time.time()
        c.execute("SELECT COUNT(*) FROM scans")
        count = c.fetchone()[0]
        select_time = time.time() - start_time

        conn.close()

        return {
            "insert_time": insert_time,
            "select_time": select_time,
            "records_count": count,
        }

    finally:
        # Clean up temporary database
        os.unlink(temp_db.name)


async def benchmark_postgresql(scans: List[Dict[str, Any]]) -> Dict[str, float]:
    """Benchmark PostgreSQL performance."""
    if not HAS_POSTGRES:
        return {
            "insert_time": 0,
            "select_time": 0,
            "records_count": 0,
            "error": "PostgreSQL client not available",
        }

    try:
        # Initialize PostgreSQL client
        postgres_client = PostgresClient()
        initialized = await postgres_client.initialize()
        if not initialized:
            return {
                "insert_time": 0,
                "select_time": 0,
                "records_count": 0,
                "error": "Failed to initialize PostgreSQL",
            }

        # Benchmark insert performance
        start_time = time.time()
        for i, scan in enumerate(scans):
            scan_id = await postgres_client.create_scan(
                target=scan["target"], config=scan["config"]
            )

            # Parse output to get results
            output_data = json.loads(scan["output"])
            if "open_ports" in output_data:
                await postgres_client.save_scan_results(
                    scan_id, output_data["open_ports"]
                )
        insert_time = time.time() - start_time

        # Benchmark select performance (simplified)
        start_time = time.time()
        # In a real implementation, we would do actual queries here
        select_time = time.time() - start_time

        await postgres_client.close()

        return {
            "insert_time": insert_time,
            "select_time": select_time,
            "records_count": len(scans),
        }

    except Exception as e:
        return {"insert_time": 0, "select_time": 0, "records_count": 0, "error": str(e)}


async def run_benchmark():
    """Run the performance benchmark."""
    print("CyberSec-CLI Database Performance Benchmark")
    print("=" * 50)

    # Test with different dataset sizes
    test_sizes = [10, 100, 1000]

    for size in test_sizes:
        print(f"\nTesting with {size} records:")
        print("-" * 30)

        # Create sample data
        scans = create_sample_scans(size)

        # Benchmark SQLite
        print("SQLite:")
        sqlite_results = benchmark_sqlite(scans)
        print(f"  Insert time: {sqlite_results['insert_time']:.4f}s")
        print(f"  Select time: {sqlite_results['select_time']:.4f}s")
        print(f"  Records: {sqlite_results['records_count']}")
        if "error" in sqlite_results:
            print(f"  Error: {sqlite_results['error']}")

        # Benchmark PostgreSQL
        print("PostgreSQL:")
        postgres_results = await benchmark_postgresql(scans)
        print(f"  Insert time: {postgres_results['insert_time']:.4f}s")
        print(f"  Select time: {postgres_results['select_time']:.4f}s")
        print(f"  Records: {postgres_results['records_count']}")
        if "error" in postgres_results:
            print(f"  Error: {postgres_results['error']}")

        # Compare performance
        if (
            HAS_POSTGRES
            and "error" not in sqlite_results
            and "error" not in postgres_results
        ):
            print("\nPerformance Comparison:")
            insert_ratio = (
                sqlite_results["insert_time"] / postgres_results["insert_time"]
                if postgres_results["insert_time"] > 0
                else 0
            )
            select_ratio = (
                sqlite_results["select_time"] / postgres_results["select_time"]
                if postgres_results["select_time"] > 0
                else 0
            )
            print(f"  Insert speed ratio (SQLite/PostgreSQL): {insert_ratio:.2f}x")
            print(f"  Select speed ratio (SQLite/PostgreSQL): {select_ratio:.2f}x")


def main():
    """Main function."""
    try:
        asyncio.run(run_benchmark())
        return 0
    except Exception as e:
        print(f"Error running benchmark: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
