"""
PostgreSQL client for CyberSec-CLI.
This module provides an async PostgreSQL client with connection pooling.
"""

import asyncio
import json
import logging
import os
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

import asyncpg

logger = logging.getLogger(__name__)

_instance: Optional["PostgresClient"] = None
_lock = asyncio.Lock()


class PostgresClient:
    """Async PostgreSQL client with connection pooling."""

    def __init__(self):
        if hasattr(self, '_initialized') and self._initialized:
            return

        self.pool = None
        self.enabled = False
        self._initialized = True

    async def initialize(self):
        """Initialize the PostgreSQL connection pool."""
        database_url = os.getenv("DATABASE_URL")
        if not database_url:
            logger.warning("DATABASE_URL not set, PostgreSQL disabled")
            return False

        try:
            # Create connection pool
            self.pool = await asyncpg.create_pool(
                database_url,
                min_size=5,
                max_size=20,
                command_timeout=60,
                acquire_timeout=60,
            )

            # Test connection
            async with self.pool.acquire() as conn:
                await conn.fetchval("SELECT 1")

            self.enabled = True
            logger.info("PostgreSQL connection pool initialized successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to initialize PostgreSQL connection pool: {e}")
            # Clean up pool on failure
            if hasattr(self, "pool") and self.pool:
                await self.pool.close()
                self.pool = None
            self.enabled = False
            raise

    async def connect(self) -> bool:
        """Alias for initialize to support singleton setup."""
        return await self.initialize()

    async def create_scan(
        self,
        target: str,
        user_id: Optional[str] = None,
        config: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Create a new scan record.

        Args:
            target: Target hostname or IP address
            user_id: Optional user identifier
            config: Optional scan configuration

        Returns:
            Scan ID (UUID as string)
        """
        if not self.enabled:
            raise Exception("PostgreSQL not enabled")

        scan_id = str(uuid.uuid4())

        try:
            async with self.pool.acquire() as conn:
                await conn.execute(
                    """
                    INSERT INTO scans (id, target, user_id, config, status)
                    VALUES ($1, $2, $3, $4, $5)
                    """,
                    scan_id,
                    target,
                    user_id,
                    json.dumps(config) if config else None,
                    "pending",
                )
            return scan_id
        except Exception as e:
            logger.error(f"Failed to create scan: {e}")
            raise

    async def update_scan_status(
        self, scan_id: str, status: str, completed_at: Optional[datetime] = None
    ):
        """
        Update scan status.

        Args:
            scan_id: Scan identifier
            status: New status
            completed_at: Completion timestamp (optional)
        """
        if not self.enabled:
            raise Exception("PostgreSQL not enabled")

        try:
            async with self.pool.acquire() as conn:
                if completed_at:
                    await conn.execute(
                        """
                        UPDATE scans
                        SET status = $1, completed_at = $2
                        WHERE id = $3
                        """,
                        status,
                        completed_at,
                        scan_id,
                    )
                else:
                    await conn.execute(
                        """
                        UPDATE scans
                        SET status = $1
                        WHERE id = $2
                        """,
                        status,
                        scan_id,
                    )
        except Exception as e:
            logger.error(f"Failed to update scan status: {e}")
            raise

    async def save_scan_results(self, scan_id: str, results: List[Dict[str, Any]]):
        """
        Save scan results.

        Args:
            scan_id: Scan identifier
            results: List of scan result dictionaries
        """
        if not self.enabled:
            raise Exception("PostgreSQL not enabled")

        if not results:
            return

        try:
            # Prepare data for bulk insert
            records = []
            for result in results:
                records.append(
                    (
                        str(uuid.uuid4()),  # id
                        scan_id,  # scan_id
                        result.get("port"),  # port
                        result.get("state"),  # state
                        result.get("service"),  # service
                        result.get("version"),  # version
                        result.get("banner"),  # banner
                        result.get("risk"),  # risk_level
                        json.dumps(result.get("metadata", {})),  # metadata
                    )
                )

            async with self.pool.acquire() as conn:
                await conn.executemany(
                    """
                    INSERT INTO scan_results
                    (id, scan_id, port, state, service, version, banner, risk_level, metadata)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                    """,
                    records,
                )
        except Exception as e:
            logger.error(f"Failed to save scan results: {e}")
            raise

    async def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """
        Get scan information.

        Args:
            scan_id: Scan identifier

        Returns:
            Scan information dictionary or None if not found
        """
        if not self.enabled:
            raise Exception("PostgreSQL not enabled")

        try:
            async with self.pool.acquire() as conn:
                row = await conn.fetchrow(
                    """
                    SELECT id, target, status, user_id, created_at, completed_at, config
                    FROM scans
                    WHERE id = $1
                    """,
                    scan_id,
                )

                if not row:
                    return None

                return {
                    "id": row["id"],
                    "target": row["target"],
                    "status": row["status"],
                    "user_id": row["user_id"],
                    "created_at": (
                        row["created_at"].isoformat() if row["created_at"] else None
                    ),
                    "completed_at": (
                        row["completed_at"].isoformat() if row["completed_at"] else None
                    ),
                    "config": json.loads(row["config"]) if row["config"] else None,
                }
        except Exception as e:
            logger.error(f"Failed to get scan: {e}")
            raise

    async def list_user_scans(
        self, user_id: str, limit: int = 50, offset: int = 0
    ) -> List[Dict[str, Any]]:
        """
        List scans for a user.

        Args:
            user_id: User identifier
            limit: Maximum number of scans to return
            offset: Offset for pagination

        Returns:
            List of scan information dictionaries
        """
        if not self.enabled:
            raise Exception("PostgreSQL not enabled")

        try:
            async with self.pool.acquire() as conn:
                rows = await conn.fetch(
                    """
                    SELECT id, target, status, user_id, created_at, completed_at
                    FROM scans
                    WHERE user_id = $1
                    ORDER BY created_at DESC
                    LIMIT $2 OFFSET $3
                    """,
                    user_id,
                    limit,
                    offset,
                )

                return [
                    {
                        "id": row["id"],
                        "target": row["target"],
                        "status": row["status"],
                        "user_id": row["user_id"],
                        "created_at": (
                            row["created_at"].isoformat() if row["created_at"] else None
                        ),
                        "completed_at": (
                            row["completed_at"].isoformat()
                            if row["completed_at"]
                            else None
                        ),
                    }
                    for row in rows
                ]
        except Exception as e:
            logger.error(f"Failed to list user scans: {e}")
            raise

    async def get_scan_results(self, scan_id: str) -> List[Dict[str, Any]]:
        """
        Get scan results.

        Args:
            scan_id: Scan identifier

        Returns:
            List of scan result dictionaries
        """
        if not self.enabled:
            raise Exception("PostgreSQL not enabled")

        try:
            async with self.pool.acquire() as conn:
                rows = await conn.fetch(
                    """
                    SELECT id, port, state, service, version, banner, risk_level, metadata
                    FROM scan_results
                    WHERE scan_id = $1
                    ORDER BY port
                    """,
                    scan_id,
                )

                return [
                    {
                        "id": row["id"],
                        "port": row["port"],
                        "state": row["state"],
                        "service": row["service"],
                        "version": row["version"],
                        "banner": row["banner"],
                        "risk": row["risk_level"],
                        "metadata": (
                            json.loads(row["metadata"]) if row["metadata"] else {}
                        ),
                    }
                    for row in rows
                ]
        except Exception as e:
            logger.error(f"Failed to get scan results: {e}")
            raise

    async def delete_scan(self, scan_id: str) -> bool:
        """
        Delete a scan and its results.

        Args:
            scan_id: Scan identifier

        Returns:
            True if deleted, False if not found
        """
        if not self.enabled:
            raise Exception("PostgreSQL not enabled")

        try:
            async with self.pool.acquire() as conn:
                result = await conn.execute(
                    """
                    DELETE FROM scans
                    WHERE id = $1
                    """,
                    scan_id,
                )
                # Due to CASCADE delete, scan results are automatically deleted
                # asyncpg returns a command tag like "DELETE <n>"
                try:
                    deleted_count = int(str(result).split()[-1])
                except (ValueError, IndexError, AttributeError):
                    logger.warning(f"Unexpected delete result tag: {result!r}")
                    return False
                return deleted_count > 0
        except Exception as e:
            logger.error(f"Failed to delete scan: {e}")
            raise

    async def close(self):
        """Close the connection pool."""
        if self.pool:
            await self.pool.close()
            logger.info("PostgreSQL connection pool closed")


async def get_postgres_client() -> "PostgresClient":
    """Get a singleton PostgresClient instance with async-safe initialization."""
    global _instance
    if _instance is None:
        async with _lock:
            if _instance is None:
                _instance = PostgresClient()
                await _instance.connect()
    return _instance
