"""
Database abstraction layer for CyberSec-CLI.
This module provides a unified interface for both SQLite and PostgreSQL databases.
"""

import logging
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

# Try to import PostgreSQL client
try:
    from .postgres_client import postgres_client

    HAS_POSTGRES = True
except ImportError:
    HAS_POSTGRES = False
    postgres_client = None

logger = logging.getLogger(__name__)


class DatabaseType:
    """Enumeration of supported database types."""

    SQLITE = "sqlite"
    POSTGRESQL = "postgresql"


def get_database_type() -> str:
    """
    Determine which database type to use based on environment variables.

    Returns:
        Database type string
    """
    database_url = os.getenv("DATABASE_URL")
    if database_url and HAS_POSTGRES and postgres_client:
        return DatabaseType.POSTGRESQL
    return DatabaseType.SQLITE


class DatabaseInterface:
    """Unified database interface supporting both SQLite and PostgreSQL."""

    def __init__(self):
        self.db_type = get_database_type()
        self.initialized = False

    async def initialize(self):
        """Initialize the database connection."""
        if self.db_type == DatabaseType.POSTGRESQL and HAS_POSTGRES:
            result = await postgres_client.initialize()
            self.initialized = result
            if result:
                logger.info("Using PostgreSQL database")
            else:
                logger.warning(
                    "Failed to initialize PostgreSQL, falling back to SQLite"
                )
                self.db_type = DatabaseType.SQLITE
        else:
            # SQLite is always available
            self.initialized = True
            logger.info("Using SQLite database")

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
            Scan ID
        """
        if (
            self.db_type == DatabaseType.POSTGRESQL
            and HAS_POSTGRES
            and self.initialized
        ):
            return await postgres_client.create_scan(target, user_id, config)
        else:
            # Fallback to SQLite implementation
            pass

            # For compatibility, we'll create a dummy scan record
            # In a real implementation, this would be properly integrated
            import uuid

            scan_id = str(uuid.uuid4())
            return scan_id

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
        if (
            self.db_type == DatabaseType.POSTGRESQL
            and HAS_POSTGRES
            and self.initialized
        ):
            await postgres_client.update_scan_status(scan_id, status, completed_at)
        else:
            # SQLite doesn't have this concept in the current implementation
            pass

    async def save_scan_results(self, scan_id: str, results: List[Dict[str, Any]]):
        """
        Save scan results.

        Args:
            scan_id: Scan identifier
            results: List of scan result dictionaries
        """
        if (
            self.db_type == DatabaseType.POSTGRESQL
            and HAS_POSTGRES
            and self.initialized
        ):
            await postgres_client.save_scan_results(scan_id, results)
        else:
            # Fallback to SQLite implementation
            # In the current implementation, results are saved as a single JSON blob
            # We'll need to modify the web API to use the new structure
            pass

    async def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """
        Get scan information.

        Args:
            scan_id: Scan identifier

        Returns:
            Scan information dictionary or None if not found
        """
        if (
            self.db_type == DatabaseType.POSTGRESQL
            and HAS_POSTGRES
            and self.initialized
        ):
            return await postgres_client.get_scan(scan_id)
        else:
            # Fallback to SQLite implementation
            from web.main import get_scan_output

            output = get_scan_output(int(scan_id) if scan_id.isdigit() else 1)
            if output:
                return {"id": scan_id, "output": output}
            return None

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
        if (
            self.db_type == DatabaseType.POSTGRESQL
            and HAS_POSTGRES
            and self.initialized
        ):
            return await postgres_client.list_user_scans(user_id, limit, offset)
        else:
            # Fallback to SQLite implementation
            from web.main import list_scans

            sqlite_scans = list_scans(limit)
            # Convert to new format
            return [
                {
                    "id": str(scan["id"]),
                    "target": scan["target"],
                    "status": "completed",  # Assume completed for SQLite scans
                    "user_id": None,
                    "created_at": scan["timestamp"],
                    "completed_at": scan["timestamp"],
                }
                for scan in sqlite_scans
            ]

    async def get_scan_results(self, scan_id: str) -> List[Dict[str, Any]]:
        """
        Get scan results.

        Args:
            scan_id: Scan identifier

        Returns:
            List of scan result dictionaries
        """
        if (
            self.db_type == DatabaseType.POSTGRESQL
            and HAS_POSTGRES
            and self.initialized
        ):
            return await postgres_client.get_scan_results(scan_id)
        else:
            # SQLite doesn't have separate results table
            # Return empty list for now
            return []

    async def delete_scan(self, scan_id: str) -> bool:
        """
        Delete a scan and its results.

        Args:
            scan_id: Scan identifier

        Returns:
            True if deleted, False if not found
        """
        if (
            self.db_type == DatabaseType.POSTGRESQL
            and HAS_POSTGRES
            and self.initialized
        ):
            return await postgres_client.delete_scan(scan_id)
        else:
            # SQLite implementation would go here
            return False

    async def close(self):
        """Close database connections."""
        if (
            self.db_type == DatabaseType.POSTGRESQL
            and HAS_POSTGRES
            and self.initialized
        ):
            await postgres_client.close()


# Create global database interface instance
db_interface = DatabaseInterface()
