#!/usr/bin/env python3
"""
Test script to verify PostgreSQL setup for CyberSec-CLI.
"""

import sys
import os

# Add the project root to the path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))


def test_postgres_client_import():
    """Test if PostgreSQL client can be imported."""
    try:
        from database.postgres_client import PostgresClient

        print("✅ PostgreSQL client imported successfully")
        return True
    except ImportError as e:
        print(f"❌ Failed to import PostgreSQL client: {e}")
        return False


def test_database_abstraction_import():
    """Test if database abstraction layer can be imported."""
    try:
        from database import db_interface

        print("✅ Database abstraction layer imported successfully")
        return True
    except ImportError as e:
        print(f"❌ Failed to import database abstraction layer: {e}")
        return False


def test_configuration():
    """Test if database configuration is available."""
    try:
        from src.cybersec_cli.config import settings

        print(f"✅ Database configuration available: type={settings.database.type}")
        return True
    except Exception as e:
        print(f"❌ Failed to access database configuration: {e}")
        return False


def test_dependencies():
    """Test if required dependencies are installed."""
    try:
        import asyncpg

        print("✅ asyncpg dependency installed successfully")
        return True
    except ImportError as e:
        print(f"❌ asyncpg dependency not installed: {e}")
        return False


def test_schema_file():
    """Test if PostgreSQL schema file exists."""
    schema_path = os.path.join(
        os.path.dirname(__file__), "database", "postgres_schema.sql"
    )
    if os.path.exists(schema_path):
        print("✅ PostgreSQL schema file exists")
        return True
    else:
        print("❌ PostgreSQL schema file not found")
        return False


def test_migration_script():
    """Test if migration script exists."""
    migration_path = os.path.join(
        os.path.dirname(__file__), "database", "migrate_sqlite_to_postgres.py"
    )
    if os.path.exists(migration_path):
        print("✅ Migration script exists")
        return True
    else:
        print("❌ Migration script not found")
        return False


def main():
    """Run all PostgreSQL setup tests."""
    print("Testing PostgreSQL Setup for CyberSec-CLI")
    print("=" * 50)

    tests = [
        test_dependencies,
        test_postgres_client_import,
        test_database_abstraction_import,
        test_configuration,
        test_schema_file,
        test_migration_script,
    ]

    passed = 0
    total = len(tests)

    for test in tests:
        if test():
            passed += 1
        print()

    print("=" * 50)
    print(f"Tests passed: {passed}/{total}")

    if passed == total:
        print("🎉 All PostgreSQL setup tests passed!")
        return 0
    else:
        print("❌ Some tests failed. Please check the output above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
