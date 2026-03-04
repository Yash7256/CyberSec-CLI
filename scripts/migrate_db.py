"""
Run this once to migrate existing scan history to normalized schema.
Usage: python scripts/migrate_db.py
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import sqlite3
from web.database.schema import init_db_v2
from web.database.migrate import run_migration

def main():
    db_path = os.environ.get("SCANS_DB", "./reports/scans.db")
    
    if not os.path.exists(db_path):
        print(f"Database not found at {db_path}")
        sys.exit(1)
    
    print(f"Migrating database: {db_path}")
    
    # Step 1: Create new tables
    conn = sqlite3.connect(db_path)
    init_db_v2(conn)
    conn.close()
    print("✓ Schema v2 tables created")
    
    # Step 2: Migrate existing data
    stats = run_migration(db_path)
    print(f"✓ Migration complete:")
    print(f"  Total scans:     {stats['total']}")
    print(f"  JSON migrated:   {stats['migrated_json']}")
    print(f"  Text preserved:  {stats['migrated_text']}")
    print(f"  Errors:          {stats['errors']}")
    
    if stats["errors"] > 0:
        print("⚠ Some scans had errors - check logs")
        sys.exit(1)
    
    print("✓ All done. Database is now on schema v2.")

if __name__ == "__main__":
    main()
