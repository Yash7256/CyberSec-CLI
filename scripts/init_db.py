#!/usr/bin/env python3
"""Initialize database schema"""
import asyncio
import asyncpg
from pathlib import Path
import os

async def init_database():
    """Run database migrations"""
    database_url = os.getenv('DATABASE_URL')
    
    if not database_url:
        print("ERROR: DATABASE_URL not set")
        return
    
    # Read schema file
    schema_path = Path(__file__).parent.parent / 'database' / 'postgres_schema.sql'
    
    if not schema_path.exists():
        print(f"ERROR: Schema file not found: {schema_path}")
        return
    
    with open(schema_path, 'r') as f:
        schema_sql = f.read()
    
    # Connect and execute
    try:
        conn = await asyncpg.connect(database_url)
        print("Connected to PostgreSQL database")
        
        print("Running database migrations...")
        await conn.execute(schema_sql)
        print("✅ Database initialized successfully")
        
        await conn.close()
        print("Connection closed")
    except Exception as e:
        print(f"❌ Migration failed: {e}")

if __name__ == '__main__':
    asyncio.run(init_database())