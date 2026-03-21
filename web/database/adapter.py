"""
Unified DB adapter — routes to PostgreSQL or SQLite based on DATABASE_URL.
All functions have the same signature as queries.py but work with both DBs.
"""
from web.database.connection import is_postgres, get_postgres_conn, get_sqlite_conn
from web.database import queries
from web.database import pg_queries
from typing import Optional, List, Dict
import os

SCANS_DB = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "reports", "scans.db"
)


async def create_scan_record(target, ip, command, user_id=None, scan_type=None, scan_uuid=None, db_path=None):
    if is_postgres():
        conn = await get_postgres_conn()
        try:
            return await pg_queries.pg_create_scan_record(
                conn, target, ip, command, user_id, scan_type, scan_uuid
            )
        finally:
            await conn.close()
    else:
        db_path = db_path or SCANS_DB
        return queries.create_scan_record(
            db_path=db_path, target=target, ip=ip, command=command,
            user_id=user_id, scan_type=scan_type, scan_uuid=scan_uuid
        )


async def save_port_result(scan_id, port_data, db_path=None):
    if is_postgres():
        conn = await get_postgres_conn()
        try:
            return await pg_queries.pg_save_port_result(conn, scan_id, port_data)
        finally:
            await conn.close()
    else:
        db_path = db_path or SCANS_DB
        return queries.save_port_result(db_path=db_path, scan_id=scan_id, port_data=port_data)


async def finalize_scan(scan_id, status="completed", raw_output=None, db_path=None):
    if is_postgres():
        conn = await get_postgres_conn()
        try:
            return await pg_queries.pg_finalize_scan(conn, scan_id, status, raw_output)
        finally:
            await conn.close()
    else:
        db_path = db_path or SCANS_DB
        return queries.finalize_scan(db_path=db_path, scan_id=scan_id, status=status, raw_output=raw_output)


async def list_scans(user_id=None, limit=50, min_cvss=None, severity=None, target=None, has_cves=None, db_path=None):
    if is_postgres():
        conn = await get_postgres_conn()
        try:
            return await pg_queries.pg_list_scans(conn, user_id, limit, min_cvss, severity, target, has_cves)
        finally:
            await conn.close()
    else:
        import sqlite3
        db_path = db_path or SCANS_DB
        with get_sqlite_conn(db_path) as conn:
            return queries.list_scans(conn, user_id, limit, min_cvss, severity, target, has_cves)


async def get_scan_detail(scan_uuid, user_id=None, db_path=None):
    if is_postgres():
        conn = await get_postgres_conn()
        try:
            return await pg_queries.pg_get_scan_detail(conn, scan_uuid, user_id)
        finally:
            await conn.close()
    else:
        import sqlite3
        db_path = db_path or SCANS_DB
        with get_sqlite_conn(db_path) as conn:
            return queries.get_scan_detail(conn, scan_uuid, user_id)
