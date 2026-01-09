"""Recurring scan scheduler using APScheduler.

Stores scheduled scans in SQLite and provides endpoints to create/list/delete/run them.
"""

import asyncio
import logging
import sqlite3
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

try:
    from apscheduler.schedulers.asyncio import AsyncIOScheduler
    from apscheduler.triggers.cron import CronTrigger

    HAS_SCHEDULER = True
except ImportError:
    HAS_SCHEDULER = False

logger = logging.getLogger(__name__)

# Base paths
BASE_DIR = Path(__file__).parent
REPORTS_DIR = Path(BASE_DIR).parent / "reports"
SCHEDULER_DB = REPORTS_DIR / "scheduler.db"

# Global scheduler instance
_scheduler: Optional["AsyncIOScheduler"] = None


def init_scheduler_db():
    """Initialize the scheduler database."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(SCHEDULER_DB)
    c = conn.cursor()
    c.execute(
        """
    CREATE TABLE IF NOT EXISTS scheduled_scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT NOT NULL,
        cron_expression TEXT NOT NULL,
        enabled BOOLEAN DEFAULT 1,
        created_at TEXT,
        last_run TEXT,
        next_run TEXT
    )
    """
    )
    conn.commit()
    conn.close()


def add_scheduled_scan(target: str, cron_expression: str) -> int:
    """Add a new scheduled scan. Returns the scan ID."""
    try:
        conn = sqlite3.connect(SCHEDULER_DB)
        c = conn.cursor()
        now = datetime.utcnow().isoformat() + "Z"
        c.execute(
            """
        INSERT INTO scheduled_scans (target, cron_expression, created_at)
        VALUES (?, ?, ?)
        """,
            (target, cron_expression, now),
        )
        conn.commit()
        scan_id = c.lastrowid
        conn.close()

        # Add job to scheduler if running
        if _scheduler and HAS_SCHEDULER:
            _add_job_to_scheduler(scan_id, target, cron_expression)

        return scan_id
    except Exception as e:
        logger.exception(f"Failed to add scheduled scan: {e}")
        return -1


def list_scheduled_scans() -> List[Dict]:
    """List all scheduled scans."""
    try:
        conn = sqlite3.connect(SCHEDULER_DB)
        c = conn.cursor()
        c.execute(
            """
        SELECT id, target, cron_expression, enabled, created_at, last_run, next_run
        FROM scheduled_scans ORDER BY id DESC
        """
        )
        rows = c.fetchall()
        conn.close()
        return [
            {
                "id": r[0],
                "target": r[1],
                "cron_expression": r[2],
                "enabled": bool(r[3]),
                "created_at": r[4],
                "last_run": r[5],
                "next_run": r[6],
            }
            for r in rows
        ]
    except Exception as e:
        logger.exception(f"Failed to list scheduled scans: {e}")
        return []


def delete_scheduled_scan(scan_id: int) -> bool:
    """Delete a scheduled scan by ID."""
    try:
        conn = sqlite3.connect(SCHEDULER_DB)
        c = conn.cursor()
        c.execute("DELETE FROM scheduled_scans WHERE id = ?", (scan_id,))
        conn.commit()
        conn.close()

        # Remove job from scheduler if running
        if _scheduler and HAS_SCHEDULER:
            job_id = f"scan_{scan_id}"
            try:
                _scheduler.remove_job(job_id)
            except Exception as e:
                logger.debug(f"Job {job_id} not found in scheduler (may already be removed): {e}")

        return True
    except Exception as e:
        logger.exception(f"Failed to delete scheduled scan: {e}")
        return False


def toggle_scheduled_scan(scan_id: int, enabled: bool) -> bool:
    """Enable or disable a scheduled scan."""
    try:
        conn = sqlite3.connect(SCHEDULER_DB)
        c = conn.cursor()
        c.execute(
            "UPDATE scheduled_scans SET enabled = ? WHERE id = ?", (enabled, scan_id)
        )
        conn.commit()
        conn.close()

        # Update job in scheduler if running
        if _scheduler and HAS_SCHEDULER:
            job_id = f"scan_{scan_id}"
            try:
                job = _scheduler.get_job(job_id)
                if job:
                    job.reschedule(trigger="cron", reschedule_on_remove=not enabled)
            except Exception as e:
                logger.debug(f"Could not reschedule job {job_id}: {e}")

        return True
    except Exception as e:
        logger.exception(f"Failed to toggle scheduled scan: {e}")
        return False


def _add_job_to_scheduler(scan_id: int, target: str, cron_expression: str):
    """Add a scan job to the running scheduler."""
    if not _scheduler or not HAS_SCHEDULER:
        return

    job_id = f"scan_{scan_id}"

    async def _run_scan():
        try:
            logger.info(f"Running scheduled scan for {target} (scan_id={scan_id})")
            cmd = f"python -m cybersec_cli scan {target}"
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=str(Path(__file__).parent.parent),
            )
            stdout, stderr = await process.communicate()

            # Update last_run
            conn = sqlite3.connect(SCHEDULER_DB)
            c = conn.cursor()
            now = datetime.utcnow().isoformat() + "Z"
            c.execute(
                "UPDATE scheduled_scans SET last_run = ? WHERE id = ?", (now, scan_id)
            )
            conn.commit()
            conn.close()

            if process.returncode == 0:
                logger.info(f"Scheduled scan {scan_id} completed successfully")
            else:
                logger.warning(
                    f"Scheduled scan {scan_id} failed with code {process.returncode}"
                )
        except Exception as e:
            logger.exception(f"Error running scheduled scan {scan_id}: {e}")

    try:
        trigger = CronTrigger.from_crontab(cron_expression)
        _scheduler.add_job(
            _run_scan,
            trigger=trigger,
            id=job_id,
            name=f"Scan {target}",
            replace_existing=True,
        )
        logger.info(f"Added job {job_id} to scheduler: {target} @ {cron_expression}")
    except Exception as e:
        logger.exception(f"Failed to add job to scheduler: {e}")


async def init_scheduler():
    """Initialize and start the scheduler."""
    global _scheduler

    if not HAS_SCHEDULER:
        logger.debug("APScheduler not available; scheduler disabled")
        return

    if _scheduler is not None:
        return  # Already initialized

    try:
        init_scheduler_db()

        _scheduler = AsyncIOScheduler()
        _scheduler.start()
        logger.info("Scheduler started")

        # Load and restore jobs
        scans = list_scheduled_scans()
        for scan in scans:
            if scan["enabled"]:
                _add_job_to_scheduler(
                    scan["id"], scan["target"], scan["cron_expression"]
                )

        logger.info(
            f'Loaded {len([s for s in scans if s["enabled"]])} enabled scheduled scans'
        )
    except Exception as e:
        logger.exception(f"Failed to initialize scheduler: {e}")
        _scheduler = None


async def shutdown_scheduler():
    """Shutdown the scheduler gracefully."""
    global _scheduler
    if _scheduler and HAS_SCHEDULER:
        try:
            _scheduler.shutdown()
            logger.info("Scheduler shut down")
        except Exception as e:
            logger.exception(f"Error shutting down scheduler: {e}")
        _scheduler = None
