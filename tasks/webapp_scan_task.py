"""
Celery task for asynchronous web application vulnerability scanning.
Mirrors the pattern used in tasks/scan_tasks.py.
"""

import asyncio
import json
import logging
import os
import sys
import time
from typing import Any, Dict, Optional

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from tasks.celery_app import celery_app

logger = logging.getLogger(__name__)


def _get_event_loop():
    """Get or create a reusable event loop for this worker."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            raise RuntimeError("closed")
        return loop
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        return loop


@celery_app.task(
    bind=True,
    name="tasks.webapp_scan",
    max_retries=2,
    default_retry_delay=5,
    track_started=True,
)
def webapp_scan_task(
    self,
    url: str,
    timeout: float = 10.0,
    max_pages: int = 20,
    crawl: bool = True,
) -> Dict[str, Any]:
    """
    Asynchronous Celery task that runs a full web app vulnerability scan.

    Args:
        url:       Full URL to scan (e.g. https://example.com)
        timeout:   Per-request HTTP timeout in seconds
        max_pages: Maximum pages to crawl
        crawl:     Whether to follow discovered links

    Returns:
        Dict serialisation of WebAppScanResult
    """
    from src.cybersec_cli.utils.webapp_scanner import scan_webapp

    logger.info("Starting webapp scan task for %s", url)
    self.update_state(state="PROGRESS", meta={"status": "scanning", "url": url})

    try:
        loop = _get_event_loop()
        result = loop.run_until_complete(
            scan_webapp(url=url, timeout=timeout, max_pages=max_pages, crawl=crawl)
        )

        # Serialise dataclasses to plain dicts for Celery result backend
        findings_data = []
        for f in result.findings:
            findings_data.append({
                "vuln_type":   f.vuln_type.value,
                "severity":    f.severity.value,
                "title":       f.title,
                "description": f.description,
                "evidence":    f.evidence,
                "path":        f.path,
                "remediation": f.remediation,
                "cvss_score":  f.cvss_score,
                "cwe_id":      f.cwe_id,
                "references":  f.references,
            })

        output = {
            "target":         result.target,
            "base_url":       result.base_url,
            "scan_duration":  result.scan_duration,
            "pages_tested":   result.pages_tested,
            "total_requests": result.total_requests,
            "risk_score":     result.risk_score,
            "findings":       findings_data,
            "technologies":   result.technologies,
            "forms_found":    result.forms_found,
            "critical_count": result.critical_count,
            "high_count":     result.high_count,
            "error":          result.error,
            "status":         "completed",
        }

        logger.info(
            "Webapp scan completed for %s — %d findings, risk score %d",
            url, len(findings_data), result.risk_score,
        )
        return output

    except Exception as exc:
        logger.exception("Webapp scan task failed for %s: %s", url, exc)
        try:
            raise self.retry(exc=exc)
        except self.MaxRetriesExceededError:
            return {
                "target":   url,
                "error":    str(exc),
                "status":   "failed",
                "findings": [],
            }
