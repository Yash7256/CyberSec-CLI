"""
Web Application Scanner API endpoints.

Adds to web/main.py:
  POST /api/webapp/scan        — start a scan (async via Celery or sync fallback)
  GET  /api/webapp/scan/{id}   — poll task status / get results
  POST /api/webapp/scan/quick  — synchronous scan for small targets (< 30s)
"""

import asyncio
import uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, validator

router = APIRouter(prefix="/api/webapp", tags=["Web App Scanner"])


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class WebAppScanRequest(BaseModel):
    url: str
    timeout: float = 10.0
    max_pages: int = 20
    crawl: bool = True

    @validator("url")
    def validate_url(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("URL cannot be empty")
        if not v.startswith(("http://", "https://")):
            v = "https://" + v
        # Basic SSRF guard — block private/loopback ranges
        import re
        blocked = [
            r"localhost", r"127\.\d+\.\d+\.\d+", r"0\.0\.0\.0",
            r"10\.\d+\.\d+\.\d+", r"172\.(1[6-9]|2\d|3[01])\.\d+\.\d+",
            r"192\.168\.\d+\.\d+", r"169\.254\.\d+\.\d+",
            r"::1", r"\[::1\]",
        ]
        for pattern in blocked:
            if re.search(pattern, v, re.IGNORECASE):
                raise ValueError(
                    f"Scanning internal/private addresses is not permitted: {v}"
                )
        if len(v) > 500:
            raise ValueError("URL too long")
        return v

    @validator("max_pages")
    def cap_pages(cls, v: int) -> int:
        return min(max(v, 1), 100)

    @validator("timeout")
    def cap_timeout(cls, v: float) -> float:
        return min(max(v, 2.0), 30.0)


class TaskStatusResponse(BaseModel):
    task_id: str
    status: str
    url: str
    created_at: str
    result: Optional[dict] = None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post(
    "/scan",
    summary="Start web application vulnerability scan",
    description=(
        "Queues a full web application vulnerability scan via Celery. "
        "Returns a task ID immediately — poll /api/webapp/scan/{task_id} for results. "
        "Falls back to synchronous execution if Celery is unavailable."
    ),
    responses={
        202: {"description": "Scan queued successfully"},
        200: {"description": "Scan completed synchronously (Celery unavailable)"},
        400: {"description": "Invalid URL"},
        429: {"description": "Rate limit exceeded"},
    },
)
async def start_webapp_scan(request_body: WebAppScanRequest, request: Request):
    """Queue or run a web application vulnerability scan."""

    # Rate limiting — reuse the existing middleware from main.py if available
    client_ip = request.client.host if request.client else "unknown"

    # Try Celery first
    try:
        from tasks.webapp_scan_task import webapp_scan_task
        task = webapp_scan_task.delay(
            url=request_body.url,
            timeout=request_body.timeout,
            max_pages=request_body.max_pages,
            crawl=request_body.crawl,
        )
        return JSONResponse(
            status_code=202,
            content={
                "task_id":    task.id,
                "status":     "queued",
                "url":        request_body.url,
                "created_at": datetime.utcnow().isoformat(),
                "poll_url":   f"/api/webapp/scan/{task.id}",
                "message":    "Scan queued. Poll the poll_url for results.",
            },
        )
    except Exception:
        pass

    # Celery unavailable — run synchronously (with a tight timeout)
    from src.cybersec_cli.utils.webapp_scanner import scan_webapp, format_webapp_report
    try:
        result = await asyncio.wait_for(
            scan_webapp(
                url=request_body.url,
                timeout=min(request_body.timeout, 10.0),
                max_pages=min(request_body.max_pages, 10),
                crawl=request_body.crawl,
            ),
            timeout=25.0,
        )
    except asyncio.TimeoutError:
        raise HTTPException(
            status_code=504,
            detail="Scan timed out. Use Celery for large targets.",
        )

    findings_data = [
        {
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
        }
        for f in result.findings
    ]

    return {
        "task_id":        str(uuid.uuid4()),
        "status":         "completed",
        "url":            result.target,
        "scan_duration":  result.scan_duration,
        "pages_tested":   result.pages_tested,
        "total_requests": result.total_requests,
        "risk_score":     result.risk_score,
        "findings":       findings_data,
        "technologies":   result.technologies,
        "critical_count": result.critical_count,
        "high_count":     result.high_count,
        "error":          result.error,
        "created_at":     datetime.utcnow().isoformat(),
    }


@router.get(
    "/scan/{task_id}",
    summary="Get web app scan status or results",
    description="Poll this endpoint after starting a scan. Returns status while running, full results when complete.",
)
async def get_webapp_scan_result(task_id: str):
    """Get the status or result of a queued scan task."""
    try:
        from celery.result import AsyncResult
        from tasks.celery_app import celery_app

        result = AsyncResult(task_id, app=celery_app)

        if result.state == "PENDING":
            return {"task_id": task_id, "status": "pending", "result": None}

        if result.state == "PROGRESS":
            return {
                "task_id": task_id,
                "status":  "running",
                "meta":    result.info,
                "result":  None,
            }

        if result.state == "SUCCESS":
            return {
                "task_id": task_id,
                "status":  "completed",
                "result":  result.result,
            }

        if result.state == "FAILURE":
            return JSONResponse(
                status_code=500,
                content={
                    "task_id": task_id,
                    "status":  "failed",
                    "error":   str(result.result),
                },
            )

        return {"task_id": task_id, "status": result.state.lower(), "result": None}

    except Exception as e:
        raise HTTPException(
            status_code=404,
            detail=f"Task {task_id} not found or Celery unavailable: {e}",
        )


@router.post(
    "/scan/quick",
    summary="Synchronous quick scan",
    description=(
        "Runs a lightweight scan synchronously — no Celery needed. "
        "Limited to 5 pages, 8s timeout. Good for CI/CD pipelines."
    ),
)
async def quick_webapp_scan(request_body: WebAppScanRequest):
    """Quick synchronous scan — limited depth, fast turnaround."""
    from src.cybersec_cli.utils.webapp_scanner import scan_webapp

    try:
        result = await asyncio.wait_for(
            scan_webapp(
                url=request_body.url,
                timeout=8.0,
                max_pages=5,
                crawl=False,   # No crawling in quick mode
            ),
            timeout=20.0,
        )
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Quick scan timed out.")

    findings_data = [
        {
            "vuln_type":   f.vuln_type.value,
            "severity":    f.severity.value,
            "title":       f.title,
            "description": f.description,
            "evidence":    f.evidence,
            "path":        f.path,
            "remediation": f.remediation,
            "cvss_score":  f.cvss_score,
            "cwe_id":      f.cwe_id,
        }
        for f in result.findings
    ]

    return {
        "status":         "completed",
        "url":            result.target,
        "scan_duration":  result.scan_duration,
        "risk_score":     result.risk_score,
        "findings":       findings_data,
        "technologies":   result.technologies,
        "critical_count": result.critical_count,
        "high_count":     result.high_count,
        "error":          result.error,
    }
