import asyncio
try:
    import asyncpg
except ImportError:  # Optional dependency for PostgreSQL support
    asyncpg = None
import functools
import hmac
import json
import logging
import os
import secrets
import signal
import socket
import sqlite3
import subprocess
import shlex
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from dotenv import load_dotenv

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

from fastapi import Depends, FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse, JSONResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from pydantic import BaseModel
from src.cybersec_cli.utils.logger import log_forced_scan
from src.cybersec_cli.core.auth import verify_api_key
from src.cybersec_cli.core.validators import validate_target, validate_port_range


def _timing_safe_compare(a: Optional[str], b: Optional[str]) -> bool:
    if not isinstance(a, str) or not isinstance(b, str):
        return False
    return hmac.compare_digest(a, b)


class OSFingerprintRequest(BaseModel):
    """Request model for OS fingerprinting operations."""

    target: str
    os_detection: bool = True
    enhanced_service_detection: bool = True
    service_detection: bool = True


# Load environment variables from .env file
load_dotenv()

# Import structured logging
try:
    from src.cybersec_cli.core.logging_config import (
        get_logger,
        setup_logging,
        set_request_id,
    )
    from src.cybersec_cli.config import settings

    setup_logging(
        log_dir=settings.logging.log_dir, audit_log_file=settings.logging.audit_log_file
    )
    HAS_STRUCTURED_LOGGING = True
except ImportError:
    HAS_STRUCTURED_LOGGING = False
    def set_request_id(_request_id: str) -> None:
        return None

# Import Redis client
try:
    from src.cybersec_cli.core.redis_client import redis_client

    HAS_REDIS = True
except ImportError:
    HAS_REDIS = False
    redis_client = None

# Import rate limiter
try:
    from src.cybersec_cli.core.rate_limiter import SmartRateLimiter

    HAS_RATE_LIMITER = True
except ImportError:
    HAS_RATE_LIMITER = False
    SmartRateLimiter = None

# Import metrics
try:
    from monitoring.metrics import metrics_collector

    HAS_METRICS = True
except ImportError:
    HAS_METRICS = False
    metrics_collector = None

# Import port priority
try:
    from src.cybersec_cli.core.port_priority import get_scan_order

    HAS_PRIORITY_MODULE = True
except ImportError:
    HAS_PRIORITY_MODULE = False

    def get_scan_order(ports: List[int]) -> List[List[int]]:
        # Fallback implementation if core module not available
        # Split ports into 4 roughly equal priority groups
        port_list = list(ports) if ports else []
        if not port_list:
            return [[], [], [], []]
        n = len(port_list)
        quarter = n // 4
        return [
            port_list[:quarter],
            port_list[quarter:quarter*2],
            port_list[quarter*2:quarter*3],
            port_list[quarter*3:]
        ]


# Optional Redis-backed rate limiting (if aioredis is available and REDIS_URL set)
REDIS_URL = os.getenv("REDIS_URL")
_redis = None


async def _redis_check_and_increment_rate(client: str) -> bool:
    """Increment per-minute rate counter in Redis and return True if under limit.

    If Redis is not configured, return False so callers will fallback to in-memory logic.
    """
    if _redis is None:
        logger.debug("Redis not configured; skipping redis rate check")
        return False
    try:
        key = f"rate:{client}"
        cnt = await _redis.incr(key)
        if cnt == 1:
            await _redis.expire(key, 60)
        if cnt > WS_RATE_LIMIT:
            # decrement back and deny
            await _redis.decr(key)
            return False
        return True
    except Exception:
        logger.debug("Redis rate check failed; falling back to in-memory")
        return False


async def _redis_increment_active(client: str) -> bool:
    """Increment active scans counter in Redis and return True if under concurrency limit.

    If Redis is not configured, return False so callers will fallback to in-memory logic.
    """
    if _redis is None:
        logger.debug("Redis not configured; skipping redis active increment")
        return False
    try:
        key = f"active:{client}"
        cnt = await _redis.incr(key)
        if cnt == 1:
            # Set a generous expiry in case of unexpected crashes (e.g., 10 minutes)
            await _redis.expire(key, 600)
        if cnt > WS_CONCURRENT_LIMIT:
            await _redis.decr(key)
            return False
        return True
    except Exception:
        logger.debug("Redis active increment failed; falling back to in-memory")
        return False


async def _redis_decrement_active(client: str):
    if _redis is None:
        logger.debug("Redis not configured; skipping redis active decrement")
        return
    try:
        key = f"active:{client}"
        await _redis.decr(key)
    except Exception:
        logger.debug("Redis active decrement failed")


# Set up logging
if HAS_STRUCTURED_LOGGING:
    logger = get_logger("api")
else:
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)


async def init_redis():
    """Initialize aioredis client if REDIS_URL is set. Safe to call multiple times.

    This function will set the module-level `_redis` variable when aioredis is available.
    """
    global _redis
    if not REDIS_URL:
        logger.debug("REDIS_URL not set; skipping redis initialization")
        return
    if _redis is not None:
        # already initialized
        return
    try:
        import aioredis

        _redis = aioredis.from_url(REDIS_URL)
        logger.info("Redis configured for rate limiting")
    except Exception as e:
        _redis = None
        logger.debug(
            f"Redis not available or failed to initialize: {e}; falling back to in-memory rate limiting"
        )


# Initialize rate limiter
rate_limiter = None


async def init_rate_limiter():
    """Initialize the advanced rate limiter."""
    global rate_limiter
    if HAS_RATE_LIMITER and HAS_REDIS and redis_client:
        rate_limiter = SmartRateLimiter(
            redis_client.redis_client, settings.rate_limit.dict()
        )
        logger.info("Advanced rate limiter initialized")
    else:
        logger.warning("Rate limiter not available")


async def rate_limit_dependency(request: Request):
    """Apply rate limiting to protected routes."""
    if not (HAS_RATE_LIMITER and rate_limiter):
        return

    client_id = request.client.host if request.client else "unknown"
    if rate_limiter.is_on_cooldown(client_id):
        raise HTTPException(status_code=429, detail="Rate limit cooldown in effect")

    if not rate_limiter.check_client_limit(client_id):
        rate_limiter.record_violation(client_id)
        rate_limiter.apply_cooldown(client_id)
        raise HTTPException(status_code=429, detail="Rate limit exceeded")


def _get_loop_time() -> float:
    """Return monotonic time from running loop or a new loop in sync contexts."""
    try:
        return asyncio.get_running_loop().time()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        try:
            return loop.time()
        finally:
            loop.close()


async def _check_and_record_rate_limit(client_host: str) -> bool:
    """Check rate limit for client using Redis (if available) or in-memory fallback.

    Returns True if allowed (and increments counter), False if rate limit exceeded.
    """
    # Try Redis first
    if _redis is not None:
        allowed = await _redis_check_and_increment_rate(client_host)
        if allowed:
            return True
        # Redis said no
        return False

    # Fallback to in-memory rate limiting
    now = int(_get_loop_time())
    rc = _rate_counters.get(client_host)
    if rc is None or now >= rc.get("reset_at", 0):
        # Reset window
        _rate_counters[client_host] = {"count": 0, "reset_at": now + 60}
        rc = _rate_counters[client_host]
    if rc["count"] >= WS_RATE_LIMIT:
        return False
    # Increment and allow
    rc["count"] += 1
    return True


class ScanConcurrencyTracker:
    """Track concurrent scans with a shared lock to prevent races."""

    def __init__(self):
        self._scan_lock = asyncio.Lock()
        self._active_scans: Dict[str, int] = {}

    async def record_scan_start(self, client_host: str) -> bool:
        """Record the start of a scan (increment concurrency counter)."""
        # Try Redis first
        if _redis is not None:
            allowed = await _redis_increment_active(client_host)
            if allowed:
                return True
            # Redis said no
            return False

        # Fallback to in-memory concurrency limiting with lock for thread safety
        async with self._scan_lock:
            if self._active_scans.get(client_host, 0) >= WS_CONCURRENT_LIMIT:
                return False
            self._active_scans[client_host] = self._active_scans.get(client_host, 0) + 1
        return True

    async def record_scan_end(self, client_host: str):
        """Record the end of a scan (decrement concurrency counter)."""
        # Try Redis first
        if _redis is not None:
            await _redis_decrement_active(client_host)
        else:
            # Fallback to in-memory with lock for thread safety
            async with self._scan_lock:
                self._active_scans[client_host] = max(
                    0, self._active_scans.get(client_host, 1) - 1
                )

    def has_active_scans(self) -> bool:
        """Return True if any in-memory scans are still active."""
        return any(v > 0 for v in self._active_scans.values())


# Base directory for the web app
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Config: optional WebSocket API key. If set, clients must provide this token as ?token=XXX
WS_API_KEY = os.getenv("WEBSOCKET_API_KEY")
# Rate limiting: scans per minute per client
WS_RATE_LIMIT = int(os.getenv("WS_RATE_LIMIT", "5"))
# Concurrent scans per client
WS_CONCURRENT_LIMIT = int(os.getenv("WS_CONCURRENT_LIMIT", "2"))

# In-memory state for rate limiting and concurrency (simple, per-process)
_rate_counters: Dict[str, Dict] = {}
_last_scan_time: Dict[str, float] = {}

# Concurrency tracker with internal lock
scan_concurrency = ScanConcurrencyTracker()

# Persistence: simple SQLite DB for scan results
REPORTS_DIR = os.path.join(os.path.dirname(BASE_DIR), "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)
SCANS_DB = os.path.join(REPORTS_DIR, "scans.db")

async def _run_blocking(func, *args, **kwargs):
    """Run blocking work in a dedicated thread pool."""
    if os.getenv("PYTEST_CURRENT_TEST"):
        return func(*args, **kwargs)
    loop = asyncio.get_running_loop()
    # Use a short-lived executor to avoid hangs in the default executor.
    with ThreadPoolExecutor(max_workers=1) as executor:
        return await loop.run_in_executor(executor, functools.partial(func, *args, **kwargs))


def init_db():
    conn = sqlite3.connect(SCANS_DB)
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
    conn.close()


def ensure_allowlists():
    # Ensure allowlist/denylist files exist (empty by default)
    try:
        repo_reports = os.path.join(os.path.dirname(BASE_DIR), "reports")
        os.makedirs(repo_reports, exist_ok=True)
        for fn in ("allowlist.txt", "denylist.txt"):
            path = os.path.join(repo_reports, fn)
            if not os.path.exists(path):
                Path(path).touch(exist_ok=True)
    except Exception:
        logger.debug("Failed to ensure allowlist/denylist files")


ensure_allowlists()


ALLOWED_SCAN_FLAGS_WITH_VALUE = {
    "-p",
    "--ports",
    "--scan-type",
    "--timeout",
    "--concurrent",
    "--rate-limit",
    "--format",
}

ALLOWED_SCAN_FLAGS_NO_VALUE = {
    "--no-service-detection",
    "--streaming",
    "--verbose",
    "-v",
    "--no-banner",
    "--require-reachable",
    "--no-require-reachable",
    "--force",
    "--test",
    "--os",
    "--os-only",
    "--adaptive",
    "--no-adaptive",
    "--enhanced-service-detection",
    "--no-enhanced-service-detection",
}


def _parse_ports_arg(ports_str: str) -> List[int]:
    ports: List[int] = []
    for part in ports_str.split(","):
        part = part.strip()
        if not part:
            raise ValueError("Empty port value")
        if "-" in part:
            start_str, end_str = part.split("-", 1)
            start = int(start_str)
            end = int(end_str)
            if start < 1 or end > 65535 or start > end:
                raise ValueError("Invalid port range")
            range_len = end - start + 1
            if len(ports) + range_len > 1000:
                raise ValueError("Port range too large")
            ports.extend(list(range(start, end + 1)))
        else:
            port = int(part)
            if port < 1 or port > 65535:
                raise ValueError("Invalid port value")
            ports.append(port)
        if len(ports) > 1000:
            raise ValueError("Port range too large")

    if not validate_port_range(ports):
        raise ValueError("Invalid port list")
    return ports


def _parse_and_validate_scan_command(raw_command: str) -> List[str]:
    tokens = shlex.split(raw_command)
    if not tokens or tokens[0].lower() != "scan":
        raise ValueError("Only 'scan' commands are allowed")

    if len(tokens) < 2:
        raise ValueError("Missing scan target")

    target = tokens[1]
    if target.startswith("-") or not validate_target(target):
        raise ValueError("Invalid target")

    safe_tokens = ["scan", target]
    i = 2
    while i < len(tokens):
        tok = tokens[i]
        if tok.startswith("--") and "=" in tok:
            flag, val = tok.split("=", 1)
            if flag not in ALLOWED_SCAN_FLAGS_WITH_VALUE:
                raise ValueError(f"Unsupported option: {flag}")
            _validate_scan_flag_value(flag, val)
            safe_tokens.extend([flag, val])
            i += 1
            continue

        if tok in ALLOWED_SCAN_FLAGS_NO_VALUE:
            safe_tokens.append(tok)
            i += 1
            continue

        if tok in ALLOWED_SCAN_FLAGS_WITH_VALUE:
            if i + 1 >= len(tokens):
                raise ValueError(f"Missing value for {tok}")
            val = tokens[i + 1]
            _validate_scan_flag_value(tok, val)
            safe_tokens.extend([tok, val])
            i += 2
            continue

        raise ValueError(f"Unsupported option: {tok}")

    return safe_tokens


def _validate_scan_flag_value(flag: str, value: str) -> None:
    if flag in ("-p", "--ports"):
        _parse_ports_arg(value)
        return

    if flag == "--scan-type":
        allowed = {"tcp_connect", "tcp_syn", "udp", "fin", "null", "xmas"}
        if value.lower() not in allowed:
            raise ValueError("Invalid scan type")
        return

    if flag == "--timeout":
        t = float(value)
        if t <= 0 or t > 60:
            raise ValueError("Invalid timeout")
        return

    if flag == "--concurrent":
        c = int(value)
        if c < 1 or c > 1000:
            raise ValueError("Invalid concurrency")
        return

    if flag == "--rate-limit":
        r = int(value)
        if r < 0 or r > 1000:
            raise ValueError("Invalid rate limit")
        return

    if flag == "--format":
        if value.lower() not in {"table", "json", "csv", "list"}:
            raise ValueError("Invalid format")
        return


def save_scan_result(target: str, ip: Optional[str], command: str, output: str) -> int:
    try:
        with sqlite3.connect(SCANS_DB) as conn:
            c = conn.cursor()
            ts = datetime.utcnow().isoformat() + "Z"
            c.execute(
                "INSERT INTO scans (timestamp, target, ip, command, output) VALUES (?, ?, ?, ?, ?)",
                (ts, target, ip or "", command, output),
            )
            conn.commit()
            return c.lastrowid
    except Exception:
        logger.exception("Failed to save scan result")
        return -1


def list_scans(limit: int = 50):
    try:
        with sqlite3.connect(SCANS_DB) as conn:
            c = conn.cursor()
            c.execute(
                "SELECT id, timestamp, target, ip, command FROM scans ORDER BY id DESC LIMIT ?",
                (limit,),
            )
            rows = c.fetchall()
        return [
            dict(id=r[0], timestamp=r[1], target=r[2], ip=r[3], command=r[4])
            for r in rows
        ]
    except Exception:
        logger.exception("Failed to list scans")
        return []


def get_scan_output(scan_id: int) -> Optional[str]:
    try:
        with sqlite3.connect(SCANS_DB) as conn:
            c = conn.cursor()
            c.execute("SELECT output FROM scans WHERE id = ?", (scan_id,))
            row = c.fetchone()
        return row[0] if row else None
    except Exception:
        logger.exception("Failed to get scan output")
        return None


# Initialize DB on startup
init_db()

# Create FastAPI app with enhanced OpenAPI schema
app = FastAPI(
    title="CyberSec-CLI API",
    description="Comprehensive cybersecurity CLI tool with web interface for network scanning, vulnerability assessment, and security analysis.",
    version="1.0.0",
    contact={
        "name": "CyberSec-CLI Team",
        "url": "https://github.com/CyberSec-CLI",
        "email": "support@cybersec-cli.com",
    },
    license_info={
        "name": "MIT License",
        "url": "https://opensource.org/licenses/MIT",
    },
    openapi_tags=[
        {"name": "Authentication", "description": "API key authentication endpoints"},
        {"name": "Scanning", "description": "Network scanning operations and results"},
        {"name": "Streaming", "description": "Real-time scan result streaming"},
        {
            "name": "Async Scanning",
            "description": "Asynchronous scan operations with Celery",
        },
        {"name": "Rate Limiting", "description": "Rate limiting and abuse prevention"},
        {"name": "Health", "description": "System health and monitoring endpoints"},
        {"name": "WebSocket", "description": "WebSocket-based real-time communication"},
    ],
)


# Initialize optional services on startup (e.g. Redis)
@app.on_event("startup")
async def _on_startup():
    await init_redis()
    await init_rate_limiter()
    await init_db_pool()


async def init_db_pool():
    """Initialize asyncpg pool for PostgreSQL if configured."""
    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        app.state.db_pool = None
        logger.info("DATABASE_URL not set; skipping PostgreSQL pool")
        return
    if asyncpg is None:
        app.state.db_pool = None
        logger.warning("asyncpg not installed; skipping PostgreSQL pool")
        return
    try:
        app.state.db_pool = await asyncpg.create_pool(database_url)
        logger.info("PostgreSQL pool initialized")
    except Exception as e:
        logger.error(f"Failed to initialize PostgreSQL pool: {e}")
        app.state.db_pool = None


async def get_db(request: Request):
    """Acquire a pooled PostgreSQL connection for the request."""
    pool = getattr(request.app.state, "db_pool", None)
    if pool is None:
        yield None
        return
    async with pool.acquire() as conn:
        yield conn


async def wait_for_active_scans() -> None:
    """Wait for active scans to complete before shutdown."""
    # Poll until all in-memory active scans have drained
    while scan_concurrency.has_active_scans():
        await asyncio.sleep(0.5)
    return None


@app.on_event("shutdown")
async def shutdown():
    """Cleanup on shutdown"""
    logger.info("Shutting down gracefully...")

    # Wait for active scans to complete (with timeout)
    try:
        await asyncio.wait_for(wait_for_active_scans(), timeout=30.0)
    except asyncio.TimeoutError:
        logger.warning("Shutdown timeout reached, forcing exit")

    # Close database connections
    pool = getattr(app.state, "db_pool", None)
    if pool:
        await pool.close()

    # Close Redis connections
    if redis_client and hasattr(redis_client, "close"):
        redis_client.close()

    logger.info("Shutdown complete")


# Include Chat Router
try:
    from web.routes.chat import router as chat_router
    app.include_router(chat_router)
    logger.info("Chat router registered")
except Exception as e:
    logger.warning(f"Failed to register chat router: {e}")


# CORS middleware
# Validate settings before using for CORS
if settings is None:
    raise RuntimeError(
        "Application settings failed to load. Check that the configuration module "
        "is properly installed and environment variables are set. "
        "Cannot start without valid settings."
    )

# Handle case where settings.cors might not be defined
cors_config = getattr(settings, "cors", None)
if cors_config is None:
    raise RuntimeError(
        "CORS configuration is missing (settings.cors is None). "
        "Set CORS settings explicitly; permissive defaults are not allowed."
    )

app.add_middleware(
    CORSMiddleware,
    allow_origins=getattr(cors_config, "allow_origins", []),
    allow_credentials=getattr(cors_config, "allow_credentials", False),
    allow_methods=getattr(cors_config, "allow_methods", ["GET", "POST", "PUT", "DELETE"]),
    allow_headers=getattr(cors_config, "allow_headers", ["Content-Type", "Authorization"]),
)

# Security headers middleware


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        nonce = secrets.token_urlsafe(16)
        request.state.csp_nonce = nonce
        response = await call_next(request)

        # Add security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
        csp = (
            f"script-src 'nonce-{nonce}' 'strict-dynamic'; "
            f"style-src 'nonce-{nonce}'; "
            "object-src 'none'; base-uri 'none';"
        )
        response.headers["Content-Security-Policy"] = csp

        return response


app.add_middleware(SecurityHeadersMiddleware)


# API Key Authentication Middleware
class APIKeyAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # List of endpoints that don't require authentication
        public_endpoints = [
            "/",
            "/health/redis",
            "/api/status",
            "/metrics",
            "/static",
            "/docs",
            "/redoc",
            "/openapi.json",
        ]

        # Check if the endpoint is public
        is_public = any(request.url.path.startswith(ep) for ep in public_endpoints)

        if not is_public:
            # Check for API key in Authorization header only (query params are not secure)
            auth_header = request.headers.get("Authorization")
            if not auth_header:
                raise HTTPException(
                    status_code=401,
                    detail="API key must be provided via Authorization header",
                )
            scheme, _, token = auth_header.partition(" ")
            if scheme.lower() != "bearer" or not token.strip():
                raise HTTPException(
                    status_code=401,
                    detail="API key must be provided via Authorization header",
                )
            api_key = token.strip()

            # Verify the API key
            key_info = verify_api_key(api_key)
            if not key_info:
                raise HTTPException(status_code=401, detail="Invalid API key")

        response = await call_next(request)
        return response


app.add_middleware(APIKeyAuthMiddleware)

# Import for request ID tracking

# Global shutdown event
shutdown_event = asyncio.Event()


# Request ID tracking middleware
class RequestIDMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Generate or extract request ID
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())

        # Add request ID to request state for access in endpoints
        request.state.request_id = request_id

        # Set context for logging
        set_request_id(request_id)

        response = await call_next(request)

        # Add request ID to response headers
        response.headers["X-Request-ID"] = request_id

        return response


app.add_middleware(RequestIDMiddleware)


def handle_shutdown(signum, frame):
    """Handle shutdown signals"""
    logger.info(f"Received signal {signum}, initiating graceful shutdown...")
    shutdown_event.set()


# Register signal handlers
signal.signal(signal.SIGTERM, handle_shutdown)
signal.signal(signal.SIGINT, handle_shutdown)


# Global exception handlers
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler for all unhandled exceptions"""
    # Log the exception with full context
    logger.error(
        f"Unhandled exception in API: {str(exc)}",
        extra={
            "context": {
                "endpoint": request.url.path,
                "method": request.method,
                "client_ip": request.client.host if request.client else None,
                "exception_type": type(exc).__name__,
            }
        },
    )

    # Return user-friendly error message
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "message": "An unexpected error occurred. Please try again later.",
            "request_id": getattr(request.state, "request_id", None),
        },
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP exceptions"""
    # Log HTTP exceptions as well
    logger.warning(
        f"HTTP exception: {exc.status_code} - {exc.detail}",
        extra={
            "context": {
                "endpoint": request.url.path,
                "method": request.method,
                "client_ip": request.client.host if request.client else None,
                "status_code": exc.status_code,
            }
        },
    )

    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": "Request error",
            "message": exc.detail,
            "request_id": getattr(request.state, "request_id", None),
        },
    )


# Static files directory
STATIC_DIR = os.path.join(BASE_DIR, "static")

# Create static directory if it doesn't exist
os.makedirs(STATIC_DIR, exist_ok=True)
os.makedirs(os.path.join(STATIC_DIR, "img"), exist_ok=True)

# Mount static files
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# Admin files
ADMIN_DIR = os.path.join(BASE_DIR, "admin")
if os.path.exists(ADMIN_DIR):
    app.mount("/admin", StaticFiles(directory=ADMIN_DIR), name="admin")

def _render_html_with_nonce(file_path: Path, nonce: str) -> HTMLResponse:
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()
    content = content.replace("{{CSP_NONCE}}", nonce)
    return HTMLResponse(content=content)


@app.get("/admin", include_in_schema=False)
async def admin_dashboard(request: Request):
    """Serve the admin dashboard page."""
    base = Path(ADMIN_DIR).resolve()
    requested = (base / "rate_limits.html").resolve()
    if not str(requested).startswith(str(base)):
        raise HTTPException(403, "Access denied")
    if requested.exists():
        nonce = getattr(request.state, "csp_nonce", "")
        return _render_html_with_nonce(requested, nonce)
    else:
        raise HTTPException(status_code=404, detail="Admin dashboard not found")


class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        # Accept the websocket first; auth will be checked in endpoint
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception as e:
                logger.error(f"Error broadcasting message: {e}")


manager = ConnectionManager()


# API Endpoints
@app.get(
    "/",
    tags=["Static Content"],
    summary="Serve main page",
    description="Serves the main HTML page for the CyberSec-CLI web interface.",
)
async def read_root(request: Request):
    index_path = Path(STATIC_DIR) / "index.html"
    nonce = getattr(request.state, "csp_nonce", "")
    return _render_html_with_nonce(index_path, nonce)


@app.get(
    "/api/status",
    tags=["Health"],
    summary="Get API status",
    description="Returns the current status of the CyberSec-CLI API.",
    responses={
        200: {
            "description": "API status information",
            "content": {
                "application/json": {
                    "example": {"status": "CyberSec-CLI API is running"}
                }
            },
        }
    },
)
async def get_status():
    return {"status": "CyberSec-CLI API is running"}


@app.get(
    "/health/redis",
    tags=["Health"],
    summary="Check Redis health",
    description="Health check endpoint for Redis connectivity and latency.",
    responses={
        200: {
            "description": "Redis health status",
            "content": {
                "application/json": {
                    "examples": {
                        "healthy": {
                            "summary": "Healthy Redis connection",
                            "value": {
                                "status": "healthy",
                                "latency_ms": 2.5,
                                "message": "Redis connection is healthy",
                            },
                        },
                        "unhealthy": {
                            "summary": "Unhealthy Redis connection",
                            "value": {
                                "status": "unhealthy",
                                "error": "Connection refused",
                                "message": "Redis connection failed",
                            },
                        },
                        "disabled": {
                            "summary": "Redis not configured",
                            "value": {
                                "status": "disabled",
                                "message": "Redis is not available or not configured",
                            },
                        },
                    }
                }
            },
        }
    },
)
async def redis_health_check():
    """Health check endpoint for Redis connectivity and latency."""
    if not HAS_REDIS or redis_client is None:
        return {
            "status": "disabled",
            "message": "Redis is not available or not configured",
        }

    try:
        start_time = time.time()
        ping_fn = (
            redis_client.redis_client.ping
            if redis_client is not None and redis_client.redis_client is not None
            else None
        )
        if ping_fn is None:
            raise ConnectionError("Redis client not initialized")

        if asyncio.iscoroutinefunction(ping_fn):
            await ping_fn()
        else:
            # Test Redis connectivity - run sync call in thread pool
            await _run_blocking(ping_fn)

        latency = (time.time() - start_time) * 1000  # Convert to milliseconds

        return {
            "status": "healthy",
            "latency_ms": round(latency, 2),
            "message": "Redis connection is healthy",
        }
    except ConnectionError as e:
        return {
            "status": "unhealthy",
            "error": str(e),
            "message": "Redis connection failed",
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e),
            "message": "Redis connection failed",
        }


@app.get(
    "/health/postgres",
    tags=["Health"],
    summary="Check PostgreSQL health",
    description="Health check endpoint for PostgreSQL connectivity.",
    responses={
        200: {
            "description": "PostgreSQL health status",
            "content": {
                "application/json": {
                    "examples": {
                        "healthy": {
                            "summary": "Healthy PostgreSQL connection",
                            "value": {
                                "status": "healthy",
                                "message": "PostgreSQL connection is healthy",
                            },
                        },
                        "unhealthy": {
                            "summary": "Unhealthy PostgreSQL connection",
                            "value": {
                                "status": "unhealthy",
                                "error": "Connection refused",
                                "message": "PostgreSQL connection failed",
                            },
                        },
                        "disabled": {
                            "summary": "PostgreSQL not configured",
                            "value": {
                                "status": "disabled",
                                "message": "PostgreSQL is not available or not configured",
                            },
                        },
                    }
                }
            },
        }
    },
)
async def postgres_health(conn=Depends(get_db)):
    """Health check endpoint for PostgreSQL connectivity."""
    if conn is None:
        return {"status": "disabled", "message": "DATABASE_URL not set"}

    try:
        await conn.fetchval("SELECT 1")
        return {"status": "healthy", "message": "PostgreSQL connection is healthy"}
    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e),
            "message": "PostgreSQL connection failed",
        }


@app.get(
    "/api/audit/forced_scans",
    tags=["Audit"],
    summary="Get forced scan audit logs",
    description="Returns the forced scan audit log as JSON list (read from reports/forced_scans.jsonl).",
    responses={
        200: {
            "description": "List of forced scan audit entries",
            "content": {
                "application/json": {
                    "example": [
                        {
                            "timestamp": "2023-01-01T12:00:00Z",
                            "target": "example.com",
                            "resolved_ip": "93.184.216.34",
                            "original_command": "scan example.com",
                            "client_host": "127.0.0.1",
                            "consent": True,
                            "note": "forced_via_websocket",
                        }
                    ]
                }
            },
        }
    },
)
def _read_forced_scans_file(reports_file: str):
    if not os.path.exists(reports_file):
        return []
    entries = []
    try:
        with open(reports_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except Exception:
                    continue
    except Exception as e:
        logger.error(f"Error reading audit file: {e}")
        return []
    return entries


async def get_forced_scans():
    """Return the forced scan audit log as JSON list (read from reports/forced_scans.jsonl)."""
    reports_file = os.path.join(
        os.path.dirname(BASE_DIR), "reports", "forced_scans.jsonl"
    )
    return await _run_blocking(_read_forced_scans_file, reports_file)


@app.get(
    "/api/scans",
    tags=["Scanning"],
    summary="List scan results",
    description="Returns a list of previous scan results.",
    dependencies=[Depends(rate_limit_dependency)],
    responses={
        200: {
            "description": "List of scan results",
            "content": {
                "application/json": {
                    "example": [
                        {
                            "id": 1,
                            "timestamp": "2023-01-01T12:00:00Z",
                            "target": "example.com",
                            "ip": "93.184.216.34",
                            "command": "scan example.com --ports 1-1000",
                        }
                    ]
                }
            },
        }
    },
)
async def api_list_scans(limit: int = 50):
    return await _run_blocking(list_scans, limit)


@app.get(
    "/api/scans/{scan_id}",
    tags=["Scanning"],
    summary="Get scan result by ID",
    description="Returns the detailed output of a specific scan by its ID.",
    dependencies=[Depends(rate_limit_dependency)],
    responses={
        200: {
            "description": "Scan result details",
            "content": {
                "application/json": {
                    "example": {"id": 1, "output": "Scan results for example.com..."}
                }
            },
        },
        404: {
            "description": "Scan not found",
            "content": {"application/json": {"example": {"detail": "Scan not found"}}},
        },
    },
)
async def api_get_scan(scan_id: int):
    out = await _run_blocking(get_scan_output, scan_id)
    if out is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"id": scan_id, "output": out}


@app.get(
    "/api/stream/scan/{target}",
    tags=["Streaming"],
    summary="Stream scan results (SSE)",
    description="Stream port scan results using Server-Sent Events (SSE). Scans ports on the target and streams results as they become available.",
    dependencies=[Depends(rate_limit_dependency)],
    responses={
        200: {
            "description": "Streaming scan results",
            "content": {
                "text/event-stream": {
                    "examples": {
                        "scan_start": {
                            "summary": "Scan started event",
                            "value": 'data: {"type": "scan_start", "target": "example.com", "total_ports": 1000, "message": "Starting scan on example.com with 1000 ports"}\n\n',
                        },
                        "open_port": {
                            "summary": "Open port event",
                            "value": 'data: {"type": "open_port", "port": {"port": 80, "service": "http", "version": "Apache/2.4.41", "banner": "Apache/2.4.41", "confidence": 0.9, "protocol": "tcp"}, "progress": 25}\n\n',
                        },
                        "scan_complete": {
                            "summary": "Scan completed event",
                            "value": 'data: {"type": "scan_complete", "message": "Scan completed", "progress": 100}\n\n',
                        },
                    }
                }
            },
        }
    },
)
async def stream_scan_results(
    target: str, ports: str = "1-1000", enhanced_service_detection: bool = True
):
    """
    Stream port scan results using Server-Sent Events (SSE).
    Scans ports on the target and streams results as they become available.
    """

    async def event_generator():
        try:
            if not validate_target(target):
                raise ValueError("Invalid target")

            # Parse ports
            port_list = _parse_ports_arg(ports)

            # Group ports by priority
            priority_groups = get_scan_order(port_list)
            priority_names = ["critical", "high", "medium", "low"]

            # Calculate total ports for progress tracking
            total_ports = sum(len(group) for group in priority_groups)
            scanned_ports = 0

            # Send initial event
            yield f"data: {json.dumps({'type': 'scan_start', 'target': target, 'total_ports': total_ports, 'message': f'Starting scan on {target} with {total_ports} ports'})}\n\n"

            # Import scanner
            from src.cybersec_cli.tools.network.port_scanner import (
                PortScanner,
                PortState,
                ScanType,
            )

            # Scan each priority group
            for i, group in enumerate(priority_groups):
                if not group:
                    continue

                # Send group start event
                yield f"data: {json.dumps({'type': 'group_start', 'priority': priority_names[i], 'count': len(group)})}\n\n"

                # Create scanner for this group with enhanced service detection
                scanner = PortScanner(
                    target=target,
                    ports=group,
                    scan_type=ScanType.TCP_CONNECT,
                    timeout=1.0,
                    max_concurrent=50,
                    enhanced_service_detection=enhanced_service_detection,
                )

                # Scan ports in this group
                results = await scanner.scan()

                # Update scanned ports count
                scanned_ports += len(group)
                progress_percentage = (
                    round((scanned_ports / total_ports) * 100) if total_ports > 0 else 0
                )

                # Send results for this group
                open_ports = []
                for result in results:
                    if result.state == PortState.OPEN:
                        port_info = {
                            "port": result.port,
                            "service": result.service or "unknown",
                            "version": result.version or "unknown",
                            "banner": result.banner or "",
                            "confidence": result.confidence,
                            "protocol": result.protocol,
                        }
                        open_ports.append(port_info)
                        yield f"data: {json.dumps({'type': 'open_port', 'port': port_info, 'progress': progress_percentage})}\n\n"

                # Send group completion event with progress
                yield f"data: {json.dumps({'type': 'group_complete', 'priority': priority_names[i], 'open_count': len(open_ports), 'progress': progress_percentage})}\n\n"

            # Send scan completion event
            yield f"data: {json.dumps({'type': 'scan_complete', 'message': 'Scan completed', 'progress': 100})}\n\n"

        except Exception as e:
            yield f"data: {json.dumps({'type': 'error', 'message': str(e), 'progress': 0})}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.get(
    "/api/scan/stream",
    tags=["Streaming"],
    summary="Stream scan results with vulnerability analysis",
    description="Stream port scan results using Server-Sent Events (SSE) after each priority tier completes, with vulnerability analysis.",
    responses={
        200: {
            "description": "Streaming scan results with vulnerability analysis",
            "content": {
                "text/event-stream": {
                    "examples": {
                        "scan_start": {
                            "summary": "Scan started event",
                            "value": 'data: {"type": "scan_start", "target": "example.com", "total_ports": 1000, "progress": 0}\n\n',
                        },
                        "tier_results": {
                            "summary": "Tier results with vulnerability analysis",
                            "value": 'data: {"type": "tier_results", "priority": "critical", "open_ports": [{"port": 22, "service": "ssh", "version": "OpenSSH_7.9", "risk": "HIGH", "cvss_score": 7.5, "vulnerabilities": ["CVE-2019-6111"]}], "progress": 25}\n\n',
                        },
                        "scan_complete": {
                            "summary": "Scan completed event",
                            "value": 'data: {"type": "scan_complete", "message": "Scan completed", "progress": 100}\n\n',
                        },
                    }
                }
            },
        }
    },
)
async def stream_scan_results_new(
    target: str, ports: str = "1-1000", enhanced_service_detection: bool = True
):
    """
    Stream port scan results using Server-Sent Events (SSE) after each priority tier completes.
    """

    async def event_generator():
        try:
            if not validate_target(target):
                raise ValueError("Invalid target")

            # Parse ports
            port_list = _parse_ports_arg(ports)

            # Group ports by priority
            priority_groups = get_scan_order(port_list)
            priority_names = ["critical", "high", "medium", "low"]

            # Calculate total ports for progress tracking
            total_ports = sum(len(group) for group in priority_groups)
            scanned_ports = 0

            # Send initial event
            yield f"data: {json.dumps({'type': 'scan_start', 'target': target, 'total_ports': total_ports, 'progress': 0})}\n\n"

            # Import scanner and analyzer
            from src.cybersec_cli.tools.network.port_scanner import (
                PortScanner,
                PortState,
                ScanType,
            )
            from src.cybersec_cli.utils.formatters import get_vulnerability_info
            # Import live enrichment
            try:
                from src.cybersec_cli.utils.cve_enrichment import enrich_service_with_live_data
            except ImportError:
                # Fallback if imports fail
                async def enrich_service_with_live_data(*args): return []


            # Track critical ports separately
            critical_ports_found = []

            # Scan each priority group
            for i, group in enumerate(priority_groups):
                if not group:
                    continue

                # Send group start event
                yield f"data: {json.dumps({'type': 'group_start', 'priority': priority_names[i], 'count': len(group), 'progress': round((scanned_ports / total_ports) * 100) if total_ports > 0 else 0})}\n\n"

                # Create scanner for this group with enhanced service detection
                scanner = PortScanner(
                    target=target,
                    ports=group,
                    scan_type=ScanType.TCP_CONNECT,
                    timeout=1.0,
                    max_concurrent=50,
                    enhanced_service_detection=enhanced_service_detection,
                )

                # Scan ports in this group
                results = await scanner.scan()

                # Update scanned ports count
                scanned_ports += len(group)
                progress_percentage = (
                    round((scanned_ports / total_ports) * 100) if total_ports > 0 else 0
                )

                # Collect open ports for this group with security findings
                open_ports = []
                for result in results:
                    if result.state == PortState.OPEN:
                        # Get vulnerability information for this port
                        vuln_info = get_vulnerability_info(result.port, result.service)
                        
                        # Live enrichment
                        if result.service and result.service != "unknown":
                            try:
                                live_cves = await enrich_service_with_live_data(result.service, result.version)
                                if live_cves:
                                    # Merge/Override with live data
                                    existing_cves = set(vuln_info.get("cves", []))
                                    for cve in live_cves:
                                        cve_id = cve.get("id")
                                        if cve_id and cve_id not in existing_cves:
                                            vuln_info.setdefault("cves", []).append(cve_id)
                                            # We can also append the description to recommendations if needed, 
                                            # or just let the frontend handle the IDs.
                                    
                                    # Update severity if we found higher severity CVEs
                                    from src.cybersec_cli.utils.formatters import Severity
                                    max_live_severity = "LOW"
                                    for c in live_cves:
                                        s = c.get("severity", "LOW")
                                        # Simple severity ranking
                                        rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
                                        if rank.get(s, 0) > rank.get(max_live_severity, 0):
                                            max_live_severity = s
                                    
                                    # Compare with current severity
                                    if max_live_severity in Severity.__members__:
                                        live_sev_enum = Severity[max_live_severity]
                                        if live_sev_enum.value > vuln_info["severity"].value:
                                            vuln_info["severity"] = live_sev_enum

                            except Exception as e:
                                logger.warning(f"Live enrichment failed: {e}")


                        port_info = {
                            "port": result.port,
                            "service": result.service or "unknown",
                            "version": result.version or "unknown",
                            "banner": result.banner or "",
                            "confidence": result.confidence,
                            "protocol": result.protocol,
                            "risk": vuln_info["severity"].name,
                            "cvss_score": vuln_info.get("cvss_score", 0.0),
                            "vulnerabilities": vuln_info.get("cves", []),
                            "recommendations": (
                                vuln_info.get("recommendation", "").split("\n")
                                if vuln_info.get("recommendation")
                                else []
                            ),
                            "exposure": vuln_info.get("exposure", "Unknown"),
                            "default_creds": vuln_info.get(
                                "default_creds", "Check documentation"
                            ),
                        }
                        open_ports.append(port_info)

                        # Track critical ports
                        if priority_names[i] == "critical":
                            critical_ports_found.append(port_info)

                # Send results after each priority tier completes
                if open_ports:
                    yield f"data: {json.dumps({'type': 'tier_results', 'priority': priority_names[i], 'open_ports': open_ports, 'progress': progress_percentage})}\n\n"

                # Send group completion event
                yield f"data: {json.dumps({'type': 'group_complete', 'priority': priority_names[i], 'open_count': len(open_ports), 'progress': progress_percentage})}\n\n"

            # Send critical ports summary first
            if critical_ports_found:
                yield f"data: {json.dumps({'type': 'critical_ports', 'ports': critical_ports_found, 'progress': 100})}\n\n"

            # Send scan completion event
            yield f"data: {json.dumps({'type': 'scan_complete', 'message': 'Scan completed', 'progress': 100})}\n\n"

        except Exception as e:
            yield f"data: {json.dumps({'type': 'error', 'message': str(e), 'progress': 0})}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")


# Celery-based asynchronous scan endpoints
try:
    # Import Celery task
    sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
    from tasks.scan_tasks import perform_scan_task

    CELERY_AVAILABLE = True
except ImportError:
    CELERY_AVAILABLE = False
    logger.warning("Celery not available, async scan endpoints will not work")

if CELERY_AVAILABLE:
    from typing import Any, Dict, Optional

    from pydantic import BaseModel

    class ScanRequest(BaseModel):
        """
        Request model for asynchronous scan operations.

        Attributes:
            target (str): Target hostname or IP address to scan
            ports (str): Port range to scan (e.g., "1-1000", "80,443", "22-25,80,443"). Default: "1-1000"
            config (Optional[Dict[str, Any]]): Configuration options for the scan
        """

        target: str
        ports: str = "1-1000"
        config: Optional[Dict[str, Any]] = None

    @app.post(
        "/api/scan",
        tags=["Async Scanning"],
        summary="Create asynchronous scan task",
        description="Create an asynchronous scan task using Celery. Returns a task ID for tracking the scan progress.",
        dependencies=[Depends(rate_limit_dependency)],
        responses={
            200: {
                "description": "Scan task created successfully",
                "content": {
                    "application/json": {
                        "example": {
                            "task_id": "c5d8e2a1-1b3f-4e8c-9d2a-4f5b8e7a1c2d",
                            "scan_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef",
                            "status": "queued",
                            "message": "Scan queued for target example.com",
                            "force": False,
                        }
                    }
                },
            },
            500: {
                "description": "Celery not available",
                "content": {
                    "application/json": {"example": {"detail": "Celery not available"}}
                },
            },
        },
    )
    async def create_async_scan(
        scan_request: ScanRequest, force: bool = False, request: Request = None
    ):
        """
        Create an asynchronous scan task using Celery.

        Args:
            scan_request: Scan request with target, ports, and config
            force: If True, bypass cache and perform fresh scan
            request: FastAPI request object for client IP

        Returns:
            Dictionary with task_id for tracking the scan progress
        """
        import uuid

        # Get client IP for rate limiting
        client_ip = request.client.host if request.client else "unknown"

        if not validate_target(scan_request.target):
            raise HTTPException(status_code=400, detail="Invalid target")

        try:
            _parse_ports_arg(scan_request.ports)
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))

        # Record scan start metrics
        if HAS_METRICS and metrics_collector:
            metrics_collector.increment_scan(status="started", user_type="api")

        scan_id = str(uuid.uuid4())

        # Add force parameter to config
        if scan_request.config is None:
            scan_request.config = {}
        scan_request.config["force"] = force

        # Queue the scan task
        task = perform_scan_task.delay(
            scan_id, scan_request.target, scan_request.ports, scan_request.config
        )

        response = {
            "task_id": task.id,
            "scan_id": scan_id,
            "status": "queued",
            "message": f"Scan queued for target {scan_request.target}",
            "force": force,
        }

        return response

    @app.get(
        "/api/scan/{task_id}",
        tags=["Async Scanning"],
        summary="Get scan task status",
        description="Get the status of an asynchronous scan task.",
        dependencies=[Depends(rate_limit_dependency)],
        responses={
            200: {
                "description": "Scan task status",
                "content": {
                    "application/json": {
                        "examples": {
                            "pending": {
                                "summary": "Task pending",
                                "value": {
                                    "state": "PENDING",
                                    "status": "Task is waiting to be processed",
                                },
                            },
                            "progress": {
                                "summary": "Task in progress",
                                "value": {
                                    "state": "PROGRESS",
                                    "status": "Scanning critical priority ports",
                                    "progress": 25,
                                },
                            },
                            "success": {
                                "summary": "Task completed",
                                "value": {
                                    "state": "SUCCESS",
                                    "result": {
                                        "scan_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef",
                                        "target": "example.com",
                                        "open_ports": [
                                            {
                                                "port": 80,
                                                "service": "http",
                                                "risk": "MEDIUM",
                                            }
                                        ],
                                        "status": "completed",
                                        "progress": 100,
                                    },
                                },
                            },
                            "error": {
                                "summary": "Task failed",
                                "value": {
                                    "state": "FAILURE",
                                    "error": "Connection timeout",
                                },
                            },
                        }
                    }
                },
            },
            404: {
                "description": "Task not found",
                "content": {
                    "application/json": {"example": {"detail": "Task not found"}}
                },
            },
        },
    )
    async def get_scan_status(task_id: str):
        """
        Get the status of an asynchronous scan task.

        Returns:
            Dictionary with task status and results if completed
        """
        from celery.result import AsyncResult

        # Get task result
        task_result = AsyncResult(task_id, app=perform_scan_task.app)

        if task_result.state == "PENDING":
            # Task is waiting to be processed
            response = {
                "state": task_result.state,
                "status": "Task is waiting to be processed",
            }
        elif task_result.state == "PROGRESS":
            # Task is currently being processed
            response = {
                "state": task_result.state,
                "status": task_result.info.get("status", ""),
                "progress": task_result.info.get("progress", 0),
            }
            # Add any additional metadata
            for key, value in task_result.info.items():
                if key not in ["status", "progress"]:
                    response[key] = value
        elif task_result.state == "SUCCESS":
            # Task completed successfully
            result_data = task_result.result
            response = {"state": task_result.state, "result": result_data}

            # Add cache information to response if available
            if isinstance(result_data, dict):
                if result_data.get("cached"):
                    response["cached"] = True
                    response["cached_at"] = result_data.get("cached_at")
                else:
                    response["cached"] = False
        else:
            # Task failed
            response = {
                "state": task_result.state,
                "error": (
                    str(task_result.info)
                    if isinstance(task_result.info, Exception)
                    else task_result.info
                ),
            }

        return response


# Admin endpoints for rate limiting
@app.post(
    "/api/admin/rate-limits/reset/{client_id}",
    tags=["Rate Limiting"],
    summary="Reset client rate limits",
    description="Reset rate limits for a specific client (admin endpoint)",
    responses={
        200: {
            "description": "Rate limits reset successfully",
            "content": {
                "application/json": {
                    "example": {"message": "Rate limits reset for client 127.0.0.1"}
                }
            },
        },
        500: {
            "description": "Rate limiter not available",
            "content": {
                "application/json": {
                    "example": {"detail": "Rate limiter not available"}
                }
            },
        },
    },
)
async def reset_client_limits(client_id: str, request: Request):
    """Reset rate limits for a specific client (admin endpoint)"""
    # In a real implementation, you would add authentication here
    if HAS_RATE_LIMITER and rate_limiter:
        rate_limiter.reset_client_limits(client_id)
        return {"message": f"Rate limits reset for client {client_id}"}
    else:
        raise HTTPException(status_code=500, detail="Rate limiter not available")


@app.get(
    "/api/admin/rate-limits",
    tags=["Rate Limiting"],
    summary="Get rate limit dashboard",
    description="Get rate limit dashboard data for monitoring",
    responses={
        200: {
            "description": "Rate limit dashboard data",
            "content": {
                "application/json": {
                    "example": {
                        "violations": {"127.0.0.1": 3, "192.168.1.100": 1},
                        "abuse_patterns": [
                            {
                                "client_id": "127.0.0.1",
                                "violation_count": 3,
                                "is_on_cooldown": True,
                            }
                        ],
                        "rate_limiter_status": "active",
                    }
                }
            },
        }
    },
)
async def get_rate_limit_dashboard():
    """Get rate limit dashboard data for monitoring"""
    if HAS_RATE_LIMITER and rate_limiter:
        violations = rate_limiter.get_all_violations()
        abuse_patterns = rate_limiter.get_abuse_patterns()
        return {
            "violations": violations,
            "abuse_patterns": abuse_patterns,
            "rate_limiter_status": "active",
        }
    else:
        return {
            "violations": {},
            "abuse_patterns": [],
            "rate_limiter_status": "inactive",
        }


@app.get(
    "/metrics",
    tags=["Health"],
    summary="Get Prometheus metrics",
    description="Prometheus metrics endpoint for system monitoring.",
    responses={
        200: {
            "description": "Prometheus metrics in text format",
            "content": {
                "text/plain": {
                    "example": '# HELP cybersec_scan_total Total number of scans\n# TYPE cybersec_scan_total counter\ncybersec_scan_total{status="completed",user_type="api"} 42\n'
                }
            },
        },
        500: {
            "description": "Metrics not available",
            "content": {
                "application/json": {"example": {"detail": "Metrics not available"}}
            },
        },
    },
)
async def get_metrics():
    """Prometheus metrics endpoint"""
    if not HAS_METRICS or not metrics_collector:
        raise HTTPException(status_code=500, detail="Metrics not available")

    return Response(content=metrics_collector.get_metrics(), media_type="text/plain")


# WebSocket endpoint for command execution
@app.websocket("/ws/command")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    # If WS_API_KEY is set, require the client to provide it as ?token=KEY
    try:
        if WS_API_KEY:
            token = websocket.query_params.get("token")
            # Use timing-safe comparison to prevent timing attacks
            if not _timing_safe_compare(token, WS_API_KEY):
                await websocket.send_text(
                    json.dumps(
                        {
                            "type": "auth_error",
                            "message": "Missing or invalid token for WebSocket connection",
                        }
                    )
                )
                await websocket.close(code=1008)
                return
    except Exception:
        # If anything goes wrong reading query params, close connection
        try:
            await websocket.send_text(
                json.dumps({"type": "auth_error", "message": "Authentication failed"})
            )
            await websocket.close(code=1008)
        except Exception as close_err:
            logger.debug(f"Error closing WebSocket after auth failure: {close_err}")
        return
    try:
        while True:
            data = await websocket.receive_text()
            payload = json.loads(data)
            command = payload.get("command", "")
            force = payload.get("force", False)

            # If this is a forced scan request coming from the client, write an audit entry
            try:
                raw_parts = shlex.split(command)
            except Exception:
                raw_parts = []
            # If this is a forced scan request coming from the client, write an audit entry
            try:
                consent_flag = payload.get("consent", False)
            except Exception:
                consent_flag = False
            if force and len(raw_parts) >= 2 and raw_parts[0].lower() == "scan":
                target = raw_parts[1]
                resolved_ip = None
                try:
                    resolved_ip = socket.gethostbyname(target)
                except Exception:
                    resolved_ip = None

                # Try to get client host (WebSocket.client may be a tuple)
                client_host = None
                try:
                    client = websocket.client
                    if isinstance(client, tuple) and len(client) >= 1:
                        client_host = client[0]
                    elif hasattr(client, "host"):
                        client_host = client.host
                except Exception:
                    client_host = None

                audit_entry = {
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "target": target,
                    "resolved_ip": resolved_ip,
                    "original_command": command,
                    "client_host": client_host,
                    "consent": bool(consent_flag),
                    "note": "forced_via_websocket",
                }
                try:
                    log_forced_scan(audit_entry)
                    logger.info(
                        f"Logged forced scan audit entry for {target} from {client_host} (consent={consent_flag})"
                    )
                except Exception as e:
                    logger.error(f"Failed to write forced scan audit entry: {e}")

            if not command:
                continue

            try:
                safe_tokens = _parse_and_validate_scan_command(command)
            except Exception as e:
                await websocket.send_text(
                    json.dumps(
                        {
                            "type": "error",
                            "message": f"Invalid scan command: {str(e)}",
                        }
                    )
                )
                continue

            parts = safe_tokens

            # Skip validation for non-scan commands
            if not parts or parts[0].lower() != "scan":
                continue

            target = parts[1]

            # Ensure target resolves
            try:
                socket.gethostbyname(target)
            except Exception:
                await websocket.send_text(
                    json.dumps(
                        {
                            "type": "error",
                            "message": f"Invalid or non-existent target: {target}. Please check the target and try again.",
                        }
                    )
                )
                continue

            # denylist/allowlist check
            try:
                repo_reports = os.path.join(os.path.dirname(BASE_DIR), "reports")
                deny_path = os.path.join(repo_reports, "denylist.txt")
                allow_path = os.path.join(repo_reports, "allowlist.txt")

                def is_in_file(path, val):
                    """Check if val is in file (case-insensitive)."""
                    if not os.path.exists(path):
                        return False
                    try:
                        normalized_val = val.strip().lower()
                        with open(path, "r", encoding="utf-8") as f:
                            for line in f:
                                file_val = line.strip().lower()
                                if not file_val:
                                    continue
                                if file_val == normalized_val:
                                    return True
                    except Exception:
                        return False
                    return False

                if len(parts) >= 2:
                    raw_target = parts[1]
                    # Normalize target for comparison
                    target = raw_target.strip().lower()
                    
                    # If denylisted, block immediately (case-insensitive)
                    if is_in_file(deny_path, target):
                        await websocket.send_text(
                            json.dumps(
                                {
                                    "type": "denied",
                                    "message": f"Target {raw_target} is deny-listed and cannot be scanned.",
                                }
                            )
                        )
                        continue
                    # If allowlist exists and target not in allowlist, notify client (case-insensitive for consistency)
                    try:
                        with open(allow_path, "r", encoding="utf-8") as f:
                            allow_lines = [line.strip().lower() for line in f if line.strip()]
                        if allow_lines and target not in allow_lines:
                            await websocket.send_text(
                                json.dumps(
                                    {
                                        "type": "allowlist_notice",
                                        "message": f"Target {raw_target} is not in allowlist. Proceed with caution.",
                                    }
                                )
                            )
                    except Exception as allow_err:
                        logger.debug(f"Error reading allowlist: {allow_err}")
            except Exception as list_err:
                logger.debug(f"Error during denylist/allowlist check: {list_err}")
            # derive client id for rate-limiting and concurrency
            client_host = None
            try:
                client = websocket.client
                if isinstance(client, tuple) and len(client) >= 1:
                    client_host = client[0]
                elif hasattr(client, "host"):
                    client_host = client.host
            except Exception:
                client_host = "unknown"

            # Rate limiting and concurrency checks (Redis + fallback)
            if len(parts) >= 2 and parts[0].lower() == "scan":
                # Check rate limit (try Redis, fallback to in-memory)
                rate_ok = await _check_and_record_rate_limit(client_host)
                if not rate_ok:
                    await websocket.send_text(
                        json.dumps(
                            {
                                "type": "rate_limit",
                                "message": f"Rate limit exceeded ({WS_RATE_LIMIT} scans per minute). Please wait.",
                            }
                        )
                    )
                    continue
            effective_force = force or ("--force" in parts)
            if len(parts) >= 2 and parts[0].lower() == "scan" and not effective_force:
                target = parts[1]
                # Resolve hostname
                try:
                    ip = socket.gethostbyname(target)
                except socket.gaierror:
                    await websocket.send_text(
                        json.dumps(
                            {
                                "type": "pre_scan_error",
                                "message": f"Could not resolve hostname '{target}'. Please check the name and try again.",
                                "target": target,
                            }
                        )
                    )
                    continue

                # Async quick check for common service ports (80, 443)
                async def _probe_ports(ip_to_check: str, ports=(80, 443), timeout=1.0):
                    for p in ports:
                        try:
                            reader, writer = await asyncio.wait_for(
                                asyncio.open_connection(ip_to_check, p), timeout=timeout
                            )
                            writer.close()
                            await writer.wait_closed()
                            return True, p
                        except Exception:
                            continue
                    return False, None

                reachable, port_ok = await _probe_ports(ip)
                if not reachable:
                    # Send a pre-scan warning to client and ask for confirmation
                    await websocket.send_text(
                        json.dumps(
                            {
                                "type": "pre_scan_warning",
                                "target": target,
                                "ip": ip,
                                "reachable": False,
                                "message": f'Target resolved to {ip} but no response on common web ports (80/443). Send the same command with {{"force": true}} to proceed.',
                                "original_command": command,
                            }
                        )
                    )
                    # Don't run the scan yet – wait for client confirmation
                    continue

            # Execute the command and stream output
            scan_started = False
            try:
                # Concurrency limit (try Redis, fallback to in-memory)
                conc_ok = await scan_concurrency.record_scan_start(client_host)
                if not conc_ok:
                    await websocket.send_text(
                        json.dumps(
                            {
                                "type": "rate_limit",
                                "message": f"Too many concurrent scans ({WS_CONCURRENT_LIMIT}) for your connection. Try again later.",
                            }
                        )
                    )
                    continue

                scan_started = True
                process = await asyncio.create_subprocess_exec(
                    sys.executable,
                    "-m",
                    "cybersec_cli",
                    *safe_tokens,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    cwd=os.getcwd(),
                )

                # Collect complete output
                stdout_data = []
                stderr_data = []

                # Read stdout and stderr
                while True:
                    # Check if process has finished
                    if process.returncode is not None:
                        # Read any remaining output
                        try:
                            remaining_stdout = await process.stdout.read()
                            if remaining_stdout:
                                try:
                                    stdout_data.append(
                                        remaining_stdout.decode("utf-8", errors="replace")
                                    )
                                except UnicodeDecodeError:
                                    # If we can't decode as UTF-8, try with error replacement
                                    stdout_data.append(
                                        remaining_stdout.decode("utf-8", errors="replace")
                                    )
                        except Exception as e:
                            logger.error(f"Error reading remaining stdout: {e}")
                        break

                    # Read available output
                    try:
                        stdout = await process.stdout.read(4096)
                        if stdout:
                            try:
                                stdout_data.append(stdout.decode("utf-8", errors="replace"))
                            except UnicodeDecodeError:
                                stdout_data.append(stdout.decode("utf-8", errors="replace"))
                    except Exception as e:
                        logger.error(f"Error reading stdout: {e}")
                        break

                    # Small delay to prevent busy waiting
                    await asyncio.sleep(0.01)

                # Read any remaining stderr
                try:
                    stderr = await process.stderr.read()
                    if stderr:
                        try:
                            stderr_data.append(stderr.decode("utf-8", errors="replace"))
                        except UnicodeDecodeError:
                            stderr_data.append(stderr.decode("utf-8", errors="replace"))
                except Exception as e:
                    logger.error(f"Error reading stderr: {e}")

                # Send complete output
                full_output = "".join(stdout_data)

                # Check if this looks like a port scan (contains the port scan header)
                if "╭─ Cybersec CLI - Port Scan Results" in full_output:
                    # Send as a single message for the port scan
                    await websocket.send_text(full_output)
                else:
                    # Send line by line for regular output
                    for line in full_output.splitlines():
                        if line.strip():
                            await websocket.send_text(f"[OUT] {line}")

                # Send any errors
                if stderr_data:
                    await websocket.send_text(f"[ERR] {''.join(stderr_data)}")

                # Send completion message
                await websocket.send_text(
                    f"[END] Command completed with return code {process.returncode}"
                )

                # Persist scan output if this was a scan command
                try:
                    if len(parts) >= 2 and parts[0].lower() == "scan":
                        # Try to determine ip for storage
                        try:
                            stored_ip = socket.gethostbyname(parts[1])
                        except Exception:
                            stored_ip = None
                        await _run_blocking(
                            save_scan_result, parts[1], stored_ip, command, full_output
                        )
                except Exception:
                    logger.exception("Failed to persist scan result")

            finally:
                if scan_started:
                    try:
                        await scan_concurrency.record_scan_end(client_host)
                    except Exception as end_err:
                        logger.debug(
                            f"Error recording scan end for {client_host}: {end_err}"
                        )

    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        await websocket.send_text(f"[ERR] Error executing command: {str(e)}")
    finally:
        manager.disconnect(websocket)


@app.post(
    "/api/os-fingerprint",
    tags=["OS Fingerprinting"],
    summary="Perform OS fingerprinting",
    description="Perform OS fingerprinting on a target host to identify the operating system.",
    responses={
        200: {
            "description": "OS fingerprinting results",
            "content": {
                "application/json": {
                    "example": {
                        "target": "example.com",
                        "ip": "93.184.216.34",
                        "os_info": {
                            "os_name": "Linux 2.6.x",
                            "vendor": "Linux",
                            "os_family": "Linux",
                            "os_gen": "2.6.x",
                            "accuracy": "98"
                        },
                        "open_ports_count": 3
                    }
                }
            },
        },
    },
)
async def os_fingerprint(req_data: OSFingerprintRequest, request: Request):
    """Perform OS fingerprinting on a target host."""
    from src.cybersec_cli.tools.network.port_scanner import PortScanner, ScanType
    
    await rate_limit_dependency(request)
    
    try:
        if not validate_target(req_data.target):
            raise HTTPException(status_code=400, detail="Invalid target")

        # Create PortScanner instance with OS detection enabled
        scanner = PortScanner(
            target=req_data.target,
            scan_type=ScanType.TCP_CONNECT,
            timeout=2.0,
            max_concurrent=50,
            os_detection=req_data.os_detection,
            service_detection=req_data.service_detection,
            enhanced_service_detection=req_data.enhanced_service_detection,
        )
        
        # Perform the scan
        results = await scanner.scan()
        
        # Get OS information from the scanner
        os_info = scanner._perform_os_detection() if req_data.os_detection else {}
        
        # Count open ports
        open_ports_count = len([r for r in results if r.state.name == "OPEN"])
        
        # Prepare response
        response_data = {
            "target": scanner.target,
            "ip": scanner.ip,
            "os_info": os_info,
            "open_ports_count": open_ports_count,
            "scan_results": [r.to_dict() for r in results]
        }
        
        # Log the scan
        save_scan_result(req_data.target, scanner.ip, f"scan {req_data.target} --os", json.dumps(response_data))
        
        return response_data
        
    except Exception as e:
        logger.error(f"OS fingerprinting error: {e}")
        raise HTTPException(status_code=500, detail="OS fingerprinting failed. Please try again later.")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
