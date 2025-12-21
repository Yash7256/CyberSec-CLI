from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, HTMLResponse
import os
from pathlib import Path
import socket
import asyncio
import json
import logging
import sqlite3
from typing import Dict, List, Optional
import subprocess
from datetime import datetime
import re
import dns.resolver
from urllib.parse import urlparse
from cybersec_cli.utils.logger import log_forced_scan

# Add imports for streaming support
from fastapi.responses import StreamingResponse
# Fix the import path for core.port_priority
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
try:
    from core.port_priority import get_scan_order
    HAS_PRIORITY_MODULE = True
except ImportError:
    HAS_PRIORITY_MODULE = False
    def get_scan_order(ports):
        # Fallback implementation if core module not available
        return [ports, [], [], []]

import asyncio
import json

# Optional Redis-backed rate limiting (if aioredis is available and REDIS_URL set)
REDIS_URL = os.getenv('REDIS_URL')
_redis = None


async def _redis_check_and_increment_rate(client: str) -> bool:
    """Increment per-minute rate counter in Redis and return True if under limit.

    If Redis is not configured, return False so callers will fallback to in-memory logic.
    """
    if _redis is None:
        logger.debug('Redis not configured; skipping redis rate check')
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
        logger.debug('Redis rate check failed; falling back to in-memory')
        return False


async def _redis_increment_active(client: str) -> bool:
    """Increment active scans counter in Redis and return True if under concurrency limit.

    If Redis is not configured, return False so callers will fallback to in-memory logic.
    """
    if _redis is None:
        logger.debug('Redis not configured; skipping redis active increment')
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
        logger.debug('Redis active increment failed; falling back to in-memory')
        return False


async def _redis_decrement_active(client: str):
    if _redis is None:
        logger.debug('Redis not configured; skipping redis active decrement')
        return
    try:
        key = f"active:{client}"
        await _redis.decr(key)
    except Exception:
        logger.debug('Redis active decrement failed')

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def init_redis():
    """Initialize aioredis client if REDIS_URL is set. Safe to call multiple times.

    This function will set the module-level `_redis` variable when aioredis is available.
    """
    global _redis
    if not REDIS_URL:
        logger.debug('REDIS_URL not set; skipping redis initialization')
        return
    if _redis is not None:
        # already initialized
        return
    try:
        import aioredis
        _redis = aioredis.from_url(REDIS_URL)
        logger.info('Redis configured for rate limiting')
    except Exception as e:
        _redis = None
        logger.debug(f'Redis not available or failed to initialize: {e}; falling back to in-memory rate limiting')


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
    now = int(asyncio.get_event_loop().time())
    rc = _rate_counters.get(client_host)
    if rc is None or now >= rc.get('reset_at', 0):
        # Reset window
        _rate_counters[client_host] = {'count': 0, 'reset_at': now + 60}
        rc = _rate_counters[client_host]
    if rc['count'] >= WS_RATE_LIMIT:
        return False
    # Increment and allow
    rc['count'] += 1
    return True


async def _record_scan_start(client_host: str) -> bool:
    """Record the start of a scan (increment concurrency counter).

    Try Redis first; fallback to in-memory. Returns True if allowed.
    """
    # Try Redis first
    if _redis is not None:
        allowed = await _redis_increment_active(client_host)
        if allowed:
            return True
        # Redis said no
        return False

    # Fallback to in-memory concurrency limiting
    if _active_scans.get(client_host, 0) >= WS_CONCURRENT_LIMIT:
        return False
    _active_scans[client_host] = _active_scans.get(client_host, 0) + 1
    return True


async def _record_scan_end(client_host: str):
    """Record the end of a scan (decrement concurrency counter).

    Try Redis first; fallback to in-memory.
    """
    # Try Redis first
    if _redis is not None:
        await _redis_decrement_active(client_host)
    else:
        # Fallback to in-memory
        _active_scans[client_host] = max(0, _active_scans.get(client_host, 1) - 1)

# Base directory for the web app
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Config: optional WebSocket API key. If set, clients must provide this token as ?token=XXX
WS_API_KEY = os.getenv('WEBSOCKET_API_KEY')
# Rate limiting: scans per minute per client
WS_RATE_LIMIT = int(os.getenv('WS_RATE_LIMIT', '5'))
# Concurrent scans per client
WS_CONCURRENT_LIMIT = int(os.getenv('WS_CONCURRENT_LIMIT', '2'))

# In-memory state for rate limiting and concurrency (simple, per-process)
_rate_counters: Dict[str, Dict] = {}
_active_scans: Dict[str, int] = {}

# Persistence: simple SQLite DB for scan results
REPORTS_DIR = os.path.join(os.path.dirname(BASE_DIR), 'reports')
os.makedirs(REPORTS_DIR, exist_ok=True)
SCANS_DB = os.path.join(REPORTS_DIR, 'scans.db')

def init_db():
    conn = sqlite3.connect(SCANS_DB)
    c = conn.cursor()
    c.execute('''
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        target TEXT,
        ip TEXT,
        command TEXT,
        output TEXT
    )
    ''')
    conn.commit()
    conn.close()

def ensure_allowlists():
    # Ensure allowlist/denylist files exist (empty by default)
    try:
        repo_reports = os.path.join(os.path.dirname(BASE_DIR), 'reports')
        os.makedirs(repo_reports, exist_ok=True)
        for fn in ('allowlist.txt', 'denylist.txt'):
            path = os.path.join(repo_reports, fn)
            if not os.path.exists(path):
                open(path, 'a').close()
    except Exception:
        logger.debug('Failed to ensure allowlist/denylist files')

ensure_allowlists()

def save_scan_result(target: str, ip: Optional[str], command: str, output: str) -> int:
    try:
        conn = sqlite3.connect(SCANS_DB)
        c = conn.cursor()
        ts = datetime.utcnow().isoformat() + 'Z'
        c.execute('INSERT INTO scans (timestamp, target, ip, command, output) VALUES (?, ?, ?, ?, ?)',
                  (ts, target, ip or '', command, output))
        conn.commit()
        rowid = c.lastrowid
        conn.close()
        return rowid
    except Exception:
        logger.exception('Failed to save scan result')
        return -1

def list_scans(limit: int = 50):
    try:
        conn = sqlite3.connect(SCANS_DB)
        c = conn.cursor()
        c.execute('SELECT id, timestamp, target, ip, command FROM scans ORDER BY id DESC LIMIT ?', (limit,))
        rows = c.fetchall()
        conn.close()
        return [dict(id=r[0], timestamp=r[1], target=r[2], ip=r[3], command=r[4]) for r in rows]
    except Exception:
        logger.exception('Failed to list scans')
        return []

def get_scan_output(scan_id: int) -> Optional[str]:
    try:
        conn = sqlite3.connect(SCANS_DB)
        c = conn.cursor()
        c.execute('SELECT output FROM scans WHERE id = ?', (scan_id,))
        row = c.fetchone()
        conn.close()
        return row[0] if row else None
    except Exception:
        logger.exception('Failed to get scan output')
        return None

# Initialize DB on startup
init_db()

app = FastAPI(title="CyberSec-CLI Web")


# Initialize optional services on startup (e.g. Redis)
@app.on_event("startup")
async def _on_startup():
    await init_redis()

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Static files directory
STATIC_DIR = os.path.join(BASE_DIR, 'static')

# Create static directory if it doesn't exist
os.makedirs(STATIC_DIR, exist_ok=True)
os.makedirs(os.path.join(STATIC_DIR, 'img'), exist_ok=True)

# Mount static files
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# WebSocket connections
active_connections: List[WebSocket] = []

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
@app.get("/")
async def read_root():
    return FileResponse(os.path.join(STATIC_DIR, 'index.html'))

@app.get("/api/status")
async def get_status():
    return {"status": "CyberSec-CLI API is running"}


@app.get('/api/audit/forced_scans')
async def get_forced_scans():
    """Return the forced scan audit log as JSON list (read from reports/forced_scans.jsonl)."""
    reports_file = os.path.join(os.path.dirname(BASE_DIR), 'reports', 'forced_scans.jsonl')
    if not os.path.exists(reports_file):
        return []
    entries = []
    try:
        with open(reports_file, 'r', encoding='utf-8') as f:
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


@app.get('/api/scans')
async def api_list_scans(limit: int = 50):
    return list_scans(limit)


@app.get('/api/scans/{scan_id}')
async def api_get_scan(scan_id: int):
    out = get_scan_output(scan_id)
    if out is None:
        raise HTTPException(status_code=404, detail='Scan not found')
    return { 'id': scan_id, 'output': out }

@app.get('/api/stream/scan/{target}')
async def stream_scan_results(target: str, ports: str = "1-1000"):
    """
    Stream port scan results using Server-Sent Events (SSE).
    Scans ports on the target and streams results as they become available.
    """
    async def event_generator():
        try:
            # Parse ports
            port_list = []
            if '-' in ports:
                start, end = map(int, ports.split('-'))
                port_list = list(range(start, end + 1))
            elif ',' in ports:
                port_list = [int(p) for p in ports.split(',')]
            else:
                port_list = [int(ports)]
            
            # Group ports by priority
            priority_groups = get_scan_order(port_list)
            priority_names = ["critical", "high", "medium", "low"]
            
            # Send initial event
            yield f"data: {json.dumps({'type': 'info', 'message': f'Starting scan on {target} with {len(port_list)} ports'})}\n\n"
            
            # Import scanner
            from cybersec_cli.tools.network.port_scanner import PortScanner, ScanType, PortState
            
            # Scan each priority group
            for i, group in enumerate(priority_groups):
                if not group:
                    continue
                
                # Send group start event
                yield f"data: {json.dumps({'type': 'group_start', 'priority': priority_names[i], 'count': len(group)})}\n\n"
                
                # Create scanner for this group
                scanner = PortScanner(
                    target=target,
                    ports=group,
                    scan_type=ScanType.TCP_CONNECT,
                    timeout=1.0,
                    max_concurrent=50
                )
                
                # Scan ports in this group
                results = await scanner.scan()
                
                # Send results for this group
                for result in results:
                    if result.state == PortState.OPEN:
                        yield f"data: {json.dumps({'type': 'open_port', 'port': result.port, 'service': result.service or 'unknown'})}\n\n"
                
                # Send group completion event
                open_count = len([r for r in results if r.state == PortState.OPEN])
                yield f"data: {json.dumps({'type': 'group_complete', 'priority': priority_names[i], 'open_count': open_count})}\n\n"
            
            # Send scan completion event
            yield f"data: {json.dumps({'type': 'scan_complete', 'message': 'Scan completed'})}\n\n"
            
        except Exception as e:
            yield f"data: {json.dumps({'type': 'error', 'message': str(e)})}\n\n"
    
    return StreamingResponse(event_generator(), media_type="text/event-stream")

# WebSocket endpoint for command execution
@app.websocket("/ws/command")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    # If WS_API_KEY is set, require the client to provide it as ?token=KEY
    try:
        if WS_API_KEY:
            token = websocket.query_params.get('token')
            if not token or token != WS_API_KEY:
                await websocket.send_text(json.dumps({
                    "type": "auth_error",
                    "message": "Missing or invalid token for WebSocket connection"
                }))
                await websocket.close(code=1008)
                return
    except Exception:
        # If anything goes wrong reading query params, close connection
        try:
            await websocket.send_text(json.dumps({"type": "auth_error", "message": "Authentication failed"}))
            await websocket.close(code=1008)
        except Exception:
            pass
        return
    try:
        while True:
            data = await websocket.receive_text()
            payload = json.loads(data)
            command = payload.get("command", "")
            force = payload.get("force", False)

            # If this is a forced scan request coming from the client, write an audit entry
            try:
                parts = command.strip().split()
            except Exception:
                parts = []
            # If this is a forced scan request coming from the client, write an audit entry
            try:
                consent_flag = payload.get('consent', False)
            except Exception:
                consent_flag = False
            if force and len(parts) >= 2 and parts[0].lower() == 'scan':
                target = parts[1]
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
                    elif hasattr(client, 'host'):
                        client_host = client.host
                except Exception:
                    client_host = None

                audit_entry = {
                    "timestamp": datetime.utcnow().isoformat() + 'Z',
                    "target": target,
                    "resolved_ip": resolved_ip,
                    "original_command": command,
                    "client_host": client_host,
                    "consent": bool(consent_flag),
                    "note": "forced_via_websocket"
                }
                try:
                    log_forced_scan(audit_entry)
                    logger.info(f"Logged forced scan audit entry for {target} from {client_host} (consent={consent_flag})")
                except Exception as e:
                    logger.error(f"Failed to write forced scan audit entry: {e}")

            if not command:
                continue

                        # Intercept 'scan' commands to perform validation
            parts = command.strip().split()
            
            # Skip validation for non-scan commands
            if not parts or parts[0].lower() != 'scan':
                continue
                
            if len(parts) < 2:
                await websocket.send_text(json.dumps({
                    'type': 'error',
                    'message': 'Please specify a target to scan. Example: scan example.com'
                }))
                continue
                
            target = parts[1]
            
            # Basic domain format validation
            def is_valid_domain(domain):
                try:
                    # Check if it's a valid domain format
                    if not re.match(
                        r'^((?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,}$', 
                        domain
                    ):
                        return False
                    
                    # Try to resolve the domain
                    try:
                        # Try both A and AAAA records
                        dns.resolver.resolve(domain, 'A')
                        return True
                    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                        try:
                            dns.resolver.resolve(domain, 'AAAA')
                            return True
                        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                            return False
                except Exception:
                    return False
            
            # Validate the target
            if not is_valid_domain(target):
                await websocket.send_text(json.dumps({
                    'type': 'error',
                    'message': f'Invalid or non-existent domain: {target}. Please check the domain and try again.'
                }))
                continue
                
            # denylist/allowlist check
            try:
                repo_reports = os.path.join(os.path.dirname(BASE_DIR), 'reports')
                deny_path = os.path.join(repo_reports, 'denylist.txt')
                allow_path = os.path.join(repo_reports, 'allowlist.txt')
                def is_in_file(path, val):
                    if not os.path.exists(path):
                        return False
                    try:
                        with open(path, 'r', encoding='utf-8') as f:
                            for line in f:
                                if line.strip() and line.strip().lower() == val.lower():
                                    return True
                    except Exception:
                        return False
                    return False
                if len(parts) >= 2:
                    tgt = parts[1]
                    # If denylisted, block immediately
                    if is_in_file(deny_path, tgt):
                        await websocket.send_text(json.dumps({
                            'type': 'denied',
                            'message': f'Target {tgt} is deny-listed and cannot be scanned.'
                        }))
                        continue
                    # If allowlist exists and target not in allowlist, notify client (will still follow pre-scan warning flow)
                    # (This is informational; enforcement can be stricter if desired)
                    try:
                        with open(allow_path, 'r', encoding='utf-8') as f:
                            allow_lines = [l.strip() for l in f if l.strip()]
                        if allow_lines and tgt not in allow_lines:
                            await websocket.send_text(json.dumps({
                                'type': 'allowlist_notice',
                                'message': f'Target {tgt} is not in allowlist. Proceed with caution.'
                            }))
                    except Exception:
                        pass
            except Exception:
                pass
            # derive client id for rate-limiting and concurrency
            client_host = None
            try:
                client = websocket.client
                if isinstance(client, tuple) and len(client) >= 1:
                    client_host = client[0]
                elif hasattr(client, 'host'):
                    client_host = client.host
            except Exception:
                client_host = 'unknown'

            # Rate limiting and concurrency checks (Redis + fallback)
            if len(parts) >= 2 and parts[0].lower() == 'scan':
                # Check rate limit (try Redis, fallback to in-memory)
                rate_ok = await _check_and_record_rate_limit(client_host)
                if not rate_ok:
                    await websocket.send_text(json.dumps({
                        'type': 'rate_limit',
                        'message': f'Rate limit exceeded ({WS_RATE_LIMIT} scans per minute). Please wait.'
                    }))
                    continue
                # Check concurrency limit (try Redis, fallback to in-memory)
                conc_ok = await _record_scan_start(client_host)
                if not conc_ok:
                    await websocket.send_text(json.dumps({
                        'type': 'rate_limit',
                        'message': f'Too many concurrent scans ({WS_CONCURRENT_LIMIT}) for your connection. Try again later.'
                    }))
                    continue
            if len(parts) >= 2 and parts[0].lower() == 'scan' and not force:
                target = parts[1]
                # Resolve hostname
                try:
                    ip = socket.gethostbyname(target)
                except socket.gaierror:
                    await websocket.send_text(json.dumps({
                        "type": "pre_scan_error",
                        "message": f"Could not resolve hostname '{target}'. Please check the name and try again.",
                        "target": target
                    }))
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
                    await websocket.send_text(json.dumps({
                        "type": "pre_scan_warning",
                        "target": target,
                        "ip": ip,
                        "reachable": False,
                        "message": f"Target resolved to {ip} but no response on common web ports (80/443). Send the same command with {{\"force\": true}} to proceed.",
                        "original_command": command
                    }))
                    # Don't run the scan yet – wait for client confirmation
                    continue

            # Execute the command and stream output
            # Execute the command and stream output. Use try/finally to ensure counters decremented.
            try:
                process = await asyncio.create_subprocess_shell(
                f"python -m cybersec_cli {command}",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=os.getcwd()
            )
            except Exception as e:
                # Decrement concurrency if we failed to start
                try:
                    if len(parts) >= 2 and parts[0].lower() == 'scan':
                        _active_scans[client_host] = max(0, _active_scans.get(client_host, 1) - 1)
                except Exception:
                    pass
                raise
            
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
                                stdout_data.append(remaining_stdout.decode('utf-8', errors='replace'))
                            except UnicodeDecodeError:
                                # If we can't decode as UTF-8, try with error replacement
                                stdout_data.append(remaining_stdout.decode('utf-8', errors='replace'))
                    except Exception as e:
                        logger.error(f"Error reading remaining stdout: {e}")
                    break
                
                # Read available output
                try:
                    stdout = await process.stdout.read(4096)
                    if stdout:
                        try:
                            stdout_data.append(stdout.decode('utf-8', errors='replace'))
                        except UnicodeDecodeError:
                            stdout_data.append(stdout.decode('utf-8', errors='replace'))
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
                        stderr_data.append(stderr.decode('utf-8', errors='replace'))
                    except UnicodeDecodeError:
                        stderr_data.append(stderr.decode('utf-8', errors='replace'))
            except Exception as e:
                logger.error(f"Error reading stderr: {e}")
            
            # Send complete output
            full_output = ''.join(stdout_data)
            
            # Check if this looks like a port scan (contains the port scan header)
            if '╭─ Cybersec CLI - Port Scan Results' in full_output:
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
            await websocket.send_text(f"[END] Command completed with return code {process.returncode}")

            # Persist scan output if this was a scan command
            try:
                if len(parts) >= 2 and parts[0].lower() == 'scan':
                    # Try to determine ip for storage
                    try:
                        stored_ip = socket.gethostbyname(parts[1])
                    except Exception:
                        stored_ip = None
                    save_scan_result(parts[1], stored_ip, command, full_output)
            except Exception:
                logger.exception('Failed to persist scan result')

            # finally decrement active scan counter for the client
            try:
                if len(parts) >= 2 and parts[0].lower() == 'scan':
                    await _record_scan_end(client_host)
            except Exception:
                pass
            
            
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        await websocket.send_text(f"[ERR] Error executing command: {str(e)}")
    finally:
        manager.disconnect(websocket)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
