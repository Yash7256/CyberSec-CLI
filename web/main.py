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
from cybersec_cli.utils.logger import log_forced_scan

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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

            # Intercept 'scan' commands to perform a quick reachability check
            parts = command.strip().split()
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

            # Simple rate limiting: per-minute counter
            if len(parts) >= 2 and parts[0].lower() == 'scan':
                now = int(asyncio.get_event_loop().time())
                rc = _rate_counters.get(client_host)
                if rc is None or now >= rc.get('reset_at', 0):
                    # reset window
                    _rate_counters[client_host] = {'count': 0, 'reset_at': now + 60}
                    rc = _rate_counters[client_host]
                if rc['count'] >= WS_RATE_LIMIT:
                    await websocket.send_text(json.dumps({
                        'type': 'rate_limit',
                        'message': f'Rate limit exceeded ({WS_RATE_LIMIT} scans per minute). Please wait.'
                    }))
                    continue
                # check concurrent
                if _active_scans.get(client_host, 0) >= WS_CONCURRENT_LIMIT:
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

            # If we reach here and this is a scan that will be executed, increment rate counters
            if len(parts) >= 2 and parts[0].lower() == 'scan':
                # increment counters
                _rate_counters.setdefault(client_host, {'count': 0, 'reset_at': int(asyncio.get_event_loop().time()) + 60})
                _rate_counters[client_host]['count'] += 1
                _active_scans[client_host] = _active_scans.get(client_host, 0) + 1

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
                    _active_scans[client_host] = max(0, _active_scans.get(client_host, 1) - 1)
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
