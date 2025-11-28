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
from typing import Dict, List, Optional
import subprocess
from datetime import datetime

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="CyberSec-CLI Web")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Get the base directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
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

# WebSocket endpoint for command execution
@app.websocket("/ws/command")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            payload = json.loads(data)
            command = payload.get("command", "")
            force = payload.get("force", False)

            if not command:
                continue

            # Intercept 'scan' commands to perform a quick reachability check
            parts = command.strip().split()
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
            process = await asyncio.create_subprocess_shell(
                f"python -m cybersec_cli {command}",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=os.getcwd()
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
