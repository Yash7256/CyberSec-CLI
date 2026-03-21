"""
Module: api/main.py
Description: Lightweight FastAPI API server for CyberSec CLI.
              Provides WebSocket connectivity and basic health endpoints.
              Note: This is a minimal API - the main web server is in web/main.py.

Dependencies:
    - fastapi: Web framework
    - uvicorn: ASGI server

Usage:
    Run: uvicorn api.main:app --host 0.0.0.0 --port 8000
    Or: python -m api.main

Environment Variables:
    - ALLOWED_ORIGINS: CORS allowed origins (comma-separated)
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import uvicorn
import logging
import os
from typing import List

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="CyberSec CLI API",
    description="Lightweight API for CyberSec CLI - WebSocket and health endpoints",
    version="1.0.0"
)

# CORS middleware - load allowed origins from environment
# SECURITY: Origins list controls which browsers may send credentialed requests.
# Format: ALLOWED_ORIGINS=https://app.example.com,https://admin.example.com
allowed_origins_env = os.environ.get("ALLOWED_ORIGINS", "")
origins = [origin.strip() for origin in allowed_origins_env.split(",") if origin.strip()]

logger.info("CORS allowed origins: %s", origins)
if not origins:
    logger.warning(
        "ALLOWED_ORIGINS not set. CORS is disabled. "
        "Set ALLOWED_ORIGINS environment variable for production."
    )

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Content-Type", "Authorization"],
)

# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        """Accept and register a new WebSocket connection."""
        await websocket.accept()
        self.active_connections.append(websocket)

    async def disconnect(self, websocket: WebSocket):
        """Remove a WebSocket connection from the active list."""
        self.active_connections.remove(websocket)

    async def broadcast(self, message: str):
        """Send a text message to all active connections, pruning failures."""
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception as e:
                logger.error(f"Error broadcasting message: {e}")
                self.active_connections.remove(connection)

manager = ConnectionManager()

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Health check endpoint
@app.get("/health")
async def health_check():
    """Simple liveness probe for orchestration/monitoring."""
    return {"status": "healthy"}

# WebSocket endpoint
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """Echo/broadcast WebSocket endpoint for real-time messaging."""
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            # Here you can add message handling logic
            await manager.broadcast(f"Message received: {data}")
    except WebSocketDisconnect:
        await manager.disconnect(websocket)
        await manager.broadcast("A client disconnected")

# Import and include routers from other modules
# from .routers import scan, analysis, etc.

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
