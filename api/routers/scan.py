from fastapi import APIRouter, HTTPException, WebSocket
from typing import List, Dict, Any
import subprocess
import shlex
import json

router = APIRouter(
    prefix="/api/scan",
    tags=["scan"],
    responses={404: {"description": "Not found"}},
)

@router.get("/nmap/{target}")
async def nmap_scan(target: str):
    """
    Perform a basic Nmap scan on the target
    """
    try:
        # Security note: In production, you should validate and sanitize the target input
        command = f"nmap -sV {target}"
        result = subprocess.run(
            shlex.split(command),
            capture_output=True,
            text=True,
            timeout=60
        )
        
        if result.returncode != 0:
            raise HTTPException(
                status_code=400,
                detail=f"Scan failed: {result.stderr}"
            )
            
        return {
            "status": "success",
            "target": target,
            "output": result.stdout
        }
        
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=408, detail="Scan timed out")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Add more scan endpoints as needed
