from fastapi import APIRouter, HTTPException
import subprocess

try:
    from cybersec_cli.core.validators import validate_target
except ImportError:
    from src.cybersec_cli.core.validators import validate_target

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
        if not target or target.startswith("-") or not validate_target(target):
            raise HTTPException(status_code=400, detail="Invalid target")

        result = subprocess.run(
            ["nmap", "-sV", target],
            capture_output=True,
            text=True,
            timeout=60,
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
