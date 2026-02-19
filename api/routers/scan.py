from fastapi import APIRouter, HTTPException
import subprocess
import sys

try:
    from cybersec_cli.core.validators import validate_target
except ImportError:
    from src.cybersec_cli.core.validators import validate_target

router = APIRouter(
    prefix="/api/scan",
    tags=["scan"],
    responses={404: {"description": "Not found"}},
)

ALLOWED_COMMANDS = {"scan", "ping", "trace"}
ALLOWED_SCAN_TYPES = frozenset({"tcp", "udp", "syn", "ack"})
COMMAND_MODULES = {
    "scan": "cybersec_cli.commands.scan",
    "ping": "cybersec_cli.commands.ping",
    "trace": "cybersec_cli.commands.trace",
}


@router.get("/{cmd}/{arg}")
async def run_command(cmd: str, arg: str, scan_type: str = "tcp"):
    """
    Run a restricted CLI command with a single argument
    """
    try:
        requested_cmd = cmd
        if requested_cmd not in ALLOWED_COMMANDS:
            raise HTTPException(status_code=400, detail="Unsupported command")

        # Validate target with strict checks
        if not arg:
            raise HTTPException(status_code=400, detail="Target is required")

        # Check for shell metacharacters that could be used for injection
        dangerous_chars = [";", "|", "&", "$", "`", "(", ")", "<", ">", "\n", "\r", "\x00"]
        if any(char in arg for char in dangerous_chars):
            raise HTTPException(status_code=400, detail="Invalid characters in target")

        # Prevent flag injection (target starting with -)
        if arg.startswith("-"):
            raise HTTPException(status_code=400, detail="Invalid target")

        # Validate target using the validator
        if not validate_target(arg):
            raise HTTPException(status_code=400, detail="Target validation failed")

        cmd = COMMAND_MODULES[requested_cmd]
        extra_args = []
        if requested_cmd == "scan":
            if scan_type not in ALLOWED_SCAN_TYPES:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid scan type. Allowed: {ALLOWED_SCAN_TYPES}",
                )
            extra_args.extend(["--scan-type", scan_type])

        # Use list form with -m to run the module safely
        result = subprocess.run(
            [sys.executable, "-m", cmd, arg, *extra_args],
            capture_output=True,
            text=True,
            timeout=60,
            shell=False,  # Explicitly use list form, not shell
        )
        
        if result.returncode != 0:
            raise HTTPException(
                status_code=400,
                detail=f"Command failed: {result.stderr}"
            )
            
        return {
            "status": "success",
            "command": requested_cmd,
            "target": arg,
            "output": result.stdout,
        }
        
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=408, detail="Scan timed out")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Add more scan endpoints as needed
