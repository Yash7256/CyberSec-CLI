"""
Celery tasks for network scanning operations.
"""

import asyncio
import json
import logging
import os
import sys
from typing import Any, Dict, List, Optional

from celery import Task

from tasks.celery_app import celery_app

# Add the project root to the path so we can import our modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Event loop management to avoid repeated asyncio.run() calls
_event_loop = None

def get_event_loop():
    """Get or create a reusable event loop for Celery tasks."""
    global _event_loop
    if _event_loop is None or _event_loop.is_closed():
        _event_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(_event_loop)
    return _event_loop

def run_async(coro):
    """Run a coroutine in the shared event loop."""
    loop = get_event_loop()
    return loop.run_until_complete(coro)

# Import structured logging
try:
    from src.cybersec_cli.core.logging_config import get_logger, setup_logging
    from src.cybersec_cli.config import settings

    setup_logging(
        log_dir=settings.logging.log_dir, audit_log_file=settings.logging.audit_log_file
    )
    HAS_STRUCTURED_LOGGING = True
except ImportError:
    HAS_STRUCTURED_LOGGING = False

# Import scanning utilities
try:
    from src.cybersec_cli.core.port_priority import get_scan_order
    from src.cybersec_cli.tools.network.port_scanner import PortScanner, PortState, ScanType
    from src.cybersec_cli.utils.formatters import get_vulnerability_info

    HAS_SCAN_MODULES = True
except ImportError as e:
    if HAS_STRUCTURED_LOGGING:
        logger = get_logger("celery")
        logger.error(f"Failed to import scan modules: {e}")
    else:
        logging.error(f"Failed to import scan modules: {e}")
    HAS_SCAN_MODULES = False

# Import database functions
try:
    from web.main import save_scan_result

    HAS_DB_MODULES = True
except ImportError as e:
    logging.error(f"Failed to import database modules: {e}")
    HAS_DB_MODULES = False

# Import scan cache
try:
    from src.cybersec_cli.core.scan_cache import scan_cache

    HAS_SCAN_CACHE = True
except ImportError:
    HAS_SCAN_CACHE = False
    scan_cache = None

# Import metrics
try:
    from monitoring.metrics import (
        metrics_collector,
        record_scan,
        start_timer,
        stop_timer,
    )

    HAS_METRICS = True
except ImportError:
    HAS_METRICS = False
    metrics_collector = None
    import time

    def _timer_now() -> float:
        """Return a monotonic timestamp from asyncio or thread context."""
        try:
            return asyncio.get_running_loop().time()
        except RuntimeError:
            return time.monotonic()

    def start_timer():
        """Start a timer - returns current time."""
        return _timer_now()

    def stop_timer(start_time):
        """Stop timer and return duration. Returns 0 if start_time is 0."""
        if start_time == 0:
            return 0
        return _timer_now() - start_time


logger = get_logger("celery") if HAS_STRUCTURED_LOGGING else logging.getLogger(__name__)


def _safe_start_timer() -> float:
    timer_fn = start_timer
    assert callable(timer_fn)
    return timer_fn()


def _safe_stop_timer(start_time: float) -> float:
    timer_fn = stop_timer
    assert callable(timer_fn)
    return timer_fn(start_time)


def _parse_ports_spec(ports: str) -> List[int]:
    """Parse a ports string into a list of validated port integers."""
    MAX_PORTS = 10000
    port_list: List[int] = []
    if not ports:
        return port_list

    if "-" in ports:
        raw_start, raw_end = ports.split("-", 1)
        try:
            start = int(raw_start)
            if not (1 <= start <= 65535):
                raise ValueError(f"Port out of range: {start}")
        except (ValueError, TypeError):
            logger.warning(f"Invalid port value skipped: {raw_start!r}")
            return []
        try:
            end = int(raw_end)
            if not (1 <= end <= 65535):
                raise ValueError(f"Port out of range: {end}")
        except (ValueError, TypeError):
            logger.warning(f"Invalid port value skipped: {raw_end!r}")
            return []
        if start > end:
            logger.warning(f"Invalid port range: {start}-{end}")
            return []
        port_list = list(range(start, end + 1))
    elif "," in ports:
        for raw_port in ports.split(","):
            raw_port = raw_port.strip()
            try:
                port = int(raw_port)
                if not (1 <= port <= 65535):
                    raise ValueError(f"Port out of range: {port}")
            except (ValueError, TypeError):
                logger.warning(f"Invalid port value skipped: {raw_port!r}")
                continue
            port_list.append(port)
    else:
        try:
            port = int(ports)
            if not (1 <= port <= 65535):
                raise ValueError(f"Port out of range: {port}")
        except (ValueError, TypeError):
            logger.warning(f"Invalid port value skipped: {ports!r}")
            return []
        port_list = [port]
    
    if len(port_list) > MAX_PORTS:
        raise ValueError(
            f"Port range too large ({len(port_list)} ports). Maximum allowed: {MAX_PORTS}."
        )
    
    return port_list


class ScanTask(Task):
    """Base class for scan tasks with common functionality."""

    def __init__(self):
        self.scan_id = None
        self.target = None
        self.ports = None
        self.config = None


async def _perform_scan_task_async(
    self,
    scan_id: str,
    target: str,
    ports: str = "1-1000",
    config: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Perform a network scan as a Celery task.

    Args:
        scan_id: Unique identifier for this scan
        target: Target hostname or IP address to scan
        ports: Port range to scan (e.g., "1-1000", "80,443", "22-25,80,443")
        config: Configuration options for the scan

    Returns:
        Dictionary containing scan results and metadata
    """
    if not HAS_SCAN_MODULES:
        raise Exception("Scan modules not available")

    if config is None:
        config = {}

    # Store task information
    self.scan_id = scan_id
    self.target = target
    self.ports = ports
    self.config = config

    logger.info(f"Starting scan task {scan_id} for target {target}")

    # Initialize scan_start_time before try block to ensure it's always defined
    scan_start_time = 0

    try:
        # Record scan start for metrics
        scan_start_time = _safe_start_timer() if HAS_METRICS else 0

        # Check cache first if caching is enabled
        force_scan = config.get("force", False) if config else False
        if HAS_SCAN_CACHE and scan_cache and not force_scan:
            # Parse ports to list for cache key with error handling
            port_list = _parse_ports_spec(ports)

            cache_key = scan_cache.get_cache_key(target, sorted(port_list))
            cached_result = await scan_cache.check_cache(cache_key)

            if cached_result:
                logger.info(f"Returning cached results for {target}")

                # Prepare cached results in the expected format
                result_data = {
                    "scan_id": scan_id,
                    "target": target,
                    "ports": ports,
                    "total_ports_scanned": len(port_list),
                    "open_ports": cached_result.get("results", []),
                    "status": "completed",
                    "progress": 100,
                    "cached": True,
                    "cached_at": cached_result.get("cached_at"),
                }

                # Record metrics for cached scan
                if HAS_METRICS:
                    scan_duration = _safe_stop_timer(scan_start_time)
                    metrics_collector.increment_cache_hit()
                    metrics_collector.observe_scan_duration(scan_duration)
                    metrics_collector.observe_ports_scanned(len(port_list))
                    metrics_collector.observe_open_ports_found(
                        len(cached_result.get("results", []))
                    )
                    metrics_collector.increment_scan(
                        status="completed", user_type="unknown"
                    )

                # Save results to database if available
                if HAS_DB_MODULES:
                    try:
                        command = f"scan {target} --ports {ports}"
                        output = json.dumps(result_data, indent=2)
                        save_scan_result(target, None, command, output)
                        logger.info(
                            f"Saved cached scan results for {scan_id} to database"
                        )
                    except Exception as e:
                        logger.error(
                            f"Failed to save cached scan results to database: {e}"
                        )

                logger.info(
                    f"Completed scan task {scan_id} for target {target} (cached)"
                )
                return result_data

        # Update task state to show we're starting
        self.update_state(
            state="PROGRESS", meta={"status": "Starting scan...", "progress": 0}
        )

        # Parse ports with error handling
        port_list = _parse_ports_spec(ports)

        # Record cache miss if applicable
        if HAS_METRICS and HAS_SCAN_CACHE and scan_cache and not force_scan:
            metrics_collector.increment_cache_miss()

        # Group ports by priority
        priority_groups = get_scan_order(port_list)
        priority_names = ["critical", "high", "medium", "low"]

        # Calculate total ports for progress tracking
        total_ports = sum(len(group) for group in priority_groups)
        scanned_ports = 0

        # Initialize results collection
        all_results = []

        # Update task state to show scanning has started
        self.update_state(
            state="PROGRESS",
            meta={
                "status": f"Starting scan on {target} with {total_ports} ports",
                "progress": 0,
                "target": target,
                "total_ports": total_ports,
            },
        )

        # Scan each priority group
        for i, group in enumerate(priority_groups):
            if not group:
                continue

            # Update task state for group start
            self.update_state(
                state="PROGRESS",
                meta={
                    "status": f"Scanning {priority_names[i]} priority ports",
                    "progress": (
                        round((scanned_ports / total_ports) * 100)
                        if total_ports > 0
                        else 0
                    ),
                    "current_group": priority_names[i],
                    "group_size": len(group),
                },
            )

            # Create scanner for this group
            scan_type = ScanType.TCP_CONNECT
            if "scan_type" in config:
                if config["scan_type"].upper() == "UDP":
                    scan_type = ScanType.UDP
                elif config["scan_type"].upper() == "SYN":
                    scan_type = ScanType.TCP_SYN

            # Resolve target once to prevent DNS rebinding
            from src.cybersec_cli.core.validators import resolve_target
            resolved_ip = resolve_target(target)
            if not resolved_ip:
                raise ValueError(f"Could not resolve target: {target}")

            timeout = config.get("timeout", 1.0)
            max_concurrent = config.get("max_concurrent", 50)
            enhanced_service_detection = config.get("enhanced_service_detection", True)

            scanner = PortScanner(
                target=target,
                resolved_ip=resolved_ip,  # Pass pre-resolved IP
                ports=group,
                scan_type=scan_type,
                timeout=timeout,
                max_concurrent=max_concurrent,
                enhanced_service_detection=enhanced_service_detection,
                force_scan=force_scan,
            )

            # Perform the scan
            results = scanner.scan_sync()  # Use the sync method

            # Update scanned ports count
            scanned_ports += len(group)
            progress_percentage = (
                round((scanned_ports / total_ports) * 100) if total_ports > 0 else 0
            )

            # Collect results
            for result in results:
                if result.state == PortState.OPEN:
                    # Get vulnerability information for this port
                    vuln_info = get_vulnerability_info(result.port, result.service)

                    port_info = {
                        "port": result.port,
                        "service": result.service or "unknown",
                        "version": result.version or "unknown",
                        "banner": result.banner or "",
                        "confidence": result.confidence,
                        "protocol": result.protocol,
                        "risk": (
                            vuln_info["severity"].name
                            if "severity" in vuln_info
                            else "UNKNOWN"
                        ),
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
                    all_results.append(port_info)

            # Update task state after group completion
            self.update_state(
                state="PROGRESS",
                meta={
                    "status": f"Completed scanning {priority_names[i]} priority ports",
                    "progress": progress_percentage,
                    "open_ports_found": len(
                        [r for r in results if r.state == PortState.OPEN]
                    ),
                    "total_scanned": scanned_ports,
                },
            )

        # Record scan completion metrics
        if HAS_METRICS:
            scan_duration = _safe_stop_timer(scan_start_time)
            record_scan(
                scan_start_time,
                status="completed",
                user_type="unknown",
                ports_count=total_ports,
                open_ports_count=len(all_results),
            )

        # Prepare final results
        result_data = {
            "scan_id": scan_id,
            "target": target,
            "ports": ports,
            "total_ports_scanned": total_ports,
            "open_ports": all_results,
            "status": "completed",
            "progress": 100,
            "cached": False,
        }

        # Store results in cache if caching is enabled and not forced
        if HAS_SCAN_CACHE and scan_cache and not force_scan:
            cache_key = scan_cache.get_cache_key(target, sorted(port_list))
            cache_data = {"results": all_results}
            await scan_cache.store_cache(cache_key, cache_data, target=target)

        # Save results to database if available
        if HAS_DB_MODULES:
            try:
                command = f"scan {target} --ports {ports}"
                output = json.dumps(result_data, indent=2)
                save_scan_result(target, None, command, output)
                logger.info(f"Saved scan results for {scan_id} to database")
            except Exception as e:
                logger.error(f"Failed to save scan results to database: {e}")

        logger.info(f"Completed scan task {scan_id} for target {target}")
        return result_data

    except Exception as exc:
        logger.error(f"Scan task {scan_id} failed: {exc}")
        # Record error metrics
        if HAS_METRICS:
            scan_duration = _safe_stop_timer(scan_start_time)
            metrics_collector.increment_scan_error(
                error_type=str(type(exc).__name__), target_type="unknown"
            )
            metrics_collector.observe_scan_duration(scan_duration)
            metrics_collector.increment_scan(status="error", user_type="unknown")
        # Retry on failure (up to max_retries times)
        raise self.retry(exc=exc, countdown=60, max_retries=3)


@celery_app.task(bind=True, base=ScanTask, max_retries=3)
def perform_scan_task(
    self,
    scan_id: str,
    target: str,
    ports: str = "1-1000",
    config: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    return run_async(_perform_scan_task_async(self, scan_id, target, ports, config))
