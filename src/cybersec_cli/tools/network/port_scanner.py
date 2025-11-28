"""
Port Scanner Module for Cybersec CLI.
Supports various scanning techniques and service detection.
"""
import asyncio
import socket
import ipaddress
from datetime import datetime as dt
import time
import random
from typing import List, Dict, Tuple, Optional, Union, Set, Any
from dataclasses import dataclass, asdict
from enum import Enum
import json
import csv
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

import aiohttp
import aiohttp
from rich.progress import (
    Progress, BarColumn, TextColumn, TimeRemainingColumn, 
    SpinnerColumn, TimeElapsedColumn
)
from rich.table import Table
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax

from cybersec_cli.utils.logger import setup_logger

from cybersec_cli.utils.logger import get_logger
from cybersec_cli.config import settings

logger = get_logger(__name__)

class PortState(Enum):
    """Enumeration of possible port states."""
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    UNFILTERED = "unfiltered"
    OPEN_FILTERED = "open|filtered"
    CLOSED_FILTERED = "closed|filtered"

@dataclass
class PortResult:
    """Represents the result of a port scan for a single port."""
    port: int
    state: PortState
    service: Optional[str] = None
    banner: Optional[str] = None
    version: Optional[str] = None
    protocol: str = "tcp"
    reason: Optional[str] = None
    ttl: Optional[float] = None

    def to_dict(self) -> Dict:
        """Convert the result to a dictionary."""
        return {
            "port": self.port,
            "state": self.state.value,
            "service": self.service,
            "banner": self.banner,
            "protocol": self.protocol,
            "reason": self.reason,
            "ttl": self.ttl
        }

class ScanType(Enum):
    """Types of port scans."""
    TCP_CONNECT = "tcp_connect"
    TCP_SYN = "tcp_syn"  # Requires root
    UDP = "udp"
    FIN = "fin"  # Stealth scan
    NULL = "null"  # Null scan
    XMAS = "xmas"  # Xmas scan

class PortScanner:
    """Asynchronous port scanner with service detection and banner grabbing."""
    
    # Common ports for quick scanning
    COMMON_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
        1723, 3306, 3389, 5900, 8080, 8443
    ]
    
    # Common services database
    COMMON_SERVICES = {
        20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
        53: "dns", 80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
        139: "netbios-ssn", 143: "imap", 443: "https", 445: "microsoft-ds",
        993: "imaps", 995: "pop3s", 1723: "pptp", 3306: "mysql", 3389: "ms-wbt-server",
        5900: "vnc", 8080: "http-proxy", 8443: "https-alt"
    }
    
    def __init__(self, 
                 target: str, 
                 ports: Optional[Union[List[int], str, int]] = None,
                 scan_type: ScanType = ScanType.TCP_CONNECT,
                 timeout: float = 1.0,
                 max_concurrent: int = 100,
                 rate_limit: int = 0,
                 service_detection: bool = True,
                 banner_grabbing: bool = True,
                 require_reachable: bool = False,
                 logger=None):
        """
        Initialize the port scanner.
        
        Args:
            target: Target hostname or IP address
            ports: Port(s) to scan. Can be a list, range (e.g., '1-1024'), or single port
            scan_type: Type of scan to perform
            timeout: Connection timeout in seconds
            max_concurrent: Maximum number of concurrent connections
            service_detection: Whether to perform service detection
            banner_grabbing: Whether to grab banners from open ports
        """
        self.logger = logger or setup_logger(__name__)
        
        # Validate target is not empty or placeholder
        if not target or not target.strip():
            raise ValueError("Target hostname or IP address cannot be empty.")
        
        # Reject common placeholder/example domains to prevent accidents
        placeholder_domains = [
            'example.com', 'example.org', 'example.net',
            'test.com', 'localhost', 'placeholder.local',
            'demo.com', 'sample.com', 'ggits.org'
        ]
        target_lower = target.lower().strip()
        if target_lower in placeholder_domains:
            raise ValueError(
                f"Target '{target}' is a placeholder/example domain. "
                f"Please specify a real hostname or IP address to scan."
            )
        
        self.target = target
        self.scan_type = scan_type
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.service_detection = service_detection
        self.banner_grabbing = banner_grabbing
        self.ports = self._parse_ports(ports) if ports is not None else self.COMMON_PORTS
        self.results: List[PortResult] = []
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self.rate_limit = rate_limit
        self.last_request_time = 0
        self.require_reachable = require_reachable
        
        # Log scanning parameters for debugging
        self.logger.info(f"Initializing port scanner for target: {target}")
        self.logger.debug(f"Ports to scan: {len(self.ports)} ports (range: {min(self.ports)}-{max(self.ports)})")
        
        # Resolve hostname to IP if needed
        try:
            self.ip = str(ipaddress.ip_address(target))
            self.hostname = target
            self.logger.info(f"Target is valid IP address: {self.ip}")
        except ValueError:
            # It's a hostname, resolve it
            try:
                self.ip = socket.gethostbyname(target)
                self.hostname = target
                self.logger.info(f"Resolved hostname '{target}' to IP {self.ip}")
            except socket.gaierror as e:
                error_msg = (
                    f"Could not resolve hostname '{target}'. "
                    f"Please verify the hostname is correct and reachable."
                )
                self.logger.error(error_msg)
                raise ValueError(error_msg) from e

        # Optional quick reachability check (synchronous, lightweight)
        if self.require_reachable:
            try:
                if not self._quick_reachable_check():
                    raise ValueError(
                        f"Target '{self.target}' ({self.ip}) did not respond on common ports (80/443)."
                    )
            except Exception as e:
                # re-raise as ValueError for callers
                raise ValueError(str(e)) from e
    
    def _parse_ports(self, ports: Union[List[int], str, int]) -> Set[int]:
        """Parse ports from various input formats."""
        if isinstance(ports, int):
            return {ports}
        elif isinstance(ports, str):
            # Handle port ranges like '1-1024' or comma-separated '80,443,8080'
            port_set = set()
            for part in ports.split(','):
                part = part.strip()
                if '-' in part:
                    start, end = map(int, part.split('-'))
                    port_set.update(range(start, end + 1))
                else:
                    port_set.add(int(part))
            return port_set
        elif isinstance(ports, (list, tuple, set)):
            return set(ports)
        else:
            raise ValueError("Invalid ports format. Expected int, str, or list of ints.")
    
    async def _rate_limit(self):
        """Enforce rate limiting if enabled."""
        if self.rate_limit > 0:
            now = time.time()
            time_since_last = now - self.last_request_time
            min_interval = 1.0 / self.rate_limit
            
            if time_since_last < min_interval:
                await asyncio.sleep(min_interval - time_since_last)
            
            self.last_request_time = time.time()
    
    async def _check_port(self, port: int) -> PortResult:
        """Check a single port asynchronously."""
        result = PortResult(port=port, state=PortState.CLOSED)
        
        try:
            async with self._semaphore:
                # Apply rate limiting
                await self._rate_limit()
                
                self.logger.debug(f"Scanning port {port}")
                
                # Try to connect to the port
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.ip, port),
                    timeout=self.timeout
                )
                writer.close()
                await writer.wait_closed()
                result = PortResult(port=port, state=PortState.OPEN)
                
                # Get service info if enabled
                if self.service_detection:
                    result.service = self.COMMON_SERVICES.get(port)
                
                # Try to grab banner if enabled
                if self.banner_grabbing and self._is_banner_port(port):
                    await self._grab_banner(port, result)
                
                return result
                
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            # Port is closed or filtered
            return PortResult(port=port, state=PortState.CLOSED)
        except Exception as e:
            self.logger.error(f"Error scanning port {port}: {e}")
            return PortResult(
                port=port, 
                state=PortState.CLOSED,
                reason=str(e)
            )
    
    def _is_banner_port(self, port: int) -> bool:
        """Check if we should attempt to grab a banner from this port."""
        return port in [
            21, 22, 23, 25, 80, 110, 143, 443, 465, 587, 993, 995, 1723, 3306, 
            3389, 5432, 5900, 8080, 8443, 27017, 27018, 27019
        ]
    
    async def _grab_banner(self, port: int, result: PortResult) -> None:
        """Grab banner from the specified port."""
        try:
            probe = self._get_probe_for_port(port)
            if not probe:
                return
                
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.ip, port),
                timeout=self.timeout
            )
            
            try:
                writer.write(probe)
                await writer.drain()
                
                # Read banner with a timeout
                banner = await asyncio.wait_for(reader.read(1024), timeout=self.timeout)
                if banner:
                    result.banner = banner.decode('utf-8', errors='ignore').strip()
                    
            except asyncio.TimeoutError:
                self.logger.debug(f"Banner grab timed out for port {port}")
            except Exception as e:
                self.logger.debug(f"Error reading banner from port {port}: {e}")
                
        except Exception as e:
            self.logger.debug(f"Banner grab failed for port {port}: {e}")
            
        finally:
            # Ensure writer is properly closed
            if 'writer' in locals():
                writer.close()
                await writer.wait_closed()

    def _get_probe_for_port(self, port: int) -> Optional[bytes]:
        """Get an appropriate probe for banner grabbing based on port."""
        probes = {
            21: b"\r\n",  # FTP
            22: b"SSH-2.0-CyberSecCLI\r\n",  # SSH
            25: b"EHLO example.com\r\n",  # SMTP
            80: b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n",  # HTTP
            110: b"USER guest\r\n",  # POP3
            143: b"a1 CAPABILITY\r\n",  # IMAP
            443: b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n",  # HTTPS
            3306: b"\x0a\x00\x00\x01\x85\xa6\x3f\x20\x00\x00\x00\x01\x21",  # MySQL
            3389: b"\x03\x00\x00\x0b\x06\xd0\x00\x00\x12\x34\x00"  # RDP
        }
        return probes.get(port, None)

    def _quick_reachable_check(self, ports: Optional[List[int]] = None, timeout: float = 1.0) -> bool:
        """
        Synchronous quick reachability check that attempts to TCP-connect to one
        of a small set of common service ports (80, 443 by default).

        Returns True if any port accepts a TCP connection, False otherwise.
        """
        check_ports = ports or [80, 443]
        for p in check_ports:
            try:
                with socket.create_connection((self.ip, p), timeout=timeout):
                    self.logger.debug(f"Quick reachability: port {p} is open on {self.ip}")
                    return True
            except Exception:
                continue
        self.logger.debug(f"Quick reachability: no response on ports {check_ports} for {self.ip}")
        return False
    
    async def scan(self) -> List[PortResult]:
        """
        Perform the port scan.
        
        Returns:
            List of PortResult objects with scan results
        """
        # Log scan initiation with detailed info
        self.logger.info(f"Starting port scan on {self.target} ({self.ip})")
        self.logger.info(f"Scan type: {self.scan_type.value}")
        self.logger.info(f"Ports to scan: {len(self.ports)} total")
        if len(self.ports) <= 20:
            self.logger.debug(f"Port list: {sorted(self.ports)}")
        else:
            port_list = sorted(self.ports)
            self.logger.debug(f"Port range: {port_list[0]}-{port_list[-1]} (showing first 5: {port_list[:5]}...)")
        
        tasks = []
        results = []
        
        # Create tasks for each port
        for port in self.ports:
            task = asyncio.create_task(self._check_port(port))
            task.add_done_callback(
                lambda t, p=port: results.append(t.result())
            )
            tasks.append(task)
        
        # Show progress if there are many ports
        if len(tasks) > 10:
            with Progress(
                TextColumn("[progress.description]{task.description}"),
                BarColumn(bar_width=None),
                "[progress.percentage]{task.percentage:>3.0f}%",
                TimeRemainingColumn(),
                console=Console()
            ) as progress:
                task = progress.add_task(
                    f"[cyan]Scanning {len(tasks)} ports on {self.target}...",
                    total=len(tasks)
                )
                
                # Wait for all tasks to complete
                for t in asyncio.as_completed(tasks):
                    await t
                    progress.update(task, advance=1)
        else:
            # For small scans, just wait for all tasks
            await asyncio.gather(*tasks)
        
        # Sort results by port number
        self.results = sorted(results, key=lambda x: x.port)
        
        # Log completion statistics
        open_count = len([r for r in self.results if r.state == PortState.OPEN])
        closed_count = len([r for r in self.results if r.state == PortState.CLOSED])
        filtered_count = len([r for r in self.results if r.state == PortState.FILTERED])
        
        self.logger.info(f"Scan completed: {open_count} open, {closed_count} closed, {filtered_count} filtered")
        if open_count > 0:
            open_ports_list = sorted([r.port for r in self.results if r.state == PortState.OPEN])
            self.logger.info(f"Open ports found: {open_ports_list}")
        
        return self.results
    
    def get_open_ports(self) -> List[PortResult]:
        """Get a list of open ports."""
        return [r for r in self.results if r.state == PortState.OPEN]
    
    def to_json(self) -> str:
        """Convert scan results to JSON."""
        return json.dumps(
            {
                "target": self.target,
                "ip": self.ip,
                "scan_type": self.scan_type.value,
                "timestamp": str(dt.utcnow()),
                "results": [r.to_dict() for r in self.results]
            },
            indent=2
        )
    
    def to_table(self) -> Table:
        """Convert scan results to a Rich Table."""
        table = Table(title=f"Port Scan Results for {self.target} ({self.ip})")
        table.add_column("Port", justify="right")
        table.add_column("State", justify="left")
        table.add_column("Service", justify="left")
        table.add_column("Banner", justify="left")
        
        for result in self.results:
            if result.state == PortState.OPEN:
                table.add_row(
                    str(result.port),
                    f"[green]{result.state.value}[/green]",
                    result.service or "unknown",
                    result.banner or ""
                )
        
        return table

# Helper function for command-line usage
async def scan_ports(
    target: str,
    ports: Optional[Union[List[int], str, int]] = None,
    scan_type: str = "tcp_connect",
    timeout: float = 1.0,
    max_concurrent: int = 100,
    service_detection: bool = True,
    banner_grabbing: bool = True,
    output_format: str = "table"
) -> str:
    """Scan ports on a target and return results in the specified format.
    
    Args:
        target: Target hostname or IP address
        ports: Port(s) to scan (e.g., [80, 443], '1-1024', 8080)
        scan_type: Type of scan ('tcp_connect', 'tcp_syn', 'udp')
        timeout: Connection timeout in seconds
        max_concurrent: Maximum number of concurrent connections
        service_detection: Whether to detect services
        banner_grabbing: Whether to grab banners
        output_format: Output format ('table', 'json', 'list')
        
    Returns:
        Formatted scan results
    """
    try:
        scanner = PortScanner(
            target=target,
            ports=ports,
            scan_type=ScanType(scan_type),
            timeout=timeout,
            max_concurrent=max_concurrent,
            service_detection=service_detection,
            banner_grabbing=banner_grabbing
        )
        
        await scanner.scan()
        
        if output_format == "json":
            return scanner.to_json()
        elif output_format == "list":
            return "\n".join(
                f"{r.port}/tcp {r.state.value}" 
                for r in scanner.get_open_ports()
            )
        else:  # table
            console = Console()
            console.print(scanner.to_table())
            return ""
            
    except Exception as e:
        return f"Error: {str(e)}"
