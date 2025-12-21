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

# Import adaptive configuration
try:
    from core.adaptive_config import AdaptiveScanConfig
    HAS_ADAPTIVE_CONFIG = True
except ImportError:
    HAS_ADAPTIVE_CONFIG = False
    # Fallback implementation if core module not available
    class AdaptiveScanConfig:
        def __init__(self, *args, **kwargs):
            pass
        def adjust_parameters(self):
            pass
        def record_attempt(self, success: bool):
            pass
        def reset_stats(self):
            pass

# Import service probes
try:
    from core.service_probes import identify_service_async, get_ssl_info
    HAS_SERVICE_PROBES = True
except ImportError:
    HAS_SERVICE_PROBES = False
    # Fallback implementation if core module not available
    async def identify_service_async(*args, **kwargs):
        return {"service": None, "version": None, "banner": None, "confidence": 0.0}
    def get_ssl_info(*args, **kwargs):
        return None

# Add import for our new priority module
try:
    from core.port_priority import get_scan_order
    HAS_PRIORITY_MODULE = True
except ImportError:
    HAS_PRIORITY_MODULE = False
    def get_scan_order(ports):
        # Fallback implementation if core module not available
        return [ports, [], [], []]

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
    confidence: float = 0.0  # Confidence level for service detection (0.0-1.0)

    def to_dict(self) -> Dict:
        """Convert the result to a dictionary."""
        return {
            "port": self.port,
            "state": self.state.value,
            "service": self.service,
            "banner": self.banner,
            "version": self.version,
            "protocol": self.protocol,
            "reason": self.reason,
            "ttl": self.ttl,
            "confidence": self.confidence
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
                 adaptive_scanning: Optional[bool] = None,
                 enhanced_service_detection: Optional[bool] = None,
                 logger=None):
        """
        Initialize the port scanner.
        
        Args:
            target: Target hostname or IP address
            ports: Port(s) to scan. Can be a list, range (e.g., '1-1024'), or single port
            scan_type: Type of scan to perform
            timeout: Connection timeout in seconds
            max_concurrent: Maximum number of concurrent connections
            rate_limit: Maximum requests per second (0 for no limit)
            service_detection: Whether to perform service detection
            banner_grabbing: Whether to grab banners from open ports
            adaptive_scanning: Whether to enable adaptive concurrency control (None to use config setting)
            enhanced_service_detection: Whether to enable enhanced service detection (None to use config setting)
        """
        self.logger = logger or setup_logger(__name__)
        
        # Validate target is not empty or placeholder
        if not target or not target.strip():
            raise ValueError("Target hostname or IP address cannot be empty.")
        
        # Only block well-known example/reserved domains
        reserved_domains = {
            'example.com': 'Reserved example domain (IANA)',
            'example.org': 'Reserved example domain (IANA)',
            'example.net': 'Reserved example domain (IANA)',
            'example.edu': 'Reserved example domain (IANA)',
            'test': 'Reserved TLD for documentation',
            'localhost': 'Localhost (use 127.0.0.1 for local scanning)',
            'local': 'Reserved for mDNS/local network',
            'invalid': 'Reserved TLD for invalid domains',
            'example': 'Example domain component'
        }
        
        target_lower = target.lower().strip()
        
        # Extract domain parts for more specific validation
        domain_parts = target_lower.split('.')
        
        # Check if it's a reserved domain or TLD
        is_reserved = (
            target_lower in reserved_domains or  # Full domain match
            (len(domain_parts) > 1 and domain_parts[-1] in reserved_domains) or  # TLD match
            any(part in reserved_domains for part in domain_parts)  # Any part match
        )
        
        if is_reserved and not getattr(self, 'force_scan', False):
            reason = reserved_domains.get(target_lower, 'reserved domain')
            raise ValueError(
                f"Target '{target}' appears to be a {reason}.\n"
                "If this is a real target, use --force to scan it anyway.\n"
                "For safe testing, use --test to scan a controlled test target."
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
        
        # Adaptive scanning configuration
        self.adaptive_scanning = adaptive_scanning if adaptive_scanning is not None else settings.scanning.adaptive_scanning
        self.adaptive_config = AdaptiveScanConfig(concurrency=max_concurrent, timeout=timeout) if HAS_ADAPTIVE_CONFIG else None
        self.attempts_since_last_adjustment = 0
        
        # Enhanced service detection configuration
        self.enhanced_service_detection = enhanced_service_detection if enhanced_service_detection is not None else settings.scanning.enhanced_service_detection
        
        # Improved rate limiting with token bucket algorithm
        self.rate_limit_tokens = rate_limit
        self.rate_limit_max_tokens = rate_limit
        self.rate_limit_refill_interval = 1.0  # Refill every second
        self.rate_limit_last_refill = time.time()
        
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
        """Enforce rate limiting using token bucket algorithm."""
        if self.rate_limit <= 0:
            return
            
        # Refill tokens based on time passed
        now = time.time()
        time_passed = now - self.rate_limit_last_refill
        tokens_to_add = int(time_passed * self.rate_limit_max_tokens)
        
        if tokens_to_add > 0:
            self.rate_limit_tokens = min(
                self.rate_limit_max_tokens,
                self.rate_limit_tokens + tokens_to_add
            )
            self.rate_limit_last_refill = now
        
        # If we have tokens, consume one
        if self.rate_limit_tokens > 0:
            self.rate_limit_tokens -= 1
        else:
            # No tokens available, wait for next refill
            time_to_wait = self.rate_limit_refill_interval - (now - self.rate_limit_last_refill)
            if time_to_wait > 0:
                await asyncio.sleep(time_to_wait)
                self.rate_limit_tokens = min(
                    self.rate_limit_max_tokens - 1,
                    int(self.rate_limit_refill_interval * self.rate_limit_max_tokens) - 1
                )
                self.rate_limit_last_refill = time.time()
    
    async def _check_port(self, port: int) -> PortResult:
        """Check a single port asynchronously."""
        result = PortResult(port=port, state=PortState.CLOSED)
        success = False
        
        try:
            async with self._semaphore:
                # Apply rate limiting
                await self._rate_limit()
                
                self.logger.debug(f"Scanning port {port}")
                
                # Handle different scan types
                if self.scan_type == ScanType.UDP:
                    result = await self._check_udp_port(port)
                    success = result.state in [PortState.OPEN, PortState.OPEN_FILTERED]
                elif self.scan_type == ScanType.TCP_SYN:
                    result = await self._check_tcp_syn_port(port)
                    success = result.state == PortState.OPEN
                elif self.scan_type == ScanType.FIN:
                    result = await self._check_fin_port(port)
                    success = result.state in [PortState.OPEN, PortState.OPEN_FILTERED]
                elif self.scan_type == ScanType.NULL:
                    result = await self._check_null_port(port)
                    success = result.state in [PortState.OPEN, PortState.OPEN_FILTERED]
                elif self.scan_type == ScanType.XMAS:
                    result = await self._check_xmas_port(port)
                    success = result.state in [PortState.OPEN, PortState.OPEN_FILTERED]
                else:  # Default to TCP connect scan
                    # Try to connect to the port
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(self.ip, port),
                        timeout=self.timeout
                    )
                    writer.close()
                    await writer.wait_closed()
                    result = PortResult(port=port, state=PortState.OPEN)
                    success = True
                    
                    # Get service info if enabled
                    if self.service_detection:
                        if self.enhanced_service_detection and HAS_SERVICE_PROBES:
                            # Use enhanced service detection
                            service_info = await identify_service_async(self.ip, port, self.timeout)
                            result.service = service_info["service"] or self.COMMON_SERVICES.get(port)
                            result.version = service_info["version"]
                            result.banner = service_info["banner"]
                            result.confidence = service_info["confidence"]
                        else:
                            # Use traditional service detection
                            result.service = self.COMMON_SERVICES.get(port)
                            # Try to grab banner if enabled
                            if self.banner_grabbing and self._is_banner_port(port):
                                await self._grab_banner(port, result)
                
                # Record attempt for adaptive scanning
                if self.adaptive_scanning and self.adaptive_config:
                    self.adaptive_config.record_attempt(success)
                    self.attempts_since_last_adjustment += 1
                    
                    # Adjust parameters after every 50 port attempts
                    if self.attempts_since_last_adjustment >= 50:
                        old_concurrency = self.adaptive_config.concurrency
                        old_timeout = self.adaptive_config.timeout
                        
                        self.adaptive_config.adjust_parameters()
                        
                        # Apply new concurrency/timeout values
                        if old_concurrency != self.adaptive_config.concurrency:
                            self.max_concurrent = self.adaptive_config.concurrency
                            # Create new semaphore with updated concurrency
                            self._semaphore = asyncio.Semaphore(self.adaptive_config.concurrency)
                        
                        if old_timeout != self.adaptive_config.timeout:
                            self.timeout = self.adaptive_config.timeout
                        
                        self.attempts_since_last_adjustment = 0
                
                return result
                
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            # Port is closed or filtered
            # Record failed attempt for adaptive scanning
            if self.adaptive_scanning and self.adaptive_config:
                self.adaptive_config.record_attempt(False)
                self.attempts_since_last_adjustment += 1
                
                # Adjust parameters after every 50 port attempts
                if self.attempts_since_last_adjustment >= 50:
                    old_concurrency = self.adaptive_config.concurrency
                    old_timeout = self.adaptive_config.timeout
                    
                    self.adaptive_config.adjust_parameters()
                    
                    # Apply new concurrency/timeout values
                    if old_concurrency != self.adaptive_config.concurrency:
                        self.max_concurrent = self.adaptive_config.concurrency
                        # Create new semaphore with updated concurrency
                        self._semaphore = asyncio.Semaphore(self.adaptive_config.concurrency)
                    
                    if old_timeout != self.adaptive_config.timeout:
                        self.timeout = self.adaptive_config.timeout
                    
                    self.attempts_since_last_adjustment = 0
            
            return PortResult(port=port, state=PortState.CLOSED)
        except Exception as e:
            self.logger.error(f"Error scanning port {port}: {e}")
            # Record failed attempt for adaptive scanning
            if self.adaptive_scanning and self.adaptive_config:
                self.adaptive_config.record_attempt(False)
                self.attempts_since_last_adjustment += 1
                
                # Adjust parameters after every 50 port attempts
                if self.attempts_since_last_adjustment >= 50:
                    old_concurrency = self.adaptive_config.concurrency
                    old_timeout = self.adaptive_config.timeout
                    
                    self.adaptive_config.adjust_parameters()
                    
                    # Apply new concurrency/timeout values
                    if old_concurrency != self.adaptive_config.concurrency:
                        self.max_concurrent = self.adaptive_config.concurrency
                        # Create new semaphore with updated concurrency
                        self._semaphore = asyncio.Semaphore(self.adaptive_config.concurrency)
                    
                    if old_timeout != self.adaptive_config.timeout:
                        self.timeout = self.adaptive_config.timeout
                    
                    self.attempts_since_last_adjustment = 0
            
            return PortResult(
                port=port, 
                state=PortState.CLOSED,
                reason=str(e)
            )
    
    async def _check_udp_port(self, port: int) -> PortResult:
        """Check a UDP port asynchronously."""
        try:
            # Create UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            # Send a simple UDP packet (empty payload)
            sock.sendto(b"", (self.ip, port))
            
            # Try to receive response
            try:
                data, addr = sock.recvfrom(1024)
                # If we receive data, port is open
                sock.close()
                result = PortResult(port=port, state=PortState.OPEN, protocol="udp")
                
                # Try to identify service from response
                if self.service_detection:
                    if self.enhanced_service_detection and HAS_SERVICE_PROBES:
                        # Use enhanced service detection
                        service_info = await identify_service_async(self.ip, port, self.timeout)
                        result.service = service_info["service"] or self._identify_udp_service(port, data)
                        result.version = service_info["version"]
                        result.banner = service_info["banner"] or data.decode('utf-8', errors='ignore').strip()
                        result.confidence = service_info["confidence"]
                    else:
                        # Use traditional UDP service detection
                        result.service = self._identify_udp_service(port, data)
                        # Try to grab banner if enabled
                        if self.banner_grabbing and data:
                            result.banner = data.decode('utf-8', errors='ignore').strip()
                
                return result
            except socket.timeout:
                # No response - port could be open or filtered
                sock.close()
                return PortResult(port=port, state=PortState.OPEN_FILTERED, protocol="udp")
                
        except Exception as e:
            # Handle specific ICMP errors that indicate port is closed
            # This is platform-dependent and may not work on all systems
            error_str = str(e).lower()
            if "network is unreachable" in error_str or "permission denied" in error_str:
                return PortResult(port=port, state=PortState.CLOSED, protocol="udp")
            else:
                # Other errors likely mean filtered
                return PortResult(port=port, state=PortState.FILTERED, protocol="udp")
    
    async def _check_tcp_syn_port(self, port: int) -> PortResult:
        """Perform a TCP SYN scan (requires root privileges on Unix systems)."""
        try:
            # Import scapy here to avoid dependency issues if not needed
            from scapy.all import IP, TCP, sr1
            
            # Create SYN packet
            packet = IP(dst=self.ip) / TCP(dport=port, flags="S")
            
            # Send packet and wait for response
            response = sr1(packet, timeout=self.timeout, verbose=0)
            
            if response is None:
                # No response - either filtered or host is down
                return PortResult(port=port, state=PortState.FILTERED)
            elif response.haslayer(TCP):
                if response.getlayer(TCP).flags == 0x12:  # SYN-ACK
                    # Port is open - send RST to close connection
                    rst_packet = IP(dst=self.ip) / TCP(dport=port, flags="R")
                    sr1(rst_packet, timeout=0.1, verbose=0)
                    return PortResult(port=port, state=PortState.OPEN)
                elif response.getlayer(TCP).flags == 0x14:  # RST-ACK
                    # Port is closed
                    return PortResult(port=port, state=PortState.CLOSED)
            
            # Unexpected response
            return PortResult(port=port, state=PortState.FILTERED)
            
        except PermissionError:
            # Scapy requires root privileges for sending raw packets
            return PortResult(
                port=port, 
                state=PortState.CLOSED,
                reason="TCP SYN scan requires root privileges"
            )
        except Exception as e:
            self.logger.error(f"Error during TCP SYN scan on port {port}: {e}")
            return PortResult(
                port=port, 
                state=PortState.CLOSED,
                reason=str(e)
            )
    
    async def _check_fin_port(self, port: int) -> PortResult:
        """Perform a FIN scan (stealth scan technique)."""
        try:
            # Import scapy here to avoid dependency issues if not needed
            from scapy.all import IP, TCP, sr1
            
            # Create FIN packet
            packet = IP(dst=self.ip) / TCP(dport=port, flags="F")
            
            # Send packet and wait for response
            response = sr1(packet, timeout=self.timeout, verbose=0)
            
            if response is None:
                # No response - port is open or filtered
                return PortResult(port=port, state=PortState.OPEN_FILTERED)
            elif response.haslayer(TCP) and response.getlayer(TCP).flags == 0x14:  # RST
                # Port is closed
                return PortResult(port=port, state=PortState.CLOSED)
            
            # Any other response means port is filtered
            return PortResult(port=port, state=PortState.FILTERED)
            
        except PermissionError:
            # Scapy requires root privileges for sending raw packets
            return PortResult(
                port=port, 
                state=PortState.CLOSED,
                reason="FIN scan requires root privileges"
            )
        except Exception as e:
            self.logger.error(f"Error during FIN scan on port {port}: {e}")
            return PortResult(
                port=port, 
                state=PortState.CLOSED,
                reason=str(e)
            )
    
    async def _check_null_port(self, port: int) -> PortResult:
        """Perform a NULL scan (no flags set)."""
        try:
            # Import scapy here to avoid dependency issues if not needed
            from scapy.all import IP, TCP, sr1
            
            # Create NULL packet (no flags)
            packet = IP(dst=self.ip) / TCP(dport=port, flags="")
            
            # Send packet and wait for response
            response = sr1(packet, timeout=self.timeout, verbose=0)
            
            if response is None:
                # No response - port is open or filtered
                return PortResult(port=port, state=PortState.OPEN_FILTERED)
            elif response.haslayer(TCP) and response.getlayer(TCP).flags == 0x14:  # RST
                # Port is closed
                return PortResult(port=port, state=PortState.CLOSED)
            
            # Any other response means port is filtered
            return PortResult(port=port, state=PortState.FILTERED)
            
        except PermissionError:
            # Scapy requires root privileges for sending raw packets
            return PortResult(
                port=port, 
                state=PortState.CLOSED,
                reason="NULL scan requires root privileges"
            )
        except Exception as e:
            self.logger.error(f"Error during NULL scan on port {port}: {e}")
            return PortResult(
                port=port, 
                state=PortState.CLOSED,
                reason=str(e)
            )
    
    async def _check_xmas_port(self, port: int) -> PortResult:
        """Perform an XMAS scan (FIN, PSH, URG flags set)."""
        try:
            # Import scapy here to avoid dependency issues if not needed
            from scapy.all import IP, TCP, sr1
            
            # Create XMAS packet (FIN, PSH, URG flags)
            packet = IP(dst=self.ip) / TCP(dport=port, flags="FPU")
            
            # Send packet and wait for response
            response = sr1(packet, timeout=self.timeout, verbose=0)
            
            if response is None:
                # No response - port is open or filtered
                return PortResult(port=port, state=PortState.OPEN_FILTERED)
            elif response.haslayer(TCP) and response.getlayer(TCP).flags == 0x14:  # RST
                # Port is closed
                return PortResult(port=port, state=PortState.CLOSED)
            
            # Any other response means port is filtered
            return PortResult(port=port, state=PortState.FILTERED)
            
        except PermissionError:
            # Scapy requires root privileges for sending raw packets
            return PortResult(
                port=port, 
                state=PortState.CLOSED,
                reason="XMAS scan requires root privileges"
            )
        except Exception as e:
            self.logger.error(f"Error during XMAS scan on port {port}: {e}")
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
    
    def _identify_udp_service(self, port: int, data: bytes) -> Optional[str]:
        """Attempt to identify UDP service based on response data."""
        # Common UDP services
        udp_services = {
            53: "dns",
            67: "dhcp",
            68: "dhcp",
            69: "tftp",
            123: "ntp",
            137: "netbios-ns",
            138: "netbios-dgm",
            161: "snmp",
            162: "snmptrap",
            500: "ike",
            514: "syslog",
            520: "rip",
            1900: "ssdp",
            5353: "mdns"
        }
        
        # Try to identify service based on port first
        if port in udp_services:
            return udp_services[port]
        
        # Try to identify based on response content
        try:
            response_str = data.decode('utf-8', errors='ignore').lower()
            
            # DNS response typically contains domain-like strings
            if "domain" in response_str or ".com" in response_str or ".org" in response_str:
                return "dns"
            
            # NTP responses have specific binary patterns
            if port == 123 and len(data) >= 48:
                # NTP packets have specific format
                leap_version_mode = data[0]
                if leap_version_mode & 0x07 in [1, 2, 3, 4]:  # Valid modes
                    return "ntp"
                    
        except Exception:
            pass
            
        return "unknown"
    
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
    
    async def scan(self, streaming: bool = False) -> List[PortResult]:
        """
        Perform the port scan.
        
        Args:
            streaming: If True, yields results after each priority tier
            
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
        
        # If streaming is enabled and we have the priority module, use priority-based scanning
        if streaming and HAS_PRIORITY_MODULE:
            return await self._scan_with_priority_streaming()
        
        # Otherwise, use the original scanning approach
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

    async def _scan_with_priority_streaming(self) -> List[PortResult]:
        """
        Perform priority-based scanning with streaming results.
        
        Returns:
            List of PortResult objects with scan results
        """
        # Group ports by priority
        priority_groups = get_scan_order(list(self.ports))
        priority_names = ["critical", "high", "medium", "low"]
        
        all_results = []
        
        # Scan each priority group separately
        for i, group in enumerate(priority_groups):
            if not group:
                continue
                
            self.logger.info(f"Scanning {len(group)} {priority_names[i]} priority ports...")
            
            tasks = []
            group_results = []
            
            # Create tasks for each port in this group
            for port in group:
                task = asyncio.create_task(self._check_port(port))
                task.add_done_callback(
                    lambda t, p=port: group_results.append(t.result())
                )
                tasks.append(task)
            
            # Show progress for this group
            with Progress(
                TextColumn("[progress.description]{task.description}"),
                BarColumn(bar_width=None),
                "[progress.percentage]{task.percentage:>3.0f}%",
                TimeRemainingColumn(),
                console=Console()
            ) as progress:
                task = progress.add_task(
                    f"[cyan]Scanning {len(tasks)} {priority_names[i]} priority ports...",
                    total=len(tasks)
                )
                
                # Wait for all tasks in this group to complete
                for t in asyncio.as_completed(tasks):
                    await t
                    progress.update(task, advance=1)
            
            # Sort group results by port number and add to all results
            group_results.sort(key=lambda x: x.port)
            all_results.extend(group_results)
            
            # Log completion of this group
            open_count = len([r for r in group_results if r.state == PortState.OPEN])
            self.logger.info(f"Completed scanning {priority_names[i]} priority ports: {open_count} open")
            
            # Yield results after each priority tier (for future streaming implementation)
            # In a real streaming scenario, we would send these results to the client here
        
        # Sort all results by port number
        all_results.sort(key=lambda x: x.port)
        self.results = all_results
        
        # Log final completion statistics
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
    output_format: str = "table",
    require_reachable: bool = False,
    force: bool = False
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
        effective_require = require_reachable and not force
        scanner = PortScanner(
            target=target,
            ports=ports,
            scan_type=ScanType(scan_type),
            timeout=timeout,
            max_concurrent=max_concurrent,
            service_detection=service_detection,
            banner_grabbing=banner_grabbing,
            require_reachable=effective_require
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
