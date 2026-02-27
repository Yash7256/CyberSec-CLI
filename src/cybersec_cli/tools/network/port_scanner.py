"""
Port Scanner Module for Cybersec CLI.
Supports various scanning techniques and service detection.
"""

import asyncio
import ipaddress
import json
import socket
import time
from dataclasses import dataclass
from datetime import datetime as dt
from enum import Enum
from typing import Dict, List, Optional, Set, Union, Any

from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    TextColumn,
    TimeRemainingColumn,
)
from rich.table import Table

from cybersec_cli.config import settings
from cybersec_cli.utils.logger import get_logger, setup_logger

# [P1-3] Smart port ordering
try:
    from cybersec_cli.utils.port_ordering import get_scan_order as _get_scan_order
    HAS_PORT_ORDERING = True
except ImportError:
    HAS_PORT_ORDERING = False
    def _get_scan_order(ports):
        return [ports, [], [], []]

# [P2-2] Version detection
try:
    from cybersec_cli.utils.version_detector import extract_version
    HAS_VERSION_DETECTOR = True
except ImportError:
    HAS_VERSION_DETECTOR = False
    def extract_version(banner, service_type=None):
        return None

# [P2-5] TLS inspection
try:
    from cybersec_cli.utils.tls_inspector import inspect_tls
    HAS_TLS_INSPECTOR = True
except ImportError:
    HAS_TLS_INSPECTOR = False
    async def inspect_tls(*args, **kwargs):
        return None

# [P3-4] Data scrubbing
try:
    from cybersec_cli.utils.data_scrubber import create_scrubbed_banner
    HAS_DATA_SCRUBBER = True
except ImportError:
    HAS_DATA_SCRUBBER = False
    def create_scrubbed_banner(text, service=None):
        return text

# [P4-4] Vulnerability correlation
try:
    from cybersec_cli.utils.vuln_correlation import find_combo_risks, calculate_exposure_score
    HAS_VULN_CORRELATION = True
except ImportError:
    HAS_VULN_CORRELATION = False
    def find_combo_risks(ports):
        return []
    def calculate_exposure_score(ports):
        return 0.0

# [P4-2] HTTP inspection
try:
    from cybersec_cli.utils.http_inspector import inspect_http
    HAS_HTTP_INSPECTOR = True
except ImportError:
    HAS_HTTP_INSPECTOR = False
    async def inspect_http(*args, **kwargs):
        return None

# Import adaptive configuration
try:
    from cybersec_cli.core.adaptive_config import AdaptiveScanConfig

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
    from cybersec_cli.core.service_probes import get_ssl_info, identify_service_async

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
    from cybersec_cli.core.port_priority import get_scan_order

    HAS_PRIORITY_MODULE = True
except ImportError:
    HAS_PRIORITY_MODULE = False

    def get_scan_order(ports):
        # Fallback implementation if core module not available
        return [ports, [], [], []]


# Import scan cache
try:
    from cybersec_cli.core.scan_cache import scan_cache

    HAS_SCAN_CACHE = True
except ImportError:
    HAS_SCAN_CACHE = False
    scan_cache = None

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
    window_size: Optional[int] = None  # TCP Window Size
    confidence: float = 0.0  # Confidence level for service detection (0.0-1.0
    cached_at: Optional[str] = None  # Timestamp when result was cached
    # [I-4] TLS inspection results
    tls_info: Optional[Dict[str, Any]] = None
    # [I-5] HTTP inspection results
    http_info: Optional[Dict[str, Any]] = None
    # CVE enrichment status
    cve_status: Optional[str] = None  # SKIPPED_LOW_CONFIDENCE, SUCCESS, etc.
    cve_note: Optional[str] = None  # Explanation of why CVE matching was skipped

    def to_dict(self) -> Dict:
        """Convert the result to a dictionary."""
        result = {
            "port": self.port,
            "state": self.state.value,
            "service": self.service,
            "banner": self.banner,
            "version": self.version,
            "protocol": self.protocol,
            "reason": self.reason,
            "ttl": self.ttl,
            "window_size": self.window_size,
            "confidence": self.confidence,
        }
        if self.cached_at:
            result["cached_at"] = self.cached_at
        if self.tls_info:
            result["tls_info"] = self.tls_info
        if self.http_info:
            result["http_info"] = self.http_info
        if self.cve_status:
            result["cve_status"] = self.cve_status
        if self.cve_note:
            result["cve_note"] = self.cve_note
        return result


@dataclass
class ScanResult:
    """Complete scan result including metadata and vulnerability correlation."""
    target: str
    ports: List[PortResult]
    scan_time: float
    combo_risks: List[Any] = None
    exposure_score: float = 0.0
    os_info: Optional[Dict[str, Any]] = None

    def __post_init__(self):
        if self.combo_risks is None:
            self.combo_risks = []

    def __iter__(self):
        return iter(self.ports)

    def __len__(self):
        return len(self.ports)

    def __getitem__(self, index):
        return self.ports[index]

    def __bool__(self):
        return len(self.ports) > 0

    def __contains__(self, item):
        return item in self.ports

    def __repr__(self):
        return (
            f"ScanResult(target={self.target!r}, "
            f"ports={len(self.ports)}, "
            f"exposure_score={self.exposure_score:.1f}, "
            f"combo_risks={len(self.combo_risks)})"
        )


# ScanResult is intentionally backwards-compatible with
# List[PortResult] via __iter__, __len__, __getitem__,
# __bool__, and __contains__.
#
# This means all existing callers work without modification:
#   for result in scanner.scan(): ...       ← works
#   if not scanner.scan(): ...              ← works
#   results[0]                              ← works
#
# New callers can access enrichment data explicitly:
#   scan = await scanner.scan()
#   scan.combo_risks    ← vulnerability combinations
#   scan.exposure_score ← overall risk score
#   scan.tls_info       ← TLS inspection (on PortResult)
#   scan.http_info      ← HTTP inspection (on PortResult)
#   scan.target         ← original target
#   scan.scan_time      ← total scan duration


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
        21,
        22,
        23,
        25,
        53,
        80,
        110,
        111,
        135,
        139,
        143,
        443,
        445,
        993,
        995,
        1723,
        3306,
        3389,
        5900,
        8080,
        8443,
    ]

    # Common services database
    COMMON_SERVICES = {
        20: "ftp-data",
        21: "ftp",
        22: "ssh",
        23: "telnet",
        25: "smtp",
        53: "dns",
        80: "http",
        110: "pop3",
        111: "rpcbind",
        135: "msrpc",
        139: "netbios-ssn",
        143: "imap",
        443: "https",
        445: "microsoft-ds",
        993: "imaps",
        995: "pop3s",
        1723: "pptp",
        3306: "mysql",
        3389: "ms-wbt-server",
        5900: "vnc",
        8080: "http-proxy",
        8443: "https-alt",
    }

    def __init__(
        self,
        target: str,
        ports: Optional[Union[List[int], str, int]] = None,
        scan_type: ScanType = ScanType.TCP_CONNECT,
        timeout: float = 1.0,
        max_concurrent: int = 100,
        rate_limit: int = 0,
        service_detection: bool = True,
        banner_grabbing: bool = True,
        os_detection: bool = False,
        require_reachable: bool = False,
        force_scan: bool = False,
        adaptive_scanning: Optional[bool] = None,
        enhanced_service_detection: Optional[bool] = None,
        resolved_ip: Optional[str] = None,
        logger=None,
    ):
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
            force_scan: Whether to bypass reserved-domain checks
            adaptive_scanning: Whether to enable adaptive concurrency control (None to use config setting)
            enhanced_service_detection: Whether to enable enhanced service detection (None to use config setting)
            resolved_ip: Pre-resolved IP address to prevent DNS rebinding attacks
        """
        self.logger = logger or setup_logger(__name__)

        self.force_scan = force_scan

        # Validate target is not empty or placeholder
        if not target or not target.strip():
            raise ValueError("Target hostname or IP address cannot be empty.")

        # Only block well-known example/reserved domains
        reserved_domains = {
            "example.com": "Reserved example domain (IANA)",
            "example.org": "Reserved example domain (IANA)",
            "example.net": "Reserved example domain (IANA)",
            "example.edu": "Reserved example domain (IANA)",
            "test": "Reserved TLD for documentation",
            "localhost": "Localhost (use 127.0.0.1 for local scanning)",
            "local": "Reserved for mDNS/local network",
            "invalid": "Reserved TLD for invalid domains",
            "example": "Example domain component",
        }

        target_lower = target.lower().strip()

        # Extract domain parts for more specific validation
        domain_parts = target_lower.split(".")

        # Check if it's a reserved domain or TLD
        is_reserved = (
            target_lower in reserved_domains  # Full domain match
            or (
                len(domain_parts) > 1 and domain_parts[-1] in reserved_domains
            )  # TLD match
            or any(part in reserved_domains for part in domain_parts)  # Any part match
        )

        if is_reserved and not self.force_scan:
            reason = reserved_domains.get(target_lower, "reserved domain")
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
        self.os_detection = os_detection
        self.ports = (
            self._parse_ports(ports) if ports is not None else self.COMMON_PORTS
        )
        self.results: List[PortResult] = []
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self.rate_limit = rate_limit
        self.last_request_time = 0
        self.require_reachable = require_reachable

        # Adaptive scanning configuration
        self.adaptive_scanning = (
            adaptive_scanning
            if adaptive_scanning is not None
            else settings.scanning.adaptive_scanning
        )
        self.adaptive_config = (
            AdaptiveScanConfig(concurrency=max_concurrent, timeout=timeout)
            if HAS_ADAPTIVE_CONFIG
            else None
        )
        self.attempts_since_last_adjustment = 0

        # Enhanced service detection configuration
        self.enhanced_service_detection = (
            enhanced_service_detection
            if enhanced_service_detection is not None
            else settings.scanning.enhanced_service_detection
        )

        # Improved rate limiting with token bucket algorithm
        self.rate_limit_tokens = rate_limit
        self.rate_limit_max_tokens = rate_limit
        self.rate_limit_refill_interval = 1.0  # Refill every second
        self.rate_limit_last_refill = time.time()

        # Log scanning parameters for debugging
        self.logger.info(f"Initializing port scanner for target: {target}")
        self.logger.debug(
            f"Ports to scan: {len(self.ports)} ports (range: {min(self.ports)}-{max(self.ports)})"
        )

        # Resolve hostname to IP if needed (use pre-resolved IP to prevent DNS rebinding)
        if resolved_ip:
            self.ip = resolved_ip
            self.hostname = target
            self.logger.info(f"Using pre-resolved IP {self.ip} for target '{target}'")
        else:
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
            for part in ports.split(","):
                part = part.strip()
                if "-" in part:
                    start, end = map(int, part.split("-"))
                    port_set.update(range(start, end + 1))
                else:
                    port_set.add(int(part))
            return port_set
        elif isinstance(ports, (list, tuple, set)):
            port_set = set(ports)
        else:
            raise ValueError(
                "Invalid ports format. Expected int, str, or list of ints."
            )
        
        # Cap the number of ports to prevent DoS
        MAX_PORTS = 65536
        if len(port_set) > MAX_PORTS:
            raise ValueError(
                f"Port range too large ({len(port_set)} ports). Maximum allowed: {MAX_PORTS}."
            )
        
        return port_set

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
                self.rate_limit_max_tokens, self.rate_limit_tokens + tokens_to_add
            )
            self.rate_limit_last_refill = now

        # If we have tokens, consume one
        if self.rate_limit_tokens > 0:
            self.rate_limit_tokens -= 1
        else:
            # No tokens available, wait for next refill
            time_to_wait = self.rate_limit_refill_interval - (
                now - self.rate_limit_last_refill
            )
            if time_to_wait > 0:
                await asyncio.sleep(time_to_wait)
                self.rate_limit_tokens = min(
                    self.rate_limit_max_tokens - 1,
                    int(self.rate_limit_refill_interval * self.rate_limit_max_tokens)
                    - 1,
                )
                self.rate_limit_last_refill = time.time()

    def _maybe_adjust_adaptive_params(self, success: bool) -> None:
        """
        Record attempt for adaptive scanning and adjust parameters if threshold reached.
        
        This method consolidates the adaptive scanning logic that was previously
        duplicated in multiple places within _check_port.
        
        Args:
            success: Whether the port scan attempt was successful
        """
        if not (self.adaptive_scanning and self.adaptive_config):
            return
            
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
                self._semaphore = asyncio.Semaphore(
                    self.adaptive_config.concurrency
                )

            if old_timeout != self.adaptive_config.timeout:
                self.timeout = self.adaptive_config.timeout

            self.attempts_since_last_adjustment = 0

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
                        asyncio.open_connection(self.ip, port), timeout=self.timeout
                    )
                    
                    # Ensure we don't hang on close (Tarpit protection)
                    try:
                        writer.close()
                        await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
                    except (asyncio.TimeoutError, Exception):
                        # If closing hangs, just ignore and move on, the socket will eventually be collected
                        pass
                        
                    result = PortResult(port=port, state=PortState.OPEN)
                    success = True

                    # Get service info if enabled
                    if self.service_detection:
                        if self.enhanced_service_detection and HAS_SERVICE_PROBES:
                            # Use enhanced service detection
                            service_info = await identify_service_async(
                                self.ip, port, self.timeout
                            )
                            result.service = service_info[
                                "service"
                            ] or self.COMMON_SERVICES.get(port)
                            result.version = service_info["version"]
                            result.banner = service_info["banner"]
                            result.confidence = service_info["confidence"]
                        else:
                            # Use traditional service detection
                            result.service = self.COMMON_SERVICES.get(port)
                            # Try to grab banner if enabled
                            if self.banner_grabbing and self._is_banner_port(port):
                                await self._grab_banner(port, result)

                        # [P2-2] Version detection - extract version from banner
                        if HAS_VERSION_DETECTOR and result.banner and result.service:
                            version_match = extract_version(result.banner, result.service)
                            if version_match and version_match.version:
                                result.version = version_match.version
                                # Boost confidence if we got a high-confidence version
                                if version_match.confidence > result.confidence:
                                    result.confidence = version_match.confidence

                        # [P3-4] Data scrubbing - sanitize banner before storing
                        if HAS_DATA_SCRUBBER and result.banner:
                            result.banner = create_scrubbed_banner(result.banner, service=result.service)

                        # [P2-5] TLS inspection for HTTPS ports
                        if HAS_TLS_INSPECTOR and port in [443, 8443, 9443, 4443]:
                            try:
                                tls_info = await inspect_tls(self.hostname or self.ip, port, self.timeout)
                                if tls_info and tls_info.is_tls:
                                    # Add TLS-specific info to banner
                                    tls_details = f"\n[TLS: {tls_info.tls_version} {tls_info.cipher_suite}]"
                                    if tls_info.certificate:
                                        tls_details += f"\n[Cert: {tls_info.certificate.subject} -> {tls_info.certificate.issuer}]"
                                        tls_details += f"\n[Cert Expiry: {tls_info.certificate.not_after}]"
                                    result.banner = (result.banner or "") + tls_details
                                    # Update confidence based on TLS inspection
                                    if tls_info.security_score >= 80:
                                        result.confidence = max(result.confidence, 0.95)
                            except Exception as e:
                                self.logger.debug(f"TLS inspection failed for port {port}: {e}")

                # Record attempt for adaptive scanning
                self._maybe_adjust_adaptive_params(success)

                return result

        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            # Port is closed or filtered
            # Record failed attempt for adaptive scanning
            self._maybe_adjust_adaptive_params(False)

            return PortResult(port=port, state=PortState.CLOSED)
        except Exception as e:
            self.logger.error(f"Error scanning port {port}: {e}")
            # Record failed attempt for adaptive scanning
            self._maybe_adjust_adaptive_params(False)

            return PortResult(port=port, state=PortState.CLOSED, reason=str(e))

    async def _check_udp_port(self, port: int) -> PortResult:
        """Check a UDP port asynchronously using asyncio DatagramProtocol."""
        class UDPScanProtocol(asyncio.DatagramProtocol):
            def __init__(self):
                self.transport = None
                self.received_data = None
                self.error = None
                self.done_future = asyncio.Future()

            def connection_made(self, transport):
                self.transport = transport

            def datagram_received(self, data, addr):
                self.received_data = data
                if not self.done_future.done():
                    self.done_future.set_result(True)

            def error_received(self, exc):
                self.error = exc
                if not self.done_future.done():
                    self.done_future.set_result(False)
            
            def connection_lost(self, exc):
                if not self.done_future.done():
                    self.done_future.set_result(False)

        try:
            loop = asyncio.get_running_loop()
            
            # Create datagram endpoint
            # We explicitly bind to port 0 to let OS choose ephemeral port
            transport, protocol = await loop.create_datagram_endpoint(
                lambda: UDPScanProtocol(),
                remote_addr=(self.ip, port)
            )

            try:
                # Send empty packet
                transport.sendto(b"")
                
                # Wait for response with timeout
                await asyncio.wait_for(protocol.done_future, timeout=self.timeout)
                
                # If we got here, we received data
                if protocol.received_data:
                    result = PortResult(port=port, state=PortState.OPEN, protocol="udp")
                    
                    # Try to identify service
                    if self.service_detection:
                         # For now, just use what we have or generic logic
                         # Full identification might need more interaction
                         if self.enhanced_service_detection and HAS_SERVICE_PROBES:
                             # This is still potentially blocking or needs refactor, 
                             # but we'll leave it for the service probe refactor step
                             # For now, use the data we got
                             result.service = self._identify_udp_service(port, protocol.received_data)
                             if self.banner_grabbing:
                                 result.banner = protocol.received_data.decode("utf-8", errors="ignore").strip()
                         else:
                             result.service = self._identify_udp_service(port, protocol.received_data)
                             if self.banner_grabbing:
                                 result.banner = protocol.received_data.decode("utf-8", errors="ignore").strip()
                                 
                    return result
                else:
                    return PortResult(port=port, state=PortState.OPEN_FILTERED, protocol="udp")

            except asyncio.TimeoutError:
                # Timeout means open|filtered for UDP
                return PortResult(port=port, state=PortState.OPEN_FILTERED, protocol="udp")
            finally:
                transport.close()

        except Exception as e:
            # Handle specific ICMP errors (ConnectionRefused usually means closed for UDP)
            # But in asyncio/UDP, we catch them in error_received or connection_lost often
            error_str = str(e).lower()
            if "connection refused" in error_str or "unreachable" in error_str:
                 return PortResult(port=port, state=PortState.CLOSED, protocol="udp")
            
            return PortResult(port=port, state=PortState.FILTERED, protocol="udp")

    async def _run_scapy_scan(self, scan_func, port: int) -> PortResult:
        """Run a blocking scapy scan function in a separate thread."""
        loop = asyncio.get_running_loop()
        try:
            # Run in default executor to avoid blocking main loop
            result = await loop.run_in_executor(None, scan_func, port)
            return result
        except Exception as e:
            self.logger.error(f"Error during scapy scan on port {port}: {e}")
            return PortResult(port=port, state=PortState.CLOSED, reason=str(e))

    def _scapy_syn_scan(self, port: int) -> PortResult:
        """Blocking SYN scan logic using scapy."""
        try:
             # Import scapy locally
            from scapy.all import IP, TCP, sr1
            
            packet = IP(dst=self.ip) / TCP(dport=port, flags="S")
            response = sr1(packet, timeout=self.timeout, verbose=0)

            if response is None:
                return PortResult(port=port, state=PortState.FILTERED)
            elif response.haslayer(TCP):
                # Extract TTL and Window for OS fingerprinting
                ttl = response.ttl
                window = response.getlayer(TCP).window
                
                if response.getlayer(TCP).flags == 0x12:  # SYN-ACK
                    rst_packet = IP(dst=self.ip) / TCP(dport=port, flags="R")
                    sr1(rst_packet, timeout=0.1, verbose=0)
                    return PortResult(
                        port=port, 
                        state=PortState.OPEN,
                        ttl=ttl,
                        window_size=window
                    )
                elif response.getlayer(TCP).flags == 0x14:  # RST-ACK
                    return PortResult(
                        port=port, 
                        state=PortState.CLOSED,
                        ttl=ttl,
                        window_size=window
                    )
            return PortResult(port=port, state=PortState.FILTERED)
        except PermissionError:
             return PortResult(port=port, state=PortState.CLOSED, reason="Requires root privileges")
        except Exception as e:
            return PortResult(port=port, state=PortState.CLOSED, reason=str(e))

    def _scapy_fin_scan(self, port: int) -> PortResult:
        """Blocking FIN scan logic using scapy."""
        try:
            from scapy.all import IP, TCP, sr1
            packet = IP(dst=self.ip) / TCP(dport=port, flags="F")
            response = sr1(packet, timeout=self.timeout, verbose=0)
            
            if response is None:
                return PortResult(port=port, state=PortState.OPEN_FILTERED)
            elif response.haslayer(TCP) and response.getlayer(TCP).flags == 0x14:
                return PortResult(port=port, state=PortState.CLOSED)
            return PortResult(port=port, state=PortState.FILTERED)
        except PermissionError:
             return PortResult(port=port, state=PortState.CLOSED, reason="Requires root privileges")
        except Exception as e:
            return PortResult(port=port, state=PortState.CLOSED, reason=str(e))

    def _scapy_null_scan(self, port: int) -> PortResult:
        """Blocking NULL scan logic using scapy."""
        try:
            from scapy.all import IP, TCP, sr1
            packet = IP(dst=self.ip) / TCP(dport=port, flags="")
            response = sr1(packet, timeout=self.timeout, verbose=0)
            
            if response is None:
                return PortResult(port=port, state=PortState.OPEN_FILTERED)
            elif response.haslayer(TCP) and response.getlayer(TCP).flags == 0x14:
                return PortResult(port=port, state=PortState.CLOSED)
            return PortResult(port=port, state=PortState.FILTERED)
        except PermissionError:
             return PortResult(port=port, state=PortState.CLOSED, reason="Requires root privileges")
        except Exception as e:
            return PortResult(port=port, state=PortState.CLOSED, reason=str(e))

    def _scapy_xmas_scan(self, port: int) -> PortResult:
        """Blocking XMAS scan logic using scapy."""
        try:
            from scapy.all import IP, TCP, sr1
            packet = IP(dst=self.ip) / TCP(dport=port, flags="FPU")
            response = sr1(packet, timeout=self.timeout, verbose=0)
            
            if response is None:
                return PortResult(port=port, state=PortState.OPEN_FILTERED)
            elif response.haslayer(TCP) and response.getlayer(TCP).flags == 0x14:
                return PortResult(port=port, state=PortState.CLOSED)
            return PortResult(port=port, state=PortState.FILTERED)
        except PermissionError:
             return PortResult(port=port, state=PortState.CLOSED, reason="Requires root privileges")
        except Exception as e:
            return PortResult(port=port, state=PortState.CLOSED, reason=str(e))

    async def _check_tcp_syn_port(self, port: int) -> PortResult:
        """Perform a TCP SYN scan (requires root privileges on Unix systems)."""
        return await self._run_scapy_scan(self._scapy_syn_scan, port)

    async def _check_fin_port(self, port: int) -> PortResult:
        """Perform a FIN scan (stealth scan technique)."""
        return await self._run_scapy_scan(self._scapy_fin_scan, port)

    async def _check_null_port(self, port: int) -> PortResult:
        """Perform a NULL scan (no flags set)."""
        return await self._run_scapy_scan(self._scapy_null_scan, port)

    async def _check_xmas_port(self, port: int) -> PortResult:
        """Perform an XMAS scan (FIN, PSH, URG flags set)."""
        return await self._run_scapy_scan(self._scapy_xmas_scan, port)

    def _is_banner_port(self, port: int) -> bool:
        """Check if we should attempt to grab a banner from this port."""
        return port in [
            21,
            22,
            23,
            25,
            80,
            110,
            143,
            443,
            465,
            587,
            993,
            995,
            1723,
            3306,
            3389,
            5432,
            5900,
            8080,
            8443,
            27017,
            27018,
            27019,
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
            5353: "mdns",
        }

        # Try to identify service based on port first
        if port in udp_services:
            return udp_services[port]

        # Try to identify based on response content
        try:
            response_str = data.decode("utf-8", errors="ignore").lower()

            # DNS response typically contains domain-like strings
            if (
                "domain" in response_str
                or ".com" in response_str
                or ".org" in response_str
            ):
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
                # Default generic probe if no specific one
                probe = b"\r\n\r\n"

            # Determine if SSL is needed
            use_ssl = (port == 443 or port == 8443)
            
            try:
                # Open connection
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.ip, port, ssl=use_ssl if use_ssl else None), 
                    timeout=self.timeout
                )

                try:
                    writer.write(probe)
                    await writer.drain()

                    # Read banner with a timeout
                    # Read slightly more to ensure we get headers
                    banner = await asyncio.wait_for(reader.read(2048), timeout=self.timeout)
                    if banner:
                        result.banner = banner.decode("utf-8", errors="ignore").strip()

                except asyncio.TimeoutError:
                    self.logger.debug(f"Banner grab timed out for port {port}")
                except Exception as e:
                    self.logger.debug(f"Error reading banner from port {port}: {e}")
                finally:
                    if writer:
                        writer.close()
                        await asyncio.sleep(0) # Yield to let close happen
                        
            except Exception as e:
                # Retry without SSL if SSL failed for 443 (sometimes it's misconfigured or user error)
                if use_ssl:
                     # Fallback logic could go here, but keep it simple for now
                     pass
                self.logger.debug(f"Connection failed for banner grab on {port}: {e}")

        except Exception as e:
            self.logger.debug(f"Banner grab failed for port {port}: {e}")

    def _get_probe_for_port(self, port: int) -> Optional[bytes]:
        """Get an appropriate probe for banner grabbing based on port."""
        host = getattr(self, "hostname", "example.com")
        
        probes = {
            21: b"\r\n",  # FTP
            22: b"SSH-2.0-CyberSecCLI\r\n",  # SSH
            25: b"EHLO " + host.encode() + b"\r\n",  # SMTP
            80: b"GET / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n",  # HTTP
            110: b"USER guest\r\n",  # POP3
            143: b"a1 CAPABILITY\r\n",  # IMAP
            443: b"GET / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n",  # HTTPS
            8080: b"GET / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n", # HTTP-Alt
            3306: b"\x0a\x00\x00\x01\x85\xa6\x3f\x20\x00\x00\x00\x01\x21",  # MySQL
            3389: b"\x03\x00\x00\x0b\x06\xd0\x00\x00\x12\x34\x00",  # RDP
        }
        return probes.get(port, None)

    def _quick_reachable_check(
        self, ports: Optional[List[int]] = None, timeout: float = 1.0
    ) -> bool:
        """
        Synchronous quick reachability check that attempts to TCP-connect to one
        of a small set of common service ports (80, 443 by default).

        Returns True if any port accepts a TCP connection, False otherwise.
        """
        check_ports = ports or [80, 443]
        for p in check_ports:
            try:
                with socket.create_connection((self.ip, p), timeout=timeout):
                    self.logger.debug(
                        f"Quick reachability: port {p} is open on {self.ip}"
                    )
                    return True
            except Exception:
                continue
        self.logger.debug(
            f"Quick reachability: no response on ports {check_ports} for {self.ip}"
        )
        return False

    async def scan(
        self, streaming: bool = False, force: bool = False
    ) -> ScanResult:
        """
        Perform the port scan with optional caching.

        Args:
            streaming: If True, yields results after each priority tier
            force: If True, bypasses cache and performs fresh scan

        Returns:
            ScanResult object containing port results and metadata
        """
        # Track scan start time for timing metadata
        self._scan_start_time = time.monotonic()
        
        # [I-1] Smart port ordering - reorder ports by statistical frequency
        if HAS_PORT_ORDERING and not streaming:
            try:
                ordered_lists = _get_scan_order(list(self.ports))
                # Flatten priority-ordered ports (critical first)
                self.ports = ordered_lists[0] + ordered_lists[1] + ordered_lists[2] + ordered_lists[3]
                self.logger.debug(f"Ports reordered by frequency priority")
            except Exception as e:
                self.logger.debug(f"Port ordering failed: {e}")

        # Check cache first if caching is enabled and force is False
        if HAS_SCAN_CACHE and scan_cache and not force:
            cache_key = scan_cache.get_cache_key(self.target, sorted(list(self.ports)))
            cached_result = await scan_cache.check_cache(cache_key)

            if cached_result:
                # Return cached results with cache metadata
                self.logger.info(f"Returning cached results for {self.target}")
                cached_results = cached_result.get("results", [])
                self.results = []
                for r in cached_results:
                    pr = PortResult(
                        port=r["port"],
                        state=PortState(r["state"]),
                        service=r.get("service"),
                        banner=r.get("banner"),
                        version=r.get("version"),
                        protocol=r.get("protocol", "tcp"),
                        reason=r.get("reason"),
                        ttl=r.get("ttl"),
                        confidence=r.get("confidence", 0.0),
                    )
                    pr.tls_info = r.get("tls_info")
                    pr.http_info = r.get("http_info")
                    pr.cached_at = cached_result.get("cached_at")
                    self.results.append(pr)

                return self.results

        # Log scan initiation with detailed info
        self.logger.info(f"Starting port scan on {self.target} ({self.ip})")
        self.logger.info(f"Scan type: {self.scan_type.value}")
        self.logger.info(f"Ports to scan: {len(self.ports)} total")
        if len(self.ports) <= 20:
            self.logger.debug(f"Port list: {sorted(self.ports)}")
        else:
            port_list = sorted(self.ports)
            self.logger.debug(
                f"Port range: {port_list[0]}-{port_list[-1]} (showing first 5: {port_list[:5]}...)"
            )

        # If streaming is enabled and we have the priority module, use priority-based scanning
        if streaming and HAS_PRIORITY_MODULE:
            results = await self._scan_with_priority_streaming()
        else:
            # Otherwise, use the original scanning approach
            tasks = []
            results = []

            # Create tasks for each port
            for port in self.ports:
                task = asyncio.create_task(self._check_port(port))
                
                def harvest_safe(t, p=port):
                    try:
                        results.append(t.result())
                    except Exception as e:
                        self.logger.error(f"Task crash on port {p}: {e}")
                        results.append(PortResult(port=p, state=PortState.CLOSED, reason=str(e)))
                
                task.add_done_callback(harvest_safe)
                tasks.append(task)

            # Show progress if there are many ports
            if len(tasks) > 10:
                with Progress(
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(bar_width=None),
                    "[progress.percentage]{task.percentage:>3.0f}%",
                    TimeRemainingColumn(),
                    console=Console(),
                ) as progress:
                    task = progress.add_task(
                        f"[cyan]Scanning {len(tasks)} ports on {self.target}...",
                        total=len(tasks),
                    )

                    # Wait for all tasks to complete
                    for t in asyncio.as_completed(tasks):
                        try:
                            await t
                        except Exception:
                            pass # Already handled in callback
                        progress.update(task, advance=1)
            else:
                # For small scans, just wait for all tasks
                try:
                    await asyncio.gather(*tasks)
                except Exception:
                    pass # Already handled in callback

            # Sort results by port number
            results = sorted(results, key=lambda x: x.port)

        self.results = results

        # Log completion statistics
        open_count = len([r for r in self.results if r.state == PortState.OPEN])
        closed_count = len([r for r in self.results if r.state == PortState.CLOSED])
        filtered_count = len([r for r in self.results if r.state == PortState.FILTERED])

        # Track scan time
        scan_time = time.monotonic() - getattr(self, '_scan_start_time', time.monotonic())

        # [I-4] TLS inspection - parallel for all HTTPS ports
        combo_risks = []
        exposure_score = 0.0
        os_info = None
        
        if HAS_TLS_INSPECTOR and open_count > 0:
            try:
                tls_candidate_ports = {443, 444, 465, 587, 993, 995, 8443, 9443, 4443}
                tls_ports = [
                    r for r in self.results
                    if r.state == PortState.OPEN
                    and (
                        r.port in tls_candidate_ports
                        or (r.service and any(s in (r.service or "").lower() for s in ["https", "ssl", "tls"]))
                    )
                ]
                if tls_ports:
                    self.logger.debug(f"Performing TLS inspection on {len(tls_ports)} ports")
                    tls_tasks = [
                        inspect_tls(self.hostname or self.target, r.port)
                        for r in tls_ports
                    ]
                    tls_results = await asyncio.gather(*tls_tasks, return_exceptions=True)
                    for port_result, tls_data in zip(tls_ports, tls_results):
                        if tls_data and not isinstance(tls_data, Exception):
                            # Convert TLS info to dict for storage
                            port_result.tls_info = {
                                'tls_version': getattr(tls_data, 'tls_version', None),
                                'cipher_suite': getattr(tls_data, 'cipher_suite', None),
                                'security_score': getattr(tls_data, 'security_score', 0),
                                'is_tls': getattr(tls_data, 'is_tls', False),
                            }
                        else:
                            # Capture error so frontend shows something
                            err_msg = str(tls_data) if isinstance(tls_data, Exception) else "TLS inspection unavailable"
                            port_result.tls_info = {'error': err_msg}
            except Exception as e:
                self.logger.debug(f"TLS inspection failed: {e}")

        # [I-5] HTTP inspection - parallel for all HTTP ports (AFTER TLS)
        if HAS_HTTP_INSPECTOR and open_count > 0:
            try:
                http_candidate_ports = {80, 81, 443, 444, 8080, 8000, 8008, 8443, 8888, 9000, 9090}
                http_ports = [
                    r for r in self.results
                    if r.state == PortState.OPEN
                    and (
                        r.port in http_candidate_ports
                        or (r.service and any(s in (r.service or "").lower() for s in ["http", "https", "proxy"]))
                    )
                ]
                if http_ports:
                    self.logger.debug(f"Performing HTTP inspection on {len(http_ports)} ports")
                    http_tasks = [
                        inspect_http(
                            self.hostname or self.target,
                            r.port,
                            use_https=(r.port in {443, 444, 8443} or (r.service and "https" in (r.service or "").lower()))
                        )
                        for r in http_ports
                    ]
                    http_results = await asyncio.gather(*http_tasks, return_exceptions=True)
                    for port_result, http_data in zip(http_ports, http_results):
                        if http_data and not isinstance(http_data, Exception):
                            port_result.http_info = {
                                'is_http': getattr(http_data, 'is_http', False),
                                'http_version': getattr(http_data, 'http_version', None),
                                'status_code': getattr(http_data, 'status_code', None),
                                'security_score': getattr(http_data, 'security_score', 0),
                                'security_headers_audit': getattr(http_data, 'security_headers_audit', {}),
                                'vulnerabilities': getattr(http_data, 'vulnerabilities', []),
                            }
                        else:
                            err_msg = str(http_data) if isinstance(http_data, Exception) else "HTTP inspection unavailable"
                            port_result.http_info = {'error': err_msg}
            except Exception as e:
                self.logger.debug(f"HTTP inspection failed: {e}")

        # Store enriched results in cache (after TLS/HTTP) if enabled
        if HAS_SCAN_CACHE and scan_cache and not force:
            cache_key = scan_cache.get_cache_key(self.target, sorted(list(self.ports)))
            serializable_results = [
                {
                    "port": r.port,
                    "state": r.state.value,
                    "service": r.service,
                    "banner": r.banner,
                    "version": r.version,
                    "protocol": r.protocol,
                    "reason": r.reason,
                    "ttl": r.ttl,
                    "confidence": r.confidence,
                    "tls_info": getattr(r, "tls_info", None),
                    "http_info": getattr(r, "http_info", None),
                }
                for r in self.results
            ]
            cache_data = {"results": serializable_results}
            await scan_cache.store_cache(cache_key, cache_data, target=self.target)

        # [I-6] Vulnerability correlation - analyze port combinations
        if HAS_VULN_CORRELATION and open_count > 0:
            try:
                open_ports_list = [r.port for r in self.results if r.state == PortState.OPEN]
                combo_risks = find_combo_risks(open_ports_list)
                exposure_score = calculate_exposure_score(open_ports_list)
                
                if combo_risks:
                    self.logger.warning(f"[VULN CORRELATION] Found {len(combo_risks)} risk(s) - Exposure Score: {exposure_score}/100")
                    for risk in combo_risks:
                        self.logger.warning(f"  - [{risk.risk.value}] {risk.name}: {risk.description[:80]}...")
            except Exception as e:
                self.logger.debug(f"Vulnerability correlation failed: {e}")

        # Perform OS detection if enabled and we have open ports
        if self.os_detection and open_count > 0:
            self.logger.info("Performing OS detection...")
            try:
                os_info = self._perform_os_detection()
                if os_info:
                    self.logger.info(f"OS Detection results: {os_info}")
            except Exception as e:
                self.logger.warning(f"OS detection failed: {e}")

        self.logger.info(
            f"Scan completed: {open_count} open, {closed_count} closed, {filtered_count} filtered"
        )
        if open_count > 0:
            open_ports_list = sorted(
                [r.port for r in self.results if r.state == PortState.OPEN]
            )
            self.logger.info(f"Open ports found: {open_ports_list}")

        # [I-6] Return ScanResult with metadata
        return ScanResult(
            target=self.target,
            ports=self.results,
            scan_time=scan_time,
            combo_risks=combo_risks,
            exposure_score=exposure_score,
            os_info=os_info,
        )

    def scan_sync(
        self, streaming: bool = False, force: bool = False
    ) -> ScanResult:
        """
        Synchronous version of the scan method for use in Celery tasks.

        Args:
            streaming: If True, yields results after each priority tier
            force: If True, bypasses cache and performs fresh scan

        Returns:
            ScanResult object containing port results and metadata
        """
        return asyncio.run(self.scan(streaming=streaming, force=force))

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

            self.logger.info(
                f"Scanning {len(group)} {priority_names[i]} priority ports..."
            )

            tasks = []
            group_results = []

            # Create tasks for each port in this group
            for port in group:
                task = asyncio.create_task(self._check_port(port))
                
                def harvest_safe_group(t, p=port):
                    try:
                        group_results.append(t.result())
                    except Exception as e:
                        self.logger.error(f"Task crash on priority port {p}: {e}")
                        group_results.append(PortResult(port=p, state=PortState.CLOSED, reason=str(e)))
                
                task.add_done_callback(harvest_safe_group)
                tasks.append(task)

            # Show progress for this group
            with Progress(
                TextColumn("[progress.description]{task.description}"),
                BarColumn(bar_width=None),
                "[progress.percentage]{task.percentage:>3.0f}%",
                TimeRemainingColumn(),
                console=Console(),
            ) as progress:
                task = progress.add_task(
                    f"[cyan]Scanning {len(tasks)} {priority_names[i]} priority ports...",
                    total=len(tasks),
                )

                # Wait for all tasks in this group to complete
                for t in asyncio.as_completed(tasks):
                    try:
                        await t
                    except Exception:
                        pass # Already handled in callback
                    progress.update(task, advance=1)

            # Sort group results by port number and add to all results
            group_results.sort(key=lambda x: x.port)
            all_results.extend(group_results)

            # Log completion of this group
            open_count = len([r for r in group_results if r.state == PortState.OPEN])
            self.logger.info(
                f"Completed scanning {priority_names[i]} priority ports: {open_count} open"
            )

            # Yield results after each priority tier (for future streaming implementation)
            # In a real streaming scenario, we would send these results to the client here

        # Sort all results by port number
        all_results.sort(key=lambda x: x.port)
        self.results = all_results

        # After streaming scan, run TLS and HTTP inspections to enrich results
        open_count = len([r for r in self.results if r.state == PortState.OPEN])
        if HAS_TLS_INSPECTOR and open_count > 0:
            try:
                tls_candidate_ports = {443, 444, 465, 587, 993, 995, 8443, 9443, 4443}
                tls_ports = [
                    r for r in self.results
                    if r.state == PortState.OPEN
                    and (
                        r.port in tls_candidate_ports
                        or (r.service and any(s in (r.service or "").lower() for s in ["https", "ssl", "tls"]))
                    )
                ]
                if tls_ports:
                    tls_tasks = [
                        inspect_tls(self.hostname or self.target, r.port)
                        for r in tls_ports
                    ]
                    tls_results = await asyncio.gather(*tls_tasks, return_exceptions=True)
                    for port_result, tls_data in zip(tls_ports, tls_results):
                        if tls_data and not isinstance(tls_data, Exception):
                            port_result.tls_info = {
                                'tls_version': getattr(tls_data, 'tls_version', None),
                                'cipher_suite': getattr(tls_data, 'cipher_suite', None),
                                'security_score': getattr(tls_data, 'security_score', 0),
                                'is_tls': getattr(tls_data, 'is_tls', False),
                            }
                        else:
                            port_result.tls_info = {'error': str(tls_data)}
            except Exception as e:
                self.logger.debug(f"TLS inspection (streaming) failed: {e}")

        if HAS_HTTP_INSPECTOR and open_count > 0:
            try:
                http_candidate_ports = {80, 81, 443, 444, 8080, 8000, 8008, 8443, 8888, 9000, 9090}
                http_ports = [
                    r for r in self.results
                    if r.state == PortState.OPEN
                    and (
                        r.port in http_candidate_ports
                        or (r.service and any(s in (r.service or "").lower() for s in ["http", "https", "proxy"]))
                    )
                ]
                if http_ports:
                    http_tasks = [
                        inspect_http(
                            self.hostname or self.target,
                            r.port,
                            use_https=(r.port in {443, 444, 8443} or (r.service and "https" in (r.service or "").lower()))
                        )
                        for r in http_ports
                    ]
                    http_results = await asyncio.gather(*http_tasks, return_exceptions=True)
                    for port_result, http_data in zip(http_ports, http_results):
                        if http_data and not isinstance(http_data, Exception):
                            port_result.http_info = {
                                'is_http': getattr(http_data, 'is_http', False),
                                'http_version': getattr(http_data, 'http_version', None),
                                'status_code': getattr(http_data, 'status_code', None),
                                'security_score': getattr(http_data, 'security_score', 0),
                                'security_headers_audit': getattr(http_data, 'security_headers_audit', {}),
                                'vulnerabilities': getattr(http_data, 'vulnerabilities', []),
                            }
                        else:
                            port_result.http_info = {'error': str(http_data)}
            except Exception as e:
                self.logger.debug(f"HTTP inspection (streaming) failed: {e}")

        # Log final completion statistics
        open_count = len([r for r in self.results if r.state == PortState.OPEN])
        closed_count = len([r for r in self.results if r.state == PortState.CLOSED])
        filtered_count = len([r for r in self.results if r.state == PortState.FILTERED])

        self.logger.info(
            f"Scan completed: {open_count} open, {closed_count} closed, {filtered_count} filtered"
        )
        if open_count > 0:
            open_ports_list = sorted(
                [r.port for r in self.results if r.state == PortState.OPEN]
            )
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
                "results": [r.to_dict() for r in self.results],
            },
            indent=2,
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
                    result.banner or "",
                )

        return table

    def _try_sync_syn_probe(self, port: int) -> Optional["PortResult"]:
        """Attempt a SYN probe safely from sync code.

        If an event loop is already running, return None and let callers
        fall back to banner-based OS detection.
        """
        try:
            loop = asyncio.get_running_loop()
            if loop.is_running():
                return None
        except RuntimeError:
            # No running loop, safe to proceed
            pass

        try:
            return asyncio.run(self._check_tcp_syn_port(port))
        except Exception:
            return None

    def _perform_os_detection(self) -> Dict[str, Any]:
        """
        Perform OS detection using passive fingerprinting (TTL and TCP Window Size).
        Replaces Nmap with native Python implementation.
        """
        if not self.results:
            return {"error": "No scan results available for OS fingerprinting"}

        # Collect fingerprints from open ports
        fingerprints = []
        for result in self.results:
            if result.state == PortState.OPEN:
                 # If TTL is missing (e.g. from TCP Connect scan), try to get it actively
                 if result.ttl is None:
                     try:
                         # Run a quick SYN probe to this port to get TTL/Window
                         # Note: This requires root privileges (sudo). 
                         # If we are not root, this will fail/return None, and we fall back to banner analysis.
                         probe_result = self._try_sync_syn_probe(result.port)
                         if probe_result and probe_result.ttl:
                             result.ttl = probe_result.ttl
                             result.window_size = probe_result.window_size
                     except Exception:
                         pass

            if result.ttl is not None:
                fp = {"ttl": int(result.ttl), "window": result.window_size}
                fingerprints.append(fp)
        
        if not fingerprints:
            # Fallback to service banner analysis (for non-root users)
            return self._perform_service_os_detection()

        # OS Signatures (Simplified)
        # (TTL, Window Size) -> (OS Name, Accuracy)
        candidates = {}
        
        for fp in fingerprints:
            ttl = fp["ttl"]
            win = fp.get("window", 0)
            
            # Estimate initial TTL
            if ttl <= 64:
                initial_ttl = 64
            elif ttl <= 128:
                initial_ttl = 128
            else:
                initial_ttl = 255
                
            # Heuristic Analysis
            if initial_ttl == 64:
                # Likely Linux, MacOS, FreeBsd
                if win is not None and win > 60000:
                    candidates["MacOS/iOS"] = candidates.get("MacOS/iOS", 0) + 1
                else:
                    candidates["Linux"] = candidates.get("Linux", 0) + 2
                    
            elif initial_ttl == 128:
                # Likely Windows
                candidates["Windows"] = candidates.get("Windows", 0) + 2
                
            elif initial_ttl == 255:
                # Likely Cisco, Solaris, etc.
                if win == 0:
                     candidates["Cisco IOS"] = candidates.get("Cisco IOS", 0) + 1
                else:
                     candidates["Solaris/Unix"] = candidates.get("Solaris/Unix", 0) + 1
                     
        if not candidates:
             # Try service fallback even if we had inconclusive packet data
             return self._perform_service_os_detection()
             
        # Select best candidate
        best_os = max(candidates.items(), key=lambda x: x[1])
        
        return {
            "os_name": best_os[0],
            "accuracy": "85%" if best_os[1] > 1 else "50%",
            "details": f"Based on TTL/Window analysis of {len(fingerprints)} packets",
            "fingerprints_analyzed": len(fingerprints)
        }

    def _perform_service_os_detection(self) -> Dict[str, Any]:
        """
        Perform OS detection based on service banners (Application Layer).
        Useful when root privileges are not available for packet analysis.
        """
        candidates = {}
        analyzed_banners = 0

        for result in self.results:
            if not result.banner:
                continue
                
            banner = result.banner.lower()
            analyzed_banners += 1
            
            # Windows Indicators
            if "windows" in banner or "microsoft" in banner or "iis/" in banner or "asp.net" in banner:
                 candidates["Windows"] = candidates.get("Windows", 0) + 3
            
            # Linux Indicators
            if "ubuntu" in banner:
                candidates["Linux (Ubuntu)"] = candidates.get("Linux (Ubuntu)", 0) + 4
                candidates["Linux"] = candidates.get("Linux", 0) + 2
            elif "debian" in banner:
                candidates["Linux (Debian)"] = candidates.get("Linux (Debian)", 0) + 4
                candidates["Linux"] = candidates.get("Linux", 0) + 2
            elif "centos" in banner or "red hat" in banner or "rhel" in banner:
                candidates["Linux (RHEL/CentOS)"] = candidates.get("Linux (RHEL/CentOS)", 0) + 4
                candidates["Linux"] = candidates.get("Linux", 0) + 2
            elif "alpine" in banner:
                candidates["Linux (Alpine)"] = candidates.get("Linux (Alpine)", 0) + 4
                candidates["Linux"] = candidates.get("Linux", 0) + 2
            elif "linux" in banner:
                candidates["Linux"] = candidates.get("Linux", 0) + 2
            
            # Weak Linux Indicators (Common Open Source software)
            if "apache" in banner or "nginx" in banner or "php" in banner or "openssl" in banner:
                 candidates["Linux"] = candidates.get("Linux", 0) + 1
            elif "gws" in banner or "sffe" in banner or "esf" in banner:
                 # Google Web Server
                 candidates["Linux (Google)"] = candidates.get("Linux (Google)", 0) + 4
            elif "cloudflare" in banner:
                 candidates["Linux (Cloudflare)"] = candidates.get("Linux (Cloudflare)", 0) + 4
                
            # Other Unix
            if "freebsd" in banner:
                 candidates["FreeBSD"] = candidates.get("FreeBSD", 0) + 4
            elif "openbsd" in banner:
                 candidates["OpenBSD"] = candidates.get("OpenBSD", 0) + 4
                 
            # Apple
            if "darwin" in banner or "macos" in banner:
                 candidates["MacOS"] = candidates.get("MacOS", 0) + 4
                 
        if not candidates:
             return {
                 "os_name": "Unknown",
                 "accuracy": "N/A",
                 "details": f"No matching signatures in {analyzed_banners} banners analyzed",
                 "fingerprints_analyzed": 0,
                 "method": "Banner Analysis"
             }
             
        # Select best candidate
        best_os = max(candidates.items(), key=lambda x: x[1])
        
        return {
            "os_name": best_os[0],
            "accuracy": "Low (Inferred)" if best_os[1] < 3 else "Medium (Banner)",
            "details": f"Inferred from application banners (analyzed {analyzed_banners} banners)",
            "fingerprints_analyzed": 0,
            "method": "Banner Analysis"
        }


# Helper function for command-line usage
async def scan_ports(
    target: str,
    ports: Optional[Union[List[int], str, int]] = None,
    scan_type: str = "tcp_connect",
    timeout: float = 1.0,
    max_concurrent: int = 100,
    service_detection: bool = True,
    banner_grabbing: bool = True,
    os_detection: bool = False,
    output_format: str = "table",
    require_reachable: bool = False,
    force: bool = False,
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
        force: If True, bypass cache and perform fresh scan

    Returns:
        Formatted scan results
    """
    # Resolve target once to prevent DNS rebinding
    from src.cybersec_cli.core.validators import resolve_target
    resolved = await resolve_target(target)
    
    # Select best candidate
    best_os = max(candidates.items(), key=lambda x: x[1])
    
    return {
        "os_name": best_os[0],
        "accuracy": "Low (Inferred)" if best_os[1] < 3 else "Medium (Banner)",
        "details": f"Inferred from application banners (analyzed {analyzed_banners} banners)",
        "fingerprints_analyzed": 0,
        "method": "Banner Analysis"
    }


# Helper function for command-line usage
async def scan_ports(
    target: str,
    ports: Optional[Union[List[int], str, int]] = None,
    scan_type: str = "tcp_connect",
    timeout: float = 1.0,
    max_concurrent: int = 100,
    service_detection: bool = True,
    banner_grabbing: bool = True,
    os_detection: bool = False,
    output_format: str = "table",
    require_reachable: bool = False,
    force: bool = False,
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
        force: If True, bypass cache and perform fresh scan

    Returns:
        Formatted scan results
    """
    # Resolve target once to prevent DNS rebinding
    from src.cybersec_cli.core.validators import resolve_target
    resolved_ip = resolve_target(target)
    if not resolved_ip:
        raise ValueError(f"Could not resolve target: {target}")
    
    try:
        effective_require = require_reachable and not force
        scanner = PortScanner(
            target=target,
            resolved_ip=resolved_ip,  # Pass pre-resolved IP
            ports=ports,
            scan_type=ScanType(scan_type),
            timeout=timeout,
            max_concurrent=max_concurrent,
            service_detection=service_detection,
            banner_grabbing=banner_grabbing,
            os_detection=os_detection,
            require_reachable=effective_require,
            force_scan=force,
        )

        await scanner.scan(force=force)  # Pass force parameter to scan method

        if output_format == "json":
            return scanner.to_json()
        elif output_format == "list":
            return "\n".join(
                f"{r.port}/tcp {r.state.value}" for r in scanner.get_open_ports()
            )
        else:  # table
            console = Console()
            console.print(scanner.to_table())
            return ""

    except Exception as e:
        return f"Error: {str(e)}"
