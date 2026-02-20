"""
Smart Port Ordering Module.
Orders ports based on statistical frequency from internet-wide scans.
This allows scanning most likely open ports first for faster discovery.
"""

from typing import List, Dict, Set, Tuple
from dataclasses import dataclass
from enum import Enum


class PriorityTier(Enum):
    """Port priority tiers."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


# Internet-wide scan statistics (based on Shodan, Censys data)
# Values represent probability of port being open on any given host
# Source: Aggregated statistics from multiple internet-wide scans
TOP_PORTS_BY_FREQUENCY = {
    # Very common (90%+ probability when service exists)
    80: 0.98,    # HTTP
    443: 0.95,   # HTTPS
    22: 0.87,    # SSH
    21: 0.38,    # FTP
    25: 0.32,    # SMTP
    53: 0.28,    # DNS
    110: 0.18,   # POP3
    143: 0.15,   # IMAP
    3389: 0.45,  # RDP
    445: 0.25,   # SMB
    
    # High frequency (50-90%)
    8080: 0.72,   # HTTP Proxy
    8443: 0.35,  # HTTPS Alt
    8888: 0.28,  # HTTP Alt
    9000: 0.22,  # SonarQube/Web
    9090: 0.18,  # Prometheus/Web
    
    # Medium frequency (20-50%)
    3306: 0.22,   # MySQL
    5432: 0.18,  # PostgreSQL
    27017: 0.15, # MongoDB
    6379: 0.12,  # Redis
    9200: 0.10,  # Elasticsearch
    5900: 0.15,  # VNC
    
    # Lower frequency (5-20%)
    23: 0.08,     # Telnet
    102: 0.05,   # Siemens S7
    139: 0.12,   # NetBIOS
    4433: 0.08,  # AJP
    5000: 0.10,  # Flask/Pl末
    7000: 0.06,  # WebDAV
    8000: 0.12,  # HTTP Alt
    8008: 0.08,  # HTTP Alt
    8081: 0.10,  # HTTP Alt
    8129: 0.05,  # Munin
    8144: 0.04,  # Puppet
    8888: 0.12,  # HTTP Alt
    9001: 0.06,  # Tor ORPort
    9091: 0.05,  # Prometheus
    9092: 0.04,  # Kafka
    9200: 0.08,  # Elasticsearch
    9300: 0.04,  # Elasticsearch
    11211: 0.06, # Memcached
    27018: 0.04, # MongoDB Shard
    27019: 0.03, # MongoDB Config
    28017: 0.03, # MongoDB HTTP
    
    # Rare but important for security (1-5%)
    1433: 0.04,   # MSSQL
    1521: 0.03,   # Oracle
    1723: 0.03,   # PPTP
    2049: 0.02,   # NFS
    3389: 0.15,  # RDP
    5060: 0.04,  # SIP
    5061: 0.03,   # SIP TLS
    5900: 0.08,  # VNC
    5985: 0.04,  # WinRM HTTP
    5986: 0.03,  # WinRM HTTPS
    6443: 0.02,  # Kubernetes API
    6667: 0.03,  # IRC
    8006: 0.03,  # Plex
    8443: 0.10,  # HTTPS Alt
    8843: 0.02,  # Unknown
    9000: 0.05,  # Various
    9093: 0.02,  # Alertmanager
    9100: 0.02,  # Printer
    10000: 0.03, # Webmin
    32768: 0.02, # RPC
    50000: 0.02, # SAP
}


# Critical ports for security scanning (always scan first)
CRITICAL_SECURITY_PORTS = {
    21,   # FTP - plaintext creds
    22,   # SSH - remote access
    23,   # Telnet - plaintext
    25,   # SMTP - spam relay
    53,   # DNS - amplification
    110,  # POP3 - plaintext
    135,  # MSRPC - Windows
    139,  # NetBIOS - Windows
    143,  # IMAP - plaintext
    445,  # SMB - ransomware
    993,  # IMAPS - plaintext
    995,  # POP3S - plaintext
    1433, # MSSQL - data theft
    1521, # Oracle - data theft
    3306, # MySQL - data theft
    3389, # RDP - ransomware
    5432, # PostgreSQL - data theft
    5900, # VNC - remote control
    6379, # Redis - RCE
    27017,# MongoDB - data theft
}


# Port categories by service type
PORT_CATEGORIES = {
    "web": {80, 443, 8080, 8443, 8888, 8000, 8008, 8081, 8090, 9000, 9090, 5000, 7000, 8129},
    "database": {3306, 5432, 27017, 6379, 9200, 11211, 1433, 1521, 5432},
    "remote_access": {22, 23, 3389, 5900, 5901, 5985, 5986},
    "mail": {25, 110, 143, 465, 587, 993, 995},
    "file_transfer": {20, 21, 22, 69, 139, 445, 2049},
    "directory": {389, 636, 3268, 3269},
    "messaging": {5222, 5269, 5310, 1883, 8883, 5672, 61613},
    "management": {10000, 8006, 9000, 9090, 9091, 6443, 2375, 2376},
}


@dataclass
class PortInfo:
    """Information about a port."""
    port: int
    frequency: float
    priority: PriorityTier
    category: str


def get_port_frequency(port: int) -> float:
    """Get the frequency score for a port.
    
    Args:
        port: Port number
        
    Returns:
        Frequency score 0.0-1.0 (higher = more common)
    """
    return TOP_PORTS_BY_FREQUENCY.get(port, 0.01)


def get_port_priority(port: int) -> PriorityTier:
    """Get the priority tier for a port.
    
    Args:
        port: Port number
        
    Returns:
        PriorityTier enum
    """
    # Critical security ports always get highest priority
    if port in CRITICAL_SECURITY_PORTS:
        return PriorityTier.CRITICAL
    
    freq = get_port_frequency(port)
    
    if freq >= 0.5:
        return PriorityTier.CRITICAL
    elif freq >= 0.2:
        return PriorityTier.HIGH
    elif freq >= 0.05:
        return PriorityTier.MEDIUM
    else:
        return PriorityTier.LOW


def get_port_category(port: int) -> str:
    """Get the category for a port.
    
    Args:
        port: Port number
        
    Returns:
        Category name or "unknown"
    """
    for category, ports in PORT_CATEGORIES.items():
        if port in ports:
            return category
    return "unknown"


def order_ports_by_frequency(ports: List[int], prioritize_critical: bool = True) -> List[int]:
    """Order ports by statistical frequency.
    
    Ports that are more commonly open will be scanned first,
    allowing faster discovery of services.
    
    Args:
        ports: List of port numbers to order
        prioritize_critical: If True, always scan critical security ports first
        
    Returns:
        Ordered list of ports (most likely open first)
    """
    if not ports:
        return []
    
    # Get priority tiers for all ports
    port_infos = []
    for port in ports:
        info = PortInfo(
            port=port,
            frequency=get_port_frequency(port),
            priority=get_port_priority(port),
            category=get_port_category(port)
        )
        port_infos.append(info)
    
    # Sort by priority first, then by frequency within each tier
    priority_order = {
        PriorityTier.CRITICAL: 0,
        PriorityTier.HIGH: 1,
        PriorityTier.MEDIUM: 2,
        PriorityTier.LOW: 3,
    }
    
    # Sort: priority first (descending), then frequency (descending)
    port_infos.sort(key=lambda x: (priority_order[x.priority], -x.frequency))
    
    return [info.port for info in port_infos]


def get_priority_buckets(ports: List[int]) -> Dict[PriorityTier, List[int]]:
    """Group ports into priority buckets.
    
    Args:
        ports: List of port numbers
        
    Returns:
        Dict mapping PriorityTier to list of ports in that tier
    """
    buckets = {
        PriorityTier.CRITICAL: [],
        PriorityTier.HIGH: [],
        PriorityTier.MEDIUM: [],
        PriorityTier.LOW: [],
    }
    
    for port in ports:
        priority = get_port_priority(port)
        buckets[priority].append(port)
    
    # Sort within each bucket by frequency
    for tier in buckets:
        buckets[tier].sort(key=lambda p: -get_port_frequency(p))
    
    return buckets


def suggest_port_ranges(target_type: str = "general") -> List[str]:
    """Suggest useful port ranges based on target type.
    
    Args:
        target_type: Type of target ("general", "web", "database", "windows", "linux")
        
    Returns:
        List of port range strings
    """
    suggestions = {
        "general": [
            "21-23",
            "25",
            "53",
            "80",
            "110",
            "143",
            "443",
            "445",
            "993",
            "995",
            "1433",
            "3306",
            "3389",
            "5432",
            "5900",
            "6379",
            "8080",
            "8443",
            "27017",
        ],
        "web": [
            "80",
            "443",
            "8000",
            "8080",
            "8081",
            "8443",
            "8888",
            "9000",
            "9090",
        ],
        "database": [
            "3306",
            "5432",
            "5433",
            "6379",
            "9200",
            "11211",
            "27017",
            "27018",
            "27019",
        ],
        "windows": [
            "135",
            "139",
            "445",
            "3389",
            "5985",
            "5986",
            "1433",
            "8080",
        ],
        "linux": [
            "22",
            "80",
            "443",
            "111",
            "2049",
            "2121",
            "3306",
            "5900",
            "6379",
        ],
    }
    
    return suggestions.get(target_type, suggestions["general"])


def get_port_info(port: int) -> PortInfo:
    """Get complete information about a port.
    
    Args:
        port: Port number
        
    Returns:
        PortInfo dataclass
    """
    return PortInfo(
        port=port,
        frequency=get_port_frequency(port),
        priority=get_port_priority(port),
        category=get_port_category(port)
    )


# Legacy function for compatibility
def get_scan_order(ports):
    """Legacy function for backward compatibility.
    
    Args:
        ports: List of ports
        
    Returns:
        List of 4 lists: [critical, high, medium, low]
    """
    buckets = get_priority_buckets(ports)
    return [
        buckets[PriorityTier.CRITICAL],
        buckets[PriorityTier.HIGH],
        buckets[PriorityTier.MEDIUM],
        buckets[PriorityTier.LOW],
    ]
