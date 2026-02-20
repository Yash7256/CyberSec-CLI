"""
Version Detection Engine.
Extracts software versions from service banners using regex patterns.
"""

import re
from typing import Optional, Dict, Tuple, List
from dataclasses import dataclass
from enum import Enum


class VersionConfidence(Enum):
    """Confidence levels for version detection."""
    HIGH = 1.0
    MEDIUM = 0.7
    LOW = 0.4
    NONE = 0.0


@dataclass
class VersionMatch:
    """Result of version extraction."""
    version: Optional[str]
    product: Optional[str]
    confidence: float
    raw_match: str


# Comprehensive version patterns for common services
VERSION_PATTERNS = {
    # SSH
    "ssh": [
        (r"SSH-(\d+\.\d+)[-\s]([^\r\n]+)", VersionConfidence.HIGH),
        (r"OpenSSH[_-]?(\d+\.\d+(?:[pP]\d+)?)[^\r\n]*", VersionConfidence.HIGH),
        (r"Dropbear_ssh_(\d+\.\d+)", VersionConfidence.MEDIUM),
        (r"libssh[_-]?(\d+\.\d+)", VersionConfidence.MEDIUM),
    ],
    
    # HTTP Servers
    "http": [
        (r"Server:\s*([^\r\n]+)", VersionConfidence.MEDIUM),
        (r"nginx[/\s](\d+\.\d+\.\d+)", VersionConfidence.HIGH),
        (r"nginx[/\s](\d+\.\d+)", VersionConfidence.HIGH),
        (r"Apache/(\d+\.\d+\.\d+[^\s]*)", VersionConfidence.HIGH),
        (r"Apache/(\d+\.\d+)[^\s]*", VersionConfidence.HIGH),
        (r"Microsoft-IIS[/\s](\d+\.\d+)", VersionConfidence.HIGH),
        (r"LiteSpeed/([^\s]+)", VersionConfidence.HIGH),
        (r"OpenLiteSpeed/([^\s]+)", VersionConfidence.HIGH),
        (r"lighttpd/(\d+\.\d+\.\d+)", VersionConfidence.HIGH),
        (r"Google Frontend", VersionConfidence.MEDIUM),
        (r"cloudflare", VersionConfidence.LOW),
    ],
    
    # Databases
    "mysql": [
        (r"(\d+\.\d+\.\d+)-[Mm]ariaDB", VersionConfidence.HIGH),
        (r"(\d+\.\d+\.\d+)[- ][Mm]ariaDB", VersionConfidence.HIGH),
        (r"MySQL[\s/]*(\d+\.\d+\.\d+)", VersionConfidence.HIGH),
        (r"MySQL[\s/]*(\d+\.\d+)", VersionConfidence.HIGH),
    ],
    "postgres": [
        (r"PostgreSQL[\s/]*(\d+\.\d+)", VersionConfidence.HIGH),
        (r"pg[\s/]*(\d+\.\d+)", VersionConfidence.MEDIUM),
    ],
    "mongodb": [
        (r"MongoDB[\s/]*(\d+\.\d+\.\d+)", VersionConfidence.HIGH),
        (r"db_version\s*(\d+\.\d+\.\d+)", VersionConfidence.MEDIUM),
    ],
    "redis": [
        (r"#\s*redis_version:(\d+\.\d+\.\d+)", VersionConfidence.HIGH),
        (r"Redis[\s/]*(\d+\.\d+\.\d+)", VersionConfidence.HIGH),
        (r"(\d+\.\d+\.\d+)\s+\(git", VersionConfidence.HIGH),
    ],
    "elasticsearch": [
        (r'"version"\s*:\s*\{[^\}]*"number"\s*:\s*"(\d+\.\d+\.\d+)"', VersionConfidence.HIGH),
        (r"Elasticsearch[\s/]*(\d+\.\d+\.\d+)", VersionConfidence.HIGH),
    ],
    "mssql": [
        (r"Version\s*(\d+\.\d+\.\d+)", VersionConfidence.MEDIUM),
    ],
    
    # Mail
    "smtp": [
        (r"220[- ]([^\r\n]+)", VersionConfidence.MEDIUM),
        (r"Postfix\s+(\w+)", VersionConfidence.HIGH),
        (r"Exim\s+(\d+[\.\d]*)", VersionConfidence.HIGH),
        (r"Courier\s+ESMTP", VersionConfidence.MEDIUM),
        (r"Microsoft[\sE]SMTP", VersionConfidence.MEDIUM),
        (r"Post.Office", VersionConfidence.MEDIUM),
    ],
    "imap": [
        (r"\*\s*OK[\s]+([^\r\n]+)", VersionConfidence.MEDIUM),
        (r"Dovecot[\s]([\d\.]+)", VersionConfidence.HIGH),
        (r"Courier-IMAP", VersionConfidence.MEDIUM),
        (r"Microsoft[\s]Exchange", VersionConfidence.MEDIUM),
    ],
    "pop3": [
        (r"\+OK[\s]+([^\r\n]+)", VersionConfidence.MEDIUM),
        (r"Dovecot[\s]([\d\.]+)", VersionConfidence.HIGH),
    ],
    
    # FTP
    "ftp": [
        (r"220[- ]([^\r\n]+)", VersionConfidence.MEDIUM),
        (r"ProFTPD[\s](\d+\.\d+[\.\d]*)", VersionConfidence.HIGH),
        (r"vsFTPD[\s](\d+\.\d+)", VersionConfidence.HIGH),
        (r"FileZilla[\s]Server[\s](\d+)", VersionConfidence.HIGH),
        (r"Pure-FTPd[\s](\d+)", VersionConfidence.HIGH),
    ],
    
    # DNS
    "dns": [
        (r"named[/\s](\d+\.\d+[\.\d]*)", VersionConfidence.HIGH),
        (r"BIND[\s](\d+\.\d+[\.\d]*)", VersionConfidence.HIGH),
        (r"PowerDNS[\s/]*(\d+\.\d+)", VersionConfidence.HIGH),
    ],
    
    # VPN
    "openvpn": [
        (r"OpenVPN[\s](\d+\.\d+)", VersionConfidence.HIGH),
    ],
    "pptp": [
        (r"MPPE", VersionConfidence.LOW),
    ],
    "ipsec": [
        (r"StrongSwan", VersionConfidence.MEDIUM),
    ],
    
    # LDAP
    "ldap": [
        (r"OpenLDAP[\s](\d+\.\d+)", VersionConfidence.HIGH),
        (r"Microsoft[\s]Active\sDirectory", VersionConfidence.MEDIUM),
    ],
    
    # SMB
    "smb": [
        (r"SMB\d+", VersionConfidence.LOW),
        (r"Samba\s+(\d+\.\d+\.\d+)", VersionConfidence.HIGH),
        (r"Windows\s+(\d+\.\d+)", VersionConfidence.HIGH),
    ],
    
    # Docker
    "docker": [
        (r"Docker", VersionConfidence.MEDIUM),
        (r"containerd", VersionConfidence.MEDIUM),
    ],
    
    # Kubernetes
    "kubernetes": [
        (r"Kubernetes", VersionConfidence.MEDIUM),
        (r"k8s", VersionConfidence.LOW),
    ],
    
    # Tomcat
    "tomcat": [
        (r"Apache\s+Coyote[\s/](\d+\.\d+)", VersionConfidence.HIGH),
        (r"Tomcat[\s/]?(\d+\.\d+\.\d+)", VersionConfidence.HIGH),
    ],
    
    # Jenkins
    "jenkins": [
        (r"Jenkins[\s](\d+\.\d+[\.\d]*)", VersionConfidence.HIGH),
    ],
    
    # RabbitMQ
    "rabbitmq": [
        (r"RabbitMQ[\s](\d+\.\d+\.\d+)", VersionConfidence.HIGH),
    ],
    
    # Memcached
    "memcached": [
        (r"memcached[\s](\d+\.\d+\.\d+)", VersionConfidence.HIGH),
    ],
    
    # Prometheus
    "prometheus": [
        (r"Prometheus[\s/](\d+\.\d+\.\d+)", VersionConfidence.HIGH),
    ],
    
    # Grafana
    "grafana": [
        (r"Grafana[\s/](\d+\.\d+\.\d+)", VersionConfidence.HIGH),
    ],
}


# Product name normalization
PRODUCT_ALIASES = {
    "openssh": "OpenSSH",
    "ssh": "SSH",
    "nginx": "Nginx",
    "apache": "Apache",
    "apache http server": "Apache",
    "microsoft-iis": "IIS",
    "iis": "IIS",
    "mysql": "MySQL",
    "mariadb": "MariaDB",
    "postgresql": "PostgreSQL",
    "postgres": "PostgreSQL",
    "mongodb": "MongoDB",
    "redis": "Redis",
    "elasticsearch": "Elasticsearch",
    "postfix": "Postfix",
    "exim": "Exim",
    "dovecot": "Dovecot",
    "proftpd": "ProFTPD",
    "vsftpd": "vsftpd",
    "filezilla": "FileZilla Server",
    "pure-ftpd": "Pure-FTPd",
    "named": "BIND",
    "bind": "BIND",
    "openvpn": "OpenVPN",
    "openldap": "OpenLDAP",
    "samba": "Samba",
    "tomcat": "Tomcat",
    "jenkins": "Jenkins",
    "rabbitmq": "RabbitMQ",
    "memcached": "Memcached",
    "prometheus": "Prometheus",
    "grafana": "Grafana",
}


def normalize_product_name(name: str) -> str:
    """Normalize product name to canonical form."""
    if not name:
        return "Unknown"
    
    name_lower = name.lower().strip()
    
    # Check aliases
    for alias, canonical in PRODUCT_ALIASES.items():
        if alias in name_lower:
            return canonical
    
    # Title case
    return name.title()


def extract_version(banner: str, service_type: str = None) -> VersionMatch:
    """Extract version information from a banner.
    
    Args:
        banner: Raw service banner text
        service_type: Optional service type hint (e.g., "http", "ssh")
        
    Returns:
        VersionMatch object with extracted version details
    """
    if not banner:
        return VersionMatch(
            version=None,
            product=None,
            confidence=VersionConfidence.NONE,
            raw_match=""
        )
    
    # Try service-specific patterns first
    if service_type and service_type in VERSION_PATTERNS:
        for pattern, confidence in VERSION_PATTERNS[service_type]:
            match = re.search(pattern, banner, re.IGNORECASE | re.MULTILINE)
            if match:
                groups = match.groups()
                if len(groups) >= 1:
                    version = groups[0].strip()
                    product = groups[1].strip() if len(groups) > 1 else None
                    
                    # Clean up version
                    version = re.sub(r'[^\d.\-_p]', '', version)
                    
                    return VersionMatch(
                        version=version,
                        product=normalize_product_name(product) if product else service_type.title(),
                        confidence=confidence.value,
                        raw_match=match.group(0)[:100]
                    )
    
    # Fall back to trying all patterns
    for svc_type, patterns in VERSION_PATTERNS.items():
        for pattern, confidence in patterns:
            match = re.search(pattern, banner, re.IGNORECASE | re.MULTILINE)
            if match:
                groups = match.groups()
                if len(groups) >= 1:
                    version = groups[0].strip()
                    product = groups[1].strip() if len(groups) > 1 else None
                    
                    version = re.sub(r'[^\d.\-_p]', '', version)
                    
                    return VersionMatch(
                        version=version if version else None,
                        product=normalize_product_name(product) if product else svc_type.title(),
                        confidence=confidence.value,
                        raw_match=match.group(0)[:100]
                    )
    
    return VersionMatch(
        version=None,
        product=None,
        confidence=VersionConfidence.NONE,
        raw_match=""
    )


def extract_all_versions(banner: str) -> List[VersionMatch]:
    """Extract all possible versions from a banner.
    
    Args:
        banner: Raw service banner text
        
    Returns:
        List of VersionMatch objects, sorted by confidence
    """
    if not banner:
        return []
    
    matches = []
    
    for svc_type, patterns in VERSION_PATTERNS.items():
        for pattern, confidence in patterns:
            for match in re.finditer(pattern, banner, re.IGNORECASE | re.MULTILINE):
                groups = match.groups()
                if len(groups) >= 1:
                    version = groups[0].strip()
                    version = re.sub(r'[^\d.\-_p]', '', version)
                    
                    if version:
                        matches.append(VersionMatch(
                            version=version,
                            product=svc_type.title(),
                            confidence=confidence.value,
                            raw_match=match.group(0)[:100]
                        ))
    
    # Sort by confidence
    matches.sort(key=lambda x: x.confidence, reverse=True)
    
    return matches
