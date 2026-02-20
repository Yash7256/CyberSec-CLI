"""Input validation and sanitization utilities for CyberSec CLI."""

import ipaddress
import logging
import os
import re
import socket
from typing import List, Optional

# Import structured logging
try:
    from cybersec_cli.core.logging_config import get_logger

    HAS_STRUCTURED_LOGGING = True
except ImportError:
    HAS_STRUCTURED_LOGGING = False

logger = (
    get_logger("scanner") if HAS_STRUCTURED_LOGGING else logging.getLogger(__name__)
)

# Blocklist of potentially dangerous targets
# Private IP ranges are NOT blocked by default - use --allow-private flag to enable
BLOCKLIST = [
    "localhost",
    "127.0.0.1",
    "::1",  # IPv6 localhost
    "0.0.0.0",
    "255.255.255.255",
    # Common internal hostnames that could cause issues
    "internal",
    "intranet",
    "corp",
    "company",
    "localdomain",
    "lan",
    "router",
    "gateway",
    "firewall",
    "printer",
]

# Whitelist for explicitly allowed IPs/hostnames (comma-separated)
WHITELIST = os.getenv("PRIVATE_IP_WHITELIST", "").split(",")

# Additional blocklist for when BLOCK_PRIVATE_IPS is enabled
PRIVATE_IP_PREFIXES = [
    "10.",
    "172.16.",
    "172.17.",
    "172.18.",
    "172.19.",
    "172.20.",
    "172.21.",
    "172.22.",
    "172.23.",
    "172.24.",
    "172.25.",
    "172.26.",
    "172.27.",
    "172.28.",
    "172.29.",
    "172.30.",
    "172.31.",
    "192.168.",
    "169.254.",  # Link-local
]

# Private IP ranges that are always blocked regardless of setting
ALWAYS_BLOCKED = [
    "127.0.0.1",
    "::1",
    "0.0.0.0",
    "255.255.255.255",
]


def resolve_target_ip(target: str) -> Optional[str]:
    """Resolve a target to a single IP address without re-resolving later.

    Returns the original IP string if already an IP, otherwise resolves hostname.
    """
    if not target or not isinstance(target, str):
        return None
    target = target.strip()
    if not target:
        return None
    try:
        # If it's already an IP address (IPv4/IPv6), return it as-is
        return str(ipaddress.ip_address(target))
    except ValueError:
        pass
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


def validate_target(
    target: str, allow_private: bool = False, resolved_ip: Optional[str] = None
) -> bool:
    """
    Validate a target string to ensure it's safe to scan.

    Args:
        target: Target hostname or IP address
        allow_private: If True, allow scanning of private IP ranges (10.x, 172.x, 192.168.x)

    Returns:
        True if target is valid and safe, False otherwise
    """
    if not target or not isinstance(target, str):
        return False

    # Strip whitespace
    target = target.strip()

    if not target:
        return False

    # Check for potentially dangerous patterns (always blocked)
    target_lower = target.lower()

    # Check against always-blocked list (no overrides)
    for blocked in ALWAYS_BLOCKED:
        if target_lower == blocked.lower():
            return False

    # Check against blocklist hostnames
    for blocked in BLOCKLIST:
        if blocked in target_lower:
            if target in WHITELIST:
                continue
            return False

    # Strict IPv4 validation for numeric dot patterns
    if re.fullmatch(r"[0-9.]+", target):
        parts = target.split(".")
        if len(parts) != 4:
            return False
        for part in parts:
            if not part.isdigit():
                return False
            if len(part) > 1 and part.startswith("0"):
                return False
            value = int(part)
            if value > 255:
                return False
        try:
            ip = ipaddress.ip_address(target)
        except ValueError:
            return False
        if ip.is_multicast:
            return False
        if not allow_private and (ip.is_private or ip.is_loopback or ip.is_link_local):
            return False
        return True

    # Check if it's a (non-IPv4) IP (e.g., IPv6)
    try:
        ip = ipaddress.ip_address(target)

        # Always block multicast
        if ip.is_multicast:
            return False

        # Always block private/loopback/link-local ranges unless explicitly allowed
        if not allow_private:
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                return False

        return True
    except ValueError:
        # Not an IP address, continue with hostname validation
        pass

    # Validate hostname format
    if not _is_valid_hostname(target):
        return False

    # Try to resolve the hostname to check if it points to a blocked IP
    try:
        if resolved_ip is None:
            resolved_ip = socket.gethostbyname(target)
        ip_obj = ipaddress.ip_address(resolved_ip)

        # Check if resolved IP is in always-blocked list
        if resolved_ip in ALWAYS_BLOCKED and resolved_ip not in WHITELIST:
            return False

        # Check resolved IP against private IP rules
        if not allow_private:
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                return False

    except socket.gaierror:
        # Hostname couldn't be resolved - might be invalid but not necessarily dangerous
        pass

    return True


def _is_valid_hostname(hostname: str) -> bool:
    """
    Validate hostname format.

    Args:
        hostname: Hostname to validate

    Returns:
        True if hostname format is valid, False otherwise
    """
    if len(hostname) > 255 or len(hostname) == 0:
        return False

    if hostname.endswith("."):
        return False

    labels = hostname.split(".")
    if any(not label for label in labels):
        return False

    tld = labels[-1]
    if len(tld) < 2 or not tld.isalpha():
        return False

    allowed = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)

    return all(allowed.match(x) for x in labels)


def validate_port_range(ports: List[int]) -> bool:
    """
    Validate a list of ports to ensure they're in a safe range.

    Args:
        ports: List of port numbers to validate

    Returns:
        True if all ports are valid, False otherwise
    """
    if not isinstance(ports, list):
        return False

    if len(ports) > 65536:  # Allow full port range
        return False

    seen = set()
    for port in ports:
        if not isinstance(port, int):
            return False
        if port < 1 or port > 65535:  # Port 0 is invalid
            return False
        if port in seen:  # No duplicates
            return False
        seen.add(port)

    return True


def sanitize_input(user_input: str) -> str:
    """
    Sanitize user input by removing potentially dangerous characters.

    Args:
        user_input: Raw user input string

    Returns:
        Sanitized string
    """
    if not isinstance(user_input, str):
        return ""

    # Remove control characters (except tab and newline)
    sanitized = "".join(
        char for char in user_input if ord(char) >= 32 or char in ["\t", "\n"]
    )

    # Remove potential command injection characters
    dangerous_chars = [
        ";",
        "&",
        "|",
        "`",
        "$",
        "(",
        ")",
        "<",
        ">",
        "*",
        "?",
        "[",
        "]",
        "{",
        "}",
        "!",
        "~",
    ]
    for char in dangerous_chars:
        sanitized = sanitized.replace(char, "")

    # Trim whitespace
    sanitized = sanitized.strip()

    return sanitized


def is_safe_path(path: str, base_path: str) -> bool:
    """
    Check if a path is safe (not attempting directory traversal).

    Args:
        path: Path to check
        base_path: Base path that's allowed

    Returns:
        True if path is safe, False otherwise
    """
    import os.path

    # Normalize the paths
    path = os.path.normpath(path)
    base_path = os.path.normpath(base_path)

    # Check if the path is within the base path
    full_path = os.path.abspath(path)
    base_full_path = os.path.abspath(base_path)

    return full_path.startswith(base_full_path)


def validate_file_path(file_path: str, allowed_extensions: List[str] = None) -> bool:
    """
    Validate a file path for safe access.

    Args:
        file_path: Path to validate
        allowed_extensions: List of allowed file extensions (e.g., ['.txt', '.json'])

    Returns:
        True if path is valid and safe, False otherwise
    """
    if not file_path or not isinstance(file_path, str):
        return False

    # Check for directory traversal
    if ".." in file_path or "./" in file_path:
        return False

    # Check file extension if specified
    if allowed_extensions:
        import os.path

        _, ext = os.path.splitext(file_path)
        if ext.lower() not in allowed_extensions:
            return False

    return True


def validate_url(url: str) -> bool:
    """
    Validate URL format.

    Args:
        url: URL to validate

    Returns:
        True if URL format is valid, False otherwise
    """
    if not url or not isinstance(url, str):
        return False

    # Basic URL regex
    url_pattern = re.compile(
        r"^https?://"  # http:// or https://
        r"(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|"  # domain...
        r"localhost|"  # localhost...
        r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"  # ...or ip
        r"(?::\d+)?"  # optional port
        r"(?:/?|[/?]\S+)$",
        re.IGNORECASE,
    )

    return url_pattern.match(url) is not None
