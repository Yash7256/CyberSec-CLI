"""Input validation and sanitization utilities for CyberSec CLI."""
import re
import ipaddress
import socket
from typing import List, Optional, Union
import os
import logging

logger = logging.getLogger(__name__)

# Blocklist of potentially dangerous targets
BLOCKLIST = [
    "localhost",
    "127.0.0.1",
    "::1",  # IPv6 localhost
    "0.0.0.0",
    "255.255.255.255",
    # Common internal hostnames
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
    # Common internal IP ranges that should be blocked unless explicitly allowed
    "10.",
    "172.",
    "192.168.",
    "169.254.",  # Link-local
]

# Whitelist for allowed private IP ranges (if needed for internal testing)
WHITELIST = os.getenv("PRIVATE_IP_WHITELIST", "").split(",")


def validate_target(target: str) -> bool:
    """
    Validate a target string to ensure it's safe to scan.
    
    Args:
        target: Target hostname or IP address
        
    Returns:
        True if target is valid and safe, False otherwise
    """
    if not target or not isinstance(target, str):
        return False
    
    # Strip whitespace
    target = target.strip()
    
    if not target:
        return False
    
    # Check for potentially dangerous patterns
    target_lower = target.lower()
    
    # Check against blocklist
    for blocked in BLOCKLIST:
        if blocked in target_lower:
            # Check if it's in the whitelist
            if target in WHITELIST:
                continue  # Allow if whitelisted
            return False
    
    # Check if it's a private IP that's not whitelisted
    try:
        ip = ipaddress.ip_address(target)
        if ip.is_private and str(ip) not in WHITELIST:
            return False
        if ip.is_loopback and str(ip) not in WHITELIST:
            return False
        if ip.is_link_local and str(ip) not in WHITELIST:
            return False
        if ip.is_multicast:
            return False
    except ValueError:
        # Not an IP address, continue with hostname validation
        pass
    
    # Validate hostname format
    if not _is_valid_hostname(target):
        return False
    
    # Try to resolve the hostname to check if it's not pointing to a private IP
    try:
        resolved_ip = socket.gethostbyname(target)
        ip_obj = ipaddress.ip_address(resolved_ip)
        
        # Check if resolved IP is private and not whitelisted
        if ip_obj.is_private and str(ip_obj) not in WHITELIST:
            return False
        if ip_obj.is_loopback and str(ip_obj) not in WHITELIST:
            return False
        if ip_obj.is_link_local and str(ip_obj) not in WHITELIST:
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
    
    if hostname[-1] == ".":
        hostname = hostname[:-1]  # Strip trailing dot if present
    
    allowed = re.compile(
        r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE
    )
    
    return all(allowed.match(x) for x in hostname.split("."))


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
    
    if len(ports) > 1000:  # Reasonable limit
        return False
    
    seen = set()
    for port in ports:
        if not isinstance(port, int):
            return False
        if port < 1 or port > 65535:
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
        char for char in user_input 
        if ord(char) >= 32 or char in ['\t', '\n']
    )
    
    # Remove potential command injection characters
    dangerous_chars = [";", "&", "|", "`", "$", "(", ")", "<", ">", "*", "?", "[", "]", "{", "}", "!", "~"]
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
    if '..' in file_path or './' in file_path:
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
        r'^https?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    
    return url_pattern.match(url) is not None