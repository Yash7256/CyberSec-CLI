"""
Sensitive Data Scrubbing Module.
Automatically detects and redacts sensitive information from banners and logs.
"""

import re
from typing import List, Dict, Any
from dataclasses import dataclass


@dataclass
class ScrubResult:
    """Result of scrubbing operation."""
    original: str
    scrubbed: str
    patterns_found: List[str]
    redactions_count: int


# Comprehensive list of sensitive patterns
SENSITIVE_PATTERNS = [
    # Credentials in various formats
    (r'password[=:]\s*\S+', 'PASSWORD'),
    (r'passwd[=:]\s*\S+', 'PASSWD'),
    (r'pwd[=:]\s*\S+', 'PWD'),
    (r'secret[=:]\s*\S+', 'SECRET'),
    
    # API keys and tokens
    (r'api[_-]?key[=:]\s*[A-Za-z0-9_\-]{16,64}', 'API_KEY'),
    (r'access[_-]?token[=:]\s*[A-Za-z0-9_\-]{16,64}', 'ACCESS_TOKEN'),
    (r'refresh[_-]?token[=:]\s*[A-Za-z0-9_\-]{16,64}', 'REFRESH_TOKEN'),
    (r'auth[_-]?token[=:]\s*[A-Za-z0-9_\-]{16,64}', 'AUTH_TOKEN'),
    (r'bearer\s+[A-Za-z0-9_\-\.]{16,}', 'BEARER_TOKEN'),
    (r'token[=:]\s*[A-Za-z0-9_\-]{16,64}', 'TOKEN'),
    
    # Private keys and certificates
    (r'-----BEGIN [A-Z ]+PRIVATE KEY-----', 'PRIVATE_KEY'),
    (r'-----BEGIN RSA PRIVATE KEY-----', 'RSA_PRIVATE_KEY'),
    (r'-----BEGIN EC PRIVATE KEY-----', 'EC_PRIVATE_KEY'),
    (r'-----BEGIN OPENSSH PRIVATE KEY-----', 'OPENSSH_PRIVATE_KEY'),
    (r'-----BEGIN CERTIFICATE-----', 'CERTIFICATE'),
    
    # Authorization headers
    (r'Authorization:\s*\S+', 'AUTHORIZATION_HEADER'),
    (r'Authorization:\s*Basic\s+[A-Za-z0-9+/=]{20,}', 'BASIC_AUTH'),
    (r'Authorization:\s*Bearer\s+[A-Za-z0-9_\-\.]{16,}', 'BEARER_AUTH'),
    
    # AWS credentials
    (r'AKIA[0-9A-Z]{16}', 'AWS_ACCESS_KEY'),
    (r'(?i)aws[_-]?secret[_-]?access[_-]?key[=:]\s*[A-Za-z0-9/+=]{40}', 'AWS_SECRET_KEY'),
    
    # Database connection strings
    (r'mysql://[^:]+:[^@]+@', 'MYSQL_CONN'),
    (r'postgresql://[^:]+:[^@]+@', 'POSTGRES_CONN'),
    (r'mongodb(\+srv)?://[^:]+:[^@]+@', 'MONGODB_CONN'),
    (r'redis://[^:]+:[^@]+@', 'REDIS_CONN'),
    (r'sqlserver://[^:]+:[^@]+@', 'MSSQL_CONN'),
    
    # IP addresses in Authorization headers (potential leaked internal IPs)
    (r'X-Forwarded-For:\s*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', 'INTERNAL_IP'),
    (r'X-Real-IP:\s*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', 'INTERNAL_IP'),
    
    # Session IDs
    (r'session[_-]?id[=:]\s*[A-Za-z0-9]{16,64}', 'SESSION_ID'),
    (r'JSESSIONID=[A-Za-z0-9]+', 'JSESSIONID'),
    (r'PHPSESSID=[A-Za-z0-9]+', 'PHPSESSID'),
    (r'ASP\.NET_SessionId=[A-Za-z0-9]+', 'ASP_SESSIONID'),
    
    # OAuth secrets
    (r'oauth[_-]?client[_-]?secret[=:]\s*[A-Za-z0-9_\-]{16,64}', 'OAUTH_SECRET'),
    (r'client[_-]?secret[=:]\s*[A-Za-z0-9_\-]{16,64}', 'CLIENT_SECRET'),
    
    # JWT tokens
    (r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', 'JWT'),
    
    # SSH keys
    (r'ssh-rsa\s+AAAA[^\s]+', 'SSH_KEY'),
    (r'ssh-ed25519\s+AAAA[^\s]+', 'SSH_KEY'),
    
    # Generic password-like values in URLs
    (r'://[^:]+:[^@]+@', 'URL_CREDENTIALS'),
]

# Compile patterns for efficiency
COMPILED_PATTERNS = [
    (re.compile(pattern, re.IGNORECASE), replacement)
    for pattern, replacement in SENSITIVE_PATTERNS
]


def scrub_sensitive(text: str, aggressive: bool = False) -> ScrubResult:
    """Scrub sensitive information from text.
    
    Args:
        text: Input text to scrub
        aggressive: If True, also redact potential passwords (words with special chars)
        
    Returns:
        ScrubResult with original, scrubbed text, and metadata
    """
    if not text:
        return ScrubResult(
            original="",
            scrubbed="",
            patterns_found=[],
            redactions_count=0
        )
    
    original = text
    patterns_found = []
    total_redactions = 0
    
    # Apply all patterns
    for pattern, replacement in COMPILED_PATTERNS:
        matches = pattern.findall(text)
        if matches:
            patterns_found.append(f"{replacement}: {len(matches)} occurrence(s)")
            total_redactions += len(matches)
            text = pattern.sub(f'[{replacement}]', text)
    
    # Aggressive mode: redact potential passwords in key=value format
    if aggressive:
        # Find patterns like password=xxx or pwd=xxx
        password_patterns = [
            (r'(\w*pass\w*[=:]\s*)[^\s,\]]+', r'\1[REDACTED]'),
            (r'(\w*secret\w*[=:]\s*)[^\s,\]]+', r'\1[REDACTED]'),
            (r'(\w*key\w*[=:]\s*)[A-Za-z0-9_\-]{8,}', r'\1[REDACTED]'),
            (r'(\w*token\w*[=:]\s*)[A-Za-z0-9_\-]{8,}', r'\1[REDACTED]'),
        ]
        
        for pattern, replacement in password_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                total_redactions += len(matches)
                text = re.sub(pattern, replacement, text, flags=re.IGNORECASE)
                patterns_found.append(f"AGGRESSIVE_REDACTION: {len(matches)}")
    
    return ScrubResult(
        original=original,
        scrubbed=text,
        patterns_found=patterns_found,
        redactions_count=total_redactions
    )


def scrub_dict(data: Dict[str, Any], aggressive: bool = False) -> Dict[str, Any]:
    """Scrub sensitive data from a dictionary.
    
    Args:
        data: Dictionary to scrub
        aggressive: If True, apply aggressive scrubbing
        
    Returns:
        New dictionary with sensitive values redacted
    """
    result = {}
    sensitive_keys = {
        'password', 'passwd', 'pwd', 'secret', 'token', 'key',
        'api_key', 'api-key', 'access_token', 'auth_token',
        'session_id', 'session-id', 'sessionid',
        'authorization', 'auth', 'credential',
        'private_key', 'private-key', 'cert', 'certificate',
    }
    
    for key, value in data.items():
        key_lower = key.lower()
        
        # Check if key is sensitive
        is_sensitive = any(s in key_lower for s in sensitive_keys)
        
        if is_sensitive:
            result[key] = '[REDACTED]'
        elif isinstance(value, str):
            # Scrub the string value
            scrubbed = scrub_sensitive(value, aggressive)
            result[key] = scrubbed.scrubbed if scrubbed.redactions_count > 0 else value
        elif isinstance(value, dict):
            result[key] = scrub_dict(value, aggressive)
        elif isinstance(value, list):
            result[key] = [
                scrub_dict(item, aggressive) if isinstance(item, dict)
                else scrub_sensitive(str(item), aggressive).scrubbed if isinstance(item, str)
                else item
                for item in value
            ]
        else:
            result[key] = value
    
    return result


def create_scrubbed_banner(banner: str, service: str = None) -> str:
    """Create a scrubbed version of a service banner.
    
    Args:
        banner: Raw service banner
        service: Optional service type hint
        
    Returns:
        Scrubbed banner safe for logging/storing
    """
    result = scrub_sensitive(banner, aggressive=False)
    
    # Also scrub common credential patterns in specific services
    if service:
        service_lower = service.lower()
        
        # MySQL specific
        if 'mysql' in service_lower or 'maria' in service_lower:
            banner = re.sub(
                r"(user'[^\s@]+@[^\s']+')",
                "[USER_REDACTED]",
                banner,
                flags=re.IGNORECASE
            )
        
        # FTP responses often contain usernames
        if 'ftp' in service_lower:
            banner = re.sub(
                r"(331\s+Password\s+required\s+for\s+)\S+",
                r"\1[USER]",
                banner,
                flags=re.IGNORECASE
            )
    
    return result.scrubbed


# For backward compatibility
def mask_credentials(text: str) -> str:
    """Legacy function name for backwards compatibility."""
    return scrub_sensitive(text).scrubbed
