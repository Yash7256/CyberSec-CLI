"""
HTTP/HTTPS Deep Inspection Module.
Comprehensive HTTP fingerprinting and security header analysis.
"""

import asyncio
import socket
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Set
from enum import Enum
import ssl


class HTTPVersion(Enum):
    """HTTP protocol versions."""
    HTTP_09 = "HTTP/0.9"
    HTTP_10 = "HTTP/1.0"
    HTTP_11 = "HTTP/1.1"
    HTTP_20 = "HTTP/2.0"
    HTTP_30 = "HTTP/3.0"
    UNKNOWN = "Unknown"


class SecurityHeaderStatus(Enum):
    """Security header presence status."""
    PRESENT = "present"
    MISSING = "missing"
    WEAK = "weak"
    INVALID = "invalid"


@dataclass
class HTTPHeaders:
    """HTTP response headers."""
    raw: Dict[str, str]
    server: Optional[str]
    x_powered_by: Optional[str]
    content_type: Optional[str]
    content_security_policy: Optional[str]
    strict_transport_security: Optional[str]
    x_frame_options: Optional[str]
    x_content_type_options: Optional[str]
    x_xss_protection: Optional[str]
    referrer_policy: Optional[str]
    permissions_policy: Optional[str]
    access_control_allow_origin: Optional[str]
    set_cookie: List[str]
    

@dataclass
class CookieInfo:
    """Information about a cookie."""
    name: str
    value: str
    secure: bool
    http_only: bool
    same_site: Optional[str]
    expires: Optional[str]


@dataclass
class RedirectInfo:
    """HTTP redirect information."""
    status_code: int
    location: str
    depth: int


@dataclass
class HTTPInspection:
    """Complete HTTP inspection result."""
    is_http: bool
    http_version: Optional[str]
    status_code: Optional[int]
    status_message: Optional[str]
    headers: Optional[HTTPHeaders]
    security_headers_audit: Dict[str, SecurityHeaderStatus]
    cookies: List[CookieInfo]
    redirects: List[RedirectInfo]
    security_score: float
    vulnerabilities: List[str]
    recommendations: List[str]


# Security headers that should be present
REQUIRED_SECURITY_HEADERS = {
    "strict_transport_security": {
        "name": "Strict-Transport-Security",
        "recommendation": "Enable HSTS with: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    },
    "x_content_type_options": {
        "name": "X-Content-Type-Options",
        "recommendation": "Add header: X-Content-Type-Options: nosniff",
    },
    "x_frame_options": {
        "name": "X-Frame-Options",
        "recommendation": "Add header: X-Frame-Options: DENY or SAMEORIGIN",
    },
    "content_security_policy": {
        "name": "Content-Security-Policy",
        "recommendation": "Implement CSP: Content-Security-Policy: default-src 'self'",
    },
}

# Security headers that should NOT have weak values
WEAK_HEADER_VALUES = {
    "x_frame_options": ["ALLOW", "allowall"],
    "referrer_policy": ["unsafe-url", "no-referrer-when-downgrade"],
    "strict_transport_security": ["max-age=0"],
}


def parse_headers(raw_headers: List[str]) -> HTTPHeaders:
    """Parse raw HTTP headers."""
    header_dict = {}
    server = None
    x_powered_by = None
    content_type = None
    csp = None
    hsts = None
    xfo = None
    xcto = None
    xxsp = None
    ref_policy = None
    perm_policy = None
    acao = None
    cookies = []
    
    for header in raw_headers:
        if ':' in header:
            key, value = header.split(':', 1)
            key = key.strip().lower()
            value = value.strip()
            header_dict[key] = value
            
            # Extract specific headers
            if key == 'server':
                server = value
            elif key == 'x-powered-by':
                x_powered_by = value
            elif key == 'content-type':
                content_type = value
            elif key == 'content-security-policy':
                csp = value
            elif key == 'strict-transport-security':
                hsts = value
            elif key == 'x-frame-options':
                xfo = value
            elif key == 'x-content-type-options':
                xcto = value
            elif key == 'x-xss-protection':
                xxsp = value
            elif key == 'referrer-policy':
                ref_policy = value
            elif key == 'permissions-policy' or key == 'feature-policy':
                perm_policy = value
            elif key == 'access-control-allow-origin':
                acao = value
            elif key == 'set-cookie':
                cookies.append(value)
    
    return HTTPHeaders(
        raw=header_dict,
        server=server,
        x_powered_by=x_powered_by,
        content_type=content_type,
        content_security_policy=csp,
        strict_transport_security=hsts,
        x_frame_options=xfo,
        x_content_type_options=xcto,
        x_xss_protection=xxsp,
        referrer_policy=ref_policy,
        permissions_policy=perm_policy,
        access_control_allow_origin=acao,
        set_cookie=cookies,
    )


def parse_cookies(set_cookie_headers: List[str]) -> List[CookieInfo]:
    """Parse Set-Cookie headers."""
    cookies = []
    
    for cookie_str in set_cookie_headers:
        parts = cookie_str.split(';')
        if not parts:
            continue
        
        # First part is name=value
        name_value = parts[0].strip()
        if '=' in name_value:
            name, value = name_value.split('=', 1)
        else:
            name = name_value
            value = ""
        
        # Parse flags
        secure = False
        http_only = False
        same_site = None
        expires = None
        
        for part in parts[1:]:
            part = part.strip().lower()
            if part == 'secure':
                secure = True
            elif part == 'httponly' or part == 'http-only':
                http_only = True
            elif part.startswith('sameparty'):
                same_site = 'sameparty'
            elif 'sameSite' in part:
                if '=' in part:
                    same_site = part.split('=')[1].strip()
            elif part.startswith('expires='):
                expires = part.split('=')[1].strip()
        
        cookies.append(CookieInfo(
            name=name,
            value=value[:20] + "..." if len(value) > 20 else value,  # Truncate for privacy
            secure=secure,
            http_only=http_only,
            same_site=same_site,
            expires=expires,
        ))
    
    return cookies


def audit_security_headers(headers: HTTPHeaders) -> Dict[str, SecurityHeaderStatus]:
    """Audit security headers and return status for each."""
    audit = {}
    
    # Check required headers
    for key, info in REQUIRED_SECURITY_HEADERS.items():
        header_value = getattr(headers, key, None)
        
        if header_value is None:
            audit[info["name"]] = SecurityHeaderStatus.MISSING
        elif key in WEAK_HEADER_VALUES:
            if any(weak in header_value.lower() for weak in WEAK_HEADER_VALUES[key]):
                audit[info["name"]] = SecurityHeaderStatus.WEAK
            else:
                audit[info["name"]] = SecurityHeaderStatus.PRESENT
        else:
            audit[info["name"]] = SecurityHeaderStatus.PRESENT
    
    # Check for information disclosure headers
    if headers.x_powered_by:
        audit["X-Powered-By"] = SecurityHeaderStatus.WEAK
    if headers.server and re.search(r'Apache/2\.2', headers.server):
        audit["Server"] = SecurityHeaderStatus.WEAK
    
    # Check CORS
    if headers.access_control_allow_origin:
        if headers.access_control_allow_origin == '*':
            audit["CORS"] = SecurityHeaderStatus.WEAK
        else:
            audit["CORS"] = SecurityHeaderStatus.PRESENT
    
    return audit


async def inspect_http(
    host: str,
    port: int = 80,
    use_https: bool = False,
    timeout: float = 5.0,
    follow_redirects: bool = True,
    max_redirects: int = 5
) -> HTTPInspection:
    """Perform deep HTTP inspection.
    
    Args:
        host: Target hostname
        port: Target port
        use_https: Use HTTPS
        timeout: Connection timeout
        follow_redirects: Follow HTTP redirects
        max_redirects: Maximum redirects to follow
        
    Returns:
        HTTPInspection with complete analysis
    """
    vulnerabilities = []
    recommendations = []
    security_score = 100.0
    redirects = []
    
    # Build request
    scheme = "https" if use_https else "http"
    path = f"{scheme}://{host}:{port}"
    
    # Prepare request
    request = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: CyberSec-CLI/1.0\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    )
    
    # Connect
    try:
        if use_https:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=context),
                timeout=timeout
            )
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )
        
        # Send request
        writer.write(request.encode())
        await writer.drain()
        
        # Read response
        response_data = await asyncio.wait_for(reader.read(8192), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        
    except Exception as e:
        return HTTPInspection(
            is_http=False,
            http_version=None,
            status_code=None,
            status_message=None,
            headers=None,
            security_headers_audit={},
            cookies=[],
            redirects=[],
            security_score=0.0,
            vulnerabilities=[f"Connection failed: {str(e)}"],
            recommendations=["Ensure HTTP service is running"],
        )
    
    # Parse response
    try:
        response_text = response_data.decode('utf-8', errors='ignore')
    except:
        response_text = str(response_data)
    
    # Split headers and body
    parts = response_text.split('\r\n\r\n', 1)
    if len(parts) < 2:
        # Try just newline
        parts = response_text.split('\n\n', 1)
    
    if len(parts) < 2:
        return HTTPInspection(
            is_http=True,
            http_version=HTTPVersion.UNKNOWN.value,
            status_code=None,
            status_message=None,
            headers=None,
            security_headers_audit={},
            cookies=[],
            redirects=[],
            security_score=0.0,
            vulnerabilities=["Invalid HTTP response"],
            recommendations=[],
        )
    
    header_lines = parts[0].split('\r\n')
    if len(header_lines) < 2:
        header_lines = parts[0].split('\n')
    
    # Parse status line
    status_line = header_lines[0]
    status_match = re.match(r'(HTTP/[\d.]+)\s+(\d+)\s*(.*)', status_line)
    
    if status_match:
        http_version = status_match.group(1)
        status_code = int(status_match.group(2))
        status_message = status_match.group(3)
    else:
        http_version = HTTPVersion.UNKNOWN.value
        status_code = None
        status_message = None
    
    # Parse headers
    headers = parse_headers(header_lines[1:])
    cookies = parse_cookies(headers.set_cookie)
    security_audit = audit_security_headers(headers)
    
    # Calculate security score
    for header, status in security_audit.items():
        if status == SecurityHeaderStatus.MISSING:
            security_score -= 10
            recommendations.append(f"Missing security header: {header}")
        elif status == SecurityHeaderStatus.WEAK:
            security_score -= 5
            recommendations.append(f"Weak security header: {header}")
    
    # Check for specific vulnerabilities
    if headers.x_powered_by:
        vulnerabilities.append(f"Information disclosure: X-Powered-By reveals {headers.x_powered_by}")
        security_score -= 5
    
    if headers.server and re.search(r'Apache/2\.[24]', headers.server):
        vulns = []
        # Check specific Apache versions
        if '2.2' in headers.server:
            vulns = ["CVE-2017-15710", "CVE-2018-1312"]
        elif '2.4' in headers.server:
            vulns = ["CVE-2017-15710"]
        
        if vulns:
            vulnerabilities.append(f"Potentially vulnerable Apache version: {', '.join(vulns)}")
            security_score -= 10
    
    # Check for redirect to HTTPS
    if not use_https and status_code in [301, 302, 303, 307, 308]:
        location = headers.raw.get('location', '')
        if location.startswith('https://'):
            redirects.append(RedirectInfo(status_code, location, 1))
            if follow_redirects and len(redirects) < max_redirects:
                # Could follow redirect here
                pass
    
    # Cookie security
    for cookie in cookies:
        if not cookie.secure and use_https:
            vulnerabilities.append(f"Cookie {cookie.name} missing Secure flag")
            security_score -= 3
        if not cookie.http_only:
            vulnerabilities.append(f"Cookie {cookie.name} missing HttpOnly flag (XSS risk)")
            security_score -= 2
        if not cookie.same_site:
            vulnerabilities.append(f"Cookie {cookie.name} missing SameSite attribute")
            security_score -= 2
    
    security_score = max(0, security_score)
    
    return HTTPInspection(
        is_http=True,
        http_version=http_version,
        status_code=status_code,
        status_message=status_message,
        headers=headers,
        security_headers_audit=security_audit,
        cookies=cookies,
        redirects=redirects,
        security_score=security_score,
        vulnerabilities=vulnerabilities,
        recommendations=recommendations,
    )


def format_http_report(inspection: HTTPInspection) -> str:
    """Format HTTP inspection as readable report."""
    lines = [
        "HTTP Security Analysis",
        "=" * 40,
    ]
    
    if not inspection.is_http:
        lines.append("No HTTP service detected")
        return "\n".join(lines)
    
    lines.extend([
        f"HTTP Version: {inspection.http_version}",
        f"Status: {inspection.status_code} {inspection.status_message or ''}",
        f"Security Score: {inspection.security_score:.0f}/100",
    ])
    
    if inspection.headers:
        if inspection.headers.server:
            lines.append(f"Server: {inspection.headers.server}")
        if inspection.headers.x_powered_by:
            lines.append(f"X-Powered-By: {inspection.headers.x_powered_by}")
    
    # Security headers
    lines.append("\nSecurity Headers:")
    for header, status in inspection.security_headers_audit.items():
        status_icon = "✓" if status == SecurityHeaderStatus.PRESENT else "⚠"
        lines.append(f"  {status_icon} {header}: {status.value}")
    
    # Vulnerabilities
    if inspection.vulnerabilities:
        lines.append("\nVulnerabilities Found:")
        for vuln in inspection.vulnerabilities:
            lines.append(f"  - {vuln}")
    
    # Recommendations
    if inspection.recommendations:
        lines.append("\nRecommendations:")
        for rec in inspection.recommendations:
            lines.append(f"  - {rec}")
    
    return "\n".join(lines)
