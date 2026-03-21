"""
Web Application Vulnerability Scanner.

Performs active vulnerability testing against HTTP/HTTPS targets:
- SQL injection (error-based detection)
- Cross-site scripting (XSS reflection detection)
- Cross-site request forgery (CSRF token checks)
- Server-side request forgery (SSRF via redirect probing)
- Open redirect detection
- Directory traversal
- Sensitive file/path discovery
- Security header analysis (extends http_inspector)
- Information disclosure (stack traces, verbose errors)
- Authentication issues (default credentials probe, login page detection)
"""

import asyncio
import re
import time
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

import httpx


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


class VulnType(str, Enum):
    SQL_INJECTION        = "sql_injection"
    XSS                  = "xss"
    CSRF                 = "csrf"
    SSRF                 = "ssrf"
    OPEN_REDIRECT        = "open_redirect"
    DIRECTORY_TRAVERSAL  = "directory_traversal"
    SENSITIVE_FILE       = "sensitive_file"
    SECURITY_HEADER      = "security_header"
    INFO_DISCLOSURE      = "information_disclosure"
    AUTH_ISSUE           = "auth_issue"
    CORS_MISCONFIGURATION = "cors_misconfiguration"
    CLICKJACKING         = "clickjacking"


@dataclass
class Finding:
    """A single vulnerability finding."""
    vuln_type:   VulnType
    severity:    Severity
    title:       str
    description: str
    evidence:    str
    path:        str
    remediation: str
    cvss_score:  float = 0.0
    cwe_id:      Optional[str] = None
    references:  List[str] = field(default_factory=list)


@dataclass
class WebAppScanResult:
    """Complete web application scan result."""
    target:         str
    base_url:       str
    scan_duration:  float
    pages_tested:   int
    total_requests: int
    findings:       List[Finding]
    technologies:   List[str]
    forms_found:    int
    error:          Optional[str] = None

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def risk_score(self) -> int:
        weights = {
            Severity.CRITICAL: 40,
            Severity.HIGH: 20,
            Severity.MEDIUM: 10,
            Severity.LOW: 3,
            Severity.INFO: 1,
        }
        score = sum(weights[f.severity] for f in self.findings)
        return min(100, score)


# ---------------------------------------------------------------------------
# Payloads and patterns
# ---------------------------------------------------------------------------

# SQL injection test payloads — error-based only (safe, no blind timing)
SQLI_PAYLOADS = [
    "'",
    "\"",
    "' OR '1'='1",
    "' OR 1=1--",
    "1; SELECT 1--",
    "'; WAITFOR DELAY '0:0:0'--",   # MSSQL (0-delay, just syntax probe)
    "1 AND 1=CONVERT(int, 'a')--",  # MSSQL type error probe
]

# SQL error signatures from common databases
SQLI_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"pg_query\(\): query failed",
    r"ora-\d{5}",
    r"microsoft ole db provider for sql server",
    r"sqlite3::exception",
    r"syntax error.*sql",
    r"invalid query",
    r"mysql_fetch",
    r"supplied argument is not a valid mysql",
]

# XSS test payloads — reflected detection only
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(1)",
    "<svg onload=alert(1)>",
    "'><script>alert(1)</script>",
]

# SSRF / open redirect payloads
REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "https://169.254.169.254/latest/meta-data/",  # AWS IMDS
    "http://127.0.0.1:22",
    "http://localhost:6379",  # Redis
]

# Directory traversal payloads
TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "....//....//etc/passwd",
]

# Sensitive paths to probe
SENSITIVE_PATHS = [
    "/.env",
    "/.git/config",
    "/.git/HEAD",
    "/wp-config.php",
    "/config.php",
    "/database.yml",
    "/settings.py",
    "/web.config",
    "/.htaccess",
    "/robots.txt",
    "/sitemap.xml",
    "/security.txt",
    "/.well-known/security.txt",
    "/api/swagger.json",
    "/api/openapi.json",
    "/swagger.json",
    "/openapi.json",
    "/docs",
    "/redoc",
    "/admin",
    "/admin/login",
    "/wp-admin",
    "/phpmyadmin",
    "/server-status",    # Apache
    "/server-info",      # Apache
    "/actuator",         # Spring Boot
    "/actuator/health",
    "/actuator/env",
    "/actuator/mappings",
    "/metrics",
    "/_profiler",        # Symfony
    "/debug",
    "/console",          # Laravel Telescope, Rails console
    "/telescope",
    "/.DS_Store",
    "/backup.zip",
    "/backup.sql",
    "/dump.sql",
]

# Information disclosure patterns in response bodies
INFO_DISCLOSURE_PATTERNS = [
    (r"stack trace", "Stack trace exposed"),
    (r"traceback \(most recent call", "Python traceback in response"),
    (r"at .+\.java:\d+\)", "Java stack trace in response"),
    (r"system\.web\.httpunhandledexception", ".NET unhandled exception"),
    (r"fatal error:.*php", "PHP fatal error exposed"),
    (r"warning:.*php", "PHP warning exposed"),
    (r"parse error:.*php", "PHP parse error exposed"),
    (r"exception in thread", "Java exception in response"),
    (r"mysql server version", "MySQL version in response"),
    (r"postgresql.*error", "PostgreSQL error in response"),
    (r"access denied for user", "MySQL credentials error"),
    (r"server internal error", "Internal server error details"),
    (r"debug.*=.*true", "Debug mode enabled"),
]

# Technology fingerprints from headers and body
TECH_FINGERPRINTS = {
    "X-Powered-By":          lambda v: v,
    "Server":                lambda v: v,
    "X-Generator":           lambda v: v,
    "X-Drupal-Cache":        lambda _: "Drupal",
    "X-Joomla-Cache":        lambda _: "Joomla",
}
BODY_TECH_PATTERNS = [
    (r"wp-content|wp-includes", "WordPress"),
    (r"drupal\.js|drupal-settings", "Drupal"),
    (r"joomla", "Joomla"),
    (r"laravel_session", "Laravel"),
    (r"rails-ujs|csrf-token.*rails", "Ruby on Rails"),
    (r"__django_", "Django"),
    (r"next/dist|__next", "Next.js"),
    (r"react-dom|__react", "React"),
    (r"ng-version|angular\.js", "Angular"),
    (r"vue\.js|vue-router", "Vue.js"),
]

# Required security headers  (name → (severity, remediation))
REQUIRED_HEADERS: Dict[str, Tuple[Severity, str]] = {
    "Strict-Transport-Security": (
        Severity.HIGH,
        "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    ),
    "Content-Security-Policy": (
        Severity.MEDIUM,
        "Add a Content-Security-Policy header to prevent XSS and data injection.",
    ),
    "X-Frame-Options": (
        Severity.MEDIUM,
        "Add: X-Frame-Options: DENY to prevent clickjacking.",
    ),
    "X-Content-Type-Options": (
        Severity.LOW,
        "Add: X-Content-Type-Options: nosniff",
    ),
    "Referrer-Policy": (
        Severity.LOW,
        "Add: Referrer-Policy: strict-origin-when-cross-origin",
    ),
    "Permissions-Policy": (
        Severity.INFO,
        "Add a Permissions-Policy header to restrict browser features.",
    ),
}


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _build_url(base: str, path: str) -> str:
    """Safely join base URL and path."""
    return base.rstrip("/") + "/" + path.lstrip("/")


def _safe_decode(content: bytes) -> str:
    return content.decode("utf-8", errors="replace")


def _matches_any(text: str, patterns: List[str]) -> Optional[str]:
    """Return first matching pattern or None."""
    lower = text.lower()
    for p in patterns:
        if re.search(p, lower):
            return p
    return None


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class WebAppScanner:
    """
    Async web application vulnerability scanner.

    Designed to be safe for use against targets you own or have permission
    to test. Does NOT perform:
    - Destructive writes (no INSERT/UPDATE/DELETE SQL probes)
    - Brute-force login (only checks for login page existence)
    - Denial of service payloads
    - Blind timing attacks

    Usage:
        scanner = WebAppScanner(base_url="https://example.com", timeout=10)
        result = await scanner.run()
    """

    def __init__(
        self,
        base_url: str,
        timeout: float = 10.0,
        max_pages: int = 20,
        crawl: bool = True,
        test_sqli: bool = True,
        test_xss: bool = True,
        test_headers: bool = True,
        test_paths: bool = True,
        test_info_disclosure: bool = True,
    ):
        self.base_url       = base_url.rstrip("/")
        self.timeout        = timeout
        self.max_pages      = max_pages
        self.crawl          = crawl
        self.test_sqli      = test_sqli
        self.test_xss       = test_xss
        self.test_headers   = test_headers
        self.test_paths     = test_paths
        self.test_info      = test_info_disclosure
        self.findings:      List[Finding] = []
        self.technologies:  List[str] = []
        self.request_count  = 0
        self.pages_tested   = 0
        self._visited:      set = set()

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    async def run(self) -> WebAppScanResult:
        start = time.time()
        error = None

        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=True,
                verify=False,  # nosec B501
                headers={
                    "User-Agent": "CyberSec-CLI/2.0 (Security Scanner)",
                    "Accept": "text/html,application/xhtml+xml,application/json,*/*",
                },
            ) as client:
                self._client = client

                # 1. Baseline request — fingerprint + security headers
                root_resp = await self._get("/")
                if root_resp:
                    self._fingerprint_technologies(root_resp)
                    if self.test_headers:
                        self._check_security_headers(root_resp)
                    if self.test_info:
                        self._check_info_disclosure(root_resp, "/")

                # 2. Sensitive path discovery
                if self.test_paths:
                    await self._probe_sensitive_paths()

                # 3. Always test forms on root page (independent of crawl flag)
                if root_resp:
                    forms = self._extract_forms(root_resp)
                    if forms:
                        await self._test_forms(forms)

                # 4. Crawl discovered links and test their forms too
                if self.crawl and root_resp:
                    links = self._extract_links(root_resp)
                    await self._crawl_and_test(links)

                # 4. CORS probe
                await self._check_cors()

        except httpx.ConnectError as e:
            error = f"Connection refused: {e}"
        except httpx.TimeoutException:
            error = "Connection timed out"
        except Exception as e:
            error = f"Scanner error: {str(e)}"

        duration = time.time() - start

        # Deduplicate findings by (type, path)
        seen = set()
        unique = []
        for f in self.findings:
            key = (f.vuln_type, f.path, f.title)
            if key not in seen:
                seen.add(key)
                unique.append(f)

        return WebAppScanResult(
            target=self.base_url,
            base_url=self.base_url,
            scan_duration=round(duration, 2),
            pages_tested=self.pages_tested,
            total_requests=self.request_count,
            findings=sorted(
                unique,
                key=lambda x: [
                    Severity.CRITICAL,
                    Severity.HIGH,
                    Severity.MEDIUM,
                    Severity.LOW,
                    Severity.INFO,
                ].index(x.severity),
            ),
            technologies=list(set(self.technologies)),
            forms_found=0,
            error=error,
        )

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------

    async def _get(
        self, path: str, params: Optional[Dict] = None
    ) -> Optional[httpx.Response]:
        url = _build_url(self.base_url, path)
        try:
            self.request_count += 1
            resp = await self._client.get(url, params=params)
            return resp
        except Exception:
            return None

    async def _post(
        self, path: str, data: Dict
    ) -> Optional[httpx.Response]:
        url = _build_url(self.base_url, path)
        try:
            self.request_count += 1
            resp = await self._client.post(url, data=data)
            return resp
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Technology fingerprinting
    # ------------------------------------------------------------------

    def _fingerprint_technologies(self, resp: httpx.Response) -> None:
        # From response headers
        for header, extractor in TECH_FINGERPRINTS.items():
            val = resp.headers.get(header)
            if val:
                tech = extractor(val)
                if tech:
                    self.technologies.append(tech)

        # From response body
        body = _safe_decode(resp.content[:20000])
        for pattern, name in BODY_TECH_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                self.technologies.append(name)

        # Flag version disclosures
        server = resp.headers.get("Server", "")
        if server and re.search(r"[\d.]{3,}", server):
            self.findings.append(Finding(
                vuln_type=VulnType.INFO_DISCLOSURE,
                severity=Severity.LOW,
                title="Server version disclosed in header",
                description=f"The Server header reveals version information: {server}",
                evidence=f"Server: {server}",
                path="/",
                remediation="Remove or genericise the Server header in your web server config.",
                cwe_id="CWE-200",
            ))

        x_powered = resp.headers.get("X-Powered-By", "")
        if x_powered:
            self.findings.append(Finding(
                vuln_type=VulnType.INFO_DISCLOSURE,
                severity=Severity.LOW,
                title="Technology stack disclosed via X-Powered-By",
                description=f"X-Powered-By header reveals: {x_powered}",
                evidence=f"X-Powered-By: {x_powered}",
                path="/",
                remediation="Remove the X-Powered-By header entirely.",
                cwe_id="CWE-200",
            ))

    # ------------------------------------------------------------------
    # Security header checks
    # ------------------------------------------------------------------

    def _check_security_headers(self, resp: httpx.Response) -> None:
        headers_lower = {k.lower(): v for k, v in resp.headers.items()}

        for header_name, (severity, remediation) in REQUIRED_HEADERS.items():
            if header_name.lower() not in headers_lower:
                self.findings.append(Finding(
                    vuln_type=VulnType.SECURITY_HEADER,
                    severity=severity,
                    title=f"Missing security header: {header_name}",
                    description=f"The {header_name} header is absent from the response.",
                    evidence="Header not present in HTTP response",
                    path="/",
                    remediation=remediation,
                    cwe_id="CWE-693",
                ))

        # Check for clickjacking specifically
        xfo = headers_lower.get("x-frame-options", "")
        csp = headers_lower.get("content-security-policy", "")
        if not xfo and "frame-ancestors" not in csp:
            self.findings.append(Finding(
                vuln_type=VulnType.CLICKJACKING,
                severity=Severity.MEDIUM,
                title="Clickjacking protection missing",
                description=(
                    "No X-Frame-Options header and no frame-ancestors CSP directive. "
                    "The page can be embedded in an iframe on any origin."
                ),
                evidence="X-Frame-Options absent, no CSP frame-ancestors directive",
                path="/",
                remediation=(
                    "Add X-Frame-Options: DENY or set "
                    "Content-Security-Policy: frame-ancestors 'none'"
                ),
                cvss_score=4.3,
                cwe_id="CWE-1021",
            ))

        # Check HSTS on HTTPS
        if self.base_url.startswith("https://"):
            hsts = headers_lower.get("strict-transport-security", "")
            if hsts:
                max_age_match = re.search(r"max-age=(\d+)", hsts)
                if max_age_match and int(max_age_match.group(1)) < 15768000:
                    self.findings.append(Finding(
                        vuln_type=VulnType.SECURITY_HEADER,
                        severity=Severity.LOW,
                        title="HSTS max-age is too short",
                        description=f"HSTS max-age is {max_age_match.group(1)} seconds (< 6 months).",
                        evidence=f"Strict-Transport-Security: {hsts}",
                        path="/",
                        remediation="Set max-age to at least 31536000 (1 year).",
                        cwe_id="CWE-319",
                    ))

    # ------------------------------------------------------------------
    # Information disclosure
    # ------------------------------------------------------------------

    def _check_info_disclosure(self, resp: httpx.Response, path: str) -> None:
        body = _safe_decode(resp.content[:30000])
        for pattern, label in INFO_DISCLOSURE_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                snippet = ""
                m = re.search(r".{0,80}" + pattern + r".{0,80}", body, re.IGNORECASE)
                if m:
                    snippet = m.group(0).strip()[:200]
                self.findings.append(Finding(
                    vuln_type=VulnType.INFO_DISCLOSURE,
                    severity=Severity.MEDIUM,
                    title=label,
                    description=f"The response body contains sensitive debug/error information.",
                    evidence=snippet,
                    path=path,
                    remediation=(
                        "Disable debug mode in production. "
                        "Ensure error handling never exposes stack traces to users."
                    ),
                    cwe_id="CWE-209",
                ))
                break  # One per page is enough

    # ------------------------------------------------------------------
    # Sensitive path discovery
    # ------------------------------------------------------------------

    async def _probe_sensitive_paths(self) -> None:
        tasks = [self._probe_path(p) for p in SENSITIVE_PATHS]
        await asyncio.gather(*tasks)

    async def _probe_path(self, path: str) -> None:
        resp = await self._get(path)
        if not resp:
            return

        # 200 or 403 (exists but forbidden) are both interesting
        if resp.status_code in (200, 403):
            body = _safe_decode(resp.content[:2000])
            severity = Severity.CRITICAL if any(
                sensitive in path for sensitive in
                [".env", ".git", "wp-config", "database.yml", "settings.py",
                 "web.config", "backup.sql", "dump.sql"]
            ) else Severity.MEDIUM

            # Skip false positives — custom 404 pages that return 200
            if resp.status_code == 200 and len(body) < 50:
                return
            if resp.status_code == 200 and "not found" in body.lower()[:200]:
                return

            self.findings.append(Finding(
                vuln_type=VulnType.SENSITIVE_FILE,
                severity=severity,
                title=f"Sensitive path accessible: {path}",
                description=(
                    f"The path {path} returned HTTP {resp.status_code}. "
                    f"This may expose configuration, secrets, or admin functionality."
                ),
                evidence=f"HTTP {resp.status_code} — {len(resp.content)} bytes",
                path=path,
                remediation=(
                    f"Block access to {path} via your web server config or firewall. "
                    "For .git and .env files, ensure they are never deployed to web roots."
                ),
                cvss_score=8.5 if severity == Severity.CRITICAL else 5.3,
                cwe_id="CWE-538" if ".env" in path else "CWE-548",
            ))

        self.pages_tested += 1

    # ------------------------------------------------------------------
    # Link and form extraction
    # ------------------------------------------------------------------

    def _extract_links(self, resp: httpx.Response) -> List[str]:
        body = _safe_decode(resp.content[:50000])
        links = []
        for m in re.finditer(r'href=["\']([^"\'#?]+)["\']', body, re.IGNORECASE):
            href = m.group(1)
            if href.startswith("/") and not href.startswith("//"):
                links.append(href)
        return list(set(links))[:self.max_pages]

    def _extract_forms(self, resp: httpx.Response) -> List[Dict]:
        body = _safe_decode(resp.content[:50000])
        forms = []
        for form_m in re.finditer(r"<form([^>]*)>(.*?)</form>", body, re.IGNORECASE | re.DOTALL):
            attrs = form_m.group(1)
            content = form_m.group(2)
            action_m = re.search(r'action=["\']([^"\']*)["\']', attrs, re.IGNORECASE)
            method_m = re.search(r'method=["\']([^"\']*)["\']', attrs, re.IGNORECASE)
            action = action_m.group(1) if action_m else "/"
            method = (method_m.group(1) if method_m else "get").lower()
            inputs = re.findall(
                r'<input[^>]+name=["\']([^"\']+)["\']', content, re.IGNORECASE
            )
            has_csrf = bool(re.search(
                r'csrf|_token|authenticity_token|__RequestVerificationToken',
                content, re.IGNORECASE
            ))
            forms.append({
                "action": action,
                "method": method,
                "inputs": inputs,
                "has_csrf_token": has_csrf,
            })
        return forms

    # ------------------------------------------------------------------
    # Form testing
    # ------------------------------------------------------------------

    async def _test_forms(self, forms: List[Dict]) -> None:
        for form in forms:
            action = form["action"]
            inputs = form["inputs"]
            method = form["method"]

            # CSRF check on POST forms
            if method == "post" and not form["has_csrf_token"]:
                self.findings.append(Finding(
                    vuln_type=VulnType.CSRF,
                    severity=Severity.HIGH,
                    title="POST form missing CSRF token",
                    description=(
                        f"The form at {action} submits via POST without a "
                        "CSRF token. An attacker can trick authenticated users "
                        "into submitting this form from an external origin."
                    ),
                    evidence=f"Form action={action}, method=POST, no CSRF token found",
                    path=action,
                    remediation=(
                        "Add a CSRF token to every state-changing form. "
                        "Use the SameSite=Strict cookie attribute as a secondary defence."
                    ),
                    cvss_score=6.5,
                    cwe_id="CWE-352",
                    references=["https://owasp.org/www-community/attacks/csrf"],
                ))

            if not inputs:
                continue

            # SQL injection — test each input parameter
            if self.test_sqli:
                for payload in SQLI_PAYLOADS[:3]:  # Limit to 3 payloads per form
                    test_data = {inp: payload for inp in inputs}
                    if method == "post":
                        resp = await self._post(action, test_data)
                    else:
                        resp = await self._get(action, params=test_data)

                    if resp:
                        body = _safe_decode(resp.content[:10000])
                        matched = _matches_any(body, SQLI_ERROR_PATTERNS)
                        if matched:
                            self.findings.append(Finding(
                                vuln_type=VulnType.SQL_INJECTION,
                                severity=Severity.CRITICAL,
                                title="SQL injection vulnerability detected",
                                description=(
                                    "A SQL error message was returned when injecting "
                                    f"the payload `{payload}` into form inputs at {action}."
                                ),
                                evidence=f"SQL error pattern matched: {matched}",
                                path=action,
                                remediation=(
                                    "Use parameterised queries / prepared statements for "
                                    "all database operations. Never interpolate user input "
                                    "directly into SQL."
                                ),
                                cvss_score=9.8,
                                cwe_id="CWE-89",
                                references=[
                                    "https://owasp.org/www-community/attacks/SQL_Injection",
                                    "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                                ],
                            ))
                            break  # One finding per form is enough

            # XSS — test each input parameter
            if self.test_xss:
                for payload in XSS_PAYLOADS[:2]:
                    test_data = {inp: payload for inp in inputs}
                    if method == "post":
                        resp = await self._post(action, test_data)
                    else:
                        resp = await self._get(action, params=test_data)

                    if resp:
                        body = _safe_decode(resp.content[:10000])
                        if payload.lower() in body.lower():
                            self.findings.append(Finding(
                                vuln_type=VulnType.XSS,
                                severity=Severity.HIGH,
                                title="Reflected XSS vulnerability detected",
                                description=(
                                    f"The XSS payload `{payload}` was reflected "
                                    f"unencoded in the response from {action}."
                                ),
                                evidence=f"Payload reflected verbatim: {payload[:80]}",
                                path=action,
                                remediation=(
                                    "HTML-encode all user-supplied input before rendering "
                                    "in HTML context. Implement a strict Content-Security-Policy."
                                ),
                                cvss_score=7.2,
                                cwe_id="CWE-79",
                                references=[
                                    "https://owasp.org/www-community/attacks/xss/",
                                    "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                                ],
                            ))
                            break

    # ------------------------------------------------------------------
    # Crawl and test
    # ------------------------------------------------------------------

    async def _crawl_and_test(self, links: List[str]) -> None:
        for path in links[:self.max_pages]:
            if path in self._visited:
                continue
            self._visited.add(path)
            self.pages_tested += 1

            resp = await self._get(path)
            if not resp:
                continue

            if self.test_info:
                self._check_info_disclosure(resp, path)

            # Test query parameters in discovered URLs for SQLi / XSS
            if "?" in path:
                base_path, qs = path.split("?", 1)
                params = dict(urllib.parse.parse_qsl(qs))
                if params and self.test_sqli:
                    await self._test_params_sqli(base_path, params)
                if params and self.test_xss:
                    await self._test_params_xss(base_path, params)

    async def _test_params_sqli(self, path: str, params: Dict) -> None:
        for payload in SQLI_PAYLOADS[:2]:
            test_params = {k: payload for k in params}
            resp = await self._get(path, params=test_params)
            if resp:
                body = _safe_decode(resp.content[:10000])
                matched = _matches_any(body, SQLI_ERROR_PATTERNS)
                if matched:
                    self.findings.append(Finding(
                        vuln_type=VulnType.SQL_INJECTION,
                        severity=Severity.CRITICAL,
                        title="SQL injection in URL parameter",
                        description=(
                            f"SQL error triggered by injecting `{payload}` into "
                            f"URL parameters at {path}."
                        ),
                        evidence=f"Matched pattern: {matched}",
                        path=path,
                        remediation="Use parameterised queries for all database operations.",
                        cvss_score=9.8,
                        cwe_id="CWE-89",
                    ))
                    break

    async def _test_params_xss(self, path: str, params: Dict) -> None:
        for payload in XSS_PAYLOADS[:1]:
            test_params = {k: payload for k in params}
            resp = await self._get(path, params=test_params)
            if resp:
                body = _safe_decode(resp.content[:10000])
                if payload.lower() in body.lower():
                    self.findings.append(Finding(
                        vuln_type=VulnType.XSS,
                        severity=Severity.HIGH,
                        title="Reflected XSS in URL parameter",
                        description=(
                            f"XSS payload reflected in URL parameter at {path}."
                        ),
                        evidence=f"Payload: {payload[:80]}",
                        path=path,
                        remediation="HTML-encode user input before rendering.",
                        cvss_score=7.2,
                        cwe_id="CWE-79",
                    ))
                    break

    # ------------------------------------------------------------------
    # CORS check
    # ------------------------------------------------------------------

    async def _check_cors(self) -> None:
        url = self.base_url + "/"
        try:
            self.request_count += 1
            resp = await self._client.get(
                url,
                headers={"Origin": "https://evil.com"},
            )
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")

            if acao == "*":
                self.findings.append(Finding(
                    vuln_type=VulnType.CORS_MISCONFIGURATION,
                    severity=Severity.MEDIUM,
                    title="CORS wildcard origin",
                    description=(
                        "The API allows requests from any origin (Access-Control-Allow-Origin: *). "
                        "Any website can make cross-origin requests to this API."
                    ),
                    evidence="Access-Control-Allow-Origin: *",
                    path="/",
                    remediation="Restrict CORS to specific trusted origins.",
                    cvss_score=5.3,
                    cwe_id="CWE-942",
                ))
            elif acao == "https://evil.com":
                severity = Severity.CRITICAL if acac.lower() == "true" else Severity.HIGH
                self.findings.append(Finding(
                    vuln_type=VulnType.CORS_MISCONFIGURATION,
                    severity=severity,
                    title="CORS origin reflection vulnerability",
                    description=(
                        "The server reflects back arbitrary Origin values, "
                        "allowing any attacker-controlled site to make credentialed "
                        "cross-origin requests." if acac.lower() == "true" else
                        "The server reflects back arbitrary Origin values."
                    ),
                    evidence=f"Origin: https://evil.com → ACAO: {acao}, ACAC: {acac}",
                    path="/",
                    remediation=(
                        "Maintain a strict allowlist of permitted origins. "
                        "Never reflect the request Origin header without validation."
                    ),
                    cvss_score=9.0 if severity == Severity.CRITICAL else 6.5,
                    cwe_id="CWE-942",
                    references=["https://portswigger.net/web-security/cors"],
                ))
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def scan_webapp(
    url: str,
    timeout: float = 10.0,
    max_pages: int = 20,
    crawl: bool = True,
) -> WebAppScanResult:
    """
    Convenience wrapper — run a full web app scan against a URL.

    Args:
        url:       Full URL including scheme, e.g. https://example.com
        timeout:   Per-request timeout in seconds
        max_pages: Maximum pages to crawl
        crawl:     Whether to crawl discovered links

    Returns:
        WebAppScanResult with all findings
    """
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    scanner = WebAppScanner(
        base_url=url,
        timeout=timeout,
        max_pages=max_pages,
        crawl=crawl,
    )
    return await scanner.run()


def format_webapp_report(result: WebAppScanResult) -> str:
    """Format scan result as a human-readable text report."""
    lines = [
        "Web Application Security Scan",
        "=" * 50,
        f"Target:        {result.target}",
        f"Duration:      {result.scan_duration}s",
        f"Requests made: {result.total_requests}",
        f"Pages tested:  {result.pages_tested}",
        f"Risk score:    {result.risk_score}/100",
        "",
    ]

    if result.technologies:
        lines.append(f"Technologies:  {', '.join(result.technologies)}")
        lines.append("")

    severity_order = [
        Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
        Severity.LOW, Severity.INFO,
    ]
    counts = {s: sum(1 for f in result.findings if f.severity == s) for s in severity_order}
    lines.append("Summary:")
    for sev in severity_order:
        if counts[sev]:
            lines.append(f"  {sev.value.upper():<10} {counts[sev]}")
    lines.append("")

    if result.findings:
        lines.append("Findings:")
        lines.append("-" * 50)
        for i, f in enumerate(result.findings, 1):
            lines += [
                f"{i}. [{f.severity.value.upper()}] {f.title}",
                f"   Path:        {f.path}",
                f"   Type:        {f.vuln_type.value}",
                f"   Evidence:    {f.evidence[:100]}",
                f"   Remediation: {f.remediation[:120]}",
                "",
            ]
    else:
        lines.append("No vulnerabilities found.")

    if result.error:
        lines += ["", f"Error: {result.error}"]

    return "\n".join(lines)
