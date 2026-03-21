"""
Tests for the web application vulnerability scanner.

Run with:
    pytest tests/test_webapp_scanner.py -v
"""

import asyncio
import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import respx

from src.cybersec_cli.utils.webapp_scanner import (
    WebAppScanner,
    WebAppScanResult,
    Finding,
    Severity,
    VulnType,
    scan_webapp,
    format_webapp_report,
    SQLI_ERROR_PATTERNS,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

BASE_URL = "http://test.example.com"

SAFE_HTML = """
<html>
<head><title>Test App</title></head>
<body>
  <h1>Welcome</h1>
  <form action="/search" method="get">
    <input name="q" type="text">
    <input type="submit">
  </form>
  <a href="/about">About</a>
  <a href="/contact">Contact</a>
</body>
</html>
"""

HEADERS_SECURE = {
    "Content-Type": "text/html",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
}

HEADERS_INSECURE = {
    "Content-Type": "text/html",
    "Server": "Apache/2.4.41 (Ubuntu)",
    "X-Powered-By": "PHP/7.4.3",
}


# ---------------------------------------------------------------------------
# Unit tests — individual checks
# ---------------------------------------------------------------------------

class TestSecurityHeaderChecks:
    @pytest.mark.asyncio
    async def test_missing_headers_flagged(self):
        with respx.mock:
            respx.get(f"{BASE_URL}/").mock(
                return_value=httpx.Response(200, html=SAFE_HTML, headers=HEADERS_INSECURE)
            )
            # Patch all other paths to 404
            respx.get(url__regex=r".*").mock(return_value=httpx.Response(404))

            scanner = WebAppScanner(BASE_URL, test_sqli=False, test_xss=False, crawl=False)
            result = await scanner.run()

        header_findings = [
            f for f in result.findings if f.vuln_type == VulnType.SECURITY_HEADER
        ]
        header_names = [f.title for f in header_findings]
        assert any("Strict-Transport-Security" in t for t in header_names)
        assert any("Content-Security-Policy" in t for t in header_names)

    @pytest.mark.asyncio
    async def test_secure_headers_not_flagged(self):
        secure_base = "https://test.example.com"
        with respx.mock:
            respx.get(url__regex=r".*").mock(
                return_value=httpx.Response(200, html=SAFE_HTML, headers=HEADERS_SECURE)
            )
            scanner = WebAppScanner(
                secure_base,
                test_sqli=False, test_xss=False, crawl=False, test_paths=False
            )
            result = await scanner.run()

        header_findings = [
            f for f in result.findings if f.vuln_type == VulnType.SECURITY_HEADER
        ]
        assert len(header_findings) == 0

    @pytest.mark.asyncio
    async def test_server_version_disclosure(self):
        with respx.mock:
            respx.get(f"{BASE_URL}/").mock(
                return_value=httpx.Response(
                    200, html=SAFE_HTML,
                    headers={"Server": "nginx/1.18.0", "Content-Type": "text/html"}
                )
            )
            respx.get(url__regex=r".*").mock(return_value=httpx.Response(404))

            scanner = WebAppScanner(BASE_URL, test_sqli=False, test_xss=False, crawl=False)
            result = await scanner.run()

        info_findings = [
            f for f in result.findings if f.vuln_type == VulnType.INFO_DISCLOSURE
        ]
        assert any("server version" in f.title.lower() for f in info_findings)

    @pytest.mark.asyncio
    async def test_x_powered_by_disclosure(self):
        with respx.mock:
            respx.get(f"{BASE_URL}/").mock(
                return_value=httpx.Response(
                    200, html=SAFE_HTML,
                    headers={"X-Powered-By": "PHP/8.1", "Content-Type": "text/html"}
                )
            )
            respx.get(url__regex=r".*").mock(return_value=httpx.Response(404))

            scanner = WebAppScanner(BASE_URL, test_sqli=False, test_xss=False, crawl=False)
            result = await scanner.run()

        info_findings = [f for f in result.findings if f.vuln_type == VulnType.INFO_DISCLOSURE]
        assert any("X-Powered-By" in f.title for f in info_findings)


class TestSQLInjection:
    @pytest.mark.asyncio
    async def test_sqli_error_detected(self):
        sql_error_html = (
            "<html><body>"
            "You have an error in your SQL syntax near '''' at line 1"
            "</body></html>"
        )
        with respx.mock:
            # Specific route must be registered BEFORE the wildcard in respx
            respx.get(url__regex=r".*/search.*").mock(
                return_value=httpx.Response(200, html=sql_error_html)
            )
            respx.get(f"{BASE_URL}/").mock(
                return_value=httpx.Response(200, html=SAFE_HTML, headers=HEADERS_INSECURE)
            )
            respx.get(url__regex=r".*").mock(return_value=httpx.Response(404))
            respx.post(url__regex=r".*").mock(return_value=httpx.Response(200, html="ok"))

            scanner = WebAppScanner(BASE_URL, test_xss=False, crawl=False, test_paths=False)
            result = await scanner.run()

        sqli_findings = [f for f in result.findings if f.vuln_type == VulnType.SQL_INJECTION]
        assert len(sqli_findings) >= 1
        assert sqli_findings[0].severity == Severity.CRITICAL
        assert sqli_findings[0].cvss_score == 9.8

    @pytest.mark.asyncio
    async def test_no_sqli_on_clean_response(self):
        with respx.mock:
            respx.get(url__regex=r".*").mock(
                return_value=httpx.Response(200, html="<html><body>Normal response</body></html>")
            )

            scanner = WebAppScanner(BASE_URL, test_xss=False, crawl=False)
            result = await scanner.run()

        sqli_findings = [f for f in result.findings if f.vuln_type == VulnType.SQL_INJECTION]
        assert len(sqli_findings) == 0


class TestXSS:
    @pytest.mark.asyncio
    async def test_reflected_xss_detected(self):
        xss_payload = "<script>alert(1)</script>"
        reflected_html = f"<html><body>You searched for: {xss_payload}</body></html>"

        with respx.mock:
            respx.get(url__regex=r".*/search.*").mock(
                return_value=httpx.Response(200, html=reflected_html)
            )
            respx.get(f"{BASE_URL}/").mock(
                return_value=httpx.Response(200, html=SAFE_HTML)
            )
            respx.get(url__regex=r".*").mock(return_value=httpx.Response(404))
            respx.post(url__regex=r".*").mock(return_value=httpx.Response(200, html="ok"))

            scanner = WebAppScanner(BASE_URL, test_sqli=False, crawl=False, test_paths=False)
            result = await scanner.run()

        xss_findings = [f for f in result.findings if f.vuln_type == VulnType.XSS]
        assert len(xss_findings) >= 1
        assert xss_findings[0].severity == Severity.HIGH


class TestCSRF:
    @pytest.mark.asyncio
    async def test_post_form_without_csrf_token_flagged(self):
        html_with_post_form = """
        <html><body>
        <form action="/delete" method="post">
          <input name="id" type="hidden" value="123">
          <input type="submit" value="Delete">
        </form>
        </body></html>
        """
        with respx.mock:
            respx.get(f"{BASE_URL}/").mock(
                return_value=httpx.Response(200, html=html_with_post_form)
            )
            respx.post(url__regex=r".*").mock(return_value=httpx.Response(200, html="ok"))
            respx.get(url__regex=r".*").mock(return_value=httpx.Response(404))

            scanner = WebAppScanner(BASE_URL, test_sqli=False, test_xss=False, crawl=False, test_paths=False)
            result = await scanner.run()

        csrf_findings = [f for f in result.findings if f.vuln_type == VulnType.CSRF]
        assert len(csrf_findings) >= 1
        assert csrf_findings[0].severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_post_form_with_csrf_token_not_flagged(self):
        html_with_csrf = """
        <html><body>
        <form action="/delete" method="post">
          <input name="_token" type="hidden" value="abc123">
          <input name="id" type="hidden" value="123">
          <input type="submit" value="Delete">
        </form>
        </body></html>
        """
        with respx.mock:
            respx.get(f"{BASE_URL}/").mock(
                return_value=httpx.Response(200, html=html_with_csrf)
            )
            respx.post(url__regex=r".*").mock(return_value=httpx.Response(200, html="ok"))
            respx.get(url__regex=r".*").mock(return_value=httpx.Response(404))

            scanner = WebAppScanner(BASE_URL, test_sqli=False, test_xss=False, crawl=False)
            result = await scanner.run()

        csrf_findings = [f for f in result.findings if f.vuln_type == VulnType.CSRF]
        assert len(csrf_findings) == 0


class TestSensitivePaths:
    @pytest.mark.asyncio
    async def test_env_file_exposure_critical(self):
        with respx.mock:
            respx.get(f"{BASE_URL}/").mock(
                return_value=httpx.Response(200, html=SAFE_HTML)
            )
            respx.get(f"{BASE_URL}/.env").mock(
                return_value=httpx.Response(
                    200,
                    text="DB_PASSWORD=supersecret\nAPI_KEY=abc123\nSECRET_KEY=xyz789",
                    headers={"Content-Type": "text/plain"},
                )
            )
            respx.get(url__regex=r".*").mock(return_value=httpx.Response(404))

            scanner = WebAppScanner(BASE_URL, test_sqli=False, test_xss=False, crawl=False)
            result = await scanner.run()

        env_findings = [
            f for f in result.findings
            if f.vuln_type == VulnType.SENSITIVE_FILE and ".env" in f.path
        ]
        assert len(env_findings) >= 1
        assert env_findings[0].severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_git_config_exposure(self):
        with respx.mock:
            respx.get(f"{BASE_URL}/").mock(
                return_value=httpx.Response(200, html=SAFE_HTML)
            )
            respx.get(f"{BASE_URL}/.git/config").mock(
                return_value=httpx.Response(
                    200,
                    text="[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = https://github.com/user/secret-repo",
                )
            )
            respx.get(url__regex=r".*").mock(return_value=httpx.Response(404))

            scanner = WebAppScanner(BASE_URL, test_sqli=False, test_xss=False, crawl=False)
            result = await scanner.run()

        git_findings = [
            f for f in result.findings
            if f.vuln_type == VulnType.SENSITIVE_FILE and ".git" in f.path
        ]
        assert len(git_findings) >= 1


class TestCORS:
    @pytest.mark.asyncio
    async def test_cors_wildcard_detected(self):
        with respx.mock:
            respx.get(url__regex=r".*").mock(
                return_value=httpx.Response(
                    200, html=SAFE_HTML,
                    headers={"Access-Control-Allow-Origin": "*"}
                )
            )

            scanner = WebAppScanner(BASE_URL, test_sqli=False, test_xss=False, crawl=False, test_paths=False)
            result = await scanner.run()

        cors_findings = [f for f in result.findings if f.vuln_type == VulnType.CORS_MISCONFIGURATION]
        assert len(cors_findings) >= 1

    @pytest.mark.asyncio
    async def test_cors_reflection_detected(self):
        with respx.mock:
            respx.get(url__regex=r".*").mock(
                return_value=httpx.Response(
                    200, html=SAFE_HTML,
                    headers={
                        "Access-Control-Allow-Origin": "https://evil.com",
                        "Access-Control-Allow-Credentials": "true",
                    }
                )
            )

            scanner = WebAppScanner(BASE_URL, test_sqli=False, test_xss=False, crawl=False, test_paths=False)
            result = await scanner.run()

        cors_findings = [f for f in result.findings if f.vuln_type == VulnType.CORS_MISCONFIGURATION]
        assert any(f.severity == Severity.CRITICAL for f in cors_findings)


class TestInformationDisclosure:
    @pytest.mark.asyncio
    async def test_stack_trace_detected(self):
        stack_trace_html = """
        <html><body>
        Internal Server Error
        Traceback (most recent call last):
          File "/app/views.py", line 42, in get_user
            user = User.objects.get(id=user_id)
        django.core.exceptions.ObjectDoesNotExist: User matching query does not exist.
        </body></html>
        """
        with respx.mock:
            respx.get(f"{BASE_URL}/").mock(
                return_value=httpx.Response(200, html=stack_trace_html)
            )
            respx.get(url__regex=r".*").mock(return_value=httpx.Response(404))

            scanner = WebAppScanner(BASE_URL, test_sqli=False, test_xss=False, crawl=False, test_paths=False)
            result = await scanner.run()

        info_findings = [f for f in result.findings if f.vuln_type == VulnType.INFO_DISCLOSURE]
        assert len(info_findings) >= 1


# ---------------------------------------------------------------------------
# Integration-style tests
# ---------------------------------------------------------------------------

class TestRiskScore:
    def test_risk_score_with_critical_findings(self):
        result = WebAppScanResult(
            target="http://example.com",
            base_url="http://example.com",
            scan_duration=1.5,
            pages_tested=5,
            total_requests=20,
            findings=[
                Finding(VulnType.SQL_INJECTION, Severity.CRITICAL, "SQLi", "", "", "/", ""),
                Finding(VulnType.XSS, Severity.HIGH, "XSS", "", "", "/search", ""),
            ],
            technologies=["WordPress"],
            forms_found=2,
        )
        assert result.risk_score == min(100, 40 + 20)
        assert result.critical_count == 1
        assert result.high_count == 1

    def test_risk_score_clean_target(self):
        result = WebAppScanResult(
            target="http://example.com",
            base_url="http://example.com",
            scan_duration=1.0,
            pages_tested=3,
            total_requests=10,
            findings=[],
            technologies=[],
            forms_found=0,
        )
        assert result.risk_score == 0


class TestFormatReport:
    def test_format_with_findings(self):
        result = WebAppScanResult(
            target="http://example.com",
            base_url="http://example.com",
            scan_duration=2.3,
            pages_tested=8,
            total_requests=35,
            findings=[
                Finding(
                    vuln_type=VulnType.SQL_INJECTION,
                    severity=Severity.CRITICAL,
                    title="SQL injection in /search",
                    description="SQL error returned",
                    evidence="you have an error in your sql syntax",
                    path="/search",
                    remediation="Use parameterised queries.",
                    cvss_score=9.8,
                    cwe_id="CWE-89",
                )
            ],
            technologies=["PHP", "MySQL"],
            forms_found=1,
        )
        report = format_webapp_report(result)
        assert "SQL injection" in report
        assert "CRITICAL" in report
        assert "9.8" not in report  # CVSS not in text report by design
        assert "http://example.com" in report

    def test_format_clean_target(self):
        result = WebAppScanResult(
            target="http://clean.example.com",
            base_url="http://clean.example.com",
            scan_duration=1.0,
            pages_tested=3,
            total_requests=15,
            findings=[],
            technologies=[],
            forms_found=0,
        )
        report = format_webapp_report(result)
        assert "No vulnerabilities found" in report


class TestURLValidation:
    def test_private_ip_blocked(self):
        from pydantic import ValidationError
        from web.routes.webapp_scanner import WebAppScanRequest

        with pytest.raises(ValidationError):
            WebAppScanRequest(url="http://192.168.1.1/")

        with pytest.raises(ValidationError):
            WebAppScanRequest(url="http://127.0.0.1/")

        with pytest.raises(ValidationError):
            WebAppScanRequest(url="http://10.0.0.1/")

    def test_scheme_added_automatically(self):
        from web.routes.webapp_scanner import WebAppScanRequest
        req = WebAppScanRequest(url="example.com")
        assert req.url.startswith("https://")

    def test_valid_public_url(self):
        from web.routes.webapp_scanner import WebAppScanRequest
        req = WebAppScanRequest(url="https://example.com")
        assert req.url == "https://example.com"
