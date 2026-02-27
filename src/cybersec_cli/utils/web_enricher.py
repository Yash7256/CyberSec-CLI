"""
Web enrichment utilities for HTTP/HTTPS services.

Performs lightweight, low-impact enrichment:
- HTTP response profile (status, redirects, headers, cache/compression/MIME)
- Security header audit
- Cookie audit
- Favicon hash + simple tech fingerprint
- Basic HTML meta extraction
- Mixed-content / forms-over-HTTP hints
- Robots/sitemap/security.txt presence
- DNS/email hygiene when available (best-effort)
- Optional TLS info comes from existing tls_inspector
"""

import asyncio
import base64
import hashlib
import re
import socket
import time
from typing import Any, Dict, List, Optional, Tuple

import httpx

try:
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:  # optional
    HAS_DNSPYTHON = False

from src.cybersec_cli.utils.http_inspector import (
    parse_headers,
    audit_security_headers,
    parse_cookies,
    HTTPHeaders,
)
try:
    from src.cybersec_cli.utils.tls_inspector import inspect_tls
    HAS_TLS = True
except ImportError:
    HAS_TLS = False


# Small helpers ---------------------------------------------------------

def _strip_html(text: str, limit: int = 5000) -> str:
    # Keep only head portion to avoid huge bodies
    return text[:limit] if text else ""


def _extract_meta(html: str) -> Dict[str, Optional[str]]:
    title_match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    title = title_match.group(1).strip() if title_match else None
    gen_match = re.search(
        r'<meta[^>]+name=["\']generator["\'][^>]*content=["\']([^"\']+)["\']',
        html,
        re.IGNORECASE,
    )
    generator = gen_match.group(1).strip() if gen_match else None
    return {"title": title, "generator": generator}


def _detect_mixed_content(html: str, scheme_https: bool) -> Dict[str, Any]:
    if not scheme_https or not html:
        return {"mixed_content": False, "http_links": 0}
    http_links = len(re.findall(r'http://', html, re.IGNORECASE))
    return {"mixed_content": http_links > 0, "http_links": http_links}


def _detect_forms_over_http(html: str, scheme_https: bool) -> bool:
    if not scheme_https or not html:
        return False
    return bool(re.search(r'<form[^>]+action=["\']http://', html, re.IGNORECASE))


def _fingerprint_tech(headers: HTTPHeaders, favicon_hash: Optional[str]) -> List[str]:
    tech = []
    if headers.server:
        tech.append(headers.server)
    if headers.x_powered_by:
        tech.append(headers.x_powered_by)
    if favicon_hash:
        tech.append(f"favicon:{favicon_hash[:12]}")  # short hash
    return tech


async def _fetch_small(client: httpx.AsyncClient, url: str, timeout: float) -> Tuple[int, Optional[str]]:
    try:
        r = await client.get(url, timeout=timeout)
        if r.status_code < 400 and r.text is not None:
            return r.status_code, r.text[:4096]
        return r.status_code, None
    except Exception:
        return 0, None


def _dns_hygiene(host: str) -> Dict[str, Any]:
    if not HAS_DNSPYTHON:
        return {"available": False}
    res = dns.resolver.Resolver()
    res.lifetime = 3.0
    res.timeout = 2.0
    info: Dict[str, Any] = {"available": True, "mx": [], "spf": None, "dmarc": None, "caa": []}
    try:
        info["mx"] = [str(r.exchange).rstrip(".") for r in res.resolve(host, "MX")]
    except Exception:
        pass
    try:
        txts = [b.decode() if isinstance(b, bytes) else str(b) for b in res.resolve(host, "TXT")]
        for t in txts:
            if t.lower().startswith("v=spf1"):
                info["spf"] = t
                break
    except Exception:
        pass
    try:
        dmarc = f"_dmarc.{host}"
        info["dmarc"] = next(
            (txt.to_text().strip('"') for txt in res.resolve(dmarc, "TXT")), None
        )
    except Exception:
        pass
    try:
        info["caa"] = [str(r.value) for r in res.resolve(host, "CAA")]
    except Exception:
        pass
    return info


# Screenshot helper ----------------------------------------------------

async def _capture_screenshot(url: str, timeout: float = 30.0) -> Dict[str, Any]:
    """Capture a PNG screenshot as base64 using Playwright if installed."""
    try:
        from playwright.sync_api import sync_playwright  # type: ignore
    except ImportError:
        # Try adding local venv site-packages if available
        import sys
        from pathlib import Path

        root = Path(__file__).resolve().parents[3]
        venv_site = root / ".venv" / "lib"
        if venv_site.exists():
            # Pick first pythonX.Y folder
            for p in venv_site.iterdir():
                sp = p / "site-packages"
                if sp.exists():
                    sys.path.append(str(sp))
        try:
            from playwright.sync_api import sync_playwright  # type: ignore
        except Exception:
            return {"error": "playwright not installed"}

    def _run() -> Dict[str, Any]:
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(
                    headless=True,
                    args=[
                        "--no-sandbox",
                        "--disable-setuid-sandbox",
                        "--disable-dev-shm-usage",
                        "--disable-gpu",
                    ],
                )
                page = browser.new_page(viewport={"width": 1280, "height": 720})
                goto_err = None
                try:
                    page.goto(url, wait_until="domcontentloaded", timeout=timeout * 1000)
                except Exception as e:
                    goto_err = str(e)
                    # Best effort: give the page a moment and still grab what rendered
                    page.wait_for_timeout(1500)
                buf = page.screenshot(full_page=True)
                browser.close()
                return {
                    "mime": "image/png",
                    "data_base64": base64.b64encode(buf).decode("ascii"),
                    "error": goto_err,
                }
        except Exception as e:
            return {"error": str(e)}

    return await asyncio.to_thread(_run)


# Main enrichment -------------------------------------------------------

async def enrich_http_site(host: str, port: int, use_https: bool = False, timeout: float = 5.0, screenshot: bool = False) -> Dict[str, Any]:
    """
    Enrich an HTTP/HTTPS endpoint with additional metadata.
    Best-effort; failures are captured in the `error` field.
    """
    scheme = "https" if use_https else "http"
    base_url = f"{scheme}://{host}:{port}"
    result: Dict[str, Any] = {
        "url": base_url,
        "status_code": None,
        "redirects": [],
        "headers": {},
        "tls": None,
        "security_headers_audit": {},
        "cookies": [],
        "compression": None,
        "cache_control": None,
        "etag": None,
        "expires": None,
        "mime": None,
        "content_length": None,
        "ttfb_ms": None,
        "server": None,
        "x_powered_by": None,
        "tech": [],
        "favicon_sha256": None,
        "meta": {},
        "body_preview": None,
        "screenshot": None,
        "mixed_content": False,
        "http_links": 0,
        "forms_over_http": False,
        "gzip": False,
        "brotli": False,
        "robots": None,
        "sitemap": None,
        "security_txt": None,
        "open_redirect": False,
        "dns": _dns_hygiene(host),
        "spf": None,
        "dmarc": None,
        "caa": None,
        "csp_warnings": [],
        "cors_warnings": [],
        "directory_listing": False,
        "ja3": None,
        "jarm": None,
        "vulnerabilities": [],
        "recommendations": [],
        "security_score": 100.0,
    }

    try:
        http_timeout = httpx.Timeout(timeout, connect=timeout, read=timeout, write=timeout)
        async with httpx.AsyncClient(follow_redirects=True, timeout=http_timeout) as client:
            start = time.perf_counter()
            resp = await client.get(base_url, timeout=timeout)
            ttfb_ms = (resp.elapsed.total_seconds() * 1000.0) if resp.elapsed else None
            result.update(
                {
                    "url": str(resp.url),
                    "status_code": resp.status_code,
                    "ttfb_ms": ttfb_ms,
                    "headers": dict(resp.headers),
                    "compression": resp.headers.get("Content-Encoding"),
                    "cache_control": resp.headers.get("Cache-Control"),
                    "etag": resp.headers.get("ETag"),
                    "expires": resp.headers.get("Expires"),
                    "mime": resp.headers.get("Content-Type"),
                    "content_length": int(resp.headers.get("Content-Length"))
                    if resp.headers.get("Content-Length", "").isdigit()
                    else None,
                    "server": resp.headers.get("Server"),
                    "x_powered_by": resp.headers.get("X-Powered-By"),
                    "gzip": "gzip" in (resp.headers.get("Content-Encoding", "") or "").lower(),
                    "brotli": "br" in (resp.headers.get("Content-Encoding", "") or "").lower(),
                }
            )

            # Redirects
            for h in resp.history:
                result["redirects"].append(
                    {"status": h.status_code, "url": str(h.url)}
                )
            if resp.history:
                # open redirect if final host differs
                try:
                    first_host = resp.history[0].url.host
                    final_host = resp.url.host
                    result["open_redirect"] = first_host and final_host and first_host != final_host
                except Exception:
                    pass

            # Security headers audit
            headers = parse_headers([f"{k}: {v}" for k, v in resp.headers.items()])
            audit = audit_security_headers(headers)
            result["security_headers_audit"] = {k: v.value for k, v in audit.items()}
            score = 100.0
            for status in audit.values():
                if status.value == "missing":
                    score -= 10
                elif status.value == "weak":
                    score -= 5
            result["security_score"] = max(0.0, score)

            # CSP / CORS warnings
            csp_val = headers.content_security_policy or ""
            if "unsafe-inline" in csp_val or "unsafe-eval" in csp_val:
                result["csp_warnings"].append("CSP allows unsafe-inline/eval")
            if "http://" in csp_val:
                result["csp_warnings"].append("CSP permits http:// sources")
            acao = headers.access_control_allow_origin or ""
            if acao == "*":
                result["cors_warnings"].append("CORS allows any origin")

            # Cookies
            result["cookies"] = [
                {
                    "name": c.name,
                    "value": c.value[:20] + "..." if len(c.value) > 20 else c.value,
                    "secure": c._raw_cookie.secure if hasattr(c, "_raw_cookie") else False,
                    "http_only": c._raw_cookie.http_only if hasattr(c, "_raw_cookie") else False,
                    "same_site": c._raw_cookie.same_site if hasattr(c, "_raw_cookie") else None,
                }
                for c in resp.cookies.jar
            ]
            # Set-Cookie parsing for flags
            sc_headers = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else resp.headers.get("set-cookie", "")
            if isinstance(sc_headers, str):
                sc_headers = [sc_headers] if sc_headers else []
            result["cookies"].extend([
                {
                    "name": c.name,
                    "value": c.value,
                    "secure": c.secure,
                    "http_only": c.http_only,
                    "same_site": c.same_site,
                    "expires": c.expires,
                }
                for c in parse_cookies(list(sc_headers))
            ])

            # HTML/meta analysis
            body_sample = _strip_html(resp.text)
            meta = _extract_meta(body_sample)
            result["meta"] = meta
            result["body_preview"] = body_sample

            # Mixed content / forms
            mix = _detect_mixed_content(body_sample, scheme_https=use_https)
            result["mixed_content"] = mix["mixed_content"]
            result["http_links"] = mix["http_links"]
            result["forms_over_http"] = _detect_forms_over_http(body_sample, use_https)
            if re.search(r"Index of /", body_sample, re.IGNORECASE):
                result["directory_listing"] = True

            # Favicon hash
            try:
                fav = await client.get(f"{scheme}://{host}:{port}/favicon.ico", timeout=timeout)
                if fav.status_code < 400 and fav.content:
                    result["favicon_sha256"] = hashlib.sha256(fav.content).hexdigest()
            except Exception:
                pass

            # Tech fingerprint
            result["tech"] = _fingerprint_tech(headers, result["favicon_sha256"])

            # Robots / sitemap / security.txt presence
            for path, key in [
                ("/robots.txt", "robots"),
                ("/sitemap.xml", "sitemap"),
                ("/.well-known/security.txt", "security_txt"),
            ]:
                status, snippet = await _fetch_small(client, f"{scheme}://{host}:{port}{path}", timeout=2.0)
                result[key] = status if status else None

            # Capture SPF / DMARC / CAA from DNS hygiene if present
            result["spf"] = result["dns"].get("spf")
            result["dmarc"] = result["dns"].get("dmarc")
            result["caa"] = result["dns"].get("caa")

            # Screenshot (optional)
            if screenshot:
                result["screenshot"] = await _capture_screenshot(result["url"], timeout=timeout)

            # TLS details (best-effort) if HTTPS
            if use_https:
                # If deeper TLS inspector available, use it
                if HAS_TLS:
                    try:
                        tls_info = await inspect_tls(host, port, timeout=timeout)
                        if tls_info and getattr(tls_info, "is_tls", False):
                            cert = tls_info.certificate
                            result["tls"] = {
                                "tls_version": tls_info.tls_version,
                                "cipher_suite": tls_info.cipher_suite,
                                "cipher_strength": tls_info.cipher_strength,
                                "security_score": tls_info.security_score,
                                "warnings": tls_info.warnings,
                                "cert_subject": cert.subject if cert else None,
                                "cert_issuer": cert.issuer if cert else None,
                                "cert_san": cert.san if cert else [],
                                "cert_not_after": cert.not_after.isoformat() if cert else None,
                                "cert_days_until_expiry": cert.days_until_expiry if cert else None,
                                "cert_is_self_signed": cert.is_self_signed if cert else None,
                            }
                        else:
                            result["tls"] = {"error": "TLS inspection failed or not TLS"}
                    except Exception as e:
                        result["tls"] = {"error": str(e)}
                else:
                    try:
                        conn = await client.get(base_url, timeout=timeout)
                        tls = conn.extensions.get("tls") if conn and conn.extensions else None
                        ssl_obj = conn.extensions.get("ssl_object") if conn and conn.extensions else None
                    except Exception:
                        tls = None
                        ssl_obj = None

                    if ssl_obj:
                        try:
                            cipher = ssl_obj.cipher()
                            version = ssl_obj.version()
                            cert = ssl_obj.getpeercert()
                            expiry = cert.get("notAfter") if cert else None
                            result["tls"] = {
                                "tls_version": version,
                                "cipher_suite": cipher[0] if cipher else None,
                                "certificate_expiry": expiry,
                            }
                        except Exception:
                            result["tls"] = {"error": "Failed to read TLS details"}

    except Exception as e:
        result["error"] = repr(e)

    return result
