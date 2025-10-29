"""
Analyzes port scan results to identify potential security issues.
"""
from typing import List, Dict, Any, Optional
from cybersec_cli.tools.network.port_scanner import PortResult

def analyze_port_result(result: PortResult) -> Optional[Dict[str, Any]]:
    """
    Analyzes a single port result and returns a finding if an issue is detected.

    Args:
        result: A PortResult object from the scanner.

    Returns:
        A dictionary representing the finding, or None if no issue is found.
    """
    banner = result.banner or ""

    # --- FTP Analysis (Port 21) ---
    if result.port == 21:
        if "Pure-FTPd" in banner:
            return {
                "port": 21,
                "severity": "Medium",
                "finding": "Information Disclosure & Insecure Protocol",
                "details": "The FTP banner reveals the software (Pure-FTPd) and user limits. FTP transmits credentials and data in cleartext.",
                "recommendation": (
                    "• Disable or customize the welcome banner in the FTP server configuration.\n"
                    "• Strongly consider using SFTP (over SSH) instead of FTP for secure file transfers."
                )
            }

    # --- SSH Analysis (Port 22) ---
    if result.port == 22:
        if "OpenSSH_7.4" in banner:
            return {
                "port": 22,
                "severity": "High",
                "finding": "Outdated Software Version",
                "details": "The banner indicates OpenSSH 7.4 (2016), which has several known vulnerabilities (e.g., CVE-2023-38408, Terrapin attack).",
                "recommendation": (
                    "• Upgrade OpenSSH to the latest stable version (9.7+).\n"
                    "• Implement key-based authentication and disable passwords.\n"
                    "• Use a tool like `fail2ban` to prevent brute-force attacks."
                )
            }

    # --- SMTP Analysis (Port 25) ---
    if result.port == 25 and result.state.value == "open":
        return {
            "port": 25,
            "severity": "Info",
            "finding": "SMTP Port Open",
            "details": "The SMTP port is open. If this server is not intended to be a mail server, this could be an unnecessary exposure.",
            "recommendation": (
                "• If not needed, close this port in your firewall.\n"
                "• If needed, ensure it is properly configured to prevent being an open relay for spam."
            )
        }

    # --- DNS Analysis (Port 53) ---
    if result.port == 53 and result.state.value == "open":
        return {
            "port": 53,
            "severity": "Info",
            "finding": "DNS Port Open",
            "details": "The DNS port is open. Misconfigured DNS servers can be used for amplification attacks.",
            "recommendation": (
                "• If this is not a DNS server, close this port.\n"
                "• If it is, ensure recursion is disabled for untrusted clients and implement rate limiting."
            )
        }

    # --- HTTP Analysis (Port 80) ---
    if result.port == 80 and ("301" in banner or "302" in banner):
        return {
            "port": 80,
            "severity": "Low",
            "finding": "HTTP Redirects to External Domain",
            "details": "The HTTP service redirects to an external domain. This could be a potential security risk if the redirect is not intentional.",
            "recommendation": (
                "• Investigate the redirect to ensure it is legitimate.\n"
                "• Implement HTTPS (port 443) with a proper SSL/TLS certificate and HSTS headers."
            )
        }
    return None



def analyze_scan_results(results: List[PortResult]) -> List[Dict[str, Any]]:
    """
    Analyzes a list of port scan results and returns a list of findings.

    Args:
        results: A list of PortResult objects.

    Returns:
        A list of dictionaries, where each dictionary is a security finding.
    """
    findings = []
    for result in results:
        finding = analyze_port_result(result)
        if finding:
            findings.append(finding)
    return findings