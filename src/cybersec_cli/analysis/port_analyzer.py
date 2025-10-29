"""
Port analysis module for cybersecurity scanning results.
"""
from datetime import datetime
from typing import List, Dict, Any
from dataclasses import dataclass

@dataclass
class PortResult:
    """Data class to store port scan results."""
    port: int
    state: str
    service: str = "unknown"
    version: str = ""
    banner: str = ""

def analyze_scan_results(open_ports: List[PortResult]) -> List[Dict[str, Any]]:
    """
    Analyze port scan results for potential security issues.
    
    Args:
        open_ports: List of PortResult objects from the port scan
        
    Returns:
        List of dictionaries containing security findings
    """
    findings = []
    
    # Enhanced vulnerable ports with detailed security information
    vulnerable_ports = {
        21: {
            "name": "FTP",
            "severity": "High",
            "finding": "FTP service detected",
            "details": "FTP service detected. FTP transmits credentials in plaintext.",
            "impact": "Credentials and data can be intercepted and compromised due to lack of encryption",
            "recommendation": "1. Replace FTP with SFTP or FTPS\n   2. Implement strong access controls\n   3. Enable encryption in transit\n   4. Consider IP whitelisting\n   5. Regular security audits",
            "cvss": {
                "score": 7.5,
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "severity": "High",
                "exploitability": 3.9,
                "impact": 3.6
            },
            "exploitability": {
                "maturity": "Functional",
                "code_available": True,
                "public_exploits": True,
                "ease_of_exploit": "Low"
            },
            "confidence": 0.95,
            "cwe_id": "CWE-319",
            "compliance": ["PCI DSS Req 4.1", "HIPAA Security Rule"],
            "mitre_attack": ["T1040", "T1078"]
        },
        22: {
            "name": "SSH",
            "severity": "Medium",
            "finding": "SSH service detected",
            "details": "SSH service detected. Ensure strong authentication is enforced.",
            "impact": "Potential unauthorized access if not properly configured",
            "recommendation": "1. Use SSH protocol version 2\n   2. Implement key-based authentication\n   3. Disable root login\n   4. Use strong ciphers\n   5. Implement fail2ban",
            "cvss": {
                "score": 5.0,
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                "severity": "Medium",
                "exploitability": 3.9,
                "impact": 1.4
            },
            "exploitability": {
                "maturity": "High",
                "code_available": True,
                "public_exploits": True,
                "ease_of_exploit": "Medium"
            },
            "confidence": 0.98,
            "cwe_id": "CWE-287",
            "compliance": ["NIST SP 800-53: AC-17"],
            "mitre_attack": ["T1110", "T1078"]
        },
        23: {
            "name": "Telnet",
            "severity": "High",
            "finding": "Telnet service detected",
            "details": "Telnet service detected. Telnet transmits data in plaintext.",
            "impact": "All transmitted data can be intercepted and read in clear text",
            "recommendation": "1. Disable Telnet immediately\n   2. Replace with SSH\n   3. Implement secure remote access policies",
            "cvss": {
                "score": 8.0,
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "severity": "High",
                "exploitability": 3.9,
                "impact": 3.6
            },
            "exploitability": {
                "maturity": "Functional",
                "code_available": True,
                "public_exploits": True,
                "ease_of_exploit": "Low"
            },
            "confidence": 0.95,
            "cwe_id": "CWE-319",
            "compliance": ["NIST SP 800-53: SC-8"],
            "mitre_attack": ["T1040", "T1078"]
        },
        53: {
            "name": "DNS",
            "severity": "Low",
            "finding": "DNS service detected",
            "details": "DNS service detected. Consider DNS security measures.",
            "impact": "Potential for DNS-based attacks and information disclosure",
            "recommendation": "1. Implement DNSSEC\n   2. Use DNS filtering\n   3. Regular updates\n   4. Monitor DNS traffic\n   5. Configure proper recursion",
            "cvss": {
                "score": 4.0,
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                "severity": "Low",
                "exploitability": 3.9,
                "impact": 1.4
            },
            "exploitability": {
                "maturity": "High",
                "code_available": True,
                "public_exploits": True,
                "ease_of_exploit": "Medium"
            },
            "confidence": 0.92,
            "cwe_id": "CWE-350",
            "compliance": ["NIST SP 800-53: SC-20,21,22"],
            "mitre_attack": ["T1078", "T1568"]
        },
        80: {
            "name": "HTTP",
            "severity": "Medium",
            "finding": "HTTP service detected",
            "details": "HTTP service detected. Consider enforcing HTTPS.",
            "impact": "Data transmitted in plaintext can be intercepted or modified",
            "recommendation": "1. Implement HTTPS with valid certificates\n   2. Use HTTP Strict Transport Security (HSTS)\n   3. Configure secure headers\n   4. Redirect all HTTP to HTTPS",
            "cvss": {
                "score": 5.5,
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                "severity": "Medium",
                "exploitability": 3.9,
                "impact": 1.4
            },
            "exploitability": {
                "maturity": "High",
                "code_available": True,
                "public_exploits": True,
                "ease_of_exploit": "Medium"
            },
            "confidence": 0.95,
            "cwe_id": "CWE-319",
            "compliance": ["PCI DSS Req 4.1"],
            "mitre_attack": ["T1078", "T1568"]
        },
        443: {
            "name": "HTTPS",
            "severity": "Low",
            "finding": "HTTPS service detected",
            "details": "HTTPS service detected. Verify certificate and configuration.",
            "impact": "Potential for SSL/TLS vulnerabilities if misconfigured",
            "recommendation": "1. Use strong TLS version (1.2+)\n   2. Configure secure cipher suites\n   3. Implement HSTS\n   4. Regular certificate maintenance\n   5. Use CAA records",
            "cvss": {
                "score": 3.5,
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                "severity": "Low",
                "exploitability": 3.9,
                "impact": 1.4
            },
            "exploitability": {
                "maturity": "High",
                "code_available": True,
                "public_exploits": True,
                "ease_of_exploit": "Medium"
            },
            "confidence": 0.92,
            "cwe_id": "CWE-295",
            "compliance": ["PCI DSS Req 4.1"],
            "mitre_attack": ["T1078", "T1568"]
        },
        3306: {
            "name": "MySQL",
            "severity": "High",
            "finding": "MySQL database detected",
            "details": "MySQL database detected. Ensure strong authentication.",
            "impact": "Unauthorized database access and data breach risks",
            "recommendation": "1. Use strong authentication\n   2. Implement network filtering\n   3. Regular security patches\n   4. Encrypt sensitive data\n   5. Audit database access",
            "cvss": {
                "score": 7.0,
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
                "severity": "High",
                "exploitability": 3.9,
                "impact": 3.6
            },
            "exploitability": {
                "maturity": "Functional",
                "code_available": True,
                "public_exploits": True,
                "ease_of_exploit": "Medium"
            },
            "confidence": 0.92,
            "cwe_id": "CWE-306",
            "compliance": ["PCI DSS Req 7", "PCI DSS Req 8"],
            "mitre_attack": ["T1213", "T1078"]
        }
    }
    
    # Process each open port and generate findings
    for port_result in open_ports:
        port = port_result.port
        service = port_result.service.lower()
        
        # Check for known vulnerable ports
        if port in vulnerable_ports:
            finding = vulnerable_ports[port].copy()
            finding["port"] = port
            finding["service"] = port_result.service
            finding["banner"] = port_result.banner
            finding["state"] = port_result.state
            finding["last_updated"] = datetime.utcnow().isoformat()
            findings.append(finding)
        
        # Check for suspicious services on non-standard ports
        elif service != "unknown" and port > 1024 and port not in [3000, 4000, 5000, 8000, 8080, 8443]:
            findings.append({
                "port": port,
                "severity": "Medium",
                "finding": f"Service '{service}' running on non-standard port {port}",
                "details": "Services running on non-standard ports can be a security risk if not properly secured.",
                "recommendation": (
                    f"1. Verify if this service needs to be exposed on port {port}\n"
                    f"2. If legitimate, document the purpose of this service\n"
                    "3. Ensure proper authentication and encryption are in place\n"
                    "4. Consider moving to a standard port if appropriate"
                )
            })
    
    return findings
