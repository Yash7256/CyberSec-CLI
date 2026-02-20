"""
Vulnerability Correlation Engine.
Detects dangerous port combinations and attack chains.
"""

from dataclasses import dataclass
from typing import Dict, List, Set, FrozenSet, Optional
from enum import Enum


class RiskLevel(Enum):
    """Risk severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class ComboRisk:
    """Represents a dangerous port combination."""
    name: str
    risk: RiskLevel
    description: str
    mitigation: str
    cve_correlations: List[str]


# Define dangerous port combinations
# These are based on common attack chains and exposure patterns
COMBO_RISKS = {
    frozenset({22, 3306}): ComboRisk(
        name="SSH + MySQL Exposed",
        risk=RiskLevel.HIGH,
        description="Both SSH and MySQL are exposed. This allows remote shell access + direct database access, enabling full system compromise.",
        mitigation="1. Restrict MySQL to localhost or VPN-only\n2. Use SSH key-based auth only\n3. Implement fail2ban for SSH\n4. Use MySQL connection encryption",
        cve_correlations=["CVE-2023-XXXX", "CVE-2022-XXXX"]
    ),
    frozenset({21, 23}): ComboRisk(
        name="FTP + Telnet (Plaintext)",
        risk=RiskLevel.CRITICAL,
        description="Both FTP and Telnet transmit credentials in plaintext. Attackers can easily intercept and reuse these credentials.",
        mitigation="1. Disable FTP and Telnet immediately\n2. Use SFTP and SSH instead\n3. Implement network segmentation",
        cve_correlations=["CVE-2021-XXXX"]
    ),
    frozenset({445, 3389}): ComboRisk(
        name="SMB + RDP Exposed",
        risk=RiskLevel.CRITICAL,
        description="Classic ransomware attack surface. SMB for lateral movement + RDP for remote access = full network encryption.",
        mitigation="1. Disable SMB if not needed\n2. Restrict RDP to VPN only\n3. Enable NLA for RDP\n4. Implement network segmentation",
        cve_correlations=["CVE-2020-XXXX", "CVE-2021-XXXX"]
    ),
    frozenset({6379}): ComboRisk(
        name="Redis Exposed",
        risk=RiskLevel.HIGH,
        description="Redis with no authentication allows RCE via config manipulation and Lua script execution.",
        mitigation="1. Enable Redis authentication\n2. Bind to localhost only\n3. Disable dangerous commands (CONFIG, FLUSHALL, etc.)\n4. Use TLS for Redis connections",
        cve_correlations=["CVE-2022-XXXX"]
    ),
    frozenset({27017}): ComboRisk(
        name="MongoDB Exposed",
        risk=RiskLevel.HIGH,
        description="MongoDB without authentication allows full data exfiltration and potential RCE.",
        mitigation="1. Enable MongoDB authentication\n2. Bind to localhost only\n3. Use TLS encryption\n4. Implement network access controls",
        cve_correlations=["CVE-2021-XXXX"]
    ),
    frozenset({5432, 5432}): ComboRisk(
        name="PostgreSQL Exposed",
        risk=RiskLevel.HIGH,
        description="PostgreSQL with weak or no authentication allows data theft and potential OS command execution.",
        mitigation="1. Enable PostgreSQL authentication\n2. Use scram-sha-256 or cert auth\n3. Restrict via pg_hba.conf\n4. Use TLS for all connections",
        cve_correlations=["CVE-2020-XXXX"]
    ),
    frozenset({9200, 9300}): ComboRisk(
        name="Elasticsearch Exposed",
        risk=RiskLevel.HIGH,
        description="Elasticsearch without X-Pack security allows full data access and potential RCE via scripts.",
        mitigation="1. Enable X-Pack security\n2. Use TLS encryption\n3. Implement index access controls\n4. Disable dynamic scripting",
        cve_correlations=["CVE-2021-XXXX"]
    ),
    frozenset({80, 443, 8080}): ComboRisk(
        name="Multiple HTTP Services",
        risk=RiskLevel.MEDIUM,
        description="Multiple HTTP services may indicate load balancers, reverse proxies, or misconfigurations that could be exploited.",
        mitigation="1. Consolidate to single entry point\n2. Implement proper load balancing\n3. Use WAF in front of all HTTP services",
        cve_correlations=[]
    ),
    frozenset({21, 20, 22}): ComboRisk(
        name="FTP + SSH + Data Transfer",
        risk=RiskLevel.MEDIUM,
        description="Multiple file transfer protocols exposed. FTP is plaintext, increasing data exfiltration risk.",
        mitigation="1. Disable FTP entirely\n2. Use SFTP only\n3. Implement file integrity monitoring",
        cve_correlations=[]
    ),
    frozenset({25, 587, 465}): ComboRisk(
        name="Multiple Email Services",
        risk=RiskLevel.MEDIUM,
        description="Multiple SMTP ports exposed. Could indicate misconfiguration or open relay risk.",
        mitigation="1. Consolidate to submission port (587)\n2. Enable SMTP authentication\n3. Implement TLS required\n4. Configure SPF/DKIM/DMARC",
        cve_correlations=[]
    ),
    frozenset({3389}): ComboRisk(
        name="RDP Exposed",
        risk=RiskLevel.HIGH,
        description="Direct RDP exposure to internet. Primary target for ransomware and brute force attacks.",
        mitigation="1. Restrict to VPN only\n2. Enable Network Level Authentication\n3. Use RDP Gateway\n4. Implement account lockout policies",
        cve_correlations=["CVE-2022-XXXX"]
    ),
    frozenset({5900}): ComboRisk(
        name="VNC Exposed",
        risk=RiskLevel.HIGH,
        description="VNC typically transmits unencrypted. High risk of credential theft and session hijacking.",
        mitigation="1. Disable VNC if possible\n2. Use VPN only\n3. Prefer RDP over VNC\n4. If required, use encrypted tunneling",
        cve_correlations=[]
    ),
    frozenset({1433}): ComboRisk(
        name="MSSQL Exposed",
        risk=RiskLevel.HIGH,
        description="Microsoft SQL Server exposed. High-value target for data theft and ransomware.",
        mitigation="1. Enable SQL Server authentication\n2. Use TLS for all connections\n3. Restrict via firewall\n4. Implement least privilege",
        cve_correlations=["CVE-2021-XXXX"]
    ),
    frozenset({5000, 5001}): ComboRisk(
        name="Docker API/REST Exposed",
        risk=RiskLevel.CRITICAL,
        description="Docker API exposed without authentication allows complete container escape and host compromise.",
        mitigation="1. Never expose Docker API to internet\n2. Use Docker socket mounting carefully\n3. Enable Docker authorization\n4. Use TLS with client certificates",
        cve_correlations=["CVE-2022-XXXX"]
    ),
    frozenset({11211}): ComboRisk(
        name="Memcached Exposed",
        risk=RiskLevel.HIGH,
        description="Memcached without authentication allows data theft and potential DDoS amplification.",
        mitigation="1. Bind to localhost only\n2. Enable authentication if supported\n3. Disable UDP if not needed\n4. Implement network segmentation",
        cve_correlations=["CVE-2020-XXXX"]
    ),
    frozenset({27018, 27019}): ComboRisk(
        name="MongoDB Sharding Exposed",
        risk=RiskLevel.HIGH,
        description="MongoDB sharded cluster ports exposed. High risk of data theft and cluster compromise.",
        mitigation="1. Enable MongoDB security\n2. Use TLS everywhere\n3. Implement auth on all cluster members\n4. Network segment cluster ports",
        cve_correlations=[]
    ),
    frozenset({2375, 2376}): ComboRisk(
        name="Docker Swarm Exposed",
        risk=RiskLevel.CRITICAL,
        description="Docker Swarm management ports exposed. Allows full container cluster compromise.",
        mitigation="1. Never expose to internet\n2. Use TLS with mutual auth\n3. Implement network policies\n4. Use private networks only",
        cve_correlations=[]
    ),
    frozenset({6443, 8443}): ComboRisk(
        name="Kubernetes API Exposed",
        risk=RiskLevel.CRITICAL,
        description="Kubernetes API server exposed. Allows full cluster takeover if unauthorized.",
        mitigation="1. Never expose to internet\n2. Enable RBAC\n3. Use API server authentication\n4. Implement network policies",
        cve_correlations=["CVE-2021-XXXX"]
    ),
}


# Individual high-risk ports that don't require combination
HIGH_RISK_PORTS = {
    22: RiskLevel.HIGH,
    23: RiskLevel.HIGH,
    3389: RiskLevel.HIGH,
    5900: RiskLevel.HIGH,
    6379: RiskLevel.HIGH,
    27017: RiskLevel.HIGH,
    5000: RiskLevel.HIGH,
    11211: RiskLevel.HIGH,
    9200: RiskLevel.MEDIUM,
}


def find_combo_risks(open_ports: List[int]) -> List[ComboRisk]:
    """Find dangerous combinations in a list of open ports.
    
    Args:
        open_ports: List of open port numbers
        
    Returns:
        List of ComboRisk objects for detected dangerous combinations
    """
    port_set = set(open_ports)
    detected_risks = []
    
    # Check each known dangerous combination
    for combo_ports, risk_info in COMBO_RISKS.items():
        # For single ports that are always risky
        if len(combo_ports) == 1:
            port = next(iter(combo_ports))
            if port in port_set and port not in [22, 21, 445, 3389]:  # Skip common ones
                # Only add if it's one of the specific single-port risks
                if risk_info.risk in [RiskLevel.CRITICAL, RiskLevel.HIGH]:
                    detected_risks.append(risk_info)
        else:
            # For combinations, check if all ports in combo are present
            if combo_ports.issubset(port_set):
                detected_risks.append(risk_info)
    
    # Also check individual high-risk ports
    for port, risk_level in HIGH_RISK_PORTS.items():
        if port in port_set:
            # Check if we already have this as a combo
            already_detected = False
            for detected in detected_risks:
                if port in COMBO_RISKS and frozenset({port}) == frozenset(COMBO_RISKS.get(frozenset({port}), frozenset())):
                    already_detected = True
                    break
            if not already_detected:
                # Add individual high-risk port as a simple combo
                pass  # Already handled by COMBO_RISKS for critical ones
    
    # Sort by risk level
    risk_order = {RiskLevel.CRITICAL: 0, RiskLevel.HIGH: 1, RiskLevel.MEDIUM: 2, RiskLevel.LOW: 3}
    detected_risks.sort(key=lambda x: risk_order.get(x.risk, 99))
    
    return detected_risks


def calculate_exposure_score(open_ports: List[int]) -> float:
    """Calculate overall exposure score (0-100, higher is worse).
    
    Args:
        open_ports: List of open port numbers
        
    Returns:
        Exposure score from 0 (safe) to 100 (critical)
    """
    port_set = set(open_ports)
    score = 0.0
    
    # Base score for number of open ports
    score += min(len(open_ports) * 2, 20)
    
    # Add risk from combinations
    combo_risks = find_combo_risks(open_ports)
    for risk in combo_risks:
        if risk.risk == RiskLevel.CRITICAL:
            score += 30
        elif risk.risk == RiskLevel.HIGH:
            score += 20
        elif risk.risk == RiskLevel.MEDIUM:
            score += 10
    
    # Add risk from individual high-risk ports
    for port, risk_level in HIGH_RISK_PORTS.items():
        if port in port_set:
            if risk_level == RiskLevel.HIGH:
                score += 10
    
    return min(score, 100)


def format_correlation_report(open_ports: List[int]) -> str:
    """Format vulnerability correlation results as a readable report.
    
    Args:
        open_ports: List of open port numbers
        
    Returns:
        Formatted report string
    """
    combo_risks = find_combo_risks(open_ports)
    exposure_score = calculate_exposure_score(open_ports)
    
    lines = [
        f"Vulnerability Correlation Analysis",
        f"=" * 40,
        f"Open Ports: {', '.join(map(str, sorted(open_ports)))}",
        f"Exposure Score: {exposure_score:.0f}/100",
        "",
    ]
    
    if not combo_risks:
        lines.append("No dangerous combinations detected.")
        return "\n".join(lines)
    
    lines.append(f"Detected Risks: {len(combo_risks)}")
    lines.append("")
    
    for i, risk in enumerate(combo_risks, 1):
        lines.append(f"{i}. [{risk.risk.value}] {risk.name}")
        lines.append(f"   {risk.description}")
        lines.append(f"   Mitigation:")
        for line in risk.mitigation.split('\n'):
            lines.append(f"     {line}")
        if risk.cve_correlations:
            lines.append(f"   Related CVEs: {', '.join(risk.cve_correlations)}")
        lines.append("")
    
    return "\n".join(lines)
