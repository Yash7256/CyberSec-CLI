"""
TLS/SSL Deep Inspection Module.
Extracts certificate details, TLS version, cipher suites without external dependencies.
"""

import ssl
import socket
import asyncio
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from enum import Enum


class TLSVersion(Enum):
    """TLS protocol versions."""
    SSL_2_0 = "SSL 2.0"
    SSL_3_0 = "SSL 3.0"
    TLS_1_0 = "TLS 1.0"
    TLS_1_1 = "TLS 1.1"
    TLS_1_2 = "TLS 1.2"
    TLS_1_3 = "TLS 1.3"
    UNKNOWN = "Unknown"


class CipherStrength(Enum):
    """Cipher suite strength classification."""
    WEAK = "weak"
    MEDIUM = "medium"
    STRONG = "strong"


@dataclass
class TLSCertificate:
    """TLS certificate information."""
    subject: str
    issuer: str
    san: List[str]  # Subject Alternative Names
    not_before: datetime
    not_after: datetime
    serial_number: str
    signature_algorithm: str
    is_self_signed: bool
    is_wildcard: bool
    days_until_expiry: int
    is_expired: bool


@dataclass
class TLSInfo:
    """Complete TLS inspection result."""
    is_tls: bool
    tls_version: Optional[str]
    cipher_suite: Optional[str]
    cipher_strength: Optional[str]
    certificate: Optional[TLSCertificate]
    warnings: List[str]
    security_score: float  # 0-100


# Weak cipher suites (incomplete list)
WEAK_CIPHERS = [
    r"^TLS_.*_EXPORT_.*",
    r"^TLS_.*_DES_.*",
    r"^SSL_.*_DES_.*",
    r"^TLS_.*_NULL_.*",
    r"^TLS_RSA_.*_MD5",
    r"^TLS_RSA_.*_SHA$",
    r"^TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
    r"^TLS_RSA_WITH_3DES_EDE_CBC_SHA",
]

# Medium cipher suites
MEDIUM_CIPHERS = [
    r"^TLS_.*_RC4_.*",
    r"^TLS_.*_CBC_.*",
]


def parse_dn(dn_string: str) -> Dict[str, str]:
    """Parse a Distinguished Name string into components."""
    result = {}
    parts = dn_string.split(',')
    for part in parts:
        if '=' in part:
            key, value = part.split('=', 1)
            result[key.strip()] = value.strip()
    return result


def check_wildcard(hostname: str, san_list: List[str]) -> bool:
    """Check if any SAN is a wildcard certificate."""
    for san in san_list:
        if san.startswith('*.'):
            base = san[2:]
            if hostname.endswith(base):
                return True
    return False


def assess_cipher_strength(cipher_suite: str) -> CipherStrength:
    """Assess cipher suite strength."""
    if not cipher_suite:
        return CipherStrength.UNKNOWN
    
    for pattern in WEAK_CIPHERS:
        if re.match(pattern, cipher_suite, re.IGNORECASE):
            return CipherStrength.WEAK
    
    for pattern in MEDIUM_CIPHERS:
        if re.match(pattern, cipher_suite, re.IGNORECASE):
            return CipherStrength.MEDIUM
    
    return CipherStrength.STRONG


async def inspect_tls(host: str, port: int, timeout: float = 5.0) -> TLSInfo:
    """Perform deep TLS inspection of a host.
    
    Args:
        host: Target hostname or IP
        port: Target port (usually 443)
        timeout: Connection timeout in seconds
        
    Returns:
        TLSInfo object with complete TLS inspection results
    """
    warnings = []
    security_score = 100.0
    
    try:
        # Create SSL context that checks certificates
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        
        # Connect with timeout
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=context),
            timeout=timeout
        )
        
        # Get the SSL object
        ssl_object = writer.get_extra_info('ssl_object')
        
        if ssl_object is None:
            writer.close()
            await writer.wait_closed()
            return TLSInfo(
                is_tls=False,
                tls_version=None,
                cipher_suite=None,
                cipher_strength=None,
                certificate=None,
                warnings=["Could not retrieve SSL object"],
                security_score=0.0
            )
        
        # Get TLS version
        version = ssl_object.version()
        tls_version = TLSVersion(version) if version in [e.value for e in TLSVersion] else TLSVersion.UNKNOWN
        
        # Check for deprecated TLS versions
        if version in ['SSL 2.0', 'SSL 3.0', 'TLS 1.0', 'TLS 1.1']:
            warnings.append(f"Deprecated TLS version: {version}")
            security_score -= 30
        
        # Get cipher suite
        cipher = ssl_object.cipher()
        cipher_suite = cipher[0] if cipher else None
        cipher_strength = assess_cipher_strength(cipher_suite) if cipher_suite else CipherStrength.UNKNOWN
        
        if cipher_strength == CipherStrength.WEAK:
            warnings.append(f"Weak cipher suite: {cipher_suite}")
            security_score -= 25
        elif cipher_strength == CipherStrength.MEDIUM:
            warnings.append(f"Medium strength cipher: {cipher_suite}")
            security_score -= 10
        
        # Get certificate
        cert = ssl_object.getpeercert(binary_form=False)
        writer.close()
        await writer.wait_closed()
        
        if not cert:
            warnings.append("No certificate presented")
            security_score -= 20
            return TLSInfo(
                is_tls=True,
                tls_version=version,
                cipher_suite=cipher_suite,
                cipher_strength=cipher_strength.name if cipher_strength else None,
                certificate=None,
                warnings=warnings,
                security_score=max(0, security_score)
            )
        
        # Parse certificate
        subject = dict(x[0] for x in cert.get('subject', []))
        issuer = dict(x[0] for x in cert.get('issuer', []))
        
        subject_cn = subject.get('commonName', '')
        issuer_cn = issuer.get('commonName', '')
        
        # Parse SANs
        san_list = []
        for ext in cert.get('extensions', []):
            if ext[0] == 'subjectAltName':
                for san_type, san_value in ext[1]:
                    if san_type == 'DNS':
                        san_list.append(san_value)
        
        # Parse validity dates
        not_before = datetime.strptime(cert.get('notBefore', ''), '%b %d %H:%M:%S %Y %Z')
        not_after = datetime.strptime(cert.get('notAfter', ''), '%b %d %H:%M:%S %Y %Z')
        
        now = datetime.now()
        days_until_expiry = (not_after - now).days
        is_expired = now > not_after
        
        if is_expired:
            warnings.append(f"Certificate expired on {not_after}")
            security_score -= 40
        elif days_until_expiry < 30:
            warnings.append(f"Certificate expires in {days_until_expiry} days")
            security_score -= 15
        
        # Check if self-signed
        is_self_signed = subject_cn == issuer_cn
        if is_self_signed:
            warnings.append("Self-signed certificate")
            security_score -= 15
        
        # Check for wildcard
        is_wildcard = check_wildcard(host, san_list) if san_list else False
        
        # Build certificate object
        certificate = TLSCertificate(
            subject=subject_cn,
            issuer=issuer_cn,
            san=san_list,
            not_before=not_before,
            not_after=not_after,
            serial_number=cert.get('serialNumber', ''),
            signature_algorithm=cert.get('signatureAlgorithm', ''),
            is_self_signed=is_self_signed,
            is_wildcard=is_wildcard,
            days_until_expiry=days_until_expiry,
            is_expired=is_expired
        )
        
        return TLSInfo(
            is_tls=True,
            tls_version=version,
            cipher_suite=cipher_suite,
            cipher_strength=cipher_strength.name if cipher_strength else None,
            certificate=certificate,
            warnings=warnings,
            security_score=max(0, security_score)
        )
        
    except ssl.SSLCertVerificationError as e:
        warnings.append(f"Certificate verification failed: {str(e)}")
        security_score -= 35
        return TLSInfo(
            is_tls=True,
            tls_version=version if 'version' in locals() else None,
            cipher_suite=cipher_suite if 'cipher_suite' in locals() else None,
            cipher_strength=cipher_strength.name if 'cipher_suite' in locals() and cipher_suite else None,
            certificate=None,
            warnings=warnings,
            security_score=max(0, security_score)
        )
    except asyncio.TimeoutError:
        warnings.append("Connection timeout")
        return TLSInfo(
            is_tls=False,
            tls_version=None,
            cipher_suite=None,
            cipher_strength=None,
            certificate=None,
            warnings=warnings,
            security_score=0.0
        )
    except Exception as e:
        warnings.append(f"TLS inspection failed: {str(e)}")
        return TLSInfo(
            is_tls=False,
            tls_version=None,
            cipher_suite=None,
            cipher_strength=None,
            certificate=None,
            warnings=warnings,
            security_score=0.0
        )


def format_tls_report(tls_info: TLSInfo) -> str:
    """Format TLS inspection result as a readable report."""
    if not tls_info.is_tls:
        return "TLS not detected on this port"
    
    lines = [
        f"TLS Version: {tls_info.tls_version}",
        f"Cipher Suite: {tls_info.cipher_suite}",
        f"Cipher Strength: {tls_info.cipher_strength}",
        f"Security Score: {tls_info.security_score:.0f}/100",
    ]
    
    if tls_info.certificate:
        cert = tls_info.certificate
        lines.extend([
            "",
            "Certificate:",
            f"  Subject: {cert.subject}",
            f"  Issuer: {cert.issuer}",
            f"  Expires: {cert.not_after} ({cert.days_until_expiry} days)",
            f"  Self-Signed: {cert.is_self_signed}",
            f"  Wildcard: {cert.is_wildcard}",
        ])
        if cert.san:
            lines.append(f"  SANs: {', '.join(cert.san[:5])}")
    
    if tls_info.warnings:
        lines.append("")
        lines.append("Warnings:")
        for warning in tls_info.warnings:
            lines.append(f"  - {warning}")
    
    return "\n".join(lines)
