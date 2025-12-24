"""
Enhanced Service Detection Probes for Cybersec CLI.

This module implements active probing for common services to improve service detection accuracy.
"""

import asyncio
import socket
import ssl
import struct
from typing import Dict, Optional, Tuple, Any
import logging

logger = logging.getLogger(__name__)

# Service probes dictionary
SERVICE_PROBES = {
    "http": [
        b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
        b"OPTIONS / HTTP/1.1\r\nHost: localhost\r\n\r\n",
    ],
    "https": [b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"],
    "ssh": [b""],  # SSH version exchange happens automatically on connection
    "ftp": [b""],
    "smtp": [b"EHLO localhost\r\n"],
    "mysql": [b"\x0a\x00\x00\x01\x85\xa6\x3f\x20\x00\x00\x00\x01\x21"],
    "postgresql": [b"\x00\x00\x00\x08\x04\xd2\x16\x2f"],
    "redis": [b"PING\r\n"],
    "mongodb": [
        b"\x3f\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00\x61\x64\x6d\x69\x6e\x2e\x24\x63\x6d\x64\x00\x00\x00\x00\x00\xff\xff\xff\x00"
    ],
}


def send_probe(ip: str, port: int, probe_data: bytes, timeout: float = 3.0) -> bytes:
    """
    Send probe data to a port and return the response.

    Args:
        ip: Target IP address
        port: Target port
        probe_data: Probe data to send
        timeout: Connection timeout in seconds

    Returns:
        Response bytes or empty bytes on failure
    """
    try:
        # Create socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        # Connect to target
        sock.connect((ip, port))

        # Send probe data if provided
        if probe_data:
            sock.send(probe_data)

        # Receive response
        response = sock.recv(4096)

        # Close socket
        sock.close()

        return response
    except Exception as e:
        logger.debug(f"Probe failed for {ip}:{port} - {e}")
        return b""


async def send_async_probe(
    ip: str, port: int, probe_data: bytes, timeout: float = 3.0
) -> bytes:
    """
    Send probe data to a port asynchronously and return the response.

    Args:
        ip: Target IP address
        port: Target port
        probe_data: Probe data to send
        timeout: Connection timeout in seconds

    Returns:
        Response bytes or empty bytes on failure
    """
    try:
        # Create connection
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )

        try:
            # Send probe data if provided
            if probe_data:
                writer.write(probe_data)
                await writer.drain()

            # Read response with timeout
            response = await asyncio.wait_for(reader.read(4096), timeout=timeout)

            return response
        finally:
            # Close connection
            writer.close()
            await writer.wait_closed()

    except Exception as e:
        logger.debug(f"Async probe failed for {ip}:{port} - {e}")
        return b""


def identify_service(ip: str, port: int, timeout: float = 3.0) -> Dict[str, Any]:
    """
    Identify service running on a port using active probing.

    Args:
        ip: Target IP address
        port: Target port
        timeout: Connection timeout in seconds

    Returns:
        Dictionary with service information:
        {
            "service": str,
            "version": Optional[str],
            "banner": Optional[str],
            "confidence": float (0.0-1.0)
        }
    """
    result = {"service": None, "version": None, "banner": None, "confidence": 0.0}

    # Try each service type
    for service_name, probes in SERVICE_PROBES.items():
        confidence = 0.0

        # Try each probe for this service
        for probe in probes:
            try:
                response = send_probe(ip, port, probe, timeout)
                if response:
                    # Analyze response to determine confidence
                    confidence = _analyze_response(service_name, response)
                    if confidence > result["confidence"]:
                        result["service"] = service_name
                        result["confidence"] = confidence
                        result["banner"] = response.decode(
                            "utf-8", errors="ignore"
                        ).strip()
                        result["version"] = _extract_version(service_name, response)

                        # If we have high confidence, we can stop
                        if confidence > 0.8:
                            return result
            except Exception as e:
                logger.debug(f"Probe failed for {service_name} on {ip}:{port} - {e}")
                continue

    # If no probes worked, fall back to port-based detection
    if result["confidence"] == 0.0:
        port_service = _get_service_by_port(port)
        if port_service:
            result["service"] = port_service
            result["confidence"] = 0.3  # Low confidence for port-based detection

    return result


async def identify_service_async(
    ip: str, port: int, timeout: float = 3.0
) -> Dict[str, Any]:
    """
    Identify service running on a port using active probing asynchronously.

    Args:
        ip: Target IP address
        port: Target port
        timeout: Connection timeout in seconds

    Returns:
        Dictionary with service information:
        {
            "service": str,
            "version": Optional[str],
            "banner": Optional[str],
            "confidence": float (0.0-1.0)
        }
    """
    result = {"service": None, "version": None, "banner": None, "confidence": 0.0}

    # Try each service type
    for service_name, probes in SERVICE_PROBES.items():
        confidence = 0.0

        # Try each probe for this service
        for probe in probes:
            try:
                response = await send_async_probe(ip, port, probe, timeout)
                if response:
                    # Analyze response to determine confidence
                    confidence = _analyze_response(service_name, response)
                    if confidence > result["confidence"]:
                        result["service"] = service_name
                        result["confidence"] = confidence
                        result["banner"] = response.decode(
                            "utf-8", errors="ignore"
                        ).strip()
                        result["version"] = _extract_version(service_name, response)

                        # If we have high confidence, we can stop
                        if confidence > 0.8:
                            return result
            except Exception as e:
                logger.debug(
                    f"Async probe failed for {service_name} on {ip}:{port} - {e}"
                )
                continue

    # If no probes worked, fall back to port-based detection
    if result["confidence"] == 0.0:
        port_service = _get_service_by_port(port)
        if port_service:
            result["service"] = port_service
            result["confidence"] = 0.3  # Low confidence for port-based detection

    return result


def _analyze_response(service_name: str, response: bytes) -> float:
    """
    Analyze response to determine confidence level.

    Args:
        service_name: Name of the service
        response: Response bytes from probe

    Returns:
        Confidence level (0.0-1.0)
    """
    response_str = response.decode("utf-8", errors="ignore").lower()

    # Service-specific response analysis
    if service_name == "http":
        if "http/" in response_str:
            return 0.9
        elif "html" in response_str:
            return 0.7
    elif service_name == "https":
        # HTTPS responses are encrypted, but we can check if we got data
        if len(response) > 0:
            return 0.8
    elif service_name == "ssh":
        if "ssh-" in response_str:
            return 0.95
    elif service_name == "ftp":
        if "ftp" in response_str or "220" in response_str:
            return 0.8
    elif service_name == "smtp":
        if "220" in response_str or "smtp" in response_str:
            return 0.85
    elif service_name == "mysql":
        # MySQL handshake packet has specific structure
        if len(response) >= 5 and response[4] == 0x0A:  # Protocol version byte
            return 0.9
    elif service_name == "postgresql":
        # PostgreSQL responses start with specific bytes
        if len(response) >= 1 and response[0] == 0x52:  # 'R' for authentication request
            return 0.9
    elif service_name == "redis":
        if "+pong" in response_str or "-" in response_str:
            return 0.85
    elif service_name == "mongodb":
        # MongoDB responses have specific structure
        if len(response) >= 4:
            # Check if it looks like a MongoDB message
            return 0.8

    # Generic check for any response
    if len(response) > 0:
        return 0.5

    return 0.0


def _extract_version(service_name: str, response: bytes) -> Optional[str]:
    """
    Extract version information from service response.

    Args:
        service_name: Name of the service
        response: Response bytes from probe

    Returns:
        Version string or None if not found
    """
    try:
        response_str = response.decode("utf-8", errors="ignore")

        if service_name == "http":
            # Look for Server header
            lines = response_str.split("\n")
            for line in lines:
                if line.lower().startswith("server:"):
                    return line.split(":", 1)[1].strip()
        elif service_name == "ssh":
            # SSH version is in the first line
            first_line = response_str.split("\n")[0]
            if first_line.startswith("SSH-"):
                return first_line.split(" ", 1)[0]
        elif service_name == "mysql":
            # MySQL version is in the handshake packet
            if len(response) >= 5 and response[4] == 0x0A:
                # Skip protocol version and null-terminated server version
                pos = 5
                while pos < len(response) and response[pos] != 0:
                    pos += 1
                pos += 1  # Skip null terminator
                # Server version string follows
                version_end = response.find(b"\x00", pos)
                if version_end != -1:
                    return response[pos:version_end].decode("utf-8", errors="ignore")
        elif service_name == "postgresql":
            # PostgreSQL version in authentication request
            pass  # More complex to extract
    except Exception as e:
        logger.debug(f"Version extraction failed: {e}")

    return None


def _get_service_by_port(port: int) -> Optional[str]:
    """
    Get service name by port number.

    Args:
        port: Port number

    Returns:
        Service name or None if not found
    """
    port_services = {
        21: "ftp",
        22: "ssh",
        23: "telnet",
        25: "smtp",
        53: "dns",
        80: "http",
        110: "pop3",
        143: "imap",
        443: "https",
        465: "smtps",
        587: "submission",
        993: "imaps",
        995: "pop3s",
        3306: "mysql",
        5432: "postgresql",
        6379: "redis",
        27017: "mongodb",
    }

    return port_services.get(port)


def get_ssl_info(ip: str, port: int, timeout: float = 5.0) -> Optional[Dict[str, Any]]:
    """
    Get SSL/TLS certificate information from a port.

    Args:
        ip: Target IP address
        port: Target port
        timeout: Connection timeout in seconds

    Returns:
        Dictionary with SSL information or None if not SSL/TLS
    """
    try:
        # Create SSL context
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        # Create socket and wrap with SSL
        sock = socket.create_connection((ip, port), timeout=timeout)
        ssl_sock = context.wrap_socket(sock, server_hostname=ip)

        # Get certificate
        cert = ssl_sock.getpeercert()
        cipher = ssl_sock.cipher()

        # Close connection
        ssl_sock.close()

        if cert:
            return {
                "subject": dict(x[0] for x in cert["subject"]),
                "issuer": dict(x[0] for x in cert["issuer"]),
                "version": cert["version"],
                "serialNumber": cert["serialNumber"],
                "notBefore": cert["notBefore"],
                "notAfter": cert["notAfter"],
                "san": cert.get("subjectAltName", []),
                "cipher": cipher,
            }
    except Exception as e:
        logger.debug(f"SSL info extraction failed for {ip}:{port} - {e}")
        return None

    return None
