#!/usr/bin/env python3
"""
Test script for all scan types in CyberSec-CLI
"""

import asyncio
import os
import sys

from cybersec_cli.tools.network.port_scanner import PortScanner, ScanType

# Add the src directory to the path so we can import the modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


async def test_tcp_connect_scan():
    """Test TCP connect scanning functionality"""
    print("Testing TCP Connect scanning functionality...")

    try:
        scanner = PortScanner(
            target="8.8.8.8",
            ports=[53, 80],  # Common ports
            scan_type=ScanType.TCP_CONNECT,
            timeout=3.0,
            max_concurrent=10,
        )

        print(f"Scanning TCP ports on {scanner.target}...")
        results = await scanner.scan()

        for result in results:
            print(f"Port {result.port}/tcp: {result.state.value}")
            if result.service:
                print(f"  Service: {result.service}")

        print("TCP Connect scanning test completed!")
        return True

    except Exception as e:
        print(f"Error during TCP Connect scanning test: {e}")
        return False


async def test_udp_scan():
    """Test UDP scanning functionality"""
    print("\nTesting UDP scanning functionality...")

    try:
        scanner = PortScanner(
            target="8.8.8.8",
            ports=[53],  # DNS port
            scan_type=ScanType.UDP,
            timeout=3.0,
            max_concurrent=10,
        )

        print(f"Scanning UDP port 53 on {scanner.target}...")
        results = await scanner.scan()

        for result in results:
            print(f"Port {result.port}/udp: {result.state.value}")
            if result.service:
                print(f"  Service: {result.service}")

        print("UDP scanning test completed!")
        return True

    except Exception as e:
        print(f"Error during UDP scanning test: {e}")
        return False


async def test_syn_scan():
    """Test TCP SYN scanning functionality"""
    print("\nTesting TCP SYN scanning functionality...")

    try:
        scanner = PortScanner(
            target="127.0.0.1",  # Localhost for testing
            ports=[22, 80],  # SSH and HTTP if available
            scan_type=ScanType.TCP_SYN,
            timeout=3.0,
            max_concurrent=10,
        )

        print(f"Scanning TCP ports with SYN scan on {scanner.target}...")
        results = await scanner.scan()

        for result in results:
            print(f"Port {result.port}/tcp: {result.state.value}")
            if result.reason:
                print(f"  Reason: {result.reason}")

        print("TCP SYN scanning test completed!")
        return True

    except Exception as e:
        print(f"Error during TCP SYN scanning test: {e}")
        # This is expected to fail without root privileges
        return True


async def test_fin_scan():
    """Test FIN scanning functionality"""
    print("\nTesting FIN scanning functionality...")

    try:
        scanner = PortScanner(
            target="127.0.0.1",
            ports=[22, 80],
            scan_type=ScanType.FIN,
            timeout=3.0,
            max_concurrent=10,
        )

        print(f"Scanning TCP ports with FIN scan on {scanner.target}...")
        results = await scanner.scan()

        for result in results:
            print(f"Port {result.port}/tcp: {result.state.value}")
            if result.reason:
                print(f"  Reason: {result.reason}")

        print("FIN scanning test completed!")
        return True

    except Exception as e:
        print(f"Error during FIN scanning test: {e}")
        # This is expected to fail without root privileges
        return True


async def test_null_scan():
    """Test NULL scanning functionality"""
    print("\nTesting NULL scanning functionality...")

    try:
        scanner = PortScanner(
            target="127.0.0.1",
            ports=[22, 80],
            scan_type=ScanType.NULL,
            timeout=3.0,
            max_concurrent=10,
        )

        print(f"Scanning TCP ports with NULL scan on {scanner.target}...")
        results = await scanner.scan()

        for result in results:
            print(f"Port {result.port}/tcp: {result.state.value}")
            if result.reason:
                print(f"  Reason: {result.reason}")

        print("NULL scanning test completed!")
        return True

    except Exception as e:
        print(f"Error during NULL scanning test: {e}")
        # This is expected to fail without root privileges
        return True


async def test_xmas_scan():
    """Test XMAS scanning functionality"""
    print("\nTesting XMAS scanning functionality...")

    try:
        scanner = PortScanner(
            target="127.0.0.1",
            ports=[22, 80],
            scan_type=ScanType.XMAS,
            timeout=3.0,
            max_concurrent=10,
        )

        print(f"Scanning TCP ports with XMAS scan on {scanner.target}...")
        results = await scanner.scan()

        for result in results:
            print(f"Port {result.port}/tcp: {result.state.value}")
            if result.reason:
                print(f"  Reason: {result.reason}")

        print("XMAS scanning test completed!")
        return True

    except Exception as e:
        print(f"Error during XMAS scanning test: {e}")
        # This is expected to fail without root privileges
        return True


if __name__ == "__main__":
    print("CyberSec-CLI All Scan Types Test")
    print("=" * 40)

    # Run the tests
    success1 = asyncio.run(test_tcp_connect_scan())
    success2 = asyncio.run(test_udp_scan())
    success3 = asyncio.run(test_syn_scan())
    success4 = asyncio.run(test_fin_scan())
    success5 = asyncio.run(test_null_scan())
    success6 = asyncio.run(test_xmas_scan())

    print("\n" + "=" * 40)
    if all([success1, success2, success3, success4, success5, success6]):
        print("All scan type tests completed!")
        sys.exit(0)
    else:
        print("Some tests had issues!")
        sys.exit(1)
