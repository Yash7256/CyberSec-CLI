#!/usr/bin/env python3
"""
Test script for UDP scanning functionality in CyberSec-CLI
"""

import asyncio
import sys
import os

# Add the src directory to the path so we can import the modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from cybersec_cli.tools.network.port_scanner import PortScanner, ScanType

async def test_udp_scanning():
    """Test UDP scanning functionality"""
    print("Testing UDP scanning functionality...")
    
    # Test with a known UDP service (DNS on Google's public DNS)
    try:
        scanner = PortScanner(
            target="8.8.8.8",
            ports=[53],  # DNS port
            scan_type=ScanType.UDP,
            timeout=3.0,
            max_concurrent=10
        )
        
        print(f"Scanning UDP port 53 on {scanner.target}...")
        results = await scanner.scan()
        
        for result in results:
            print(f"Port {result.port}/{result.protocol}: {result.state.value}")
            if result.service:
                print(f"  Service: {result.service}")
            if result.banner:
                print(f"  Banner: {result.banner}")
                
        print("UDP scanning test completed successfully!")
        return True
        
    except Exception as e:
        print(f"Error during UDP scanning test: {e}")
        return False

async def test_multiple_udp_ports():
    """Test scanning multiple UDP ports"""
    print("\nTesting multiple UDP port scanning...")
    
    try:
        scanner = PortScanner(
            target="8.8.8.8",
            ports=[53, 123],  # DNS and NTP ports
            scan_type=ScanType.UDP,
            timeout=3.0,
            max_concurrent=10
        )
        
        print(f"Scanning UDP ports on {scanner.target}...")
        results = await scanner.scan()
        
        for result in results:
            print(f"Port {result.port}/{result.protocol}: {result.state.value}")
            if result.service:
                print(f"  Service: {result.service}")
                
        print("Multiple UDP port scanning test completed!")
        return True
        
    except Exception as e:
        print(f"Error during multiple UDP port scanning test: {e}")
        return False

if __name__ == "__main__":
    print("CyberSec-CLI UDP Scanning Test")
    print("=" * 40)
    
    # Run the tests
    success1 = asyncio.run(test_udp_scanning())
    success2 = asyncio.run(test_multiple_udp_ports())
    
    if success1 and success2:
        print("\nAll UDP scanning tests passed!")
        sys.exit(0)
    else:
        print("\nSome tests failed!")
        sys.exit(1)