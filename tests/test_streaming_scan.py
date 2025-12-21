"""
Test script to demonstrate streaming scan functionality.
"""

import asyncio
import sys
import os

# Add the src directory to the path so we can import the modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from cybersec_cli.tools.network.port_scanner import PortScanner, ScanType


async def test_streaming_scan():
    """Test streaming scan functionality."""
    print("Testing streaming scan functionality...")
    
    try:
        # Create a scanner with streaming enabled
        scanner = PortScanner(
            target="127.0.0.1",  # localhost
            ports=[21, 22, 80, 443, 3306, 8080, 1000, 2000],  # Mix of priority and non-priority ports
            scan_type=ScanType.TCP_CONNECT,
            timeout=1.0,
            max_concurrent=10,
            service_detection=True,
            banner_grabbing=False
        )
        
        print(f"Scanning ports on {scanner.target} with streaming...")
        
        # Perform the scan with streaming enabled
        results = await scanner.scan(streaming=True)
        
        print(f"Scan completed. Found {len([r for r in results if r.state.name == 'OPEN'])} open ports:")
        for result in results:
            if result.state.name == "OPEN":
                print(f"  Port {result.port}: {result.service or 'unknown'}")
                
        print("Streaming scan test completed successfully!")
        return True
        
    except Exception as e:
        print(f"Error during streaming scan test: {e}")
        return False


if __name__ == "__main__":
    print("CyberSec-CLI Streaming Scan Test")
    print("=" * 40)
    
    # Run the test
    success = asyncio.run(test_streaming_scan())
    
    if success:
        print("\nStreaming scan test passed!")
        sys.exit(0)
    else:
        print("\nStreaming scan test failed!")
        sys.exit(1)