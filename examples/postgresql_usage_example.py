#!/usr/bin/env python3
"""
Example script demonstrating how to use the PostgreSQL database for CyberSec-CLI.
"""

import sys
import os
import asyncio

# Add the project root to the path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

async def demonstrate_postgresql_usage():
    """Demonstrate PostgreSQL database usage."""
    print("CyberSec-CLI PostgreSQL Usage Example")
    print("=" * 50)
    
    try:
        # Import the database interface
        from database import db_interface
        
        # Initialize the database
        print("1. Initializing database interface...")
        await db_interface.initialize()
        print(f"   Database type: {db_interface.db_type}")
        print(f"   Initialized: {db_interface.initialized}")
        print()
        
        # Create a sample scan
        print("2. Creating a sample scan...")
        scan_id = await db_interface.create_scan(
            target="example.com",
            user_id="user_123",
            config={
                "scan_type": "TCP",
                "ports": "1-1000",
                "timeout": 1.0
            }
        )
        print(f"   Scan created with ID: {scan_id}")
        print()
        
        # Update scan status
        print("3. Updating scan status...")
        await db_interface.update_scan_status(scan_id, "running")
        print("   Scan status updated to 'running'")
        print()
        
        # Save sample scan results
        print("4. Saving sample scan results...")
        sample_results = [
            {
                "port": 22,
                "state": "open",
                "service": "ssh",
                "version": "OpenSSH 8.0",
                "banner": "SSH-2.0-OpenSSH_8.0",
                "risk": "low",
                "metadata": {
                    "cve": [],
                    "confidence": 0.95
                }
            },
            {
                "port": 80,
                "state": "open",
                "service": "http",
                "version": "Apache 2.4.6",
                "banner": "Apache/2.4.6 (CentOS)",
                "risk": "medium",
                "metadata": {
                    "cve": ["CVE-2021-41773"],
                    "confidence": 0.90
                }
            },
            {
                "port": 443,
                "state": "open",
                "service": "https",
                "version": "nginx 1.20.1",
                "banner": "nginx/1.20.1",
                "risk": "low",
                "metadata": {
                    "cve": [],
                    "confidence": 0.92
                }
            }
        ]
        
        await db_interface.save_scan_results(scan_id, sample_results)
        print(f"   Saved {len(sample_results)} scan results")
        print()
        
        # Update scan status to completed
        print("5. Marking scan as completed...")
        from datetime import datetime
        await db_interface.update_scan_status(scan_id, "completed", datetime.now())
        print("   Scan marked as completed")
        print()
        
        # Retrieve scan information
        print("6. Retrieving scan information...")
        scan_info = await db_interface.get_scan(scan_id)
        if scan_info:
            print(f"   Target: {scan_info.get('target')}")
            print(f"   Status: {scan_info.get('status')}")
            print(f"   User ID: {scan_info.get('user_id')}")
            print(f"   Created: {scan_info.get('created_at')}")
        print()
        
        # Retrieve scan results
        print("7. Retrieving scan results...")
        results = await db_interface.get_scan_results(scan_id)
        print(f"   Found {len(results)} scan results:")
        for result in results:
            print(f"     Port {result['port']}: {result['service']} ({result['state']})")
        print()
        
        # List user scans
        print("8. Listing user scans...")
        user_scans = await db_interface.list_user_scans("user_123", limit=10)
        print(f"   Found {len(user_scans)} scans for user")
        for scan in user_scans:
            print(f"     Scan {scan['id']}: {scan['target']} - {scan['status']}")
        print()
        
        print("✅ PostgreSQL usage demonstration completed successfully!")
        return True
        
    except Exception as e:
        print(f"❌ Error during demonstration: {e}")
        return False

def main():
    """Main function."""
    try:
        result = asyncio.run(demonstrate_postgresql_usage())
        return 0 if result else 1
    except Exception as e:
        print(f"❌ Failed to run demonstration: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())