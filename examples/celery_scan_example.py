#!/usr/bin/env python3
"""
Example script demonstrating how to use the Celery task queue for scanning.
"""

import os
import sys
import time

import requests

# Add the project root to the path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


def queue_scan(target, ports="1-100", scan_type="TCP"):
    """
    Queue a scan task using the web API.

    Args:
        target (str): Target hostname or IP to scan
        ports (str): Port range to scan
        scan_type (str): Type of scan (TCP, UDP, etc.)

    Returns:
        dict: Response from the API
    """
    url = "http://localhost:8000/api/scan"

    payload = {
        "target": target,
        "ports": ports,
        "config": {"scan_type": scan_type, "timeout": 1.0, "max_concurrent": 20},
    }

    try:
        response = requests.post(url, json=payload)
        return response.json()
    except Exception as e:
        print(f"Error queuing scan: {e}")
        return None


def check_scan_status(task_id):
    """
    Check the status of a scan task.

    Args:
        task_id (str): Task ID returned when queuing the scan

    Returns:
        dict: Status information
    """
    url = f"http://localhost:8000/api/scan/{task_id}"

    try:
        response = requests.get(url)
        return response.json()
    except Exception as e:
        print(f"Error checking scan status: {e}")
        return None


def monitor_scan(task_id, poll_interval=2):
    """
    Monitor a scan task until completion.

    Args:
        task_id (str): Task ID to monitor
        poll_interval (int): Seconds between status checks
    """
    print(f"Monitoring scan task: {task_id}")
    print("-" * 50)

    while True:
        status = check_scan_status(task_id)
        if not status:
            print("Failed to get status")
            break

        state = status.get("state", "UNKNOWN")
        print(f"State: {state}")

        if state == "PROGRESS":
            progress = status.get("progress", 0)
            status_msg = status.get("status", "Processing")
            print(f"Progress: {progress}% - {status_msg}")

            # Print additional metadata if available
            for key, value in status.items():
                if key not in ["state", "progress", "status"]:
                    print(f"{key}: {value}")

        elif state == "SUCCESS":
            result = status.get("result", {})
            print("Scan completed successfully!")
            print(f"Target: {result.get('target', 'Unknown')}")
            print(f"Ports scanned: {result.get('total_ports_scanned', 0)}")
            print(f"Open ports found: {len(result.get('open_ports', []))}")
            break

        elif state in ["FAILURE", "REVOKED"]:
            error = status.get("error", "Unknown error")
            print(f"Scan failed: {error}")
            break

        print(f"Waiting {poll_interval} seconds before next check...")
        time.sleep(poll_interval)
        print()


def main():
    """Demonstrate Celery scan task usage."""
    print("CyberSec-CLI Celery Scan Example")
    print("=" * 50)

    # Example 1: Queue a simple scan
    print("1. Queuing a scan task...")
    response = queue_scan("scanme.nmap.org", "22-80")

    if not response:
        print("❌ Failed to queue scan")
        return 1

    task_id = response.get("task_id")
    if not task_id:
        print("❌ No task ID returned")
        return 1

    print(f"✅ Scan queued successfully")
    print(f"Task ID: {task_id}")
    print(f"Message: {response.get('message', 'No message')}")
    print()

    # Example 2: Monitor the scan
    print("2. Monitoring scan progress...")
    monitor_scan(task_id)

    print("\n🎉 Example completed!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
