"""
Python example for CyberSec-CLI API
"""

import json
import time

import requests

# Configuration
BASE_URL = "https://your-domain.com/api"
API_KEY = "your-api-key-here"

# Headers for authenticated requests
HEADERS = {"X-API-Key": API_KEY, "Content-Type": "application/json"}


def simple_scan_sync(target, ports="1-1000"):
    """
    Perform a simple synchronous scan using the streaming endpoint.
    """
    url = f"{BASE_URL}/stream/scan/{target}"
    params = {"ports": ports, "enhanced_service_detection": True}

    response = requests.get(url, params=params)

    if response.status_code == 200:
        # Process Server-Sent Events
        for line in response.iter_lines():
            if line:
                line_str = line.decode("utf-8")
                if line_str.startswith("data: "):
                    event_data = json.loads(line_str[6:])  # Remove 'data: ' prefix
                    print(f"Event: {event_data}")
    else:
        print(f"Error: {response.status_code} - {response.text}")


def async_scan_with_polling(target, ports="1-1000"):
    """
    Perform an asynchronous scan and poll for results.
    """
    # Create async scan task
    scan_request = {
        "target": target,
        "ports": ports,
        "config": {
            "timeout": 1.0,
            "max_concurrent": 50,
            "enhanced_service_detection": True,
        },
    }

    response = requests.post(f"{BASE_URL}/scan", headers=HEADERS, json=scan_request)

    if response.status_code == 200:
        task_info = response.json()
        task_id = task_info["task_id"]
        print(f"Scan started with task ID: {task_id}")

        # Poll for results
        while True:
            status_response = requests.get(
                f"{BASE_URL}/scan/{task_id}", headers=HEADERS
            )

            if status_response.status_code == 200:
                status_info = status_response.json()
                print(f"Status: {status_info['state']}")

                if status_info["state"] == "SUCCESS":
                    print("Scan completed!")
                    print(json.dumps(status_info["result"], indent=2))
                    break
                elif status_info["state"] == "FAILURE":
                    print(f"Scan failed: {status_info.get('error', 'Unknown error')}")
                    break
                else:
                    # Wait before polling again
                    time.sleep(5)
            else:
                print(f"Error getting status: {status_response.status_code}")
                break
    else:
        print(f"Error starting scan: {response.status_code} - {response.text}")


async def async_scan_with_websocket(target, ports="1-1000"):
    """
    Perform a scan using WebSocket for real-time results.
    Note: This is a simplified example; you'll need to install websockets library.
    """
    import websockets

    # WebSocket connection requires token if configured
    ws_url = "ws://your-domain.com/ws/command?token=your-ws-token"

    command_payload = {
        "command": f"scan {target} --ports {ports}",
        "force": False,
        "consent": True,
    }

    try:
        async with websockets.connect(ws_url) as websocket:
            # Send scan command
            await websocket.send(json.dumps(command_payload))

            # Receive results in real-time
            async for message in websocket:
                print(f"Received: {message}")

                # Break when scan completes
                if "[END]" in message:
                    break
    except Exception as e:
        print(f"WebSocket error: {e}")


def get_scan_history(limit=10):
    """
    Get recent scan history.
    """
    response = requests.get(
        f"{BASE_URL}/scans", headers=HEADERS, params={"limit": limit}
    )

    if response.status_code == 200:
        scans = response.json()
        print(f"Found {len(scans)} recent scans:")
        for scan in scans:
            print(
                f"  ID: {scan['id']}, Target: {scan['target']}, Time: {scan['timestamp']}"
            )
    else:
        print(f"Error getting scan history: {response.status_code}")


def get_rate_limit_info():
    """
    Get rate limiting information and violations.
    """
    response = requests.get(f"{BASE_URL}/admin/rate-limits", headers=HEADERS)

    if response.status_code == 200:
        rate_info = response.json()
        print("Rate Limiting Information:")
        print(f"  Status: {rate_info['rate_limiter_status']}")
        print(f"  Violations: {rate_info['violations']}")
        print(f"  Abuse Patterns: {rate_info['abuse_patterns']}")
    else:
        print(f"Error getting rate limit info: {response.status_code}")


if __name__ == "__main__":
    # Example usage
    print("=== CyberSec-CLI Python Example ===")

    # Get rate limit information
    print("\n1. Rate Limit Information:")
    get_rate_limit_info()

    # Perform a simple scan
    print("\n2. Performing simple scan (example.com)...")
    # simple_scan_sync("example.com", "1-100")

    # Perform an async scan with polling
    print("\n3. Starting async scan (example.com)...")
    # async_scan_with_polling("example.com", "1-50")

    # Get scan history
    print("\n4. Recent scan history:")
    get_scan_history()
