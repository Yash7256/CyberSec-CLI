#!/usr/bin/env python3
"""
Test script to verify the streaming interface is working correctly.
"""

import requests
import json
import time

def test_streaming_endpoint():
    """Test the streaming endpoint with a simple scan."""
    url = "http://localhost:8000/api/scan/stream"
    
    # Test parameters
    params = {
        "target": "127.0.0.1",
        "ports": "22,80,443",
        "enhanced_service_detection": "true"
    }
    
    print("Testing streaming endpoint...")
    print(f"URL: {url}")
    print(f"Parameters: {params}")
    
    try:
        # Make the request with streaming
        response = requests.get(url, params=params, stream=True)
        
        print("\nResponse status code:", response.status_code)
        print("Response headers:", dict(response.headers))
        
        if response.status_code == 200:
            print("\nStreaming results:")
            print("-" * 50)
            
            # Process the streamed events
            for line in response.iter_lines():
                if line:
                    decoded_line = line.decode('utf-8')
                    if decoded_line.startswith('data:'):
                        # Parse the JSON data
                        json_data = decoded_line[6:]  # Remove 'data: ' prefix
                        try:
                            data = json.loads(json_data)
                            print(f"Event: {data.get('type', 'unknown')}")
                            if 'progress' in data:
                                print(f"  Progress: {data['progress']}%")
                            if 'priority' in data:
                                print(f"  Priority: {data['priority']}")
                            if 'open_ports' in data:
                                print(f"  Open ports: {len(data['open_ports'])}")
                                for port in data['open_ports']:
                                    print(f"    Port {port['port']}: {port['service']}")
                            print()
                        except json.JSONDecodeError:
                            print(f"Raw data: {json_data}")
        else:
            print(f"Error: {response.status_code}")
            print(response.text)
            
    except requests.exceptions.ConnectionError:
        print("Error: Could not connect to the server. Make sure it's running on port 8000.")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    test_streaming_endpoint()