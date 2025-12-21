"""
Example script demonstrating how to use the SSE streaming scan endpoint.
"""

import requests
import json
import time

def demonstrate_sse_streaming():
    """
    Demonstrate how to use the SSE streaming endpoint.
    This would typically be used from a JavaScript frontend.
    """
    print("Demonstrating SSE streaming scan endpoint usage")
    print("=" * 50)
    
    # In a real scenario, you would connect to the SSE endpoint like this:
    # curl "http://localhost:8000/api/stream/scan/example.com?ports=1-100"
    
    # For demonstration purposes, let's show what the events would look like:
    example_events = [
        {"type": "info", "message": "Starting scan on example.com with 100 ports"},
        {"type": "group_start", "priority": "critical", "count": 11},
        {"type": "open_port", "port": 22, "service": "ssh"},
        {"type": "open_port", "port": 80, "service": "http"},
        {"type": "group_complete", "priority": "critical", "open_count": 2},
        {"type": "group_start", "priority": "high", "count": 11},
        {"type": "open_port", "port": 443, "service": "https"},
        {"type": "group_complete", "priority": "high", "open_count": 1},
        {"type": "scan_complete", "message": "Scan completed"}
    ]
    
    print("Example events that would be streamed:")
    for event in example_events:
        print(f"Event: {json.dumps(event)}")
        time.sleep(0.5)  # Simulate delay between events
    
    print("\nIn a JavaScript frontend, you would use:")
    print("""
```javascript
const eventSource = new EventSource('http://localhost:8000/api/stream/scan/example.com?ports=1-1000');

eventSource.onmessage = function(event) {
    const data = JSON.parse(event.data);
    console.log('Received:', data);
    
    // Handle different event types
    switch(data.type) {
        case 'info':
            console.log('Info:', data.message);
            break;
        case 'group_start':
            console.log(`Scanning ${data.count} ${data.priority} priority ports`);
            break;
        case 'open_port':
            console.log(`Found open port: ${data.port} (${data.service})`);
            break;
        case 'group_complete':
            console.log(`Completed ${data.priority} priority group with ${data.open_count} open ports`);
            break;
        case 'scan_complete':
            console.log('Scan completed');
            eventSource.close(); // Close connection
            break;
        case 'error':
            console.error('Error:', data.message);
            eventSource.close();
            break;
    }
};

eventSource.onerror = function(err) {
    console.error('EventSource failed:', err);
};
```
    """)

if __name__ == "__main__":
    demonstrate_sse_streaming()