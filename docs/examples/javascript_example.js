/**
 * JavaScript example for CyberSec-CLI API
 */

// Configuration
const BASE_URL = "https://your-domain.com/api";
const API_KEY = "your-api-key-here";

// Headers for authenticated requests
const HEADERS = {
    "X-API-Key": API_KEY,
    "Content-Type": "application/json"
};

/**
 * Perform a simple synchronous scan using the streaming endpoint.
 */
async function simpleScanSync(target, ports = "1-1000") {
    const url = `${BASE_URL}/stream/scan/${target}?ports=${ports}&enhanced_service_detection=true`;
    
    try {
        const response = await fetch(url);
        
        if (response.ok) {
            const reader = response.body.getReader();
            const decoder = new TextDecoder();
            
            while (true) {
                const { done, value } = await reader.read();
                
                if (done) break;
                
                const chunk = decoder.decode(value);
                const lines = chunk.split('\n');
                
                for (const line of lines) {
                    if (line.startsWith('data: ')) {
                        const eventData = JSON.parse(line.substring(6));
                        console.log('Event:', eventData);
                    }
                }
            }
        } else {
            console.error(`Error: ${response.status} - ${response.statusText}`);
        }
    } catch (error) {
        console.error('Error during scan:', error);
    }
}

/**
 * Perform an asynchronous scan and poll for results.
 */
async function asyncScanWithPolling(target, ports = "1-1000") {
    // Create async scan task
    const scanRequest = {
        target: target,
        ports: ports,
        config: {
            timeout: 1.0,
            max_concurrent: 50,
            enhanced_service_detection: true
        }
    };
    
    try {
        const response = await fetch(`${BASE_URL}/scan`, {
            method: 'POST',
            headers: HEADERS,
            body: JSON.stringify(scanRequest)
        });
        
        if (response.ok) {
            const taskInfo = await response.json();
            const taskId = taskInfo.task_id;
            console.log(`Scan started with task ID: ${taskId}`);
            
            // Poll for results
            while (true) {
                const statusResponse = await fetch(`${BASE_URL}/scan/${taskId}`, {
                    headers: HEADERS
                });
                
                if (statusResponse.ok) {
                    const statusInfo = await statusResponse.json();
                    console.log(`Status: ${statusInfo.state}`);
                    
                    if (statusInfo.state === 'SUCCESS') {
                        console.log('Scan completed!');
                        console.log(JSON.stringify(statusInfo.result, null, 2));
                        break;
                    } else if (statusInfo.state === 'FAILURE') {
                        console.log(`Scan failed: ${statusInfo.error || 'Unknown error'}`);
                        break;
                    } else {
                        // Wait before polling again
                        await new Promise(resolve => setTimeout(resolve, 5000));
                    }
                } else {
                    console.error(`Error getting status: ${statusResponse.status}`);
                    break;
                }
            }
        } else {
            console.error(`Error starting scan: ${response.status} - ${response.statusText}`);
        }
    } catch (error) {
        console.error('Error during async scan:', error);
    }
}

/**
 * Perform a scan using WebSocket for real-time results.
 */
async function asyncScanWithWebSocket(target, ports = "1-1000") {
    // WebSocket connection requires token if configured
    const wsUrl = `ws://your-domain.com/ws/command?token=your-ws-token`;
    
    const commandPayload = {
        command: `scan ${target} --ports ${ports}`,
        force: false,
        consent: true
    };
    
    return new Promise((resolve, reject) => {
        const ws = new WebSocket(wsUrl);
        
        ws.onopen = function() {
            console.log('WebSocket connected');
            ws.send(JSON.stringify(commandPayload));
        };
        
        ws.onmessage = function(event) {
            console.log('Received:', event.data);
            
            // Close connection when scan completes
            if (event.data.includes('[END]')) {
                ws.close();
                resolve();
            }
        };
        
        ws.onerror = function(error) {
            console.error('WebSocket error:', error);
            reject(error);
        };
        
        ws.onclose = function() {
            console.log('WebSocket connection closed');
        };
    });
}

/**
 * Get recent scan history.
 */
async function getScanHistory(limit = 10) {
    try {
        const response = await fetch(`${BASE_URL}/scans?limit=${limit}`, {
            headers: HEADERS
        });
        
        if (response.ok) {
            const scans = await response.json();
            console.log(`Found ${scans.length} recent scans:`);
            scans.forEach(scan => {
                console.log(`  ID: ${scan.id}, Target: ${scan.target}, Time: ${scan.timestamp}`);
            });
        } else {
            console.error(`Error getting scan history: ${response.status}`);
        }
    } catch (error) {
        console.error('Error getting scan history:', error);
    }
}

/**
 * Get rate limiting information and violations.
 */
async function getRateLimitInfo() {
    try {
        const response = await fetch(`${BASE_URL}/admin/rate-limits`, {
            headers: HEADERS
        });
        
        if (response.ok) {
            const rateInfo = await response.json();
            console.log('Rate Limiting Information:');
            console.log(`  Status: ${rateInfo.rate_limiter_status}`);
            console.log(`  Violations:`, rateInfo.violations);
            console.log(`  Abuse Patterns:`, rateInfo.abuse_patterns);
        } else {
            console.error(`Error getting rate limit info: ${response.status}`);
        }
    } catch (error) {
        console.error('Error getting rate limit info:', error);
    }
}

// Example usage
async function main() {
    console.log('=== CyberSec-CLI JavaScript Example ===');
    
    // Get rate limit information
    console.log('\n1. Rate Limit Information:');
    await getRateLimitInfo();
    
    // Get scan history
    console.log('\n2. Recent scan history:');
    await getScanHistory();
    
    // Perform an async scan with polling
    console.log('\n3. Starting async scan (example.com)...');
    // await asyncScanWithPolling("example.com", "1-50");
    
    // Perform a simple scan (commented out to avoid actual execution)
    // console.log('\n4. Performing simple scan (example.com)...');
    // await simpleScanSync("example.com", "1-100");
}

// Run the example
main().catch(console.error);