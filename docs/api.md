# CyberSec-CLI API Documentation

## Overview

The CyberSec-CLI API provides a comprehensive RESTful interface for network scanning, vulnerability assessment, and security analysis operations. The API supports both synchronous and asynchronous operations, real-time streaming, and extensive rate limiting for security and performance.

### Base URL
```
https://your-domain.com/api/
```

### Authentication

The API uses API key authentication for protected endpoints. Include your API key in the request headers:

```
X-API-Key: your-api-key-here
```

Or as a query parameter:
```
?api_key=your-api-key-here
```

> **Note**: Authentication is not required for health check endpoints, static content, and the main status endpoint.

### Rate Limiting

The API implements multiple layers of rate limiting:

- **Per-minute limit**: 5 scans per minute per client
- **Concurrent scans**: 2 concurrent scans per client
- **Advanced rate limiting**: Sliding window with exponential backoff for abuse detection

## API Endpoints

### Health & Status

#### GET /api/status
Get the current status of the CyberSec-CLI API.

**Response:**
```json
{
  "status": "CyberSec-CLI API is running"
}
```

#### GET /health/redis
Check Redis connectivity and latency.

**Response:**
```json
{
  "status": "healthy",
  "latency_ms": 2.5,
  "message": "Redis connection is healthy"
}
```

#### GET /metrics
Prometheus metrics endpoint for system monitoring.

**Response:**
```
# HELP cybersec_scan_total Total number of scans
# TYPE cybersec_scan_total counter
cybersec_scan_total{status="completed",user_type="api"} 42
```

### Scan Operations

#### GET /api/scans
List previous scan results with optional limit parameter.

**Parameters:**
- `limit` (integer, optional, default: 50): Maximum number of results to return

**Response:**
```json
[
  {
    "id": 1,
    "timestamp": "2023-01-01T12:00:00Z",
    "target": "example.com",
    "ip": "93.184.216.34",
    "command": "scan example.com --ports 1-1000"
  }
]
```

#### GET /api/scans/{scan_id}
Get detailed output of a specific scan by its ID.

**Path Parameters:**
- `scan_id` (integer): The ID of the scan to retrieve

**Response:**
```json
{
  "id": 1,
  "output": "Scan results for example.com..."
}
```

### Streaming Scan Results

#### GET /api/stream/scan/{target}
Stream port scan results using Server-Sent Events (SSE).

**Path Parameters:**
- `target` (string): Target hostname or IP address to scan

**Query Parameters:**
- `ports` (string, optional, default: "1-1000"): Port range to scan (e.g., "1-1000", "80,443", "22-25,80,443")
- `enhanced_service_detection` (boolean, optional, default: true): Enable enhanced service detection

**Response (SSE Events):**
```
data: {"type": "scan_start", "target": "example.com", "total_ports": 1000, "message": "Starting scan on example.com with 1000 ports"}

data: {"type": "open_port", "port": {"port": 80, "service": "http", "version": "Apache/2.4.41", "banner": "Apache/2.4.41", "confidence": 0.9, "protocol": "tcp"}, "progress": 25}

data: {"type": "scan_complete", "message": "Scan completed", "progress": 100}
```

#### GET /api/scan/stream
Stream port scan results with vulnerability analysis using Server-Sent Events (SSE).

**Query Parameters:**
- `target` (string): Target hostname or IP address to scan
- `ports` (string, optional, default: "1-1000"): Port range to scan (e.g., "1-1000", "80,443", "22-25,80,443")
- `enhanced_service_detection` (boolean, optional, default: true): Enable enhanced service detection

**Response (SSE Events):**
```
data: {"type": "scan_start", "target": "example.com", "total_ports": 1000, "progress": 0}

data: {"type": "tier_results", "priority": "critical", "open_ports": [{"port": 22, "service": "ssh", "version": "OpenSSH_7.9", "risk": "HIGH", "cvss_score": 7.5, "vulnerabilities": ["CVE-2019-6111"]}], "progress": 25}

data: {"type": "scan_complete", "message": "Scan completed", "progress": 100}
```

### Asynchronous Scanning

#### POST /api/scan
Create an asynchronous scan task using Celery. Returns a task ID for tracking the scan progress.

**Request Body:**
```json
{
  "target": "example.com",
  "ports": "1-1000",
  "config": {
    "timeout": 1.0,
    "max_concurrent": 50,
    "enhanced_service_detection": true
  }
}
```

**Query Parameters:**
- `force` (boolean, optional, default: false): If true, bypass cache and perform fresh scan

**Response:**
```json
{
  "task_id": "c5d8e2a1-1b3f-4e8c-9d2a-4f5b8e7a1c2d",
  "scan_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef",
  "status": "queued",
  "message": "Scan queued for target example.com",
  "force": false
}
```

#### GET /api/scan/{task_id}
Get the status of an asynchronous scan task.

**Path Parameters:**
- `task_id` (string): The Celery task ID to check

**Response:**
```json
{
  "state": "SUCCESS",
  "result": {
    "scan_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef",
    "target": "example.com",
    "open_ports": [
      {
        "port": 80,
        "service": "http",
        "risk": "MEDIUM"
      }
    ],
    "status": "completed",
    "progress": 100
  }
}
```

### Rate Limiting Management

#### POST /api/admin/rate-limits/reset/{client_id}
Reset rate limits for a specific client (admin endpoint).

**Path Parameters:**
- `client_id` (string): The client ID to reset rate limits for

**Response:**
```json
{
  "message": "Rate limits reset for client 127.0.0.1"
}
```

#### GET /api/admin/rate-limits
Get rate limit dashboard data for monitoring.

**Response:**
```json
{
  "violations": {
    "127.0.0.1": 3,
    "192.168.1.100": 1
  },
  "abuse_patterns": [
    {
      "client_id": "127.0.0.1",
      "violation_count": 3,
      "is_on_cooldown": true
    }
  ],
  "rate_limiter_status": "active"
}
```

### Audit Logs

#### GET /api/audit/forced_scans
Get forced scan audit logs.

**Response:**
```json
[
  {
    "timestamp": "2023-01-01T12:00:00Z",
    "target": "example.com",
    "resolved_ip": "93.184.216.34",
    "original_command": "scan example.com",
    "client_host": "127.0.0.1",
    "consent": true,
    "note": "forced_via_websocket"
  }
]
```

## WebSocket Interface

### WebSocket /ws/command
Real-time command execution with authentication and rate limiting.

**Authentication:**
If `WEBSOCKET_API_KEY` environment variable is set, include the token as a query parameter:
```
ws://your-domain.com/ws/command?token=your-websocket-api-key
```

**Message Format:**
```json
{
  "command": "scan example.com --ports 1-1000",
  "force": false,
  "consent": true
}
```

**Response Events:**
- `auth_error`: Authentication failed
- `error`: Command execution error
- `rate_limit`: Rate limit exceeded
- `pre_scan_warning`: Pre-scan warning requiring confirmation
- `[OUT]`: Command output
- `[ERR]`: Command error output
- `[END]`: Command completion

## Error Handling

The API returns standard HTTP status codes:

- `200`: Success
- `400`: Bad request
- `401`: Unauthorized (missing or invalid API key)
- `404`: Not found
- `429`: Rate limit exceeded
- `500`: Internal server error

Error responses include:
```json
{
  "error": "Request error",
  "message": "Error details here",
  "request_id": "unique-request-id"
}
```

## Example Workflows

### Simple Scan
```bash
curl -X GET "https://your-domain.com/api/stream/scan/example.com?ports=1-100" \
  -H "X-API-Key: your-api-key"
```

### Scan with Caching
```bash
curl -X POST "https://your-domain.com/api/scan?force=false" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{
    "target": "example.com",
    "ports": "1-1000",
    "config": {
      "enhanced_service_detection": true
    }
  }'
```

### Asynchronous Scan with Celery
```bash
# Start the scan
RESPONSE=$(curl -X POST "https://your-domain.com/api/scan" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{
    "target": "example.com",
    "ports": "1-65535"
  }')

TASK_ID=$(echo $RESPONSE | jq -r '.task_id')

# Check status
curl -X GET "https://your-domain.com/api/scan/$TASK_ID" \
  -H "X-API-Key: your-api-key"
```

### Streaming Results
```bash
curl -X GET "https://your-domain.com/api/scan/stream?target=example.com&ports=1-1000" \
  -H "X-API-Key: your-api-key" \
  -H "Accept: text/event-stream"
```

## Security Headers

All API responses include security headers:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Strict-Transport-Security: max-age=31536000; includeSubDomains`
- `Content-Security-Policy: default-src 'self'; ...`

## Request Tracking

All requests include a unique `X-Request-ID` header for tracking and debugging purposes.