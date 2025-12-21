# Enhanced Service Detection

CyberSec-CLI includes an enhanced service detection system that uses active probing to accurately identify services running on open ports. This feature improves upon the basic port-based service detection by sending specific probes to ports and analyzing the responses.

## How It Works

The enhanced service detection system sends service-specific probes to open ports and analyzes the responses to determine:

1. **Service Type** - What service is running (HTTP, SSH, MySQL, etc.)
2. **Version Information** - Software version when available
3. **Banner Information** - Raw response from the service
4. **Confidence Level** - How certain the detection is (0.0-1.0)

### Supported Services

The system includes probes for the following services:

- **HTTP/HTTPS** - GET and OPTIONS requests
- **SSH** - Version exchange detection
- **FTP** - Connection and banner reading
- **SMTP** - EHLO command
- **MySQL** - Connection packet
- **PostgreSQL** - Connection packet
- **Redis** - PING command
- **MongoDB** - Connection check

### Detection Process

1. For each open port, the system tries multiple service-specific probes
2. Responses are analyzed to determine the service type and confidence level
3. If no probes succeed, the system falls back to port-based detection
4. SSL/TLS certificate information is extracted for HTTPS ports

## Configuration Options

### Environment Variable

```bash
# Enable/disable enhanced service detection (default: true)
SCAN_ENHANCED_SERVICE_DETECTION=true
```

### CLI Flag

```bash
# Enable enhanced service detection
cybersec scan example.com --enhanced-service-detection

# Disable enhanced service detection
cybersec scan example.com --no-enhanced-service-detection
```

### Programmatic Configuration

In code, you can control this feature through the `ScanningConfig` class:

```python
from cybersec_cli.config import settings

# Enable enhanced service detection
settings.scanning.enhanced_service_detection = True
```

## Service Result Fields

The enhanced service detection populates additional fields in the scan results:

- **service** - Detected service name
- **version** - Software version (when available)
- **banner** - Raw service response
- **confidence** - Detection confidence level (0.0-1.0)

## Benefits

1. **Improved Accuracy** - More accurate service identification than port-based detection
2. **Detailed Information** - Provides version and banner information when available
3. **Flexible Configuration** - Can be enabled/disabled as needed
4. **Fallback Mechanism** - Falls back to port-based detection if probes fail
5. **Performance Balanced** - Efficient probing that doesn't significantly slow scans

## Example Usage

```bash
# Standard scan with enhanced service detection
cybersec scan example.com

# Scan with enhanced service detection explicitly enabled
cybersec scan example.com --enhanced-service-detection

# Scan with enhanced service detection disabled (faster, less detailed)
cybersec scan example.com --no-enhanced-service-detection
```

## Confidence Levels

The confidence level indicates how certain the system is about the service detection:

- **0.9+** - Very high confidence (specific service response matched)
- **0.7-0.9** - High confidence (recognizable service pattern)
- **0.5-0.7** - Medium confidence (generic response received)
- **0.3** - Low confidence (fallback to port-based detection)
- **0.0** - No detection

## Performance Impact

The enhanced service detection adds minimal overhead to scans:

- Probes are sent only to open ports
- Each probe has a short timeout (typically 3 seconds)
- Probing stops as soon as a high-confidence match is found
- Can be disabled for performance-critical scans

## Error Handling

The system gracefully handles:

- Connection timeouts
- Service not responding to probes
- Unrecognized service responses
- Network errors

In all cases, the system will fall back to port-based detection with low confidence rather than failing completely.