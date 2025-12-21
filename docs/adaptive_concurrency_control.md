# Adaptive Concurrency Control

CyberSec-CLI includes an adaptive concurrency control system that automatically adjusts scanning speed based on network performance. This feature helps optimize scan performance while preventing network overload.

## How It Works

The adaptive concurrency control system monitors the success rate of connection attempts and dynamically adjusts two key parameters:

1. **Concurrency Level** - The number of simultaneous connections
2. **Timeout Duration** - How long to wait for a connection response

### Adjustment Logic

- **Low Success Rate (< 70%)**: Network is struggling
  - Reduce concurrency by 50%
  - Increase timeout by 0.5 seconds

- **High Success Rate (> 90%)**: Network is performing well
  - Increase concurrency by 50% (up to maximum of 500)
  - Reduce timeout by 0.2 seconds (down to minimum of 0.5 seconds)

- **Moderate Success Rate (70-90%)**: Network performance is acceptable
  - Maintain current settings

Adjustments are made after every 50 port attempts and all changes are logged with reasoning.

## Configuration Options

### Environment Variable

```bash
# Enable/disable adaptive scanning (default: true)
SCAN_ADAPTIVE_SCANNING=true
```

### CLI Flag

```bash
# Enable adaptive scanning
cybersec scan example.com --adaptive

# Disable adaptive scanning
cybersec scan example.com --no-adaptive
```

### Web Interface

In the web interface, there is a checkbox labeled "Adaptive scanning" that can be toggled to enable or disable this feature.

## Default Values

- **Initial Concurrency**: 50 connections
- **Initial Timeout**: 1.0 seconds
- **Maximum Concurrency**: 500 connections
- **Minimum Timeout**: 0.5 seconds
- **Adjustment Interval**: Every 50 port attempts

## Benefits

1. **Optimized Performance**: Automatically finds the optimal scanning speed for each target
2. **Network Protection**: Prevents overwhelming targets with too many concurrent connections
3. **Reliability**: Adapts to varying network conditions and target responsiveness
4. **Transparency**: All adjustments are logged for troubleshooting and analysis

## Example Scenarios

### Slow Network Target

When scanning a target with high latency or packet loss:
- Success rate drops below 70%
- Concurrency decreases from 50 to 25
- Timeout increases from 1.0s to 1.5s
- Results in more reliable but slower scanning

### Fast Network Target

When scanning a responsive target on a fast network:
- Success rate stays above 90%
- Concurrency increases from 50 to 75, then 112, up to maximum of 500
- Timeout decreases from 1.0s to 0.8s, then 0.6s, down to minimum of 0.5s
- Results in faster scanning with more concurrent connections

## Disabling Adaptive Control

If you prefer to manually control concurrency and timeout settings, you can disable adaptive control:

```bash
# Via environment variable
SCAN_ADAPTIVE_SCANNING=false

# Via CLI flag
cybersec scan example.com --no-adaptive --concurrent 100 --timeout 2.0
```

When disabled, the scanner will use fixed concurrency and timeout values as specified by the `--concurrent` and `--timeout` CLI flags or their default values.