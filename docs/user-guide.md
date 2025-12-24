# User Guide

Welcome to the CyberSec-CLI user guide! This comprehensive guide will help you understand and effectively use both the CLI and web interfaces of the CyberSec-CLI tool.

## Table of Contents

1. [CLI Usage](#cli-usage)
2. [Web Interface](#web-interface)
3. [Configuration](#configuration)
4. [Advanced Features](#advanced-features)
5. [Troubleshooting](#troubleshooting)

## CLI Usage

### Installation

#### Prerequisites

Before installing CyberSec-CLI, ensure you have:

- Python 3.10 or higher
- pip package manager
- Nmap installed on your system
- Git (for source installation)

#### Installation Methods

**Option 1: Using pip (Recommended)**

```bash
pip install cybersec-cli
```

**Option 2: From Source**

```bash
git clone https://github.com/yourusername/cybersec-cli.git
cd cybersec-cli
pip install -r requirements.txt
pip install -e .
```

**Option 3: Using Docker**

```bash
docker pull cybersec/cli:latest
```

### Basic Commands

#### Starting the CLI

```bash
cybersec
```

This will launch the interactive shell where you can run commands.

#### Help System

```bash
help
```

This command provides information about available commands and their usage.

### Core Commands

#### Scan Commands

**Basic Scan:**
```bash
scan example.com
```

**Scan Specific Ports:**
```bash
scan example.com --ports 1-1000
scan example.com --ports 22,80,443,3389
```

**Advanced Scanning Options:**
```bash
# SSL/TLS certificate check
scan example.com --ssl

# OS detection
scan example.com --os

# Vulnerability scan
scan example.com --vuln

# Top ports scan (fast scan)
scan example.com --top-ports

# Fast scan (top ports only)
scan example.com --fast
```

#### AI Commands

**Ask Security Questions:**
```bash
ask "What is the difference between a vulnerability and an exploit?"
```

**Explain Security Concepts:**
```bash
explain "SSL certificate"
```

**Get Tool Suggestions:**
```bash
suggest nmap example.com
```

**Generate Security Reports:**
```bash
report example.com
```

#### Utility Commands

**Theme Management:**
```bash
# List available themes
theme list

# Set a theme
theme set matrix
theme set cyberpunk
theme set minimal
```

**Configuration Management:**
```bash
# Show current configuration
config show

# Edit configuration interactively
config edit
```

**Export Results:**
```bash
# Export scan results to various formats
export example.com json
export example.com csv
export example.com pdf
```

### Advanced Options

#### Port Ranges

CyberSec-CLI supports various port range formats:

```bash
# Single port
scan example.com --ports 80

# Port range
scan example.com --ports 1-1000

# Multiple ports
scan example.com --ports 22,80,443

# Multiple ranges
scan example.com --ports 1-100,443,8000-9000
```

#### Output Formats

You can customize the output format:

```bash
# JSON output
scan example.com --json

# Verbose output
scan example.com --verbose

# Quiet output (minimal)
scan example.com --quiet
```

### Output Formats

CyberSec-CLI supports multiple output formats:

- **Standard**: Rich text output with colors and formatting
- **JSON**: Structured JSON output for programmatic use
- **CSV**: Comma-separated values for spreadsheet import
- **XML**: XML format for integration with other tools

## Web Interface

### Accessing the Interface

The web interface can be accessed in multiple ways:

#### Using the CLI Command

```bash
cybersec web
```

#### Direct Execution

```bash
cd web
python main.py
```

#### Docker Execution

```bash
docker run -p 8000:8000 cybersec/cli:latest web
```

The web interface will be available at `http://localhost:8000` (or the configured port).

### Web Interface Features

#### Dashboard

The main dashboard provides:

- **Live scan results**: Real-time updates as scans progress
- **Scan history**: Previous scan results with timestamps
- **Performance metrics**: CPU, memory, and network usage
- **System status**: Redis, database, and API status indicators

#### Scan Interface

The scan interface allows you to:

- **Start new scans**: Enter targets and configure scan parameters
- **View live results**: See scan progress in real-time via Server-Sent Events
- **Export results**: Download results in various formats
- **Filter results**: Apply filters to scan results

#### API Access

The web interface provides a complete API with:

- **RESTful endpoints** for programmatic access
- **WebSocket support** for real-time communication
- **Comprehensive documentation** at `/docs`
- **API key management** for secure access

### Running Scans via Web Interface

1. Navigate to the scan page
2. Enter the target (IP address or domain)
3. Configure scan options:
   - Port range (e.g., "1-1000", "22,80,443", "top-ports")
   - Scan type (basic, SSL, OS detection, vulnerability)
   - Output format
4. Click "Start Scan"
5. Monitor results in real-time
6. Export results when complete

### Understanding Results

Scan results are displayed in a structured format:

#### Port Information
- **Port Number**: The port being scanned
- **State**: open, closed, filtered
- **Service**: Detected service name
- **Version**: Service version (if detected)

#### Service Detection
- **Service Name**: Name of the detected service
- **Product**: Product name and version
- **Extra Info**: Additional service information
- **Method**: Detection method used

#### Vulnerability Information
- **Severity**: Critical, High, Medium, Low
- **Description**: Vulnerability description
- **Recommendation**: How to address the vulnerability

### Exporting Reports

The web interface supports exporting scan results in multiple formats:

- **JSON**: Full structured data for programmatic use
- **CSV**: Tabular data for spreadsheet analysis
- **PDF**: Formatted report for sharing
- **XML**: Standard XML format for integration

To export:
1. Complete a scan or select a historical scan
2. Click the "Export" button
3. Select your preferred format
4. Download the file

## Configuration

### Environment Variables

CyberSec-CLI uses environment variables for configuration:

#### Authentication
- `OPENAI_API_KEY`: Your OpenAI API key for AI features
- `WEBSOCKET_API_KEY`: API key for WebSocket connections

#### Redis Configuration
- `REDIS_URL`: Redis connection URL (default: redis://localhost:6379)
- `REDIS_PASSWORD`: Redis password (optional)
- `REDIS_DB`: Redis database number (default: 0)
- `ENABLE_REDIS`: Enable/disable Redis (default: true)

#### Database Configuration
- `DATABASE_URL`: Database connection string (default: sqlite:///cybersec.db)

#### Web Interface Configuration
- `CYBERSEC_THEME`: Default theme (matrix, cyberpunk, minimal)
- `WS_RATE_LIMIT`: Rate limit for WebSocket connections (default: 5)
- `WS_CONCURRENT_LIMIT`: Concurrent connections limit (default: 2)
- `ALLOWED_ORIGINS`: Comma-separated list of allowed origins for CORS

#### Port Scanning Configuration
- `DEFAULT_TIMEOUT`: Default timeout for port scans (default: 1.0)
- `MAX_CONCURRENT`: Maximum concurrent scans (default: 10)
- `DEFAULT_PORTS`: Default port range (default: "top-ports")

### Configuration File

The configuration file is located at `~/.cybersec/config.yaml`:

```yaml
# CyberSec-CLI Configuration
general:
  theme: "matrix"
  language: "en"
  log_level: "INFO"

scanning:
  default_timeout: 1.0
  max_concurrent: 10
  default_ports: "top-ports"
  enable_service_detection: true
  enable_os_detection: false

redis:
  enabled: true
  url: "redis://localhost:6379"
  db: 0
  password: null

database:
  url: "sqlite:///cybersec.db"

api:
  websocket_rate_limit: 5
  websocket_concurrent_limit: 2
  allowed_origins:
    - "http://localhost:8000"
    - "http://127.0.0.1:8000"

ai:
  openai_api_key: "your-api-key-here"
```

### Common Configurations

#### Development Configuration

For development, you might want to:

- Set log level to DEBUG
- Use a local Redis instance
- Enable verbose output
- Use a test database

#### Production Configuration

For production, consider:

- Setting log level to WARNING or ERROR
- Using a secure Redis instance with authentication
- Using a production database (PostgreSQL/MySQL)
- Setting appropriate rate limits
- Using HTTPS and secure origins

## Advanced Features

### Caching System

CyberSec-CLI includes an intelligent caching system:

- **Automatic caching**: Scan results are automatically cached
- **TTL expiration**: Cache entries expire after a configurable time
- **Compression**: Large results are compressed to save space
- **Cache invalidation**: Manual and automatic cache clearing

### Rate Limiting

Advanced rate limiting features:

- **Sliding window**: Requests are tracked in a time window
- **Client-based limits**: Limits per client IP
- **Target-based limits**: Limits per target
- **Exponential backoff**: Progressive delays for violations
- **Admin bypass**: Administrative accounts bypass limits

### Adaptive Concurrency

The system automatically adjusts scanning concurrency:

- **Network responsiveness**: Adjusts based on network response time
- **Performance metrics**: Monitors scan performance
- **Dynamic adjustment**: Changes concurrency during scans
- **Resource utilization**: Considers system resources

### Service Detection

Advanced service detection capabilities:

- **Active probing**: Sends specific requests to identify services
- **Version detection**: Determines service versions
- **Fingerprinting**: Identifies service fingerprints
- **Banner grabbing**: Retrieves service banners

## Troubleshooting

### Common Issues

#### Installation Issues

**Problem**: Installation fails with permission errors
**Solution**: Use `pip install --user` or run in a virtual environment

**Problem**: Missing dependencies
**Solution**: Install system dependencies like Nmap first

#### Scanning Issues

**Problem**: Scans fail with connection errors
**Solution**: Check network connectivity and firewall settings

**Problem**: Slow scan performance
**Solution**: Adjust concurrency settings or check network conditions

#### Web Interface Issues

**Problem**: Web interface doesn't start
**Solution**: Check if port 8000 is available and not used by another service

**Problem**: WebSocket connections fail
**Solution**: Check API key configuration and CORS settings

### Debug Mode

To enable debug mode:

```bash
# CLI
cybersec --debug

# Web interface
export LOG_LEVEL=DEBUG
cybersec web
```

### Log Locations

Logs are stored in:

- **CLI logs**: `~/.cybersec/logs/cli.log`
- **Web logs**: `~/.cybersec/logs/web.log`
- **Scan logs**: `~/.cybersec/logs/scans/`

### Performance Tuning

For better performance:

- **Increase Redis memory**: Allocate more memory to Redis
- **Adjust concurrency**: Set appropriate concurrency levels
- **Use SSD storage**: For faster database operations
- **Monitor resources**: Keep an eye on CPU and memory usage

### FAQ

**Q: Can I scan multiple targets simultaneously?**
A: Yes, but be mindful of rate limits and system resources.

**Q: How do I update the tool?**
A: Use `pip install --upgrade cybersec-cli` or pull the latest Docker image.

**Q: Is my data secure?**
A: All data is stored locally by default, with optional cloud features that require explicit configuration.

**Q: Can I extend the functionality?**
A: Yes, the tool has an extensible architecture with plugin support.