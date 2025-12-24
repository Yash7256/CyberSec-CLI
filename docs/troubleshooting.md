# Troubleshooting Guide

This guide provides solutions to common issues you may encounter when using CyberSec-CLI, along with performance tuning tips and frequently asked questions.

## Table of Contents

1. [Common Errors and Solutions](#common-errors-and-solutions)
2. [Performance Tuning](#performance-tuning)
3. [Debug Mode](#debug-mode)
4. [Log Locations](#log-locations)
5. [FAQ](#faq)

## Common Errors and Solutions

### Installation Issues

#### Problem: Permission Denied During Installation

**Error Message:**
```
PermissionError: [Errno 13] Permission denied: '/usr/local/lib/python3.x/site-packages/...'
```

**Solution:**
1. Use a virtual environment:
   ```bash
   python -m venv cybersec-env
   source cybersec-env/bin/activate  # On Windows: cybersec-env\Scripts\activate
   pip install cybersec-cli
   ```

2. Or install to user directory:
   ```bash
   pip install --user cybersec-cli
   ```

#### Problem: Missing System Dependencies

**Error Message:**
```
error: command 'gcc' failed with exit status 1
```

**Solution:**
Install system dependencies:
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y nmap python3-dev build-essential

# CentOS/RHEL
sudo yum install -y nmap python3-devel gcc

# macOS
brew install nmap
```

#### Problem: Package Conflicts

**Error Message:**
```
ERROR: Cannot install cybersec-cli because these package versions have conflicting dependencies.
```

**Solution:**
1. Create a clean virtual environment:
   ```bash
   python -m venv fresh-env
   source fresh-env/bin/activate
   pip install --upgrade pip
   pip install cybersec-cli
   ```

2. Or force reinstall:
   ```bash
   pip install --force-reinstall cybersec-cli
   ```

### Runtime Issues

#### Problem: Redis Connection Error

**Error Message:**
```
redis.exceptions.ConnectionError: Connection refused
```

**Solution:**
1. Start Redis server:
   ```bash
   # Using Docker
   docker run -d -p 6379:6379 redis:7-alpine
   
   # Using system package
   sudo systemctl start redis
   ```

2. Configure Redis URL:
   ```bash
   export REDIS_URL=redis://localhost:6379
   ```

3. Or disable Redis:
   ```bash
   export ENABLE_REDIS=false
   ```

#### Problem: Database Connection Error

**Error Message:**
```
sqlalchemy.exc.OperationalError: (sqlite3.OperationalError) unable to open database file
```

**Solution:**
1. Ensure directory exists:
   ```bash
   mkdir -p ~/.cybersec/data
   ```

2. Check permissions:
   ```bash
   chmod 755 ~/.cybersec
   chmod 644 ~/.cybersec/data/cybersec.db
   ```

#### Problem: Port Already in Use

**Error Message:**
```
OSError: [Errno 48] Address already in use
```

**Solution:**
1. Find the process using the port:
   ```bash
   lsof -i :8000
   ```

2. Kill the process:
   ```bash
   kill -9 <PID>
   ```

3. Or use a different port:
   ```bash
   # For web interface
   PORT=8001 cybersec web
   ```

### Scanning Issues

#### Problem: Nmap Not Found

**Error Message:**
```
FileNotFoundError: [Errno 2] No such file or directory: 'nmap'
```

**Solution:**
1. Install Nmap:
   ```bash
   # Ubuntu/Debian
   sudo apt-get install nmap
   
   # CentOS/RHEL
   sudo yum install nmap
   
   # macOS
   brew install nmap
   ```

2. Verify installation:
   ```bash
   nmap --version
   ```

#### Problem: Scan Times Out

**Error Message:**
```
nmap3.exceptions.NmapExecutionError: Nmap scan execution failed
```

**Solution:**
1. Increase timeout:
   ```bash
   cybersec
   scan example.com --timeout 5.0
   ```

2. Use fewer ports:
   ```bash
   scan example.com --top-ports
   ```

3. Check network connectivity:
   ```bash
   ping example.com
   ```

#### Problem: Rate Limit Exceeded

**Error Message:**
```
HTTPException: Rate limit exceeded. Please wait before making another request.
```

**Solution:**
1. Wait for the rate limit to reset (typically 1 minute)
2. Check your rate limit configuration
3. If you're an admin, use admin credentials to bypass limits

### Web Interface Issues

#### Problem: Web Interface Won't Start

**Error Message:**
```
uvicorn.errors.ServerError: Error loading ASGI app
```

**Solution:**
1. Check Python version (must be 3.10+):
   ```bash
   python --version
   ```

2. Verify dependencies:
   ```bash
   pip list | grep -E "(fastapi|uvicorn)"
   ```

3. Try direct execution:
   ```bash
   cd web
   python main.py
   ```

#### Problem: WebSocket Connection Fails

**Error Message:**
```
WebSocket connection to 'ws://localhost:8000/ws' failed
```

**Solution:**
1. Check API key configuration:
   ```bash
   export WEBSOCKET_API_KEY=your_api_key
   ```

2. Verify CORS settings:
   ```bash
   export ALLOWED_ORIGINS=http://localhost:8000,http://127.0.0.1:8000
   ```

3. Check firewall settings to ensure WebSocket connections are allowed

### AI Features Issues

#### Problem: OpenAI API Key Error

**Error Message:**
```
openai.error.AuthenticationError: Incorrect API key provided
```

**Solution:**
1. Verify API key is set:
   ```bash
   echo $OPENAI_API_KEY
   ```

2. Set the API key:
   ```bash
   export OPENAI_API_KEY=your_openai_api_key_here
   ```

3. Check for typos in the API key

#### Problem: AI Requests Timeout

**Error Message:**
```
openai.error.Timeout: Request timed out
```

**Solution:**
1. Check internet connectivity
2. Try again later (API might be temporarily unavailable)
3. Increase timeout settings if possible

## Performance Tuning

### System Resource Optimization

#### Memory Usage

1. **Reduce concurrent scans:**
   ```bash
   # Lower the max concurrent setting
   export MAX_CONCURRENT=5  # Default is 10
   ```

2. **Limit scan results:**
   ```bash
   # Use top ports instead of full port range
   scan example.com --top-ports
   ```

3. **Enable result compression:**
   ```bash
   # Results are automatically compressed in Redis
   # Consider using faster storage for Redis
   ```

#### CPU Usage

1. **Adjust concurrency based on CPU cores:**
   ```bash
   # For a 4-core system, use max 4 concurrent scans
   export MAX_CONCURRENT=4
   ```

2. **Use efficient scan methods:**
   ```bash
   # Fast scan methods use less CPU
   scan example.com --fast
   ```

#### Network Usage

1. **Adjust scan speed:**
   ```bash
   # Slower scans use less network bandwidth
   cybersec
   scan example.com --timeout 3.0
   ```

2. **Limit concurrent network connections:**
   ```bash
   # Reduce concurrent scans
   export MAX_CONCURRENT=2
   ```

### Database Performance

#### SQLite Optimization

1. **Use WAL mode for better concurrency:**
   ```bash
   # This is handled automatically by the application
   ```

2. **Regular maintenance:**
   ```bash
   # Vacuum the database periodically
   sqlite3 ~/.cybersec/data/cybersec.db "VACUUM;"
   ```

#### PostgreSQL Optimization (if using)

1. **Connection pooling:**
   ```bash
   # Configure connection pool in DATABASE_URL
   export DATABASE_URL="postgresql://user:pass@host:5432/db?pool_pre_ping=true"
   ```

2. **Index optimization:**
   ```sql
   -- The application creates necessary indexes automatically
   ```

### Redis Performance

#### Memory Management

1. **Set appropriate memory limits:**
   ```bash
   # In redis.conf
   maxmemory 2gb
   maxmemory-policy allkeys-lru
   ```

2. **Enable compression for large values:**
   ```bash
   # This is handled automatically by the application
   ```

#### Persistence

1. **Configure appropriate persistence:**
   ```bash
   # For development: RDB snapshot every 900 seconds
   save 900 1
   
   # For production: AOF for better durability
   appendonly yes
   ```

### Network Scanning Optimization

#### Port Scanning Speed

1. **Use appropriate timeout values:**
   ```bash
   # Shorter timeout for faster scans (less accurate)
   scan example.com --timeout 0.5
   
   # Longer timeout for more accurate results
   scan example.com --timeout 3.0
   ```

2. **Scan fewer ports when possible:**
   ```bash
   # Top ports scan is faster than full port scan
   scan example.com --top-ports
   ```

#### Adaptive Concurrency

The application automatically adjusts concurrency based on network conditions, but you can configure the parameters:

```bash
# Set minimum and maximum concurrent connections
export MIN_CONCURRENT=1
export MAX_CONCURRENT=10
```

## Debug Mode

### Enabling Debug Mode

#### CLI Debug Mode

```bash
# Run with debug flag
cybersec --debug

# Or set environment variable
export LOG_LEVEL=DEBUG
cybersec
```

#### Web Interface Debug Mode

```bash
# Set environment variable
export LOG_LEVEL=DEBUG
export DEBUG=true
cybersec web
```

### Debug Information

When in debug mode, you'll see:

1. **Detailed logging**: All internal operations are logged
2. **SQL queries**: Database queries with parameters
3. **API calls**: All external API calls with details
4. **Performance metrics**: Execution time for operations
5. **Memory usage**: Memory consumption tracking

### Debugging Specific Components

#### Scanning Debug

```bash
# Enable scanning debug
export SCAN_DEBUG=true
cybersec
scan example.com --verbose
```

#### Redis Debug

```bash
# Enable Redis debug
export REDIS_DEBUG=true
```

#### Database Debug

```bash
# Enable database debug
export DB_DEBUG=true
```

### Debugging with Docker

```bash
# Run with debug in Docker
docker run -it \
  -e LOG_LEVEL=DEBUG \
  -e DEBUG=true \
  cybersec/cli:latest cybersec --debug
```

## Log Locations

### Log File Locations

#### CLI Logs
- **Linux/macOS**: `~/.cybersec/logs/cli.log`
- **Windows**: `%USERPROFILE%\.cybersec\logs\cli.log`

#### Web Interface Logs
- **Linux/macOS**: `~/.cybersec/logs/web.log`
- **Windows**: `%USERPROFILE%\.cybersec\logs\web.log`

#### Scan Result Logs
- **Linux/macOS**: `~/.cybersec/logs/scans/`
- **Windows**: `%USERPROFILE%\.cybersec\logs\scans\`

### Log Rotation

Logs are automatically rotated:

- **Size-based**: Files are rotated when they reach 10MB
- **Time-based**: Daily rotation at midnight
- **Retention**: Keep last 30 days of logs

### Log Levels

#### Log Level Descriptions

- **DEBUG**: Detailed diagnostic information for troubleshooting
- **INFO**: General operational information
- **WARNING**: Potential issues that don't affect operation
- **ERROR**: Errors that occurred but didn't stop execution
- **CRITICAL**: Critical errors that may stop operation

### Viewing Logs

#### CLI Log Viewing

```bash
# View recent CLI logs
tail -f ~/.cybersec/logs/cli.log

# Search for specific errors
grep "ERROR" ~/.cybersec/logs/cli.log

# View logs with timestamps
cat ~/.cybersec/logs/cli.log | grep "$(date +%Y-%m-%d)"
```

#### Web Interface Log Viewing

```bash
# View recent web logs
tail -f ~/.cybersec/logs/web.log

# Monitor in real-time
watch -n 1 "tail -n 20 ~/.cybersec/logs/web.log"
```

#### Docker Log Viewing

```bash
# View Docker logs
docker logs <container_name>

# Follow logs in real-time
docker logs -f <container_name>

# View recent logs
docker logs --tail 50 <container_name>
```

### Log Analysis

#### Performance Analysis

```bash
# Find slow operations
grep "duration" ~/.cybersec/logs/web.log | sort -k6 -n

# Count error occurrences
grep "ERROR" ~/.cybersec/logs/cli.log | wc -l
```

#### Error Analysis

```bash
# Find unique error types
grep "ERROR" ~/.cybersec/logs/web.log | cut -d' ' -f5- | sort | uniq -c

# Find errors by time period
grep "$(date +%Y-%m-%d)" ~/.cybersec/logs/cli.log | grep "ERROR"
```

## FAQ

### General Questions

**Q: How do I update CyberSec-CLI?**
A: You can update using pip:
```bash
pip install --upgrade cybersec-cli
```
Or pull the latest Docker image:
```bash
docker pull cybersec/cli:latest
```

**Q: Is CyberSec-CLI free to use?**
A: Yes, CyberSec-CLI is open-source and free to use under the MIT license. However, some features like AI assistance require external API keys that may have usage costs.

**Q: Can I use CyberSec-CLI for commercial purposes?**
A: Yes, the tool is licensed under MIT which allows commercial use. However, always ensure you have proper authorization before scanning systems you don't own.

### Configuration Questions

**Q: How do I change the default theme?**
A: You can change the theme in the CLI:
```
theme set cyberpunk
```
Or set the environment variable:
```bash
export CYBERSEC_THEME=cyberpunk
```

**Q: Can I run CyberSec-CLI without Redis?**
A: Yes, set `ENABLE_REDIS=false`, but you'll lose caching and rate limiting features.

**Q: How do I configure the database connection?**
A: Set the `DATABASE_URL` environment variable:
```bash
export DATABASE_URL=postgresql://user:pass@localhost:5432/cybersec
```

### Scanning Questions

**Q: How can I scan a range of IP addresses?**
A: Currently, the tool scans one target at a time. You can script multiple scans:
```bash
for ip in 192.168.1.{1..10}; do
  cybersec scan $ip
done
```

**Q: What's the difference between --top-ports and --fast?**
A: `--top-ports` scans the 1000 most common ports, while `--fast` may use additional optimizations for quicker results.

**Q: How do I export scan results?**
A: Use the export command:
```
export example.com json
export example.com csv
export example.com pdf
```

### Web Interface Questions

**Q: How do I secure the web interface?**
A: 
1. Use HTTPS in production
2. Set strong API keys
3. Configure proper CORS settings
4. Use a reverse proxy with authentication
5. Limit access to trusted networks

**Q: Can multiple users access the web interface simultaneously?**
A: Yes, but each user should have their own API key for proper rate limiting and access control.

**Q: How do I backup scan results?**
A: The database and Redis contain scan results. Backup these regularly:
```bash
# Backup SQLite database
cp ~/.cybersec/data/cybersec.db /backup/location/

# Backup Redis data (if using RDB)
cp /var/lib/redis/dump.rdb /backup/location/
```

### Performance Questions

**Q: Why are my scans slow?**
A: Scans can be slow due to:
- Network latency
- Target system response time
- Too many concurrent scans
- Insufficient system resources
- Firewall or IDS interference

**Q: How can I speed up scans?**
A: 
- Reduce the number of ports scanned
- Use appropriate timeout values
- Ensure adequate system resources
- Scan during off-peak hours
- Use faster network connections

**Q: How much memory does CyberSec-CLI need?**
A: Minimum: 512MB, Recommended: 2GB+ for optimal performance with multiple concurrent scans.

### Troubleshooting Questions

**Q: Where are configuration files stored?**
A: Configuration is stored in `~/.cybersec/config.yaml` with logs in `~/.cybersec/logs/`.

**Q: How do I reset all settings to default?**
A: Remove the configuration directory:
```bash
rm -rf ~/.cybersec/config.yaml
```
The application will recreate defaults on next startup.

**Q: What should I do if I encounter a bug?**
A: 
1. Enable debug mode and reproduce the issue
2. Check logs for error messages
3. Search existing issues in the repository
4. Create a new issue with detailed information
5. Include version, environment, and steps to reproduce

### Security Questions

**Q: How are API keys stored and secured?**
A: API keys are stored as environment variables and in-memory only. They are never written to disk.

**Q: Is data encrypted?**
A: Data at rest is not encrypted by default. For sensitive data, consider encrypting the storage location or using encrypted volumes.

**Q: How do I audit access to the system?**
A: Check logs in `~/.cybersec/logs/` for access records. The system logs all API requests and user actions.