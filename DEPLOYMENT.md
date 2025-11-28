# CyberSec-CLI Deployment Guide

This guide covers deploying the CyberSec-CLI application in various environments.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Local Development](#local-development)
3. [Production Deployment](#production-deployment)
4. [Docker Deployment](#docker-deployment)
5. [Web Interface Deployment](#web-interface-deployment)
6. [CLI Tool Deployment](#cli-tool-deployment)
7. [Configuration](#configuration)
8. [Security Considerations](#security-considerations)
9. [Troubleshooting](#troubleshooting)

## Prerequisites

- **Python 3.10+** (recommended: 3.11+)
- **pip** (latest version)
- **Git** (for cloning the repository)
- **Docker & Docker Compose** (optional, for containerized deployment)
- **Virtual Environment Tools** (venv or conda)
- **OpenAI API Key** (OPTIONAL - for advanced GPT-4 analysis)

### System Requirements

- **Minimum**: 2GB RAM, 2 CPU cores
- **Recommended**: 4GB RAM, 4 CPU cores
- **Storage**: 500MB for application + dependencies
- **Network**: Optional outbound HTTPS for OpenAI API (only if using AI features)

## Local Development

### 1. Clone the Repository

```bash
git clone https://github.com/Yash7256/cybersec-cli.git
cd cybersec-cli
```

### 2. Create and Activate Virtual Environment

Using venv:
```bash
python3.10 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

Using conda:
```bash
conda create -n cybersec python=3.10
conda activate cybersec
```

### 3. Install Dependencies

```bash
# Install both CLI and web server dependencies
pip install -r requirements.txt
pip install -r web/requirements.txt

# Or install in development mode
pip install -e .
```

### 4. Set Environment Variables

Create a `.env` file in the project root:

```bash
cat > .env << 'EOF'
# OpenAI Configuration
OPENAI_API_KEY=your_api_key_here

# CLI Settings
CYBERSEC_THEME=matrix  # Options: matrix, cyberpunk, minimal
UI_SHOW_BANNER=true
UI_COLOR_OUTPUT=true

# Scanning Configuration
SCAN_DEFAULT_TIMEOUT=2
SCAN_MAX_THREADS=50
SCAN_RATE_LIMIT=10

# Output Configuration
OUTPUT_DEFAULT_FORMAT=table  # Options: table, json, csv, markdown
OUTPUT_SAVE_RESULTS=true
OUTPUT_EXPORT_PATH=./reports/

# Security
SECURITY_REQUIRE_CONFIRMATION=true
SECURITY_LOG_ALL_COMMANDS=true
SECURITY_ENCRYPT_STORED_DATA=true
EOF
```

### 5. Run the Application

**CLI Mode (Interactive)**:
```bash
python -m cybersec_cli
# Or use the console script (after installation)
cybersec
```

**Web Interface**:
```bash
cd web
python main.py
# Access at http://localhost:8000
```

**Specific Commands**:
```bash
# Run a scan
python -m cybersec_cli scan example.com

# Run with verbose output
python -m cybersec_cli --verbose scan example.com

# Enable debug mode
python -m cybersec_cli --debug scan example.com
```

## Production Deployment

### 1. System Preparation

```bash
# Update system packages
sudo apt-get update && sudo apt-get upgrade -y

# Install system dependencies
sudo apt-get install -y python3.10 python3-pip python3-venv \
    git curl wget build-essential libssl-dev libffi-dev

# Install nmap (if using advanced scanning features)
sudo apt-get install -y nmap
```

### 2. Create Application User

```bash
# Create a dedicated user for the application
sudo useradd -m -s /bin/bash cybersec
sudo su - cybersec
```

### 3. Deploy the Application

```bash
# Clone repository
git clone https://github.com/Yash7256/cybersec-cli.git
cd cybersec-cli

# Create virtual environment
python3.10 -m venv venv
source venv/bin/activate

# Install dependencies
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
pip install -r web/requirements.txt
pip install -e .

# Create necessary directories
mkdir -p ~/.cybersec/models
mkdir -p reports
```

### 4. Configure Production Environment

```bash
# Create .env file with production settings
cat > ~/.cybersec/.env << 'EOF'
OPENAI_API_KEY=your_production_api_key
CYBERSEC_THEME=matrix
UI_SHOW_BANNER=true
SCAN_DEFAULT_TIMEOUT=5
SCAN_MAX_THREADS=25
SECURITY_LOG_ALL_COMMANDS=true
SECURITY_ENCRYPT_STORED_DATA=true
OUTPUT_SAVE_RESULTS=true
OUTPUT_EXPORT_PATH=/var/log/cybersec/reports/
EOF

# Restrict permissions
chmod 600 ~/.cybersec/.env
```

### 5. Set Up Systemd Service (for CLI daemon)

Create `/etc/systemd/system/cybersec-cli.service`:

```ini
[Unit]
Description=CyberSec CLI Service
After=network.target

[Service]
Type=simple
User=cybersec
WorkingDirectory=/home/cybersec/cybersec-cli
Environment="PATH=/home/cybersec/cybersec-cli/venv/bin"
EnvironmentFile=/home/cybersec/.cybersec/.env
ExecStart=/home/cybersec/cybersec-cli/venv/bin/python -m cybersec_cli
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Enable and start the service
sudo systemctl daemon-reload
sudo systemctl enable cybersec-cli
sudo systemctl start cybersec-cli
```

### 6. Set Up Systemd Service (for Web Interface)

Create `/etc/systemd/system/cybersec-web.service`:

```ini
[Unit]
Description=CyberSec Web Interface
After=network.target

[Service]
Type=simple
User=cybersec
WorkingDirectory=/home/cybersec/cybersec-cli/web
Environment="PATH=/home/cybersec/cybersec-cli/venv/bin"
EnvironmentFile=/home/cybersec/.cybersec/.env
ExecStart=/home/cybersec/cybersec-cli/venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Enable and start the service
sudo systemctl daemon-reload
sudo systemctl enable cybersec-web
sudo systemctl start cybersec-web
```

### 7. Configure Nginx Reverse Proxy

Create `/etc/nginx/sites-available/cybersec`:

```nginx
upstream cybersec_web {
    server 127.0.0.1:8000;
}

server {
    listen 80;
    server_name cybersec.example.com;
    
    # Redirect to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name cybersec.example.com;

    # SSL Configuration
    ssl_certificate /etc/letsencrypt/live/cybersec.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/cybersec.example.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    client_max_body_size 10M;

    # Gzip compression
    gzip on;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml;

    location / {
        proxy_pass http://cybersec_web;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_redirect off;
    }

    location /ws/ {
        proxy_pass http://cybersec_web;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    # Deny access to sensitive files
    location ~ /\.env {
        deny all;
    }
}
```

Enable the site:
```bash
sudo ln -s /etc/nginx/sites-available/cybersec /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

### 8. Set Up SSL Certificate (Let's Encrypt)

```bash
sudo apt-get install -y certbot python3-certbot-nginx
sudo certbot certonly --nginx -d cybersec.example.com
```

## Docker Deployment

### 1. Build Docker Image

The Docker image can be built using the provided Dockerfile:

```bash
docker build -t cybersec-cli:latest .
```

### 2. Run Container (CLI)

```bash
docker run -it --rm \
  -e OPENAI_API_KEY=your_api_key \
  -v $(pwd)/reports:/app/reports \
  cybersec-cli:latest
```

### 3. Run Container (Web)

```bash
docker run -d \
  -e OPENAI_API_KEY=your_api_key \
  -p 8000:8000 \
  -v $(pwd)/reports:/app/reports \
  --name cybersec-web \
  cybersec-cli:latest python web/main.py
```

### 4. Docker Compose

Create `docker-compose.yml`:

```yaml
version: '3.8'

services:
  cybersec-web:
    build: .
    container_name: cybersec-web
    ports:
      - "8000:8000"
    environment:
      OPENAI_API_KEY: ${OPENAI_API_KEY}
      CYBERSEC_THEME: matrix
      OUTPUT_SAVE_RESULTS: "true"
    volumes:
      - ./reports:/app/reports
      - ./logs:/app/logs
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/api/status"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

  nginx:
    image: nginx:alpine
    container_name: cybersec-nginx
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./certs:/etc/nginx/certs:ro
      - ./logs/nginx:/var/log/nginx
    depends_on:
      - cybersec-web
    restart: unless-stopped

volumes:
  reports:
  logs:
```

Run with Docker Compose:
```bash
docker-compose up -d
```

## Web Interface Deployment

### Standalone Web Server

```bash
cd web
uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4
```

### With Gunicorn (for WSGI compatibility)

```bash
pip install gunicorn
gunicorn -w 4 -k uvicorn.workers.UvicornWorker main:app --bind 0.0.0.0:8000
```

### Production-Grade Setup with Supervisor

Create `/etc/supervisor/conf.d/cybersec-web.conf`:

```ini
[program:cybersec-web]
command=/home/cybersec/cybersec-cli/venv/bin/uvicorn web.main:app --host 127.0.0.1 --port 8000
directory=/home/cybersec/cybersec-cli
user=cybersec
autostart=true
autorestart=true
redirect_stderr=true
stdout_logfile=/var/log/cybersec/web.log
```

## CLI Tool Deployment

### Install as System Command

```bash
# From the project directory
pip install -e .

# Verify installation
which cybersec
cybersec --version
```

### Create System-Wide Installation

```bash
# Copy to system location
sudo cp -r /home/cybersec/cybersec-cli /opt/cybersec-cli

# Create symlink
sudo ln -s /opt/cybersec-cli/venv/bin/cybersec /usr/local/bin/cybersec

# Verify
cybersec --help
```

## Configuration

### Configuration File Location

The configuration file is stored at: `~/.cybersec/config.yaml`

### Environment Variables

All configuration can be overridden using environment variables:

```bash
# Theme
CYBERSEC_THEME=cyberpunk

# AI Configuration
AI_PROVIDER=openai
AI_MODEL=gpt-4
AI_TEMPERATURE=0.7
AI_MAX_TOKENS=2000

# Scanning
SCAN_DEFAULT_TIMEOUT=5
SCAN_MAX_THREADS=50
SCAN_RATE_LIMIT=10

# Output
OUTPUT_DEFAULT_FORMAT=json
OUTPUT_SAVE_RESULTS=true
OUTPUT_EXPORT_PATH=/var/reports/

# Security
SECURITY_LOG_ALL_COMMANDS=true
SECURITY_ENCRYPT_STORED_DATA=true
```

## Security Considerations

### 1. API Key Management

- Never commit `.env` files to version control
- Use AWS Secrets Manager, HashiCorp Vault, or similar for production
- Rotate API keys regularly
- Restrict API key permissions at the provider level

### 2. Network Security

- Always use HTTPS/TLS in production
- Implement firewall rules to restrict access
- Use VPN for remote access
- Enable rate limiting and DDoS protection

### 3. Access Control

- Run the application with minimal required privileges
- Implement authentication for the web interface
- Use SSH keys for remote access (no passwords)
- Regularly audit user access and permissions

### 4. Logging and Monitoring

- Enable comprehensive logging
- Set up centralized log collection (ELK stack, Splunk)
- Monitor for suspicious activities
- Set up alerts for critical events

### 5. Compliance

- Run only on authorized systems
- Obtain proper authorization before performing scans
- Keep audit logs for compliance
- Review logs regularly for security events

## Troubleshooting

### Issue: Import Errors

```bash
# Clear Python cache
find . -type d -name __pycache__ -exec rm -r {} +
rm -rf build dist *.egg-info

# Reinstall dependencies
pip install --upgrade --force-reinstall -r requirements.txt
```

### Issue: OpenAI API Key Not Working

```bash
# Verify the key is set
echo $OPENAI_API_KEY

# Test the connection
python -c "import openai; openai.api_key = 'your_key'; print('Connected')"
```

### Issue: Port Already in Use

```bash
# Find process using port 8000
lsof -i :8000

# Kill the process
kill -9 <PID>

# Or use a different port
uvicorn web.main:app --port 8001
```

### Issue: Permission Denied (Scanning)

Some scanning features require elevated privileges:

```bash
# For TCP SYN scans
sudo python -m cybersec_cli scan example.com --scan-type tcp_syn

# Or run the container with root
docker run --rm -it --user root cybersec-cli:latest
```

### Issue: Database Connection Errors

```bash
# Reset database
rm ~/.cybersec/cybersec.db

# The application will recreate it on next run
```

### Check Application Logs

```bash
# Systemd service logs
sudo journalctl -u cybersec-web -f

# Docker logs
docker logs -f cybersec-web

# Application logs
tail -f logs/cybersec.log
```

## Performance Optimization

### Database Optimization

```sql
-- Create indexes for faster queries
CREATE INDEX idx_scan_results_timestamp ON scan_results(timestamp);
CREATE INDEX idx_findings_severity ON findings(severity);
```

### Caching

```python
# Redis caching (optional)
pip install redis
```

### Load Balancing

Use multiple instances behind a load balancer:

```nginx
upstream cybersec_backend {
    server 127.0.0.1:8000;
    server 127.0.0.1:8001;
    server 127.0.0.1:8002;
}
```

## Scaling

### Horizontal Scaling

1. Deploy multiple instances
2. Use load balancer (Nginx, HAProxy)
3. Share configuration via network storage
4. Use centralized database for results

### Vertical Scaling

1. Increase CPU and RAM
2. Optimize database queries
3. Enable caching layer (Redis)
4. Use connection pooling

## Backup and Recovery

### Create Backups

```bash
# Backup configuration
tar -czf cybersec-config-backup.tar.gz ~/.cybersec/

# Backup reports and results
tar -czf cybersec-reports-backup.tar.gz reports/

# Full application backup
tar -czf cybersec-full-backup.tar.gz cybersec-cli/
```

### Restore from Backup

```bash
# Restore configuration
tar -xzf cybersec-config-backup.tar.gz -C ~/

# Restore reports
tar -xzf cybersec-reports-backup.tar.gz -C ./
```

## Next Steps

- [Contributing Guidelines](CONTRIBUTING.md)
- [API Documentation](docs/API.md)
- [User Guide](docs/USER_GUIDE.md)
- [Troubleshooting Guide](docs/TROUBLESHOOTING.md)

## Support

For issues and questions:
- GitHub Issues: https://github.com/Yash7256/cybersec-cli/issues
- Documentation: https://cybersec-cli.readthedocs.io/
- Email: support@cybersec-cli.example.com

---

**Last Updated**: 2025-11-28
**Version**: 0.1.0
