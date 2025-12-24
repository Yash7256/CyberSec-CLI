# CyberSec-CLI Web Deployment - Public Website Edition

> Deploy CyberSec-CLI as a **public website** that anyone can access via browser

**Status**: ✅ Production-Ready  
**Accessibility**: 🌐 Public (anyone with URL can access)  
**Setup Time**: 15-30 minutes  
**Cost**: Free (your server only)  
**API Required**: ❌ No

---

## 🎯 Overview

This guide shows you how to deploy CyberSec-CLI as a **public website** where anyone can:
- ✅ Access via web browser
- ✅ Run port scans on targets
- ✅ View real-time results
- ✅ Export reports in multiple formats
- ✅ Use without installing anything locally

### Architecture Diagram

```
┌─────────────────────────────────────────────────────┐
│         Internet Users (Anyone)                     │
│      (Browser: http://your-domain.com)              │
└────────────────────┬────────────────────────────────┘
                     │ HTTPS (Secure)
                     ▼
┌─────────────────────────────────────────────────────┐
│  Nginx Reverse Proxy (Port 80/443)                  │
│  • SSL/TLS encryption                               │
│  • Rate limiting                                    │
│  • Security headers                                 │
│  • DDoS protection                                  │
└────────────────────┬────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────┐
│  CyberSec-CLI Web Server (Port 8000)                │
│  • FastAPI application                              │
│  • Real-time WebSocket                              │
│  • Security analysis                                │
│  • Report generation                                │
└─────────────────────────────────────────────────────┘
```

---

## 🚀 Deployment Methods

### Method 1: Docker (Recommended for Web)

**Setup Time**: 15 minutes  
**Requirements**: Docker, Docker Compose, domain (optional)

```bash
# 1. Clone repository
git clone https://github.com/Yash7256/cybersec-cli.git
cd cybersec-cli

# 2. Deploy with Docker
docker-compose up -d

# 3. Access at http://localhost:8000
# or http://your-server-ip:8000
```

### Method 2: Virtual Server (VPS / Cloud)

**Setup Time**: 20-30 minutes  
**Requirements**: Ubuntu/Debian server, domain (optional)

```bash
# 1. SSH into your server
ssh user@your-server.com

# 2. Clone and deploy
git clone https://github.com/Yash7256/cybersec-cli.git
cd cybersec-cli
sudo bash scripts/deploy.sh

# 3. Access at http://your-server-ip:8000
# or https://your-domain.com (with SSL)
```

### Method 3: Cloud Platforms

**Setup Time**: 10-15 minutes  
**Platforms**: AWS, DigitalOcean, Heroku, Render

See [Cloud Deployment](#-cloud-deployment-aws-digitalocean-heroku) section below.

---

## 🌐 Making It Publicly Accessible

### Option A: IP Address (Simplest)

Access via your server's IP:
```
http://192.168.1.100:8000
or
http://123.45.67.89:8000
```

**Pros**: Instant, no domain needed  
**Cons**: Not secure, hard to remember

### Option B: Domain Name (Best)

Access via your own domain:
```
https://cybersec.example.com
or
https://security-scanner.example.com
```

**Pros**: Professional, secure (HTTPS), easy to share  
**Cons**: Requires domain + SSL certificate

#### Setup Domain + SSL

**1. Get a Domain**
- Options: Namecheap, GoDaddy, Google Domains (~$10-15/year)
- Point your domain to your server's IP

**2. Get SSL Certificate (Free)**
```bash
# Using Let's Encrypt (automatic)
sudo apt-get update
sudo apt-get install certbot python3-certbot-nginx

# Generate certificate
sudo certbot certonly --standalone -d cybersec.example.com

# Auto-renew
sudo certbot renew --dry-run
```

**3. Update Nginx Configuration**
```nginx
server {
    listen 443 ssl http2;
    server_name cybersec.example.com;

    ssl_certificate /etc/letsencrypt/live/cybersec.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/cybersec.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name cybersec.example.com;
    return 301 https://$server_name$request_uri;
}
```

---

## 🔒 Security Configuration for Public Web

### 1. Rate Limiting (Prevent Abuse)

```nginx
# In nginx.conf
limit_req_zone $binary_remote_addr zone=api_limit:10m rate=10r/s;

location /api/ {
    limit_req zone=api_limit burst=20 nodelay;
    proxy_pass http://127.0.0.1:8000;
}
```

### 2. Authentication (Optional but Recommended)

Add user authentication to restrict access:

**Simple Token-Based Auth**
```python
# In web/main.py
from fastapi.security import HTTPBearer

security = HTTPBearer()

@app.get("/api/scan")
async def scan(credentials: HTTPAuthCredentials = Depends(security)):
    if credentials.credentials != "your-secret-token":
        raise HTTPException(status_code=401, detail="Unauthorized")
    # Run scan...
```

**Access via**:
```bash
curl -H "Authorization: Bearer your-secret-token" \
  http://localhost:8000/api/scan
```

### 3. IP Whitelist (For Private Access)

```nginx
location /api/ {
    # Allow only specific IPs
    allow 192.168.1.100;
    allow 10.0.0.0/8;
    deny all;
    
    proxy_pass http://127.0.0.1:8000;
}
```

### 4. DDoS Protection

**Using Cloudflare (Free)**
1. Sign up at cloudflare.com
2. Add your domain
3. Point DNS to Cloudflare
4. Enable DDoS protection

**Using fail2ban (Self-hosted)**
```bash
sudo apt-get install fail2ban

# Create /etc/fail2ban/jail.local
[cybersec-api]
enabled = true
port = http,https
filter = cybersec-api
logpath = /var/log/nginx/access.log
maxretry = 5
findtime = 600
bantime = 3600
```

### 5. Security Headers

```nginx
# Add to nginx.conf
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "no-referrer-when-downgrade" always;
add_header Content-Security-Policy "default-src 'self'" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
```

---

## 💻 Web Interface Features

### For End Users

Users can access the web interface to:

**1. Scan Targets**
```
Enter: IP address or domain
Select: Scan type (basic/full/custom)
Click: Start Scan
View: Real-time progress
```

**2. View Results**
```
Open ports
Services detected
Version information
Security recommendations
```

**3. Export Reports**
```
JSON format
CSV format
Table format
Markdown format
```

**4. History**
```
View previous scans
Re-run scans
Compare results
```

### REST API (For Developers)

```bash
# Start a scan
curl -X POST http://localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{
    "target": "example.com",
    "scan_type": "basic",
    "ports": "1-1000"
  }'

# Get scan status
curl http://localhost:8000/api/scan/123

# Get results
curl http://localhost:8000/api/scan/123/results

# Export as JSON
curl http://localhost:8000/api/scan/123/export?format=json
```

---

## 📊 Cloud Deployment Options

### AWS EC2 (Free Tier Eligible)

```bash
# 1. Launch EC2 instance (Ubuntu 22.04)
# 2. SSH into instance
ssh -i key.pem ubuntu@ec2-xxxxx.compute-1.amazonaws.com

# 3. Deploy
git clone https://github.com/Yash7256/cybersec-cli.git
cd cybersec-cli
sudo bash scripts/deploy.sh

# 4. Add security group rules
# Allow: HTTP (80), HTTPS (443)
# Allow: SSH (22) from your IP only

# 5. Get Elastic IP and point domain
# http://elastic-ip:8000
```

**Cost**: ~$5-10/month (free first year eligible)

### DigitalOcean (Simple & Cheap)

```bash
# 1. Create Droplet (Ubuntu 22.04, $5/month)
# 2. SSH into droplet
ssh root@your-droplet-ip

# 3. Deploy
git clone https://github.com/Yash7256/cybersec-cli.git
cd cybersec-cli
sudo bash scripts/deploy.sh

# 4. Create DNS record pointing to droplet
# cybersec.example.com → your-droplet-ip

# 5. Access
# https://cybersec.example.com
```

**Cost**: $5/month (smallest droplet)

### Render.com (Docker Native)

```bash
# 1. Connect GitHub repo to Render
# 2. Create web service
# 3. Set environment: PORT=8000
# 4. Deploy automatically
# 5. Access: https://cybersec-cli.onrender.com
```

**Cost**: $7/month (starter plan)

### Heroku

```bash
# 1. Install Heroku CLI
curl https://cli.heroku.com/install.sh | sh

# 2. Login
heroku login

# 3. Create app
heroku create cybersec-cli

# 4. Deploy
git push heroku main

# 5. Access
# https://cybersec-cli.herokuapp.com
```

**Cost**: $7/month (eco dyno)

---

## ⚙️ Configuration for Public Web

### Environment Variables

Create `.env` file:

```bash
# Web Configuration
WEB_HOST=0.0.0.0          # Listen on all interfaces
WEB_PORT=8000              # Internal port
WORKERS=4                  # Number of worker processes

# Security
RATE_LIMIT=100             # Requests per minute per IP
MAX_CONCURRENT_SCANS=10    # Limit simultaneous scans
SCAN_TIMEOUT=300           # 5 minutes per scan
MAX_PORTS=5000             # Max ports per scan

# Authentication (Optional)
REQUIRE_AUTH=false         # Enable authentication
API_TOKEN=your-secret-key  # If auth enabled

# Scanning Limits
MAX_TARGETS_PER_HOUR=1000
MAX_PORTS_PER_SCAN=5000
ALLOWED_DOMAINS=*          # Or comma-separated list

# Database (for storing results)
DATABASE_URL=sqlite:///./scans.db

# Logging
LOG_LEVEL=INFO
LOG_FILE=/var/log/cybersec/app.log
```

### Docker Compose for Web

```yaml
version: '3.8'

services:
  web:
    image: cybersec-cli:latest
    ports:
      - "8000:8000"
    environment:
      - WEB_HOST=0.0.0.0
      - WEB_PORT=8000
      - WORKERS=4
      - RATE_LIMIT=100
    restart: always
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
    volumes:
      - ./reports:/app/reports
      - ./logs:/app/logs
    networks:
      - cybersec-network

  nginx:
    image: nginx:latest
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - /etc/letsencrypt:/etc/letsencrypt:ro
    depends_on:
      - web
    restart: always
    networks:
      - cybersec-network

networks:
  cybersec-network:
    driver: bridge
```

---

## 📈 Monitoring & Analytics

### Health Checks

```bash
# Check if application is running
curl http://localhost:8000/health

# Response:
# {"status": "healthy", "uptime": 12345}
```

### Logging

```bash
# View logs
docker-compose logs -f web

# Or systemd
sudo journalctl -u cybersec-web -f
```

### Metrics

Monitor:
- **Response time**: < 5 seconds
- **Error rate**: < 1%
- **Concurrent users**: Track in logs
- **Scan success rate**: Monitor database
- **API usage**: Track requests

### Backup Scans

```bash
# Backup scan results
docker-compose exec web bash -c "cp -r /app/reports /backup/$(date +%Y%m%d)"

# Or automated backup
0 2 * * * docker-compose -f /path/to/docker-compose.yml exec web \
  bash -c "cp -r /app/reports /backup/$(date +%Y%m%d)" 2>/dev/null
```

---

## 🚨 Troubleshooting Web Deployment

### Port Already in Use

```bash
# Find what's using port 8000
lsof -i :8000

# Kill the process
kill -9 <PID>

# Or use different port in docker-compose
ports:
  - "9000:8000"  # Access at :9000
```

### SSL Certificate Issues

```bash
# Check certificate
sudo certbot certificates

# Renew certificate
sudo certbot renew

# Force renewal
sudo certbot renew --force-renewal
```

### High CPU Usage

```bash
# Monitor resource usage
docker stats

# Reduce worker count
WORKERS=2  # In .env

# Limit concurrent scans
MAX_CONCURRENT_SCANS=5  # In .env
```

### Database Connection Issues

```bash
# Check database exists
ls -la scans.db

# Backup and reset database
cp scans.db scans.db.backup
rm scans.db

# Restart to recreate
docker-compose restart web
```

### Slow Scans

```bash
# Check network
ping -c 4 8.8.8.8

# Check DNS
nslookup google.com

# Increase timeout
SCAN_TIMEOUT=600  # 10 minutes in .env
```

---

## 📋 Deployment Checklist

### Pre-Deployment
- [ ] Server/hosting account created
- [ ] Domain name registered (optional)
- [ ] DNS configured
- [ ] SSH access verified
- [ ] Docker installed (if using Docker)
- [ ] Port 80/443 open in firewall

### Deployment
- [ ] Repository cloned
- [ ] Environment variables configured
- [ ] SSL certificate generated (if using domain)
- [ ] Application deployed
- [ ] Health check passing
- [ ] Can access via URL

### Post-Deployment
- [ ] Website accessible to public
- [ ] HTTPS working (if domain)
- [ ] Rate limiting active
- [ ] Logging working
- [ ] Backups configured
- [ ] Monitoring setup
- [ ] Security headers verified

---

## 🔐 Security Best Practices

### Do's ✅
- ✅ Use HTTPS (SSL/TLS)
- ✅ Enable rate limiting
- ✅ Regular backups
- ✅ Keep software updated
- ✅ Monitor logs
- ✅ Use strong authentication
- ✅ Hide sensitive info in .env
- ✅ Use firewall rules
- ✅ Enable DDoS protection

### Don'ts ❌
- ❌ Use HTTP without HTTPS
- ❌ Disable rate limiting
- ❌ Ignore security updates
- ❌ Commit secrets to git
- ❌ Run as root
- ❌ Allow unlimited scan duration
- ❌ Expose internal IPs
- ❌ Disable logging
- ❌ Trust all input

---

## 📊 Expected Performance

### Capacity

| Metric | Value |
|--------|-------|
| **Concurrent Users** | 50-100 |
| **Scans/hour** | 500-1000 |
| **Response Time** | 2-5 seconds |
| **Uptime** | 99.9% |
| **Data Transfer** | 10-50 GB/month |

### Server Requirements

| Metric | Minimum | Recommended |
|--------|---------|-------------|
| **CPU** | 1 core | 2-4 cores |
| **RAM** | 2 GB | 4-8 GB |
| **Storage** | 10 GB | 50-100 GB |
| **Bandwidth** | 1 Mbps | 10+ Mbps |

---

## 💰 Cost Breakdown

### Domain (Optional)
- Domain name: ~$10-15/year
- SSL certificate: Free (Let's Encrypt)

### Hosting
- VPS (DigitalOcean): $5-20/month
- AWS EC2: $5-20/month
- Heroku: $7-50/month

### Total: $5-50/month

---

## 🎯 Quick Start (Docker)

```bash
# 1. Clone
git clone https://github.com/Yash7256/cybersec-cli.git
cd cybersec-cli

# 2. Configure (optional)
cp .env.example .env
nano .env  # Adjust settings

# 3. Deploy
docker-compose up -d

# 4. Access
open http://localhost:8000
# Or: http://your-server-ip:8000

# 5. View logs
docker-compose logs -f web

# 6. Stop
docker-compose down
```

---

## 📖 Next Steps

1. **Choose deployment method** (Docker, VPS, Cloud)
2. **Setup infrastructure** (Server, domain, SSL)
3. **Deploy application** (Run scripts)
4. **Configure security** (Rate limiting, auth, SSL)
5. **Test publicly** (Share URL with others)
6. **Monitor & maintain** (Check logs, update)

---

## 🆘 Support

**Documentation**:
- [DEPLOYMENT.md](DEPLOYMENT.md) - Full reference
- [DEPLOYMENT_NO_API.md](DEPLOYMENT_NO_API.md) - No-API setup
- [INDEX.md](INDEX.md) - Navigation

**Troubleshooting**:
- Check logs: `docker-compose logs web`
- Test endpoint: `curl http://localhost:8000/health`
- Verify network: `curl -I http://your-domain.com`

---

## ✨ Summary

Your CyberSec-CLI can now be deployed as a **public website** where:
- ✅ Anyone can access via browser
- ✅ No installation needed
- ✅ Real-time scanning & analysis
- ✅ Professional & secure
- ✅ Affordable to host
- ✅ Easy to scale

Choose your deployment method and get started! 🚀

