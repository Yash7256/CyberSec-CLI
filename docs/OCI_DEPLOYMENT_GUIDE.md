# 🌐 Oracle Cloud Infrastructure (OCI) Free Tier Deployment Guide

## 📋 Table of Contents
- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [OCI Free Tier Limitations](#oci-free-tier-limitations)
- [Architecture](#architecture)
- [Step-by-Step Deployment](#step-by-step-deployment)
- [Security Configuration](#security-configuration)
- [Post-Deployment Verification](#post-deployment-verification)
- [Monitoring & Maintenance](#monitoring--maintenance)
- [Troubleshooting](#troubleshooting)
- [Scaling Considerations](#scaling-considerations)

---

## Overview

This guide provides comprehensive instructions for deploying CyberSec-CLI on Oracle Cloud Infrastructure (OCI) Free Tier. The CyberSec-CLI is a powerful cybersecurity scanning and analysis tool that includes a web interface, real-time scanning capabilities, AI-powered analysis, and comprehensive reporting features.

### Features Included:
- 🕵️ Real-time port scanning
- 🔍 Service detection and vulnerability assessment
- 🤖 AI-powered analysis (GROQ/Grok integration)
- 📊 Web interface with WebSocket support
- 📈 Real-time monitoring and metrics
- 🛡️ Security hardening features
- 🔄 Task queue with Celery workers
- 💾 PostgreSQL database integration
- 🧠 Redis caching and session storage

### Benefits of OCI Free Tier:
- ✅ Always-free resources (2 VMs, 4 vCPUs, 24GB RAM)
- ✅ High availability and reliability
- ✅ Global presence with multiple regions
- ✅ Strong security posture
- ✅ Integration with Oracle ecosystem

---

## Prerequisites

### Before You Begin
- [ ] Oracle Cloud account (sign up at https://www.oracle.com/cloud/free/)
- [ ] Valid credit card (required for verification, but you won't be charged for Free Tier usage)
- [ ] SSH key pair for secure access
- [ ] GitHub account with repository access
- [ ] API keys for AI services (OpenAI, GROQ, Grok - optional but recommended)

### Required Skills
- [ ] Basic Linux command line knowledge
- [ ] Understanding of Docker and containerization
- [ ] Familiarity with networking concepts
- [ ] Basic knowledge of security groups and firewalls

---

## OCI Free Tier Limitations

### Always-Free Resources (Per Region)
- **Compute**: 2 VMs (each with 1/8 OCPU and 1 GB memory)
- **Block Volume**: 20 GB total
- [ ] **Object Storage**: 10 GB
- [ ] **Load Balancer**: 10 Mbps bandwidth
- [ ] **Bandwidth**: 10 TB/month egress
- [ ] **Database**: Autonomous Database (1 OCPU, 1 TB storage)

### Important Notes
- [ ] VMs must be stopped manually if you need to stay within free tier
- [ ] Monitor usage through OCI Console to avoid charges
- [ ] Free tier resources are region-specific
- [ ] Some advanced features may incur costs beyond free tier

---

## Architecture

### CyberSec-CLI on OCI Components

```
┌─────────────────────────────────────────────────────────────┐
│                    OCI Infrastructure                       │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────┐ │
│  │   Load Balancer │  │   Web App VM    │  │  Database VM │ │
│  │     (Public)    │  │    (Private)    │  │   (Private)  │ │
│  └─────────────────┘  └─────────────────┘  └──────────────┘ │
│         │                      │                  │         │
│         │                ┌─────▼─────┐            │         │
│         └────────────────►  Firewall │◄───────────┘         │
│                          └───────────┘                      │
│                                                             │
│  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────┐ │
│  │   Redis Cache   │  │  Celery Worker  │  │  Prometheus  │ │
│  │   (Container)   │  │   (Container)   │  │   (Container)│ │
│  └─────────────────┘  └─────────────────┘  └──────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

### Network Layout
- **Public Subnet**: Load Balancer and public-facing services
- **Private Subnet**: Application servers, databases, caches
- **Security Groups**: Fine-grained network access control

---

## Step-by-Step Deployment

### Phase 1: OCI Setup

#### 1. Create Oracle Cloud Account
```bash
# 1. Navigate to https://www.oracle.com/cloud/free/
# 2. Click "Start for Free"
# 3. Enter your email and phone number for verification
# 4. Provide credit card information (you won't be charged for Free Tier)
# 5. Verify your phone number via SMS
# 6. Complete the registration process
```

#### 2. Create Compartment (Optional but Recommended)
```bash
# 1. Login to OCI Console
# 2. Navigate to Identity & Security → Compartments
# 3. Click "Create Compartment"
# 4. Name: "CyberSec-CLI-Compartment"
# 5. Description: "Compartment for CyberSec-CLI deployment"
# 6. Click "Create Compartment"
```

#### 3. Generate SSH Keys (if you don't have them)
```bash
# On your local machine
ssh-keygen -t rsa -b 2048 -f ~/.ssh/oci-cybersec -C "cybersec-deployment"
```

#### 4. Upload Public Key to OCI
```bash
# 1. Go to Profile → API Keys
# 2. Click "Add Public Key"
# 3. Paste contents of ~/.ssh/oci-cybersec.pub
# 4. Click "Add"
```

### Phase 2: Virtual Machine Setup

#### 5. Launch Compute Instance

1. **Navigate to Compute → Instances**
2. **Click "Create Instance"**
3. **Configure the instance:**

   **Name and Placement:**
   - Name: `cybersec-app-server`
   - Compartment: Select your compartment
   - Availability Domain: Choose any available domain

   **Image and Shape:**
   - Image: Oracle Linux 8.x (or Ubuntu 22.04 LTS)
   - Shape: VM.Standard.E2.1.Micro (Free Tier eligible)

   **Networking:**
   - Virtual Cloud Network Compartment: Select your compartment
   - Network: Create new VCN "cybersec-vcn"
   - Subnet: Create new subnet (public)
   - Assign a public IP: Yes

   **Add SSH Keys:**
   - Paste your public key (~/.ssh/oci-cybersec.pub)

4. **Click "Create"**

#### 6. Create Security Lists (Firewall Rules)

In the OCI Console:
1. Navigate to Networking → Virtual Cloud Networks
2. Click on your VCN "cybersec-vcn"
3. Go to "Security Lists"
4. Edit the default security list and add these ingress rules:

```
Type: Stateful
Source: 0.0.0.0/0
Protocol: TCP
Source Port Range: All
Destination Port Range: 22 (SSH)
Description: SSH Access

Type: Stateful
Source: 0.0.0.0/0
Protocol: TCP
Source Port Range: All
Destination Port Range: 80 (HTTP)
Description: HTTP Access

Type: Stateful
Source: 0.0.0.0/0
Protocol: TCP
Source Port Range: All
Destination Port Range: 443 (HTTPS)
Description: HTTPS Access

Type: Stateful
Source: 0.0.0.0/0
Protocol: TCP
Source Port Range: All
Destination Port Range: 8000 (Web Interface)
Description: CyberSec-CLI Web Interface
```

### Phase 3: Application Setup

#### 7. Connect to Your Instance
```bash
# SSH to your instance
ssh -i ~/.ssh/oci-cybersec opc@YOUR_INSTANCE_PUBLIC_IP

# Update system packages
sudo yum update -y  # For Oracle Linux
# OR
sudo apt update && sudo apt upgrade -y  # For Ubuntu
```

#### 8. Install Prerequisites
```bash
# For Oracle Linux
sudo yum install -y docker git curl python3 python3-pip python3-devel gcc openssl-devel libffi-devel make

# For Ubuntu
sudo apt install -y docker.io git curl python3 python3-pip python3-dev build-essential libssl-dev libffi-dev

# Start and enable Docker
sudo systemctl start docker
sudo systemctl enable docker

# Add current user to docker group
sudo usermod -aG docker $USER
newgrp docker
```

#### 9. Clone the Repository
```bash
# Clone the CyberSec-CLI repository
git clone https://github.com/Yash7256/cybersec-cli.git
cd cybersec-cli

# Copy environment file
cp .env.example .env
```

#### 10. Configure Environment Variables
```bash
# Edit the .env file
nano .env
```

**Essential Environment Variables:**
```
# Database Configuration (using SQLite for Free Tier - alternatively can use Oracle Autonomous Database)
DATABASE_URL=sqlite:///./cybersec.db

# Redis Configuration (local for now, can be upgraded later)
REDIS_URL=redis://localhost:6379

# Security Configuration
WEBSOCKET_API_KEY=your-very-secure-api-key-here
SECRET_KEY=your-very-long-secret-key-here

# Optional: AI Service Keys (for enhanced analysis)
OPENAI_API_KEY=your_openai_api_key
GROQ_API_KEY=your_groq_api_key
```

#### 11. Build and Deploy Using Docker Compose
```bash
# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Build and start the application
sudo docker-compose up -d --build
```

#### 12. Alternative: Manual Installation (Without Docker)
```bash
# Install Python dependencies
pip3 install -r requirements.txt
pip3 install -r web/requirements.txt

# Install the package
pip3 install -e .

# Initialize database
python3 scripts/init_db.py

# Start the web application
python3 -m uvicorn web.main:app --host 0.0.0.0 --port 8000
```

### Phase 4: Production Configuration

#### 13. Set Up Reverse Proxy with Nginx
```bash
# Install Nginx
sudo yum install nginx  # Oracle Linux
# OR
sudo apt install nginx  # Ubuntu

# Configure Nginx
sudo nano /etc/nginx/sites-available/cybersec
```

**Nginx Configuration:**
```
server {
    listen 80;
    server_name YOUR_DOMAIN_OR_IP;

    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        
        # Timeout settings
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    location /static/ {
        alias /home/opc/cybersec-cli/web/static/;
        expires 1d;
        add_header Cache-Control "public, immutable";
    }
}
```

```bash
# Enable the site
sudo ln -s /etc/nginx/sites-available/cybersec /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
sudo systemctl enable nginx
```

#### 14. SSL Certificate Setup (Optional but Recommended)
```bash
# Install Certbot
sudo yum install certbot python3-certbot-nginx  # Oracle Linux
# OR
sudo apt install certbot python3-certbot-nginx  # Ubuntu

# Obtain SSL certificate
sudo certbot --nginx -d YOUR_DOMAIN_NAME
```

#### 15. Systemd Service Setup (For Production)
```bash
# Create systemd service file
sudo nano /etc/systemd/system/cybersec-web.service
```

**Service Configuration:**
```
[Unit]
Description=CyberSec-CLI Web Service
After=network.target

[Service]
Type=simple
User=opc
WorkingDirectory=/home/opc/cybersec-cli
EnvironmentFile=/home/opc/cybersec-cli/.env
ExecStart=/usr/local/bin/docker-compose -f /home/opc/cybersec-cli/docker-compose.yml up
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
# Reload systemd and start service
sudo systemctl daemon-reload
sudo systemctl enable cybersec-web
sudo systemctl start cybersec-web
```

### Phase 5: Database Configuration (Optional - Advanced Setup)

#### 16. Oracle Autonomous Database Setup (Alternative to Local Database)

If you want to use Oracle's Free Tier Autonomous Database:

1. **Navigate to Databases → Autonomous Transaction Processing**
2. **Click "Create Autonomous Database"**
3. **Configuration:**
   - Display Name: `cybersec-db`
   - Database Name: `cybersecdatabase`
   - Workload Type: Transaction Processing
   - Deployment: Shared Infrastructure
   - Always Free: Check this box
   - Password: Set a strong password

4. **After creation, download the connection wallet:**
   - Click on your database
   - Click "DB Connection"
   - Download "Wallet" as a zip file

5. **Configure application to use ATP:**
```bash
# Extract wallet to /home/opc/wallet/
unzip Wallet_cybersecdatabase.zip -d /home/opc/wallet/

# Update .env file
DATABASE_URL=oracle+cx_oracle://ADMIN:password@cybersecdatabase_low?wallet_location=/home/opc/wallet/
```

---

## Security Configuration

### 17. Essential Security Hardening

#### Firewall Configuration
```bash
# Ensure only necessary ports are open
sudo ufw enable
sudo ufw allow ssh
sudo ufw allow 'Nginx Full'  # Or specific ports: 80, 443, 8000
sudo ufw deny 22/tcp from any to any port 22 proto tcp
sudo ufw allow from YOUR_IP_ADDRESS to any port 22  # Restrict SSH access
```

#### Update Environment Variables for Security
```
# Security Settings
SECURITY_REQUIRE_CONFIRMATION=true
SECURITY_LOG_ALL_COMMANDS=true
SECURITY_ENCRYPT_STORED_DATA=true
RATE_LIMIT_ENABLED=true
CLIENT_RATE_LIMIT=10
TARGET_RATE_LIMIT=50
MAX_CONCURRENCY=50
DEFAULT_TIMEOUT=3.0
```

#### Set Proper File Permissions
```bash
# Secure sensitive files
chmod 600 .env
chmod 600 ~/.ssh/id_rsa
chmod 644 ~/.ssh/id_rsa.pub
```

### 18. API Key Management
```bash
# Generate secure API keys
export WEBSOCKET_API_KEY=$(openssl rand -hex 32)
export SECRET_KEY=$(openssl rand -hex 64)

# Update .env file with these values
sed -i "s/your-secure-api-key-here/$WEBSOCKET_API_KEY/" .env
sed -i "s/your-secret-key-here/$SECRET_KEY/" .env
```

---

## Post-Deployment Verification

### 19. Health Checks

#### Application Status
```bash
# Check if services are running
sudo docker-compose ps

# Check application logs
sudo docker-compose logs cybersec-web

# Test the API endpoint
curl http://localhost:8000/api/status
```

#### Connectivity Tests
```bash
# Test WebSocket connection
curl -H "Connection: Upgrade" -H "Upgrade: websocket" -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" -H "Sec-WebSocket-Version: 13" http://YOUR_IP:8000/ws

# Test various scan endpoints
curl -X POST http://YOUR_IP:8000/api/scan -H "Content-Type: application/json" -d '{"target": "scanme.nmap.org", "ports": "80,443"}'
```

### 20. Performance Validation

#### Monitor Resource Usage
```bash
# Check system resources
htop
docker stats

# Check application logs for performance metrics
sudo docker-compose logs cybersec-web | grep -i performance
```

#### Test Scanning Capabilities
```bash
# Run a simple scan to verify functionality
curl -X POST http://YOUR_IP:8000/api/scan -H "Content-Type: application/json" -d '{"target": "scanme.nmap.org", "ports": "22,80,443"}'
```

---

## Monitoring & Maintenance

### 21. Log Management
```bash
# Set up log rotation
sudo nano /etc/logrotate.d/cybersec
```

```
/home/opc/cybersec-cli/logs/*.log {
    daily
    missingok
    rotate 52
    compress
    delaycompress
    notifempty
    copytruncate
}
```

### 22. Backup Strategy
```bash
# Create backup script
sudo nano /home/opc/backup-cybersec.sh
```

```bash
#!/bin/bash
BACKUP_DIR="/home/opc/backups"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p $BACKUP_DIR

# Backup database
cp /home/opc/cybersec-cli/cybersec.db $BACKUP_DIR/cybersec_$DATE.db

# Backup configuration
tar -czf $BACKUP_DIR/config_$DATE.tar.gz -C /home/opc/cybersec-cli .env docker-compose.yml nginx.conf

# Cleanup old backups (keep last 7 days)
find $BACKUP_DIR -name "*.db" -mtime +7 -delete
find $BACKUP_DIR -name "*.tar.gz" -mtime +7 -delete
```

```bash
# Make executable and schedule with cron
chmod +x /home/opc/backup-cybersec.sh

# Add to crontab
crontab -e
# Add: 0 2 * * * /home/opc/backup-cybersec.sh
```

### 23. Monitoring Dashboard
The deployment includes Prometheus and Grafana for monitoring:

- **Prometheus**: http://YOUR_IP:9090
- **Grafana**: http://YOUR_IP:3000 (admin/admin, change password immediately)

---

## Troubleshooting

### Common Issues and Solutions

#### Issue: Application not starting
**Symptoms**: Docker containers failing to start
**Solution**:
```bash
# Check logs
sudo docker-compose logs cybersec-web

# Check resource usage
free -h
df -h

# Restart containers
sudo docker-compose down
sudo docker-compose up -d
```

#### Issue: Database connection errors
**Symptoms**: "Could not connect to database" errors
**Solution**:
```bash
# Check if database service is running
sudo docker-compose ps

# Check database logs
sudo docker-compose logs postgres

# Verify database configuration in .env
cat .env | grep DATABASE
```

#### Issue: WebSocket connection failures
**Symptoms**: Cannot establish WebSocket connections
**Solution**:
```bash
# Check firewall rules
sudo ufw status

# Verify Nginx configuration
sudo nginx -t

# Test direct connection to app port
curl -I http://localhost:8000
```

#### Issue: High resource usage
**Symptoms**: VM running out of memory or CPU
**Solution**:
```bash
# Reduce concurrency in .env
echo "MAX_CONCURRENCY=20" >> .env
echo "WEB_WORKERS=2" >> .env

# Restart services
sudo docker-compose restart cybersec-web
```

### Diagnostic Commands
```bash
# Check system resources
top
docker stats

# Check application health
curl http://localhost:8000/api/health

# Check network connectivity
netstat -tuln | grep 8000

# Check disk usage
df -h
du -sh /home/opc/cybersec-cli/*

# Check process status
ps aux | grep cybersec
```

---

## Scaling Considerations

### Free Tier Optimizations
```bash
# Optimize Docker for resource-constrained environments
echo '{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "default-ulimits": {
    "nofile": {
      "Hard": 64000,
      "Name": "nofile",
      "Soft": 64000
    }
  }
}' | sudo tee /etc/docker/daemon.json

sudo systemctl restart docker
```

### Environment Variables for Resource Efficiency
```
# Resource-efficient settings for Free Tier
MAX_CONCURRENCY=20
WEB_WORKERS=2
SCAN_MAX_THREADS=10
DEFAULT_TIMEOUT=5.0
LOG_LEVEL=WARNING
ENABLE_METRICS=false  # Set to true if monitoring is needed
```

### OCI Console Monitoring
Monitor your usage through the OCI Console:
1. Navigate to "My Services" → "Usage & Costs"
2. Check compute, storage, and network usage
3. Set up billing alerts to avoid unexpected charges

---

## Maintenance Schedule

### Daily Tasks
- [ ] Check application logs for errors
- [ ] Verify services are running
- [ ] Monitor resource usage

### Weekly Tasks
- [ ] Review security logs
- [ ] Check for updates
- [ ] Verify backup integrity

### Monthly Tasks
- [ ] Update dependencies
- [ ] Review security settings
- [ ] Clean up old logs
- [ ] Check usage against Free Tier limits

---

## Cost Optimization Tips

### Staying Within Free Tier
1. **Stop instances when not needed**: Use OCI Console or CLI to stop VMs during off-hours
2. **Monitor usage regularly**: Check the Usage & Costs dashboard
3. **Use resource-efficient configurations**: Optimize application settings for minimal resource usage
4. **Clean up unused resources**: Remove unused images, volumes, and snapshots

### OCI CLI Commands for Cost Management
```bash
# Stop instance (when not in use)
oci compute instance action --action STOP --instance-id YOUR_INSTANCE_ID

# Start instance (when needed)
oci compute instance action --action START --instance-id YOUR_INSTANCE_ID

# Check current usage
oci osms usage-agreement list --compartment-id YOUR_COMPARTMENT_ID
```

---

## Conclusion

Congratulations! You have successfully deployed CyberSec-CLI on Oracle Cloud Infrastructure Free Tier. Your installation includes:

✅ Full-featured web interface with real-time scanning  
✅ WebSocket support for live updates  
✅ AI-powered analysis capabilities  
✅ Comprehensive monitoring and logging  
✅ Security hardening measures  
✅ Automated backup capabilities  

### Next Steps
1. **Access your application**: Visit `http://YOUR_IP_ADDRESS:8000`
2. **Configure API keys**: Add your AI service keys to .env for enhanced features
3. **Customize settings**: Adjust configuration in .env based on your needs
4. **Set up monitoring**: Configure Grafana dashboards for ongoing monitoring
5. **Plan maintenance**: Establish a regular maintenance schedule

### Support Resources
- **Documentation**: Check the `/docs` folder in your installation
- **GitHub Issues**: Report problems at https://github.com/Yash7256/cybersec-cli/issues
- **Community**: Join discussions in the project repository

Remember to monitor your OCI usage to stay within Free Tier limits!

---

**Last Updated**: February 2026  
**Application Version**: CyberSec-CLI v1.0.0  
**Documentation Version**: 1.0