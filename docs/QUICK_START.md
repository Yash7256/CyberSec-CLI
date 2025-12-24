# CyberSec-CLI Deployment Guide - Quick Reference

## 🚀 Quick Start (5 minutes)

### Local Development (Recommended for Beginners)

```bash
# 1. Clone the repository
git clone https://github.com/Yash7256/cybersec-cli.git
cd cybersec-cli

# 2. Run the quick start script (automatic setup)
bash scripts/quickstart.sh

# 3. Configure your settings
nano .env
# Add your OPENAI_API_KEY=sk-...

# 4. Run the application
python -m cybersec_cli
```

### Docker Deployment (Recommended for Production)

```bash
# 1. Clone the repository
git clone https://github.com/Yash7256/cybersec-cli.git
cd cybersec-cli

# 2. Copy the environment template
cp .env.example .env

# 3. Edit environment variables
nano .env
# Add your OPENAI_API_KEY and other settings

# 4. Make the deployment script executable
chmod +x scripts/docker-deploy.sh

# 5. Start the application with Docker
./scripts/docker-deploy.sh up

# 6. Access the web interface
# http://localhost:8000
```

## 📋 Deployment Options

### 1. **Local Development** (Easiest for Testing)
- **Best For**: Development, testing, learning
- **Time**: 5-10 minutes
- **Resources**: Minimal
- **Setup**: `bash scripts/quickstart.sh`
- **Run**: `python -m cybersec_cli` or `cd web && python main.py`

### 2. **Docker (Recommended)** (Best for Production)
- **Best For**: Production, portability, scalability
- **Time**: 10-15 minutes
- **Resources**: Moderate
- **Setup**: `./scripts/docker-deploy.sh up`
- **Access**: http://localhost:8000

### 3. **Linux System Service** (Advanced Production)
- **Best For**: Permanent server deployment
- **Time**: 20-30 minutes
- **Resources**: Moderate to High
- **Setup**: `sudo bash scripts/deploy.sh`
- **Manage**: `sudo systemctl status cybersec-web`

### 4. **Cloud Deployment** (Enterprise)
- **Best For**: Global scalability, high availability
- **Platforms**: AWS, GCP, Azure, DigitalOcean
- **Setup**: Varies by provider
- **See**: Docker deployment section

## 📊 Comparison Table

| Feature | Local Dev | Docker | System Service | Cloud |
|---------|-----------|--------|-----------------|-------|
| Setup Time | 5 min | 10 min | 30 min | 30+ min |
| Production Ready | ❌ | ✅ | ✅ | ✅ |
| Auto Restart | ❌ | ✅ | ✅ | ✅ |
| Scaling | ❌ | ✅ | Partial | ✅ |
| SSL/HTTPS | ❌ | Partial | ✅ | ✅ |
| Monitoring | Limited | Good | Excellent | Excellent |
| Cost | Free | Low | Low | Medium |

## 🐳 Docker Quick Reference

```bash
# Build and start
./scripts/docker-deploy.sh up

# View logs
./scripts/docker-deploy.sh logs cybersec-web

# Restart service
./scripts/docker-deploy.sh restart cybersec-web

# Stop all containers
./scripts/docker-deploy.sh down

# View status
./scripts/docker-deploy.sh status

# Health check
./scripts/docker-deploy.sh health
```

## 🖥️ System Service Quick Reference (Linux)

```bash
# Install and deploy
sudo bash scripts/deploy.sh production

# Check status
sudo systemctl status cybersec-web

# View logs
sudo journalctl -u cybersec-web -f

# Restart service
sudo systemctl restart cybersec-web

# Stop service
sudo systemctl stop cybersec-web

# Enable auto-start
sudo systemctl enable cybersec-web
```

## 🔐 Configuration

### Essential Settings (.env file)

```bash
# Required: Your OpenAI API Key
OPENAI_API_KEY=sk-your_key_here

# Recommended: Security settings
SECURITY_LOG_ALL_COMMANDS=true
SECURITY_ENCRYPT_STORED_DATA=true

# Optional: Customize appearance
CYBERSEC_THEME=matrix  # or cyberpunk, minimal
OUTPUT_SAVE_RESULTS=true
```

### Generate Configuration Template

```bash
cp .env.example .env
nano .env  # Edit and add your API key
```

## 🚀 Accessing the Application

### Web Interface
- **Local**: http://localhost:8000
- **Docker**: http://localhost:8000
- **Remote**: https://your-domain.com

### CLI Interface
```bash
# Interactive mode
cybersec

# Single command
cybersec scan example.com

# Help
cybersec --help
```

## 🔍 Health Checks

### Check if Service is Running

```bash
# Using curl
curl http://localhost:8000/api/status

# Using Docker
docker ps | grep cybersec-web

# Using systemd
systemctl is-active cybersec-web
```

### View Logs

```bash
# Docker
docker logs cybersec-web

# Systemd
journalctl -u cybersec-web -f

# Local development
tail -f logs/cybersec.log
```

## 🐛 Troubleshooting

### Port Already in Use

```bash
# Find what's using port 8000
lsof -i :8000

# Kill the process
kill -9 <PID>

# Or use a different port (update configuration)
```

### API Key Error

```bash
# Verify API key is set
echo $OPENAI_API_KEY

# Update .env
nano .env
# Restart the application
```

### Container Won't Start

```bash
# Check logs
docker logs cybersec-web

# Rebuild the image
./scripts/docker-deploy.sh build

# Restart
./scripts/docker-deploy.sh up
```

### Permission Denied (Scanning)

Some network scanning requires elevated privileges:

```bash
# For Docker
docker run --privileged cybersec-cli:latest

# For local development
sudo python -m cybersec_cli scan example.com

# For systemd service - already configured
sudo systemctl status cybersec-web
```

## 📱 Web Interface Guide

### Main Features

1. **Dashboard**
   - Real-time statistics
   - Recent scans
   - Quick actions

2. **Port Scanner**
   - Enter target hostname/IP
   - Select ports to scan
   - View detailed results

3. **Reports**
   - Download scan reports
   - View historical data
   - Export results

## 🔄 Updating the Application

### Docker

```bash
cd cybersec-cli
git pull origin main
./scripts/docker-deploy.sh build
./scripts/docker-deploy.sh up
```

### Local Development

```bash
cd cybersec-cli
git pull origin main
source venv/bin/activate
pip install -r requirements.txt
pip install -r web/requirements.txt
```

### System Service

```bash
cd ~/cybersec-cli
git pull origin main
source venv/bin/activate
pip install -r requirements.txt
sudo systemctl restart cybersec-web
```

## 📊 Performance Tuning

### Increase Scanning Speed

```bash
# Edit .env
SCAN_MAX_THREADS=100        # Increase from 50
SCAN_DEFAULT_TIMEOUT=1      # Decrease from 2
```

### Docker Resource Limits

```yaml
# In docker-compose.yml
services:
  cybersec-web:
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 4G
```

## 🔒 Security Best Practices

1. **Secure Your API Key**
   - Never commit .env to Git
   - Use environment variables in production
   - Rotate keys regularly

2. **Network Security**
   - Enable firewall rules
   - Use HTTPS/TLS
   - Restrict access to trusted IPs

3. **Access Control**
   - Use strong passwords
   - Enable 2FA if available
   - Regular security audits

4. **Monitoring**
   - Enable logging
   - Set up alerts
   - Review logs regularly

## 📚 Additional Resources

- [Full Deployment Guide](DEPLOYMENT.md)
- [README](README.md)
- [Features List](FEATURES.md)
- [GitHub Repository](https://github.com/Yash7256/cybersec-cli)

## ❓ Getting Help

### Check Application Logs

```bash
# Docker
docker logs -f cybersec-web

# Systemd
sudo journalctl -u cybersec-web -f

# Local development
tail -f logs/cybersec.log
```

### Common Issues and Solutions

**Q: "ModuleNotFoundError: No module named 'cybersec_cli'"**
```bash
# Solution: Install package in development mode
pip install -e .
```

**Q: "Connection refused" on port 8000**
```bash
# Solution: Application might not be running
# For Docker:
./scripts/docker-deploy.sh status
# For Local:
python -m cybersec_cli
```

**Q: "OpenAI API Error"**
```bash
# Solution: Check your API key
grep OPENAI_API_KEY .env
# Make sure it starts with 'sk-'
```

## 🤝 Contributing

Want to help? Check out the [Contributing Guidelines](CONTRIBUTING.md)

## 📄 License

MIT License - See [LICENSE](LICENSE) file

---

**Last Updated**: 2025-11-28
**Maintained by**: Yash7256
**Version**: 0.1.0
