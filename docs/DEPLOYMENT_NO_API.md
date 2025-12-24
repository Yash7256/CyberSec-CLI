# CyberSec-CLI Deployment Without OpenAI API

> ✅ CyberSec-CLI **works perfectly without OpenAI API**
> 
> - **Rule-based security analysis** built-in
> - **No API key required**
> - **No recurring API costs**
> - **Faster response times** (no network latency)
> - **Full port scanning & service detection**

---

## 🚀 Quick Start (No API)

### Option 1: Local Installation (Fastest - 5 minutes)

```bash
# 1. Clone the repository
git clone https://github.com/Yash7256/cybersec-cli.git
cd cybersec-cli

# 2. Create virtual environment
python3.10 -m venv venv
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Skip API configuration (leave OPENAI_API_KEY empty)
cp .env.example .env
# Edit .env and comment out or leave OPENAI_API_KEY empty:
# # OPENAI_API_KEY=sk-...    <- Leave this commented

# 5. Run the application
python -m cybersec_cli

# ✅ Done! Application running with built-in analysis
```

### Option 2: Docker Deployment (Easiest - 3 minutes)

```bash
# 1. Clone the repository
git clone https://github.com/Yash7256/cybersec-cli.git
cd cybersec-cli

# 2. Create .env file (without API key)
cp .env.example .env
# Edit to comment out: # OPENAI_API_KEY=sk-...

# 3. Start with Docker
docker-compose up -d

# 4. Access the web interface
# http://localhost:8000

# View logs
docker-compose logs -f web
```

### Option 3: Systemd Service (Production - 10 minutes)

```bash
# 1. Clone the repository
git clone https://github.com/Yash7256/cybersec-cli.git
cd cybersec-cli

# 2. Run deployment script (automated setup)
sudo bash scripts/deploy.sh

# 3. Skip API configuration when prompted:
# Enter OPENAI_API_KEY (leave empty to use fallback analysis): [press Enter]

# 4. Start the service
sudo systemctl start cybersec-web
sudo systemctl status cybersec-web

# 5. Access the web interface
# http://localhost:8000
```

---

## 📊 Built-in Analysis Features (No API Required)

### Port Security Analysis
```
User: "What about port 22?"

System Response:
🔍 Port Security Analysis:

Port 22 (SSH):
  • Service: Remote access
  • Recommendation: Critical - Control access with firewall rules
  
General Port Security Best Practices:
  1. Close unnecessary ports
  2. Use firewalls to restrict access
  3. Run services on non-standard ports
  4. Implement VPN for remote access
  5. Monitor for suspicious connections
```

### Service Security Analysis
```
User: "Is MySQL safe?"

System Response:
🛡️ Service Security Analysis:

MySQL Database:

Risks:
  • Database exposure
  • SQL injection
  • Unauthorized access

Recommendations:
  ✓ Restrict to private network
  ✓ Strong passwords
  ✓ Use firewall
  ✓ Regular backups
```

### Automated Analysis for Known Ports
Built-in knowledge for:
- **22** (SSH) - Remote access security
- **80** (HTTP) - Web server security
- **443** (HTTPS) - Secure web configuration
- **3306** (MySQL) - Database security
- **5432** (PostgreSQL) - Database security
- **6379** (Redis) - Cache security
- **27017** (MongoDB) - Database security
- **8080** (HTTP Alt) - Web proxy/app security

---

## ⚙️ Configuration

### Minimal .env for No-API Deployment

Create `.env` file with:

```bash
# CyberSec-CLI Configuration

# === SCANNING ===
SCAN_DEFAULT_TIMEOUT=2
SCAN_MAX_THREADS=50
SCAN_RATE_LIMIT=10

# === UI ===
UI_THEME=matrix
UI_SHOW_BANNER=true
UI_COLOR_OUTPUT=true
UI_ANIMATION_SPEED=normal

# === SECURITY ===
SECURITY_REQUIRE_CONFIRMATION=true
SECURITY_LOG_ALL_COMMANDS=true

# === OUTPUT ===
OUTPUT_DEFAULT_FORMAT=table
OUTPUT_SAVE_RESULTS=true
OUTPUT_EXPORT_PATH=./reports/

# === AI (Optional - leave commented for fallback analysis) ===
# AI_PROVIDER=openai
# OPENAI_API_KEY=sk-...    <- Keep this commented
# AI_MODEL=gpt-4
# AI_TEMPERATURE=0.7
```

### Run Without Configuration File

```bash
# Application works with defaults if .env is missing
python -m cybersec_cli
```

---

## 🎯 Comparison: With vs Without API

| Feature | Without API | With API |
|---------|------------|----------|
| **Port Scanning** | ✅ Full | ✅ Full |
| **Service Detection** | ✅ Yes | ✅ Yes |
| **Rule-based Analysis** | ✅ Built-in | ✅ Built-in |
| **Basic Recommendations** | ✅ Yes | ✅ Yes |
| **GPT-4 Intelligence** | ❌ No | ✅ Yes |
| **Custom Explanations** | ❌ No | ✅ Yes |
| **CVE Integration** | ❌ No | ✅ Yes |
| **Cost** | ✅ Free | 💰 ~$0.01-0.05/scan |
| **Response Time** | ✅ Instant | ⏱️ 1-2 seconds |
| **Privacy** | ✅ 100% Local | ⚠️ Data sent to OpenAI |

---

## 🔧 Troubleshooting

### Port Already in Use

```bash
# Find what's using port 8000
lsof -i :8000

# Change port in .env
OUTPUT_EXPORT_PATH=./reports/
# Or use Docker with different port
docker-compose down
# Edit docker-compose.yml port mapping
docker-compose up -d
```

### Permission Denied

```bash
# Make scripts executable
chmod +x scripts/*.sh

# Run with proper permissions
bash scripts/deploy.sh
```

### Module Not Found

```bash
# Reinstall dependencies
pip install -r requirements.txt

# Verify installation
python -c "import cybersec_cli; print('✅ OK')"
```

### Analysis Not Working

```bash
# Check if running in fallback mode
grep "fallback" ~/.cybersec/logs/*.log

# This is normal if API key not configured
# Application should still scan ports and services
```

---

## 📈 Performance Expectations

### Without OpenAI API
- **Port Scan**: 2-10 seconds (depending on port range)
- **Service Detection**: < 1 second
- **Analysis Generation**: < 100ms
- **Total Time**: 2-12 seconds

### With OpenAI API
- **Port Scan**: 2-10 seconds
- **Service Detection**: < 1 second
- **API Call**: 1-3 seconds (network dependent)
- **Analysis Generation**: < 100ms
- **Total Time**: 3-15 seconds

---

## 🌐 Web Interface Usage (No API)

### Accessing the Web Interface

```
Local: http://localhost:8000
Docker: http://localhost:8000
Systemd: http://localhost:8000
```

### Scanning a Target

1. **Enter Target IP/Domain**
   ```
   Example: 192.168.1.1 or example.com
   ```

2. **Select Scan Type**
   ```
   • Basic (top 100 ports)
   • Full (all 65535 ports)
   • Custom (specify ports)
   ```

3. **Start Scan**
   ```
   Real-time output shows:
   - Open ports
   - Services detected
   - Security recommendations
   ```

4. **View Analysis**
   ```
   Built-in analysis appears automatically
   No API latency, instant response
   ```

---

## 📋 Systemd Service Management

### Check Service Status

```bash
sudo systemctl status cybersec-web
```

### View Logs

```bash
# Last 50 lines
sudo journalctl -u cybersec-web -n 50 --no-pager

# Real-time logs
sudo journalctl -u cybersec-web -f

# Last hour
sudo journalctl -u cybersec-web --since "1 hour ago"
```

### Restart Service

```bash
sudo systemctl restart cybersec-web
sudo systemctl status cybersec-web
```

### Enable Auto-start

```bash
sudo systemctl enable cybersec-web
# Now starts automatically on reboot
```

---

## 🐳 Docker Commands

### Start/Stop

```bash
# Start
docker-compose up -d

# Stop
docker-compose down

# Restart
docker-compose restart

# View logs
docker-compose logs -f web
```

### Health Check

```bash
# Container status
docker-compose ps

# Check web service health
curl http://localhost:8000/health
```

### Remove Everything

```bash
# Stop and remove containers
docker-compose down --volumes

# Remove images
docker rmi cybersec-cli:latest nginx:latest
```

---

## 🚀 Next Steps

### 1. First Scan

```bash
# Once deployed, scan your local network
Enter target: 192.168.1.1
Scan type: Basic
```

### 2. Review Results

```
Open Ports: 22, 80, 443
Services: SSH, HTTP, HTTPS
Recommendations: (Built-in analysis)
```

### 3. Add API Later (Optional)

```bash
# Get API key: https://platform.openai.com/account/api-keys
nano .env
# Add: OPENAI_API_KEY=sk-...
# Restart application
```

### 4. Customize Configuration

```bash
nano .env
# Adjust scanning parameters, themes, output formats
```

---

## 📞 Support

### Common Issues

| Issue | Solution |
|-------|----------|
| Port already in use | Change port in docker-compose.yml or .env |
| Permission denied | Run with `sudo` or fix file permissions |
| Module not found | Run `pip install -r requirements.txt` again |
| Analysis not showing | Normal if using fallback - check logs |

### Getting Help

1. Check logs: `docker-compose logs` or `journalctl -u cybersec-web`
2. Verify configuration: `cat .env`
3. Test connectivity: `curl http://localhost:8000/health`

---

## ✨ Summary

**CyberSec-CLI without API**:
- ✅ **Works out of the box** - No API key needed
- ✅ **Full scanning capability** - Ports, services, versions
- ✅ **Built-in analysis** - Rule-based security recommendations
- ✅ **Zero cost** - No API usage fees
- ✅ **Fast response** - No network latency
- ✅ **Privacy focused** - All data stays local

**Ready to deploy?**

Choose your method:
1. **[Local Dev]** - `bash scripts/quickstart.sh`
2. **[Docker]** - `docker-compose up -d`
3. **[Systemd]** - `sudo bash scripts/deploy.sh`

Then access: **http://localhost:8000**

---

**Questions?** Check DEPLOYMENT.md for more detailed information.
