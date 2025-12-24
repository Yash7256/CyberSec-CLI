# 🌐 Quick Web Deployment Guide

Deploy CyberSec-CLI as a **public website in 15 minutes**

---

## ⚡ Super Quick Start (Local Testing)

### 1. Start the Application
```bash
cd /home/yash/CyberSec-CLI
docker-compose up -d
```

### 2. Access Immediately
```
http://localhost:8000
```

Done! You have a working web interface. Now make it public...

---

## 🌍 Make It Public (3 Options)

### Option 1: Using Your Server IP (Immediate)

**Access via**: `http://your-server-ip:8000`

**Find your IP**:
```bash
hostname -I
# Output: 192.168.1.100 10.0.0.5
```

**Access from anywhere**:
- On same network: `http://192.168.1.100:8000`
- From internet: `http://123.45.67.89:8000` (if port forwarded)

⚠️ **Not recommended for public** (no HTTPS, no domain)

---

### Option 2: With Domain + HTTPS (Best - 30 min)

**1. Get a Domain** (~$10/year)
- Namecheap, GoDaddy, Google Domains
- Example: `cybersec.example.com`

**2. Point Domain to Your Server**
```
Login to registrar → DNS settings
Add A record:
  Name: cybersec.example.com
  Type: A
  Value: your-server-ip (e.g., 123.45.67.89)
```

**3. Run Setup Script**
```bash
cd /home/yash/CyberSec-CLI
bash scripts/web-deploy.sh setup
# Enter your domain when prompted
```

**4. Setup SSL Certificate** (automatic)
```bash
bash scripts/web-deploy.sh ssl
# Enter your email when prompted
```

**5. Access Securely**
```
https://cybersec.example.com
```

✅ **Professional, secure, easy to share**

---

### Option 3: Cloud Deployment (Easiest - 10 min)

#### Using Render.com (No Docker needed!)

**1. Push to GitHub**
```bash
git add .
git commit -m "Deploy to web"
git push origin main
```

**2. Connect to Render**
- Go to render.com
- Sign up with GitHub
- Click "New +" → "Web Service"
- Connect your GitHub repo
- Set: `CMD: python -m uvicorn web.main:app --host 0.0.0.0 --port $PORT`
- Click "Deploy"

**3. Auto-generated URL**
```
https://cybersec-cli-abc123.onrender.com
```

✅ **Automatic HTTPS, no domain needed**

---

## 🎯 Next Steps After Deployment

### Share Your Website
- Give URL to others: `https://cybersec.example.com`
- No installation needed
- Works in any browser

### Configure Security (Recommended)
```bash
nano .env
# Set rate limiting:
RATE_LIMIT=100        # 100 requests/min
MAX_CONCURRENT_SCANS=10

# Set scan limits:
MAX_PORTS_PER_SCAN=5000
SCAN_TIMEOUT=300  # 5 minutes
```

### Monitor Usage
```bash
# View logs
docker-compose logs -f web

# Check performance
curl http://your-domain:8000/health
```

---

## 🔒 Basic Security (Do This!)

```bash
# Add rate limiting in .env
echo "RATE_LIMIT=100" >> .env
echo "MAX_CONCURRENT_SCANS=10" >> .env

# Restart app
docker-compose restart web
```

---

## 💰 Cost Breakdown

| Item | Cost | Notes |
|------|------|-------|
| Domain | $10-15/year | Optional, pick any registrar |
| SSL | FREE | Let's Encrypt (automatic) |
| Hosting | Varies | Your server or cloud provider |
| **Total** | **$0-15/year** | **Very affordable** |

**Popular Options**:
- **DigitalOcean**: $5/month (smallest droplet)
- **AWS**: Free first year, then ~$5-20/month
- **Render.com**: $7/month (free tier available)
- **Heroku**: $7/month

---

## 📊 What Users Will See

### Web Interface
```
┌─────────────────────────────────────────┐
│         CyberSec-CLI Scanner            │
├─────────────────────────────────────────┤
│                                         │
│  Target:  [ example.com .............. ]│
│  Type:    [ Basic ▼ ]                  │
│  Ports:   [ 1-1000 ]                   │
│                                         │
│           [ Start Scan ]                │
│                                         │
│  Results:                               │
│  ───────────────────────────────────   │
│  22  (SSH)    - OPEN                   │
│  80  (HTTP)   - OPEN                   │
│  443 (HTTPS)  - OPEN                   │
│  3306 (MySQL) - CLOSED                 │
│                                         │
│  [ Download Report ▼ ]                 │
│                                         │
└─────────────────────────────────────────┘
```

---

## 🚀 Deployment Comparison

| Method | Time | Cost | SSL | Domain | Difficulty |
|--------|------|------|-----|--------|------------|
| **IP** | 5 min | $0 | ❌ | ❌ | ⭐ Easy |
| **Domain+SSL** | 30 min | $10/yr | ✅ | ✅ | ⭐⭐ Medium |
| **Cloud** | 10 min | $5+/mo | ✅ | Optional | ⭐ Easy |

**Recommendation**: Start with **Cloud** (Render.com) for simplicity, then upgrade to **Domain+SSL** later

---

## ✅ Verification

After deployment, verify it works:

```bash
# Test endpoint
curl https://cybersec.example.com/health

# Expected response:
# {"status": "healthy", "uptime": 12345}

# Test scan
curl -X POST https://cybersec.example.com/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "localhost", "scan_type": "basic"}'
```

---

## 🆘 Troubleshooting

### "Connection refused"
```bash
# Check if app is running
docker-compose ps

# Should show "Up"
# If not: docker-compose up -d
```

### "Domain not working"
```bash
# Check DNS propagation
nslookup cybersec.example.com

# Should return your IP
# If not: Wait 24 hours or check registrar DNS settings
```

### "SSL not working"
```bash
# Check certificate
sudo certbot certificates

# Renew if needed
sudo certbot renew --force-renewal
```

### Slow response
```bash
# Check server resources
docker stats

# Reduce load:
# WORKERS=2 in .env
# MAX_CONCURRENT_SCANS=5 in .env
```

---

## 📚 Full Documentation

For more details:
- **Full Guide**: [DEPLOYMENT_WEB_PUBLIC.md](DEPLOYMENT_WEB_PUBLIC.md)
- **Security**: [WEB_SECURITY.md](WEB_SECURITY.md)
- **Cloud Setup**: [DEPLOYMENT_WEB_PUBLIC.md#-cloud-deployment-aws-digitalocean-heroku](DEPLOYMENT_WEB_PUBLIC.md#-cloud-deployment-aws-digitalocean-heroku)

---

## 🎯 Your Deployment Path

```
START HERE
    ↓
Run: docker-compose up -d
    ↓
Test: http://localhost:8000
    ↓
Ready for web? Pick one:
    ├─ Just use IP: http://your-ip:8000
    ├─ Add domain: Point DNS + run setup script
    └─ Use cloud: Deploy to Render.com
    ↓
Share URL with others!
```

---

## 🎊 You're Ready!

Your CyberSec-CLI is now ready to be a public website.

**Choose your path**:
1. 🚀 **Fastest**: Use IP address (5 minutes)
2. 🌐 **Best**: Add domain + SSL (30 minutes)
3. ☁️ **Easiest**: Use cloud (10 minutes)

**Next**: Pick an option above and follow the steps!

