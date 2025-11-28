# 🌐 Cloud Deployment Guide - CyberSec-CLI

Deploy your CyberSec-CLI application to the cloud in 10 minutes with instant HTTPS, auto-scaling, and zero server management!

## 📊 Cloud Platform Comparison

| Platform | Setup Time | Free Tier | Cost | HTTPS | Scaling | Best For |
|----------|-----------|-----------|------|-------|---------|----------|
| **Render.com** ⭐ | 5 min | ✅ Yes | Free | ✅ Auto | ✅ Yes | Quick start, free |
| **Heroku** | 5 min | ❌ No (free tier ended) | $7+/mo | ✅ Auto | ✅ Yes | Quick deploy, students |
| **DigitalOcean App Platform** | 10 min | ❌ No | $5+/mo | ✅ Auto | ✅ Yes | Best value, reliable |
| **AWS EC2** | 15 min | ✅ Free tier (1 year) | Free-5/mo | ✅ Manual | ✅ Yes | Enterprise, scaling |
| **Railway.app** | 5 min | ✅ Yes | Pay as you go | ✅ Auto | ✅ Yes | Simple, modern |

---

## 🚀 Option 1: Render.com (Recommended - Fastest)

**Why Render?**
- ✅ Free tier available
- ✅ Deploys in 5 minutes
- ✅ Automatic HTTPS
- ✅ Instant auto-scaling
- ✅ No credit card required for free tier
- ✅ Built for Python/Docker

### Step 1: Prepare Your Repository

```bash
# 1. Initialize git if not already done
cd /home/yash/CyberSec-CLI
git init

# 2. Create .gitignore (if not exists)
cat > .gitignore << 'EOF'
venv/
__pycache__/
*.pyc
.env
.env.local
reports/
logs/
certs/
EOF

# 3. Add all files
git add .
git commit -m "Initial commit: CyberSec-CLI ready for cloud deployment"

# 4. Push to GitHub
# First, create a new repo on GitHub.com
# Then:
git remote add origin https://github.com/YOUR_USERNAME/CyberSec-CLI.git
git branch -M main
git push -u origin main
```

### Step 2: Deploy on Render

1. **Go to Render.com**
   - Visit: https://render.com
   - Click "Sign up"
   - Use GitHub account for faster setup

2. **Create New Web Service**
   - Dashboard → New → Web Service
   - Connect your GitHub repository
   - Select: `CyberSec-CLI` repository

3. **Configure Service**
   ```
   Name: cybersec-cli
   Environment: Docker
   Region: Choose closest to your users
   Plan: Free (or Starter $7/month for production)
   ```

4. **Set Environment Variables**
   - Click "Advanced" → Environment Variables
   - Add these variables:
   ```
   OPENAI_API_KEY=optional_your_api_key_here
   CYBERSEC_THEME=matrix
   UI_SHOW_BANNER=true
   SCAN_RATE_LIMIT=10
   ```

5. **Deploy**
   - Click "Deploy"
   - Wait 3-5 minutes
   - Your app is live! ✅

6. **Access Your Application**
   - Render gives you a URL: `https://cybersec-cli-xxxxx.onrender.com`
   - Share this with anyone!

### Keep Your Free App From Sleeping

Render's free tier puts apps to sleep after 15 min of inactivity:

**Option A: Free Solution (Recommended)**
- Use `https://kaffeine.app` to ping your app every 5 minutes
- Simply enter your URL
- Your app stays awake 24/7

**Option B: Premium ($7/month)**
- Upgrade to "Starter" plan
- App never sleeps

---

## 🚀 Option 2: DigitalOcean App Platform ($5/month)

**Why DigitalOcean?**
- ✅ $5/month for production app
- ✅ Reliable, enterprise-grade
- ✅ Auto-scaling included
- ✅ Excellent documentation
- ✅ Free $100 credit for students

### Step 1: Create DigitalOcean Account

1. Go to: https://www.digitalocean.com
2. Sign up (use promo code for $100 credit if student)
3. Verify email

### Step 2: Create App Platform App

1. **Dashboard → Apps → Create App**

2. **Connect Repository**
   - Select GitHub
   - Authorize DigitalOcean
   - Select `CyberSec-CLI` repository
   - Branch: `main`
   - Autodeploy: ✅ Enable

3. **Configure App**
   - Name: `cybersec-cli`
   - Resources: Basic (default)
   - HTTP Port: `8000`

4. **Set Environment Variables**
   ```
   OPENAI_API_KEY=optional_your_api_key
   CYBERSEC_THEME=matrix
   SCAN_RATE_LIMIT=10
   ```

5. **Deploy**
   - Click "Deploy App"
   - Wait 5-10 minutes
   - You get a live URL!

### Access Your Application
- DigitalOcean provides: `https://cybersec-cli-xxxx.ondigitalocean.app`
- Automatic HTTPS
- Share with users!

---

## 🚀 Option 3: AWS EC2 (Free First Year)

**Why AWS?**
- ✅ Free tier for 12 months
- ✅ `t2.micro` instance free
- ✅ Scalable to enterprise
- ✅ 750 hours/month free

### Step 1: Create AWS Account

1. Go to: https://aws.amazon.com
2. Sign up
3. Create account (requires credit card, but won't charge for free tier)

### Step 2: Launch EC2 Instance

1. **Go to EC2 Dashboard**
   - Services → EC2
   - Click "Launch Instance"

2. **Choose AMI**
   - Select: "Ubuntu Server 22.04 LTS"
   - Click "Select"

3. **Choose Instance Type**
   - Select: `t2.micro` (free tier eligible)
   - Click "Next"

4. **Configure Instance**
   - Keep defaults
   - Click "Next"

5. **Add Storage**
   - Size: 30 GB (free tier: up to 30 GB)
   - Click "Next"

6. **Add Tags** (Optional)
   - Key: `Name`
   - Value: `cybersec-cli`
   - Click "Next"

7. **Configure Security Group**
   - Add rules:
   ```
   HTTP  80    0.0.0.0/0
   HTTPS 443   0.0.0.0/0
   SSH   22    YOUR_IP/32
   ```
   - Click "Review and Launch"

8. **Review and Launch**
   - Click "Launch"
   - Select key pair (create new: `cybersec-cli-key`)
   - Download key
   - Click "Launch"

### Step 3: Connect and Deploy

```bash
# 1. Make key readable
chmod 400 /path/to/cybersec-cli-key.pem

# 2. SSH into instance
ssh -i /path/to/cybersec-cli-key.pem ubuntu@YOUR_INSTANCE_IP

# 3. Update system
sudo apt-get update && sudo apt-get upgrade -y

# 4. Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker ubuntu

# 5. Clone repository
git clone https://github.com/YOUR_USERNAME/CyberSec-CLI.git
cd CyberSec-CLI

# 6. Start application
docker-compose up -d

# 7. Your app is running on http://YOUR_INSTANCE_IP:8000
```

### Step 4: Setup HTTPS with Let's Encrypt

```bash
# Install Certbot
sudo apt-get install certbot python3-certbot-nginx -y

# Get domain (Route 53 or external registrar)
# Point domain to your instance IP

# Get certificate
sudo certbot certonly --nginx -d your-domain.com

# Configure Nginx for HTTPS
# (Update nginx.conf accordingly)
```

---

## 🚀 Option 4: Railway.app (Simple & Modern)

**Why Railway?**
- ✅ Free tier available
- ✅ Simplest setup
- ✅ Pay-as-you-go pricing
- ✅ GitHub integration
- ✅ PostgreSQL/Redis included

### Step 1: Deploy on Railway

1. Go to: https://railway.app
2. Click "Start Project"
3. Select "Deploy from GitHub"
4. Choose `CyberSec-CLI` repo
5. Click "Deploy"

### Step 2: Configure

1. **Add Services**
   - Click "New"
   - Select "Dockerfile"
   - Point to your repository

2. **Set Variables**
   - Variables tab
   - Add environment variables

3. **Done!**
   - Railway generates: `https://yourdomain.railway.app`
   - Auto-deploys on push to GitHub

---

## 📊 Performance & Capacity

| Platform | Concurrent Users | Requests/sec | Auto-Scale |
|----------|-----------------|--------------|-----------|
| Render Free | 10-20 | 5-10 | No |
| Render Starter | 50-100 | 20-30 | Yes |
| DigitalOcean $5 | 50-100 | 20-30 | Manual |
| AWS t2.micro | 20-50 | 10-20 | Manual |
| AWS t2.small | 100+ | 50+ | Manual |

---

## 🔒 Security Checklist

Before deploying to production:

- [ ] Set `OPENAI_API_KEY` (or leave empty for rule-based mode)
- [ ] Configure rate limiting in WEB_SECURITY.md
- [ ] Enable authentication (API key/token)
- [ ] Update environment variables
- [ ] Test application thoroughly
- [ ] Monitor logs for errors
- [ ] Setup uptime monitoring (optional)

---

## 🛠️ Post-Deployment Setup

### 1. Enable Health Checks

Your app includes health endpoints:
```
GET /api/status
GET /api/health
```

Most platforms auto-detect these.

### 2. Setup Monitoring

**Render.com**
- Dashboard → Logs
- Real-time logs available

**DigitalOcean**
- App Platform → Monitoring
- CPU, Memory, Network graphs

**AWS**
- CloudWatch → Metrics
- Complete monitoring

### 3. Setup Alerts (Optional)

Get notified if your app goes down:

**Render.com**
- Settings → Notifications
- Email alerts for failures

**DigitalOcean**
- Monitoring → Create Alert
- Email when metrics exceed limits

**AWS CloudWatch**
- CloudWatch → Alarms
- Create alarm for CPU/Memory

---

## 🚨 Troubleshooting

### App Won't Start

**Check Logs:**
```bash
# Render.com: Dashboard → Logs
# DigitalOcean: App Platform → Logs
# AWS: tail -f /var/log/docker-compose.log
```

**Common Issues:**
- Missing environment variables
- Port conflicts
- Insufficient resources

### Slow Performance

**Solutions:**
1. Upgrade to higher tier
2. Enable caching
3. Optimize database queries
4. Check rate limiting settings

### HTTPS Not Working

**Check:**
1. Domain pointing to correct IP
2. SSL certificate installed
3. Nginx configuration correct
4. Port 443 open in firewall

---

## 💰 Cost Breakdown

### Monthly Cost Estimates

```
Render.com Free Tier:        $0 (with Kaffeine ping to stay awake)
Render.com Starter:          $7/month

DigitalOcean App Platform:   $5+/month (per app)
DigitalOcean Domain:         ~$10/year (~$1/month)

AWS t2.micro (free year):    $0-3/month after free year
AWS Domain (Route 53):       ~$10/year

Railway.app:                 $0-5/month (pay as you go)
Railway.app Domain:          ~$10/year
```

### Annual Cost Examples

**Budget Option (Render Free + Kaffeine):**
- Free tier: $0
- Service: Included in free tier
- Domain: Optional
- **Total: $0-10/year**

**Best Value (DigitalOcean Starter):**
- App Platform: $60/year
- Domain: $10/year
- **Total: $70/year (~$6/month)**

**Enterprise (AWS)**
- EC2 t2.small: $50-100/year after free tier
- Domain: $10/year
- **Total: $60-110/year (~$7/month)**

---

## 🎯 Recommended Path

1. **Start Here:** Deploy on **Render.com** (free, 5 min, no credit card)
2. **Production:** Upgrade to **DigitalOcean** ($5/month, better performance)
3. **Scale:** Move to **AWS** (when you need enterprise features)

---

## 📚 Next Steps

1. ✅ Choose your platform above
2. ✅ Follow the deployment steps
3. ✅ Test your application at the provided URL
4. ✅ Share URL with users
5. ✅ Monitor logs and performance
6. ✅ Configure security settings (WEB_SECURITY.md)
7. ✅ Setup custom domain (optional)

---

## 🆘 Support & Help

**Need help?**
- Check logs on your platform's dashboard
- Review DEPLOYMENT_WEB_PUBLIC.md for more details
- Check WEB_SECURITY.md for security setup
- See WEB_QUICK_START.md for quick reference

**Having issues?**
1. Check application logs
2. Verify environment variables
3. Ensure Docker runs locally first
4. Verify repository has all files

---

## ✅ Success Indicators

After deployment, you should see:

```
✅ Application accessible at public URL
✅ Web interface loads in browser
✅ Can perform port scans via web UI
✅ Can download reports
✅ Application responds within 2 seconds
✅ Health check passes (/api/status returns 200)
```

---

**Happy Deploying! 🚀**

Got your cloud URL? Share it in your deployment summary!
