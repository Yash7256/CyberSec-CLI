# 🚀 Vercel + Railway Deployment Guide

## 🎯 Architecture Overview

Deploy your CyberSec-CLI application with:
- **Frontend**: Vercel (Static site hosting + Serverless Functions)
- **Backend**: Railway (API Server + Database + Workers)

```
┌─────────────────┐    API Calls    ┌──────────────────┐
│   Vercel CDN    │ ◄──────────────► │   Railway API    │
│  (Frontend)     │                 │   (Backend)      │
│                 │                 │                  │
│  index.html     │                 │  FastAPI Server  │
│  CSS/JS Assets  │                 │  PostgreSQL DB   │
│  Static Files   │                 │  Redis Cache     │
└─────────────────┘                 └──────────────────┘
         │                                   │
         ▼                                   ▼
   Global CDN Delivery              Auto-scaling Backend
```

## 📋 Prerequisites

### Accounts Needed
- [ ] GitHub account
- [ ] Vercel account (free)
- [ ] Railway account (free tier available)

### Tools Required
- [ ] Git CLI
- [ ] Node.js (for local testing)
- [ ] API keys for AI services (optional)

---

## 🎨 Frontend Deployment (Vercel)

### 1. Prepare Frontend Files

First, let's extract the static frontend files:

```bash
# Create frontend directory structure
mkdir -p frontend/{public,api}
cd frontend

# Copy static files
cp -r ../web/static/* public/

# Create vercel.json configuration
cat > vercel.json << 'EOF'
{
  "version": 2,
  "builds": [
    {
      "src": "public/**/*",
      "use": "@vercel/static"
    },
    {
      "src": "api/**/*.js",
      "use": "@vercel/node"
    }
  ],
  "routes": [
    {
      "src": "/api/(.*)",
      "dest": "/api/$1"
    },
    {
      "src": "/(.*)",
      "dest": "/public/$1"
    }
  ],
  "env": {
    "NEXT_PUBLIC_API_URL": "@api_url"
  }
}
EOF
```

### 2. Create API Proxy (Optional)

For handling API calls through Vercel:

```bash
# Create API proxy endpoint
mkdir -p api/proxy

cat > api/proxy/[...path].js << 'EOF'
export default async function handler(req, res) {
  const { path } = req.query;
  const apiUrl = process.env.BACKEND_API_URL || 'https://your-railway-app.up.railway.app';
  
  try {
    const response = await fetch(`${apiUrl}/${path.join('/')}`, {
      method: req.method,
      headers: {
        'Content-Type': 'application/json',
        ...req.headers,
      },
      body: req.method !== 'GET' ? JSON.stringify(req.body) : undefined,
    });
    
    const data = await response.json();
    res.status(response.status).json(data);
  } catch (error) {
    res.status(500).json({ error: 'Proxy error', message: error.message });
  }
}
EOF
```

### 3. Configure Environment Variables

Create `.env.local` for local development:

```bash
cat > .env.local << 'EOF'
NEXT_PUBLIC_API_URL=https://your-railway-app.up.railway.app
NEXT_PUBLIC_WEBSOCKET_URL=wss://your-railway-app.up.railway.app
EOF
```

### 4. Update Frontend to Use External API

Modify the frontend JavaScript to point to your Railway backend:

```bash
# Update the API endpoint in your frontend JS files
sed -i 's|http://localhost:8000|https://your-railway-app.up.railway.app|g' public/js/app.js
sed -i 's|ws://localhost:8000|wss://your-railway-app.up.railway.app|g' public/js/app.js
```

### 5. Deploy to Vercel

```bash
# Install Vercel CLI
npm install -g vercel

# Login to Vercel
vercel login

# Deploy
cd frontend
vercel --prod

# Or deploy via Git
git init
git add .
git commit -m "Initial frontend commit"
git remote add origin https://github.com/yourusername/cybersec-frontend.git
git push -u origin main
```

Then go to [Vercel Dashboard](https://vercel.com/dashboard) and import your repository.

---

## 🚄 Backend Deployment (Railway)

### 1. Prepare Backend for Railway

Create Railway-specific configuration:

```bash
# Create railway.toml
cat > railway.toml << 'EOF'
[build]
builder = "DOCKER"

[deploy]
startCommand = "uvicorn web.main:app --host 0.0.0.0 --port $PORT"
healthcheckPath = "/api/status"
healthcheckTimeout = 300
restartPolicyType = "ON_FAILURE"
restartPolicyMaxRetries = 10
EOF
```

### 2. Create Dockerfile for Railway

```bash
# Create simplified Dockerfile for Railway
cat > Dockerfile.railway << 'EOF'
FROM python:3.10-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libssl-dev \
    libffi-dev \
    nmap \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy requirements
COPY requirements.txt .
COPY web/requirements.txt ./web_requirements.txt

# Install Python dependencies
RUN pip install --upgrade pip && \
    pip install -r requirements.txt && \
    pip install -r web_requirements.txt

# Copy application
COPY . .

# Install package
RUN pip install -e .

# Create non-root user
RUN useradd -m -u 1000 cybersec && \
    chown -R cybersec:cybersec /app

USER cybersec

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8000/api/status || exit 1

# Start command
CMD ["uvicorn", "web.main:app", "--host", "0.0.0.0", "--port", "8000"]
EOF
```

### 3. Configure Environment Variables

Create `.env.railway` template:

```bash
cat > .env.railway << 'EOF'
# Database Configuration
DATABASE_URL=postgresql://postgres:password@postgres.railway.internal:5432/railway

# Redis Configuration
REDIS_URL=redis://redis.railway.internal:6379

# Security Configuration
SECRET_KEY=your-very-secure-secret-key-here
WEBSOCKET_API_KEY=your-secure-api-key-here

# Web Configuration
WEB_HOST=0.0.0.0
WEB_PORT=8000
WEB_WORKERS=2

# Rate Limiting
RATE_LIMIT_ENABLED=true
CLIENT_RATE_LIMIT=50
TARGET_RATE_LIMIT=100

# Scanning Configuration
MAX_CONCURRENCY=50
DEFAULT_TIMEOUT=5.0
SCAN_MAX_THREADS=20

# AI Services (Optional)
OPENAI_API_KEY=your_openai_api_key
GROQ_API_KEY=your_groq_api_key

# Logging
LOG_LEVEL=INFO
EOF
```

### 4. Railway Deployment Steps

1. **Create Railway Project:**
   - Go to [railway.app](https://railway.app)
   - Click "New Project"
   - Choose "Deploy from GitHub repo"
   - Select your CyberSec-CLI repository

2. **Configure Build Settings:**
   - In Railway dashboard, go to your service
   - Click "Settings" → "Build"
   - Set Dockerfile path: `Dockerfile.railway`

3. **Add Environment Variables:**
   - Go to "Variables" tab
   - Add all variables from `.env.railway`
   - Railway will automatically provide `PORT` variable

4. **Add PostgreSQL Database:**
   - In Railway dashboard, click "+ New" → "Database"
   - Choose "PostgreSQL"
   - Railway will automatically set `DATABASE_URL`

5. **Add Redis (Optional but Recommended):**
   - Click "+ New" → "Database"
   - Choose "Redis"
   - Railway will automatically set `REDIS_URL`

### 5. Railway CLI Deployment (Alternative)

```bash
# Install Railway CLI
npm install -g @railway/cli

# Login
railway login

# Initialize project
railway init

# Link to existing project (if you created via web)
railway link

# Deploy
railway up

# View logs
railway logs

# Get deployment URL
railway url
```

---

## 🔧 Configuration Updates

### Update Frontend API Endpoints

After deploying to Railway, update your frontend:

```javascript
// In your frontend JavaScript files
const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'https://your-railway-app.up.railway.app';
const WEBSOCKET_URL = process.env.NEXT_PUBLIC_WEBSOCKET_URL || 'wss://your-railway-app.up.railway.app';
```

### CORS Configuration

Update your FastAPI app to allow Vercel domains:

```python
# In web/main.py, update CORS middleware
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",  # Local development
        "http://localhost:8080",  # Alternative local port
        "https://your-vercel-app.vercel.app",  # Your Vercel deployment
        "https://your-custom-domain.com",     # Your custom domain (if any)
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

### Environment-Specific Configurations

Create different environment files:

```bash
# For development
cat > .env.development << 'EOF'
API_BASE_URL=http://localhost:8000
WEBSOCKET_URL=ws://localhost:8000
EOF

# For production
cat > .env.production << 'EOF'
API_BASE_URL=https://your-railway-app.up.railway.app
WEBSOCKET_URL=wss://your-railway-app.up.railway.app
EOF
```

---

## 🛡️ Security Considerations

### 1. API Key Management
```bash
# Generate secure keys
openssl rand -hex 32  # For SECRET_KEY
openssl rand -hex 64  # For WEBSOCKET_API_KEY
```

### 2. Rate Limiting Configuration
```python
# In your FastAPI app
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

# Add middleware
app.add_middleware(
    SlowAPIMiddleware,
    default_limits=["100/minute"]  # Adjust based on your needs
)
```

### 3. Input Validation
Ensure all API endpoints have proper validation:

```python
from pydantic import BaseModel, validator

class ScanRequest(BaseModel):
    target: str
    ports: str
    timeout: int = 5
    
    @validator('target')
    def validate_target(cls, v):
        # Add target validation logic
        if not v or len(v) > 255:
            raise ValueError('Invalid target')
        return v
```

---

## 📊 Monitoring & Analytics

### Vercel Analytics
Add to your frontend:

```html
<!-- Add to index.html head -->
<script>
  window.va = window.va || function () { (window.vaq = window.vaq || []).push(arguments); };
</script>
<script defer src="/_vercel/insights/script.js"></script>
```

### Railway Monitoring
Railway provides built-in monitoring:
- CPU/Memory usage
- Request logs
- Error tracking
- Deployment history

---

## 🔧 Troubleshooting

### Common Issues

#### 1. CORS Errors
```bash
# Check if your Railway app allows Vercel origins
curl -H "Origin: https://your-vercel-app.vercel.app" \
     -H "Access-Control-Request-Method: POST" \
     -H "Access-Control-Request-Headers: X-Requested-With" \
     -X OPTIONS \
     https://your-railway-app.up.railway.app/api/status
```

#### 2. WebSocket Connection Issues
```javascript
// Add error handling in frontend
const ws = new WebSocket(WEBSOCKET_URL);

ws.onerror = (error) => {
    console.error('WebSocket error:', error);
    // Fallback to polling or show error message
};

ws.onclose = (event) => {
    console.log('WebSocket closed:', event.code, event.reason);
    // Attempt to reconnect
    setTimeout(() => {
        connectWebSocket();
    }, 5000);
};
```

#### 3. Database Connection Issues
```bash
# Test database connection from Railway
railway shell
python -c "import psycopg2; print('DB connection successful')"
```

### Debugging Commands

```bash
# Check Railway logs
railway logs

# Check Vercel logs
vercel logs

# Test API endpoints
curl https://your-railway-app.up.railway.app/api/status
curl https://your-vercel-app.vercel.app

# Check environment variables
railway variables
```

---

## 💰 Cost Breakdown

### Free Tier Usage
| Service | Free Tier | Monthly Cost | Notes |
|---------|-----------|--------------|-------|
| Vercel | 100GB bandwidth, 100 deployments | $0 | Generous free tier |
| Railway | $5 credit/month | $0 | Covers basic usage |
| Domain | Optional | $10-15/year | Not required for testing |

### Scaling Costs
| Usage Level | Vercel | Railway | Total |
|-------------|--------|---------|-------|
| Light (personal) | $0 | $0 | $0 |
| Medium (small team) | $0 | $5-10 | $5-10 |
| Heavy (production) | $20 | $20 | $40 |

---

## 🚀 Advanced Optimizations

### 1. Custom Domain Setup

**Vercel Custom Domain:**
1. Go to Vercel Dashboard → Project → Settings → Domains
2. Add your domain
3. Update DNS records as instructed

**Railway Custom Domain:**
1. Go to Railway Dashboard → Project → Settings → Domains
2. Add custom domain
3. Configure DNS CNAME record

### 2. CI/CD Pipeline

Create GitHub Actions workflow:

```yaml
# .github/workflows/deploy.yml
name: Deploy to Vercel + Railway

on:
  push:
    branches: [main]

jobs:
  deploy-frontend:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: amondnet/vercel-action@v25
        with:
          vercel-token: ${{ secrets.VERCEL_TOKEN }}
          vercel-org-id: ${{ secrets.VERCEL_ORG_ID }}
          vercel-project-id: ${{ secrets.VERCEL_PROJECT_ID }}
          working-directory: ./frontend

  deploy-backend:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: railwayapp/action@v1
        with:
          railway-token: ${{ secrets.RAILWAY_TOKEN }}
```

### 3. Performance Optimization

**Frontend:**
```javascript
// Implement service worker for caching
if ('serviceWorker' in navigator) {
    window.addEventListener('load', () => {
        navigator.serviceWorker.register('/sw.js');
    });
}
```

**Backend:**
```python
# Add caching middleware
from fastapi.middleware.gzip import GZipMiddleware

app.add_middleware(GZipMiddleware, minimum_size=1000)
```

---

## 🎯 Next Steps

1. **Deploy frontend to Vercel** using the steps above
2. **Deploy backend to Railway** with proper environment configuration
3. **Update frontend API endpoints** to point to your Railway URL
4. **Test the integration** thoroughly
5. **Set up monitoring** and analytics
6. **Configure custom domains** (optional)
7. **Implement CI/CD** for automated deployments

This architecture gives you:
✅ **Global CDN delivery** via Vercel
✅ **Auto-scaling backend** via Railway
✅ **Separation of concerns** (frontend/backend)
✅ **Independent scaling** capabilities
✅ **Modern deployment pipeline**
✅ **Cost-effective hosting**

Your CyberSec-CLI will be production-ready with enterprise-grade infrastructure!