# 🚀 Quick Start: Vercel + Railway Deployment

## 🎯 One-Command Deployment

```bash
# Make the deployment script executable and run it
chmod +x scripts/deploy-vercel-railway.sh
./scripts/deploy-vercel-railway.sh
```

This interactive script will guide you through:
1. Checking requirements
2. Setting up environment files
3. Deploying backend to Railway
4. Deploying frontend to Vercel
5. Configuring the integration

## 📋 Manual Steps (If you prefer)

### 1. Prerequisites
```bash
# Install required tools
npm install -g vercel @railway/cli

# Login to services
vercel login
railway login
```

### 2. Deploy Backend (Railway)
```bash
# Go to project root
cd /home/yash/Documents/CyberSec-CLI

# Deploy to Railway
railway init
railway up
```

### 3. Deploy Frontend (Vercel)
```bash
# Prepare frontend files
mkdir -p frontend/public
cp -r web/static/* frontend/public/

# Deploy to Vercel
cd frontend
vercel --prod
```

### 4. Configure Integration
Update your frontend to use the Railway backend URL:
```javascript
// In your frontend JavaScript
const API_BASE_URL = 'https://your-railway-app.up.railway.app';
const WEBSOCKET_URL = 'wss://your-railway-app.up.railway.app';
```

## 🎨 Architecture Benefits

✅ **Vercel Frontend**: Global CDN, automatic HTTPS, serverless functions  
✅ **Railway Backend**: Auto-scaling, built-in database, easy deployment  
✅ **Separation of Concerns**: Independent scaling and maintenance  
✅ **Cost Effective**: Generous free tiers for both platforms  
✅ **Modern Stack**: Industry-standard deployment approach  

## 📊 Cost Structure

| Service | Free Tier | Paid Usage |
|---------|-----------|------------|
| Vercel | 100GB bandwidth, 100 deployments | $20/month for teams |
| Railway | $5/month credit | Pay-as-you-go |

## 🔧 Environment Variables

### Backend (.env.railway)
```
DATABASE_URL=postgresql://...
REDIS_URL=redis://...
SECRET_KEY=...
WEBSOCKET_API_KEY=...
```

### Frontend (.env.local)
```
NEXT_PUBLIC_API_URL=https://your-railway-app.up.railway.app
NEXT_PUBLIC_WEBSOCKET_URL=wss://your-railway-app.up.railway.app
```

## 🚀 Next Steps After Deployment

1. **Test the integration** by accessing your Vercel frontend
2. **Configure custom domains** (optional)
3. **Set up monitoring** and analytics
4. **Implement CI/CD** for automated deployments
5. **Add security headers** and rate limiting

## 📚 Documentation

For detailed instructions, see:
- [VERCEL_RAILWAY_DEPLOYMENT.md](VERCEL_RAILWAY_DEPLOYMENT.md) - Complete guide
- [OCI_DEPLOYMENT_GUIDE.md](OCI_DEPLOYMENT_GUIDE.md) - Alternative deployment options

## 💡 Pro Tips

- Use the deployment script for automatic setup
- Keep frontend and backend repositories separate for better CI/CD
- Monitor usage to stay within free tier limits
- Use environment variables for configuration
- Enable automatic deployments for both platforms

Your CyberSec-CLI will be production-ready with enterprise-grade infrastructure!