#!/bin/bash
# Vercel + Railway Deployment Automation Script
# Automates the deployment of CyberSec-CLI frontend to Vercel and backend to Railway

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
FRONTEND_DIR="$PROJECT_ROOT/frontend"
BACKEND_DIR="$PROJECT_ROOT"

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

show_menu() {
    echo -e "\n${BLUE}═══════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}Vercel + Railway Deployment${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}\n"
    
    echo "Choose deployment option:"
    echo "  1) Full Deployment (Frontend + Backend)"
    echo "  2) Deploy Frontend Only (Vercel)"
    echo "  3) Deploy Backend Only (Railway)"
    echo "  4) Setup Environment Files"
    echo "  5) Check Requirements"
    echo "  6) Exit"
    echo ""
}

check_requirements() {
    log_info "Checking requirements..."
    
    # Check Git
    if ! command -v git &> /dev/null; then
        log_error "Git is not installed"
        return 1
    fi
    
    # Check Node.js for Vercel
    if ! command -v node &> /dev/null; then
        log_warning "Node.js not found - needed for Vercel deployment"
    else
        NODE_VERSION=$(node --version)
        log_success "Node.js: $NODE_VERSION"
    fi
    
    # Check Vercel CLI
    if ! command -v vercel &> /dev/null; then
        log_warning "Vercel CLI not found"
        echo "Install with: npm install -g vercel"
    else
        VERCEL_VERSION=$(vercel --version | head -1)
        log_success "Vercel CLI: $VERCEL_VERSION"
    fi
    
    # Check Railway CLI
    if ! command -v railway &> /dev/null; then
        log_warning "Railway CLI not found"
        echo "Install with: npm install -g @railway/cli"
    else
        RAILWAY_VERSION=$(railway --version)
        log_success "Railway CLI: $RAILWAY_VERSION"
    fi
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        log_warning "Docker not found - Railway can deploy without local Docker"
    else
        DOCKER_VERSION=$(docker --version)
        log_success "Docker: $DOCKER_VERSION"
    fi
    
    log_success "Requirements check completed"
    return 0
}

setup_environment() {
    log_info "Setting up environment files..."
    
    # Create frontend env file
    if [ ! -f "$FRONTEND_DIR/.env.local" ]; then
        cat > "$FRONTEND_DIR/.env.local" << 'EOF'
NEXT_PUBLIC_API_URL=https://your-railway-app.up.railway.app
NEXT_PUBLIC_WEBSOCKET_URL=wss://your-railway-app.up.railway.app
EOF
        log_success "Created frontend .env.local"
    fi
    
    # Create backend env file template
    if [ ! -f "$BACKEND_DIR/.env.railway" ]; then
        cat > "$BACKEND_DIR/.env.railway" << 'EOF'
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
        log_success "Created backend .env.railway template"
    fi
    
    # Generate secure keys if needed
    if grep -q "your-very-secure-secret-key-here" "$BACKEND_DIR/.env.railway"; then
        SECRET_KEY=$(openssl rand -hex 64 2>/dev/null || echo "generate-this-key-manually")
        WS_API_KEY=$(openssl rand -hex 32 2>/dev/null || echo "generate-this-key-manually")
        
        sed -i "s|your-very-secure-secret-key-here|$SECRET_KEY|" "$BACKEND_DIR/.env.railway"
        sed -i "s|your-secure-api-key-here|$WS_API_KEY|" "$BACKEND_DIR/.env.railway"
        
        log_success "Generated secure keys for backend configuration"
    fi
    
    log_success "Environment setup completed"
}

deploy_frontend() {
    log_info "Deploying frontend to Vercel..."
    
    # Create frontend directory if it doesn't exist
    mkdir -p "$FRONTEND_DIR/public"
    
    # Copy static files
    log_info "Copying static files..."
    if [ -d "$PROJECT_ROOT/web/static" ]; then
        cp -r "$PROJECT_ROOT/web/static/"* "$FRONTEND_DIR/public/"
        log_success "Static files copied to frontend directory"
    else
        log_error "Static files directory not found: $PROJECT_ROOT/web/static"
        return 1
    fi
    
    # Go to frontend directory
    cd "$FRONTEND_DIR"
    
    # Check if this is a git repository
    if [ ! -d ".git" ]; then
        log_info "Initializing git repository..."
        git init
        git add .
        git commit -m "Initial frontend commit"
    fi
    
    # Deploy to Vercel
    if command -v vercel &> /dev/null; then
        log_info "Deploying with Vercel CLI..."
        vercel --prod --confirm
        log_success "Frontend deployed successfully!"
        
        echo ""
        echo "Frontend URL: https://your-vercel-app.vercel.app"
        echo "Note: Update your frontend to use the actual Railway backend URL"
    else
        log_warning "Vercel CLI not found"
        echo "To deploy frontend:"
        echo "1. Install Vercel CLI: npm install -g vercel"
        echo "2. Run: vercel --prod in the frontend directory"
        echo "3. Or deploy via https://vercel.com/dashboard"
        return 1
    fi
}

deploy_backend() {
    log_info "Deploying backend to Railway..."
    
    # Check if Railway CLI is available
    if ! command -v railway &> /dev/null; then
        log_warning "Railway CLI not found"
        echo "Deploying via Railway web interface..."
        echo ""
        echo "1. Go to https://railway.app/new"
        echo "2. Select 'Deploy from GitHub repo'"
        echo "3. Connect your GitHub account"
        echo "4. Select the CyberSec-CLI repository"
        echo "5. Set Dockerfile path to 'Dockerfile.railway' in the service settings"
        echo "6. Add environment variables from .env.railway"
        echo "7. Railway will auto-deploy when you push changes"
        echo ""
        log_success "Railway deployment instructions provided above"
        return 0
    fi
    
    # Deploy using Railway CLI
    cd "$BACKEND_DIR"
    
    # Login to Railway if needed
    if [ "$(railway status | grep -c "No project found" || true)" -gt 0 ]; then
        echo "Please login to Railway CLI:"
        railway login
    fi
    
    # Initialize if not already done
    if [ ! -f "railway.toml" ]; then
        log_error "Railway configuration not found"
        return 1
    fi
    
    # Set Railway specific config (assuming one deployment to CLI)
    ENV=production || usage
    
    # Deploy
    log_info "Deploying to Railway..."
    railway up
    
    # Get deployment URL
    DEPLOYMENT_URL=$(railway url)
    log_success "Backend deployed successfully!"
    echo "Backend URL: $DEPLOYMENT_URL"
    
    # Update frontend configuration
    echo ""
    echo "Update your frontend environment variables:"
    echo "NEXT_PUBLIC_API_URL=$DEPLOYMENT_URL"
    echo "NEXT_PUBLIC_WEBSOCKET_URL=${DEPLOYMENT_URL/https/wss}"
}

full_deployment() {
    log_info "Starting full deployment..."
    
    # Setup environment
    setup_environment
    
    # Deploy backend first (to get URL)
    echo ""
    log_info "Step 1: Deploying backend to Railway..."
    deploy_backend
    
    # Get backend URL
    if command -v railway &> /dev/null; then
        BACKEND_URL=$(railway url 2>/dev/null || echo "https://your-railway-app.up.railway.app")
        WS_URL="${BACKEND_URL/https/wss}"
    else
        BACKEND_URL="https://your-railway-app.up.railway.app"
        WS_URL="wss://your-railway-app.up.railway.app"
    fi
    
    # Update frontend config
    sed -i "s|https://your-railway-app.up.railway.app|$BACKEND_URL|g" "$FRONTEND_DIR/.env.local"
    sed -i "s|wss://your-railway-app.up.railway.app|$WS_URL|g" "$FRONTEND_DIR/.env.local"
    
    # Deploy frontend
    echo ""
    log_info "Step 2: Deploying frontend to Vercel..."
    deploy_frontend
    
    # Summary
    echo ""
    echo "🎉 Deployment Complete!"
    echo "======================"
    echo "Backend URL: $BACKEND_URL"
    echo "Frontend URL: https://your-vercel-app.vercel.app"
    echo ""
    echo "Next steps:"
    echo "1. Update your frontend JavaScript to use the backend URL"
    echo "2. Test the integration by accessing the frontend URL"
    echo "3. Configure custom domains if needed"
    echo "4. Set up monitoring and analytics"
}

main() {
    while true; do
        show_menu
        read -p "Enter your choice (1-6): " choice
        
        case $choice in
            1)
                full_deployment
                break
                ;;
            2)
                deploy_frontend
                break
                ;;
            3)
                deploy_backend
                break
                ;;
            4)
                setup_environment
                ;;
            5)
                check_requirements
                ;;
            6)
                echo "Goodbye!"
                exit 0
                ;;
            *)
                log_error "Invalid option. Please choose 1-6."
                ;;
        esac
        
        echo ""
        read -p "Press Enter to continue..."
    done
}

# Run main function
main "$@"