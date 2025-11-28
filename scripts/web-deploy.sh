#!/bin/bash
# CyberSec-CLI Web Deployment Script
# Deploy as a public website accessible to anyone
# Usage: bash scripts/web-deploy.sh [setup|start|stop|logs|status|ssl|healthcheck]

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOMAIN="${DOMAIN:-}"
EMAIL="${EMAIL:-}"
PORT="${PORT:-8000}"
WORKERS="${WORKERS:-4}"

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

# Display menu
show_menu() {
    echo -e "\n${BLUE}═══════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}CyberSec-CLI Web Deployment${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}\n"
    
    echo "Choose an option:"
    echo "  1) Full Setup (recommended)"
    echo "  2) Start application"
    echo "  3) Stop application"
    echo "  4) View logs"
    echo "  5) Check status"
    echo "  6) Setup SSL certificate"
    echo "  7) Health check"
    echo "  8) Configure domain"
    echo "  9) Exit"
    echo ""
}

# Check dependencies
check_dependencies() {
    log_info "Checking dependencies..."
    
    local missing_deps=()
    
    if ! command -v docker &> /dev/null; then
        missing_deps+=("Docker")
    fi
    
    if ! command -v docker-compose &> /dev/null; then
        missing_deps+=("Docker Compose")
    fi
    
    if [ ${#missing_deps[@]} -gt 0 ]; then
        log_error "Missing dependencies: ${missing_deps[*]}"
        echo ""
        echo "Install Docker and Docker Compose:"
        echo "  Ubuntu/Debian:"
        echo "    curl -fsSL https://get.docker.com -o get-docker.sh"
        echo "    bash get-docker.sh"
        echo "    sudo usermod -aG docker \$USER"
        echo ""
        exit 1
    fi
    
    log_success "All dependencies installed"
}

# Setup environment
setup_env() {
    log_info "Setting up environment..."
    
    if [ ! -f "$APP_DIR/.env" ]; then
        cp "$APP_DIR/.env.example" "$APP_DIR/.env"
        log_success "Created .env from template"
    fi
    
    # Ask for domain
    if [ -z "$DOMAIN" ]; then
        echo ""
        echo "Optional: Enter your domain (press Enter to skip):"
        echo "  Example: cybersec.example.com"
        read -p "Domain: " DOMAIN || true
    fi
    
    # Ask for email (for SSL)
    if [ -n "$DOMAIN" ] && [ -z "$EMAIL" ]; then
        echo ""
        echo "Enter email for SSL certificate:"
        read -p "Email: " EMAIL || true
    fi
    
    # Update .env with configuration
    if [ -n "$DOMAIN" ]; then
        log_info "Configuring for domain: $DOMAIN"
    else
        log_info "Deploying with local access only"
    fi
}

# Build Docker image
build_image() {
    log_info "Building Docker image..."
    cd "$APP_DIR"
    
    if docker-compose build 2>&1 | tee /tmp/docker-build.log | tail -20; then
        log_success "Docker image built successfully"
    else
        log_error "Failed to build Docker image"
        cat /tmp/docker-build.log
        exit 1
    fi
}

# Start application
start_app() {
    log_info "Starting application..."
    cd "$APP_DIR"
    
    # Create necessary directories
    mkdir -p reports logs
    
    if docker-compose up -d 2>&1 | tail -10; then
        log_success "Application started"
        
        # Wait for service to be ready
        log_info "Waiting for service to be ready..."
        sleep 5
        
        if healthcheck; then
            echo ""
            echo -e "${GREEN}✓ Application is ready!${NC}"
            echo ""
            
            if [ -n "$DOMAIN" ]; then
                echo "Access at: https://$DOMAIN"
            else
                echo "Access at: http://localhost:$PORT"
                echo "         or http://$(hostname -I | awk '{print $1}'):$PORT"
            fi
            echo ""
        else
            log_warning "Service may still be starting..."
        fi
    else
        log_error "Failed to start application"
        exit 1
    fi
}

# Stop application
stop_app() {
    log_info "Stopping application..."
    cd "$APP_DIR"
    
    if docker-compose down; then
        log_success "Application stopped"
    else
        log_error "Failed to stop application"
        exit 1
    fi
}

# View logs
view_logs() {
    cd "$APP_DIR"
    
    echo -e "\n${BLUE}Application Logs (Ctrl+C to exit)${NC}\n"
    
    if [ "$1" == "tail" ]; then
        docker-compose logs --tail=50 -f web
    else
        docker-compose logs web | tail -100
    fi
}

# Check status
check_status() {
    log_info "Checking application status..."
    echo ""
    
    cd "$APP_DIR"
    docker-compose ps
    
    echo ""
    if docker-compose ps | grep -q "Up"; then
        log_success "Application is running"
    else
        log_warning "Application is not running"
    fi
}

# Health check
healthcheck() {
    local max_attempts=30
    local attempt=0
    
    while [ $attempt -lt $max_attempts ]; do
        if curl -sf http://localhost:$PORT/health > /dev/null 2>&1; then
            return 0
        fi
        
        attempt=$((attempt + 1))
        sleep 1
    done
    
    return 1
}

# Setup SSL certificate
setup_ssl() {
    if [ -z "$DOMAIN" ]; then
        log_warning "No domain configured. Cannot setup SSL."
        echo "Run 'bash scripts/web-deploy.sh' and configure domain first."
        return 1
    fi
    
    log_info "Setting up SSL certificate for $DOMAIN..."
    
    if ! command -v certbot &> /dev/null; then
        log_info "Installing Certbot..."
        sudo apt-get update
        sudo apt-get install -y certbot python3-certbot-nginx
    fi
    
    # Generate certificate
    if [ -z "$EMAIL" ]; then
        log_error "Email not configured for SSL"
        return 1
    fi
    
    log_info "Generating SSL certificate..."
    sudo certbot certonly \
        --standalone \
        -d "$DOMAIN" \
        -m "$EMAIL" \
        --agree-tos \
        --non-interactive \
        --preferred-challenges http
    
    if [ -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]; then
        log_success "SSL certificate installed successfully"
        log_info "Certificate location: /etc/letsencrypt/live/$DOMAIN/"
        
        # Create certificate info file
        echo "DOMAIN=$DOMAIN" > "$APP_DIR/.ssl-info"
        echo "CERT_PATH=/etc/letsencrypt/live/$DOMAIN/fullchain.pem" >> "$APP_DIR/.ssl-info"
        echo "KEY_PATH=/etc/letsencrypt/live/$DOMAIN/privkey.pem" >> "$APP_DIR/.ssl-info"
        
        return 0
    else
        log_error "Failed to generate SSL certificate"
        return 1
    fi
}

# Configure domain
configure_domain() {
    echo ""
    echo "Domain Configuration"
    echo "===================="
    echo ""
    
    echo "1. Register a domain (if you don't have one)"
    echo "   - Providers: Namecheap, GoDaddy, Google Domains"
    echo "   - Cost: ~\$10-15/year"
    echo ""
    
    echo "2. Point domain to your server"
    echo "   - Go to domain registrar's DNS settings"
    echo "   - Create A record pointing to your server IP"
    echo "   - Server IP: $(hostname -I | awk '{print $1}')"
    echo "   - Example: cybersec.example.com -> 192.168.1.100"
    echo ""
    
    echo "3. DNS propagation (can take 5-48 hours)"
    echo "   - Check status: nslookup cybersec.example.com"
    echo ""
    
    echo "4. Setup SSL certificate"
    echo "   - Run: bash scripts/web-deploy.sh ssl"
    echo ""
    
    echo "5. Access your website"
    echo "   - https://cybersec.example.com"
    echo ""
}

# Main menu loop
main_menu() {
    while true; do
        show_menu
        read -p "Select option (1-9): " choice
        
        case $choice in
            1)
                check_dependencies
                setup_env
                build_image
                start_app
                ;;
            2)
                start_app
                ;;
            3)
                stop_app
                ;;
            4)
                view_logs "tail"
                ;;
            5)
                check_status
                ;;
            6)
                setup_ssl
                ;;
            7)
                if healthcheck; then
                    log_success "Application is healthy"
                else
                    log_error "Application health check failed"
                fi
                ;;
            8)
                configure_domain
                ;;
            9)
                echo "Exiting..."
                exit 0
                ;;
            *)
                log_error "Invalid option"
                ;;
        esac
    done
}

# Command-line argument handling
if [ $# -gt 0 ]; then
    case $1 in
        setup)
            check_dependencies
            setup_env
            build_image
            start_app
            ;;
        start)
            start_app
            ;;
        stop)
            stop_app
            ;;
        logs)
            view_logs "${2:-tail}"
            ;;
        status)
            check_status
            ;;
        ssl)
            setup_ssl
            ;;
        healthcheck)
            if healthcheck; then
                log_success "Application is healthy"
                exit 0
            else
                log_error "Health check failed"
                exit 1
            fi
            ;;
        *)
            echo "Usage: $0 [setup|start|stop|logs|status|ssl|healthcheck]"
            exit 1
            ;;
    esac
else
    # Interactive mode
    main_menu
fi
