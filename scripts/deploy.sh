#!/bin/bash
# CyberSec-CLI Deployment Script for Production
# Usage: sudo bash deploy.sh [production|staging|development]

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
ENVIRONMENT="${1:-production}"
APP_USER="cybersec"
APP_HOME="/home/${APP_USER}"
APP_DIR="${APP_HOME}/cybersec-cli"
VENV_DIR="${APP_DIR}/venv"
SERVICE_NAME="cybersec-web"

# Functions
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

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

install_dependencies() {
    log_info "Installing system dependencies..."
    apt-get update
    apt-get install -y --no-install-recommends \
        python3.10 \
        python3.10-venv \
        python3-pip \
        git \
        curl \
        wget \
        build-essential \
        libssl-dev \
        libffi-dev \
        nmap \
        nginx \
        certbot \
        python3-certbot-nginx
    log_success "System dependencies installed"
}

create_app_user() {
    log_info "Setting up application user..."
    
    if ! id "${APP_USER}" &>/dev/null; then
        useradd -m -s /bin/bash "${APP_USER}"
        log_success "User '${APP_USER}' created"
    else
        log_warning "User '${APP_USER}' already exists"
    fi
}

clone_repository() {
    log_info "Cloning repository..."
    
    if [ ! -d "${APP_DIR}" ]; then
        sudo -u "${APP_USER}" git clone \
            https://github.com/Yash7256/cybersec-cli.git \
            "${APP_DIR}"
        log_success "Repository cloned"
    else
        log_warning "Repository already exists, pulling latest changes..."
        cd "${APP_DIR}"
        sudo -u "${APP_USER}" git pull origin main
        log_success "Repository updated"
    fi
}

setup_virtual_environment() {
    log_info "Setting up Python virtual environment..."
    
    if [ ! -d "${VENV_DIR}" ]; then
        sudo -u "${APP_USER}" python3.10 -m venv "${VENV_DIR}"
        log_success "Virtual environment created"
    else
        log_warning "Virtual environment already exists"
    fi
    
    # Upgrade pip, setuptools, and wheel
    sudo -u "${APP_USER}" "${VENV_DIR}"/bin/pip install \
        --upgrade pip setuptools wheel
}

install_python_dependencies() {
    log_info "Installing Python dependencies..."
    
    cd "${APP_DIR}"
    
    # Combine requirements
    cat requirements.txt web/requirements.txt | sort -u > combined_requirements.txt
    
    sudo -u "${APP_USER}" "${VENV_DIR}"/bin/pip install -r combined_requirements.txt
    sudo -u "${APP_USER}" "${VENV_DIR}"/bin/pip install -e .
    
    log_success "Python dependencies installed"
}

setup_configuration() {
    log_info "Setting up configuration..."
    
    CONFIG_DIR="${APP_HOME}/.cybersec"
    mkdir -p "${CONFIG_DIR}"
    chown -R "${APP_USER}:${APP_USER}" "${CONFIG_DIR}"
    
    # Create .env file if it doesn't exist
    if [ ! -f "${CONFIG_DIR}/.env" ]; then
        cat > "${CONFIG_DIR}/.env" << 'EOF'
# OpenAI Configuration (OPTIONAL - leave commented for built-in analysis)
# OPENAI_API_KEY=your_api_key_here

# CLI Settings
CYBERSEC_THEME=matrix
UI_SHOW_BANNER=true
UI_COLOR_OUTPUT=true

# Scanning Configuration
SCAN_DEFAULT_TIMEOUT=2
SCAN_MAX_THREADS=50
SCAN_RATE_LIMIT=10

# Output Configuration
OUTPUT_DEFAULT_FORMAT=table
OUTPUT_SAVE_RESULTS=true
OUTPUT_EXPORT_PATH=/var/log/cybersec/reports/

# Security
SECURITY_REQUIRE_CONFIRMATION=true
SECURITY_LOG_ALL_COMMANDS=true
SECURITY_ENCRYPT_STORED_DATA=true
EOF
        chmod 600 "${CONFIG_DIR}/.env"
        chown "${APP_USER}:${APP_USER}" "${CONFIG_DIR}/.env"
        log_success "Configuration created at ${CONFIG_DIR}/.env"
        log_info "API key is OPTIONAL - application works without it!"
    else
        log_warning "Configuration file already exists"
    fi
    
    # Create necessary directories
    mkdir -p "${APP_DIR}/reports"
    mkdir -p "${APP_DIR}/logs"
    mkdir -p "${CONFIG_DIR}/models"
    mkdir -p /var/log/cybersec
    
    chown -R "${APP_USER}:${APP_USER}" \
        "${APP_DIR}/reports" \
        "${APP_DIR}/logs" \
        "${CONFIG_DIR}/models" \
        /var/log/cybersec
    
    chmod 755 /var/log/cybersec
}

setup_systemd_service() {
    log_info "Setting up systemd service..."
    
    # Copy service file
    cp "${APP_DIR}/systemd/cybersec-web.service" \
        "/etc/systemd/system/${SERVICE_NAME}.service"
    
    # Update paths in service file
    sed -i "s|/home/cybersec|${APP_HOME}|g" \
        "/etc/systemd/system/${SERVICE_NAME}.service"
    
    # Reload systemd
    systemctl daemon-reload
    
    # Enable service
    systemctl enable "${SERVICE_NAME}.service"
    
    log_success "Systemd service installed"
}

setup_nginx() {
    log_info "Setting up Nginx..."
    
    # Copy nginx configuration
    cp "${APP_DIR}/nginx.conf" /etc/nginx/nginx.conf
    
    # Test configuration
    if nginx -t; then
        log_success "Nginx configuration is valid"
    else
        log_error "Nginx configuration has errors"
        return 1
    fi
}

configure_ssl() {
    log_info "Configuring SSL/TLS..."
    
    read -p "Enter your domain name (or press Enter to skip SSL setup): " DOMAIN
    
    if [ -n "${DOMAIN}" ]; then
        log_info "Setting up Let's Encrypt certificate for ${DOMAIN}..."
        
        certbot certonly --nginx \
            --non-interactive \
            --agree-tos \
            --email admin@${DOMAIN} \
            -d "${DOMAIN}" || log_warning "SSL setup failed, you may need to configure manually"
        
        log_success "SSL certificate configured"
    else
        log_warning "SSL setup skipped"
    fi
}

start_services() {
    log_info "Starting services..."
    
    systemctl restart nginx || log_error "Failed to start Nginx"
    systemctl start "${SERVICE_NAME}" || log_error "Failed to start ${SERVICE_NAME}"
    
    log_success "Services started"
}

verify_installation() {
    log_info "Verifying installation..."
    
    # Check if service is running
    if systemctl is-active --quiet "${SERVICE_NAME}"; then
        log_success "Service is running"
    else
        log_error "Service is not running"
        systemctl status "${SERVICE_NAME}" || true
        return 1
    fi
    
    # Check if Nginx is running
    if systemctl is-active --quiet nginx; then
        log_success "Nginx is running"
    else
        log_error "Nginx is not running"
        systemctl status nginx || true
        return 1
    fi
    
    # Check if the application is responding
    sleep 2
    if curl -f http://localhost:8000/api/status 2>/dev/null | grep -q "running"; then
        log_success "Application is responding correctly"
    else
        log_warning "Application may not be responding correctly, check logs"
        log_info "View logs with: journalctl -u ${SERVICE_NAME} -f"
    fi
}

print_summary() {
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║${NC}  CyberSec-CLI Installation Complete!${NC}                     ${GREEN}║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "Installation Summary:"
    echo "  Environment: ${ENVIRONMENT}"
    echo "  Application User: ${APP_USER}"
    echo "  Application Directory: ${APP_DIR}"
    echo "  Configuration: ${APP_HOME}/.cybersec/.env"
    echo ""
    echo "Next Steps:"
    echo "  1. (Optional) Add OpenAI API key for GPT-4 analysis:"
    echo "     sudo nano ${APP_HOME}/.cybersec/.env"
    echo "     Uncomment and set: OPENAI_API_KEY=sk-..."
    echo ""
    echo "  2. Restart the service (if you added API key):"
    echo "     sudo systemctl restart ${SERVICE_NAME}"
    echo ""
    echo "  3. Check logs:"
    echo "     sudo journalctl -u ${SERVICE_NAME} -f"
    echo ""
    echo "  4. Access the web interface:"
    echo "     http://localhost:8000"
    echo ""
    echo "  5. The application works WITHOUT API key using built-in analysis!"
    echo ""
    echo "For support, visit: https://github.com/Yash7256/cybersec-cli"
    echo ""
}

# Main execution
main() {
    log_info "Starting CyberSec-CLI deployment (${ENVIRONMENT})..."
    
    check_root
    install_dependencies
    create_app_user
    clone_repository
    setup_virtual_environment
    install_python_dependencies
    setup_configuration
    setup_systemd_service
    setup_nginx
    configure_ssl
    start_services
    verify_installation
    print_summary
    
    log_success "Deployment completed successfully!"
}

# Run main function
main
