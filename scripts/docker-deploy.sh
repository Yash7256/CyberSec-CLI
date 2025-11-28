#!/bin/bash
# CyberSec-CLI Docker Deployment Script
# Usage: bash docker-deploy.sh [build|up|down|logs|restart|clean]

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
DOCKER_COMPOSE_FILE="docker-compose.yml"
SERVICE_NAME="cybersec-web"
IMAGE_NAME="cybersec-cli"
REGISTRY="${REGISTRY:-}"

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

check_docker() {
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed"
        exit 1
    fi
    
    if ! command -v docker-compose &> /dev/null; then
        log_error "Docker Compose is not installed"
        exit 1
    fi
    
    log_success "Docker and Docker Compose are installed"
}

check_env_file() {
    if [ ! -f .env ]; then
        log_warning ".env file not found, creating from template..."
        if [ -f .env.example ]; then
            cp .env.example .env
            log_info "Created .env from .env.example"
            log_info "API key is OPTIONAL - application works without it"
        else
            cat > .env << 'EOF'
# OpenAI API is OPTIONAL - leave commented for built-in analysis
# OPENAI_API_KEY=your_api_key_here
CYBERSEC_THEME=matrix
OUTPUT_SAVE_RESULTS=true
OUTPUT_EXPORT_PATH=/app/reports/
SECURITY_LOG_ALL_COMMANDS=true
EOF
            log_info "Created .env with defaults. API key is optional!"
        fi
    fi
}

build_image() {
    log_info "Building Docker image..."
    docker-compose -f "${DOCKER_COMPOSE_FILE}" build
    log_success "Docker image built successfully"
}

up() {
    log_info "Starting containers..."
    docker-compose -f "${DOCKER_COMPOSE_FILE}" up -d
    log_success "Containers started"
    
    log_info "Waiting for services to be ready..."
    sleep 5
    
    if docker-compose -f "${DOCKER_COMPOSE_FILE}" ps | grep -q "Up"; then
        log_success "Services are running"
        docker-compose -f "${DOCKER_COMPOSE_FILE}" ps
    else
        log_error "Services failed to start"
        docker-compose -f "${DOCKER_COMPOSE_FILE}" logs
        exit 1
    fi
}

down() {
    log_info "Stopping containers..."
    docker-compose -f "${DOCKER_COMPOSE_FILE}" down
    log_success "Containers stopped"
}

logs() {
    SERVICE="${1:-${SERVICE_NAME}}"
    log_info "Showing logs for ${SERVICE}..."
    docker-compose -f "${DOCKER_COMPOSE_FILE}" logs -f "${SERVICE}"
}

restart() {
    SERVICE="${1:-${SERVICE_NAME}}"
    log_info "Restarting ${SERVICE}..."
    docker-compose -f "${DOCKER_COMPOSE_FILE}" restart "${SERVICE}"
    log_success "Service restarted"
}

clean() {
    log_warning "This will remove all containers, networks, and volumes"
    read -p "Are you sure? (yes/no): " -r
    if [[ $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
        docker-compose -f "${DOCKER_COMPOSE_FILE}" down -v
        log_success "Cleanup completed"
    else
        log_info "Cleanup cancelled"
    fi
}

status() {
    log_info "Container status:"
    docker-compose -f "${DOCKER_COMPOSE_FILE}" ps
}

push() {
    if [ -z "${REGISTRY}" ]; then
        log_error "REGISTRY environment variable not set"
        exit 1
    fi
    
    log_info "Tagging image for registry..."
    docker tag "${IMAGE_NAME}:latest" "${REGISTRY}/${IMAGE_NAME}:latest"
    
    log_info "Pushing image to registry..."
    docker push "${REGISTRY}/${IMAGE_NAME}:latest"
    
    log_success "Image pushed successfully"
}

health_check() {
    log_info "Running health checks..."
    
    # Check web service
    if docker-compose -f "${DOCKER_COMPOSE_FILE}" exec -T "${SERVICE_NAME}" \
        curl -f http://localhost:8000/api/status > /dev/null 2>&1; then
        log_success "Web service is healthy"
    else
        log_error "Web service health check failed"
        return 1
    fi
    
    # Check Nginx
    if docker-compose -f "${DOCKER_COMPOSE_FILE}" exec -T nginx \
        wget -q -O- http://localhost/api/status > /dev/null 2>&1; then
        log_success "Nginx is healthy"
    else
        log_warning "Nginx health check returned non-200 status"
    fi
}

print_info() {
    echo ""
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC}     CyberSec-CLI Docker Deployment${NC}                       ${BLUE}║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "Available commands:"
    echo "  build         - Build Docker image"
    echo "  up            - Start containers"
    echo "  down          - Stop containers"
    echo "  restart [sv]  - Restart service (default: ${SERVICE_NAME})"
    echo "  logs [sv]     - View logs (default: ${SERVICE_NAME})"
    echo "  status        - Show container status"
    echo "  health        - Run health checks"
    echo "  clean         - Remove all containers and volumes"
    echo "  push          - Push image to registry (requires REGISTRY env var)"
    echo ""
    echo "Usage: $0 <command>"
    echo ""
}

main() {
    COMMAND="${1:-status}"
    
    check_docker
    check_env_file
    
    case "${COMMAND}" in
        build)
            build_image
            ;;
        up)
            build_image
            up
            status
            ;;
        down)
            down
            ;;
        restart)
            restart "${2:-${SERVICE_NAME}}"
            ;;
        logs)
            logs "${2:-${SERVICE_NAME}}"
            ;;
        status)
            status
            ;;
        health)
            health_check
            ;;
        clean)
            clean
            ;;
        push)
            push
            ;;
        help|-h|--help)
            print_info
            ;;
        *)
            log_error "Unknown command: ${COMMAND}"
            print_info
            exit 1
            ;;
    esac
}

main "$@"
