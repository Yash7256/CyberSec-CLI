#!/bin/bash
# Quick start script for CyberSec-CLI
# This script helps you get started quickly

set -euo pipefail

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}"
echo "╔════════════════════════════════════════════════════════════╗"
echo "║          CyberSec-CLI Quick Start Setup                    ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check Python
echo -e "\n${BLUE}[1/6]${NC} Checking Python installation..."
if command -v python3.10 &> /dev/null; then
    PYTHON_CMD="python3.10"
elif command -v python3 &> /dev/null; then
    PYTHON_CMD="python3"
    PYTHON_VERSION=$($PYTHON_CMD --version 2>&1 | awk '{print $2}')
    echo -e "${YELLOW}Warning: Found Python ${PYTHON_VERSION}, Python 3.10+ recommended${NC}"
else
    echo -e "${RED}Error: Python 3 is not installed${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Python found: $($PYTHON_CMD --version)${NC}"

# Create virtual environment
echo -e "\n${BLUE}[2/6]${NC} Setting up virtual environment..."
if [ ! -d "venv" ]; then
    $PYTHON_CMD -m venv venv
    echo -e "${GREEN}✓ Virtual environment created${NC}"
else
    echo -e "${YELLOW}Virtual environment already exists${NC}"
fi

# Activate virtual environment
echo -e "\n${BLUE}[3/6]${NC} Activating virtual environment..."
source venv/bin/activate
echo -e "${GREEN}✓ Virtual environment activated${NC}"

# Upgrade pip
echo -e "\n${BLUE}[4/6]${NC} Upgrading pip, setuptools, and wheel..."
pip install --upgrade pip setuptools wheel > /dev/null 2>&1
echo -e "${GREEN}✓ Pip upgraded${NC}"

# Install dependencies
echo -e "\n${BLUE}[5/6]${NC} Installing dependencies..."
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt > /dev/null 2>&1
    echo -e "${GREEN}✓ Main dependencies installed${NC}"
fi

if [ -f "web/requirements.txt" ]; then
    pip install -r web/requirements.txt > /dev/null 2>&1
    echo -e "${GREEN}✓ Web dependencies installed${NC}"
fi

pip install -e . > /dev/null 2>&1
echo -e "${GREEN}✓ Package installed in development mode${NC}"

# Create .env file
echo -e "\n${BLUE}[6/6]${NC} Setting up configuration..."
if [ ! -f ".env" ]; then
    if [ -f ".env.example" ]; then
        cp .env.example .env
        echo -e "${GREEN}✓ Configuration file created from template${NC}"
    fi
fi

# Create necessary directories
mkdir -p ~/.cybersec/models
mkdir -p reports
mkdir -p logs

echo -e "\n${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║          Setup Complete! 🎉${NC}                             ${GREEN}║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"

echo -e "\n${YELLOW}Next Steps:${NC}\n"
echo "1. (Optional) Configure your environment:"
echo -e "   ${BLUE}nano .env${NC}"
echo "   - Add OPENAI_API_KEY for GPT-4 analysis (optional)"
echo "   - Application works without API key - uses built-in analysis"
echo "   - Adjust other settings as needed"
echo ""
echo "2. Start the interactive CLI:"
echo -e "   ${BLUE}python -m cybersec_cli${NC}"
echo "   or"
echo -e "   ${BLUE}cybersec${NC}"
echo ""
echo "3. Or start the web interface:"
echo -e "   ${BLUE}cd web && python main.py${NC}"
echo "   - Access at: http://localhost:8000"
echo ""
echo -e "${BLUE}Virtual environment activated. Type 'deactivate' to exit.${NC}\n"

# Check if API key is configured
if grep -q "OPENAI_API_KEY=sk-" .env 2>/dev/null; then
    echo -e "${GREEN}✓ OpenAI API key is configured${NC}\n"
else
    echo -e "${YELLOW}ℹ OpenAI API key not set - using built-in rule-based analysis${NC}\n"
fi
