#!/bin/bash
set -e

echo "Setting up CyberSec-CLI Benchmark Environment..."

# Update system
sudo apt-get update && sudo apt-get install -y \
    python3-pip \
    python3-venv \
    git \
    nmap \
    build-essential \
    libssl-dev \
    libffi-dev \
    libpcap-dev \
    tmux

# Setup Environment (assuming we are in the repo root)
if [ ! -f "setup.py" ]; then
    echo "Error: setup.py not found. Please run this script from the repository root."
    exit 1
fi

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -e .

echo "Setup Complete! To run endurance test:"
echo "source venv/bin/activate"
echo "tmux new -s endurance"
echo "python tests/benchmarking/reliability/test_endurance.py --duration=168"
