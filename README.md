<p align="center">
  <img src="logo.png" alt="CyberSec CLI Logo" width="200"/>
</p>

# CyberSec CLI

[![Python Version](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](https://www.docker.com/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104.1-green.svg)](https://fastapi.tiangolo.com/)

> AI-Powered Cybersecurity Assistant for Security Professionals

CyberSec CLI is a comprehensive, production-ready cybersecurity platform that combines an intelligent command-line interface with a modern web application. It features advanced network scanning capabilities, AI-powered security analysis, and enterprise-grade deployment options with Redis caching, PostgreSQL database, and comprehensive monitoring.

## 🌟 Key Features

### 🔍 Advanced Scanning Engine
- **High-Performance Scanning**: 76,260 packets/second with adaptive concurrency control
- **Multiple Scan Types**: TCP connect, SYN scan, UDP scanning, service detection
- **Intelligent Service Detection**: Enhanced active probing for accurate service identification
- **CVE Enrichment**: Automatic vulnerability intelligence integration
- **Port Priority System**: Smart port prioritization for efficient scanning

### 🤖 AI-Powered Analysis
- **Natural Language Interface**: Ask security questions in plain English
- **Intelligent Threat Analysis**: AI-driven vulnerability assessment and recommendations
- **Multi-Provider Support**: OpenAI GPT, Anthropic Claude, and local LLM options
- **Real-time Security Insights**: Context-aware security recommendations

### 🖥️ Dual Interface Design
- **Interactive CLI**: Rich terminal UI with themes, progress bars, and live updates
- **Modern Web Interface**: Real-time dashboard with WebSocket support
- **RESTful API**: Comprehensive API with WebSocket streaming
- **Mobile Responsive**: Optimized for desktop and mobile devices

### 🚀 Enterprise Features
- **Redis Integration**: Intelligent caching and job queuing with automatic fallback
- **PostgreSQL Database**: Scalable data storage with migration support
- **Rate Limiting**: Advanced abuse protection with sliding window algorithms
- **Monitoring & Metrics**: Prometheus integration with Grafana dashboards
- **Docker Deployment**: Production-ready containerized deployment

## 📊 Performance Benchmarks

| Metric | CyberSec CLI | Nmap | Masscan | RustScan |
|--------|--------------|------|---------|----------|
| **Scanning Speed** | **76,260 p/s** | ~10-100 p/s | 10M+ p/s | Very Fast |
| **Accuracy (F1)** | **1.0** | High | Low | Medium |
| **Adaptive Logic** | **Yes (ML-driven)** | Limited | No | Partial |
| **Resource Efficiency** | **~0.5% CPU / 45MB** | Medium | High | Low |

## 🚀 Quick Start

### Prerequisites

- Python 3.10 or higher
- Docker & Docker Compose (for containerized deployment)
- Redis (optional, for enhanced performance)
- PostgreSQL (optional, for production deployments)

### Option 1: Quick Installation

```bash
# Clone the repository
git clone https://github.com/Yash7256/cybersec-cli.git
cd cybersec-cli

# Run the quick start script
bash scripts/quickstart.sh

# Configure your environment
cp .env.example .env
# Edit .env and add your OPENAI_API_KEY

# Start the CLI
python -m cybersec_cli
```

### Option 2: Docker Deployment (Production)

```bash
# Clone and setup
git clone https://github.com/Yash7256/cybersec-cli.git
cd cybersec-cli
cp .env.example .env

# Configure environment variables
nano .env
# Add your OPENAI_API_KEY and other settings

# Start the full stack
docker-compose up -d

# Access the web interface
open http://localhost:8000
```

### Option 3: pip Installation

```bash
# Install from PyPI (when available)
pip install cybersec-cli

# Or install from source
pip install -e .
```

## 💻 Basic Usage

### Interactive CLI

```bash
# Start the interactive shell
cybersec

# Show help
help

# Basic network scan
scan example.com

# Advanced scanning options
scan 192.168.1.1-254 --ports 1-1000 --service-detection --cve-enrichment

# AI-powered security analysis
ask "What are the security implications of an open SSH port?"

# Generate security report
report example.com --format pdf --export-path ./reports/
```

### Web Interface

Access the modern web dashboard at `http://localhost:8000`:

- **Real-time Scanning**: Live scan progress with Server-Sent Events
- **Historical Analysis**: Scan history and trend analysis
- **API Access**: Comprehensive REST API with interactive documentation
- **Export Capabilities**: Multiple formats (JSON, CSV, PDF, XML)

### API Usage

```bash
# Start a scan via API
curl -X POST "http://localhost:8000/api/scan" \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com", "ports": "1-1000"}'

# Stream scan results in real-time
curl "http://localhost:8000/api/scan/stream?target=example.com"
```

## 🛠️ Advanced Configuration

### Environment Variables

Create a `.env` file in the project root:

```bash
# Required for AI features
OPENAI_API_KEY=sk-your-openai-api-key

# Database Configuration
DATABASE_URL=postgresql://user:password@localhost:5432/cybersec
REDIS_URL=redis://localhost:6379

# Scanning Configuration
ADAPTIVE_SCANNING=true
MAX_CONCURRENCY=100
DEFAULT_TIMEOUT=3.0

# Security
SECRET_KEY=your-secret-key-here
WEBSOCKET_API_KEY=your-websocket-api-key

# Rate Limiting
RATE_LIMIT_ENABLED=true
CLIENT_RATE_LIMIT=10
TARGET_RATE_LIMIT=50
```

### Custom Configuration

The application uses a hierarchical configuration system:

1. **Environment Variables** (highest priority)
2. **Configuration File**: `~/.cybersec/config.yaml`
3. **Default Values** (lowest priority)

Example `config.yaml`:

```yaml
ai:
  provider: "openai"
  model: "gpt-4"
  temperature: 0.7

scanning:
  default_timeout: 3
  max_threads: 50
  adaptive_scanning: true
  enhanced_service_detection: true

ui:
  theme: "matrix"
  show_banner: true
  color_output: true

output:
  default_format: "table"
  save_results: true
  export_path: "./reports/"
```

## 🐳 Docker Deployment

### Full Stack Deployment

The `docker-compose.yml` includes:

- **Redis**: Caching and job queuing
- **PostgreSQL**: Primary database
- **CyberSec Web**: Main application
- **Celery Worker**: Background task processing
- **Nginx**: Reverse proxy and SSL termination
- **Prometheus**: Metrics collection
- **Grafana**: Visualization dashboard

### Scaling and Monitoring

```bash
# Scale the workers
docker-compose up -d --scale celery-worker=4

# View logs
docker-compose logs -f cybersec-web

# Monitor metrics
open http://localhost:3000  # Grafana
open http://localhost:9090  # Prometheus
```

## 📚 Documentation

### Core Documentation
- [User Guide](docs/user-guide.md) - Complete CLI and web interface usage
- [API Documentation](docs/api.md) - RESTful API and WebSocket interface
- [Deployment Guide](docs/deployment.md) - Docker, Kubernetes, and cloud deployment
- [Configuration Guide](docs/configuration.md) - Advanced configuration options

### Specialized Guides
- [Redis Integration](docs/redis_integration.md) - Caching and performance optimization
- [Security Best Practices](docs/SECURITY.md) - Security configuration and hardening
- [Performance Tuning](docs/performance-report.md) - Optimization and benchmarking
- [Troubleshooting](docs/troubleshooting.md) - Common issues and solutions

### Examples and Tutorials
- [CLI Examples](docs/examples/) - Practical command-line examples
- [API Examples](docs/examples/) - Code samples and integration guides
- [Deployment Scripts](scripts/) - Automation and deployment scripts

## 🧪 Testing

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=cybersec_cli --cov-report=html

# Run specific test categories
pytest -m unit          # Unit tests only
pytest -m integration   # Integration tests only
pytest -m slow          # Include slow tests
```

### Benchmarking

```bash
# Run performance benchmarks
python tests/benchmarking/run_all_benchmarks.py

# Generate comparison reports
python tests/benchmarking/tools/generate_report.py
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Setup

```bash
# Clone the repository
git clone https://github.com/Yash7256/cybersec-cli.git
cd cybersec-cli

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in development mode
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install

# Run the development server
python -m cybersec_cli --debug
```

### Code Quality

- **Linting**: `flake8 src/`
- **Formatting**: `black src/`
- **Type Checking**: `mypy src/`
- **Security**: `bandit -r src/`

## 🏗️ Project Structure

```
cybersec-cli/
├── src/cybersec_cli/          # Main application code
│   ├── commands/              # CLI command implementations
│   ├── tools/                # Security tools and scanners
│   ├── analysis/             # Security analysis modules
│   ├── ai/                   # AI integration
│   ├── core/                 # Core functionality
│   ├── utils/                # Utility functions
│   └── ui/                   # User interface components
├── web/                      # Web application
│   ├── routes/               # API endpoints
│   └── static/               # Static assets
├── api/                      # API-specific code
├── tasks/                    # Background tasks (Celery)
├── scripts/                  # Deployment and utility scripts
├── docs/                     # Documentation
├── tests/                    # Test suite
├── monitoring/               # Monitoring configuration
└── systemd/                  # Systemd service files
```

## 🔒 Security

This tool is designed for authorized security testing and educational purposes only. Users are responsible for:

- **Legal Compliance**: Ensure you have proper authorization before scanning
- **Responsible Usage**: Use only on networks you own or have permission to test
- **Data Privacy**: Handle scan results according to applicable regulations

For security concerns, see our [Security Policy](SECURITY.md).

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built with ❤️ using Python, FastAPI, and modern web technologies
- Inspired by industry-standard tools like Nmap, Masscan, and security best practices
- Powered by OpenAI and other amazing AI providers
- Community contributions and feedback

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/Yash7256/cybersec-cli/issues)
- **Discussions**: [GitHub Discussions](https://github.com/Yash7256/cybersec-cli/discussions)
- **Documentation**: [Wiki](https://github.com/Yash7256/cybersec-cli/wiki)

---

<div align="center">
  <strong>Made by the CyberSec Team</strong><br>
  <em>Empowering security professionals with intelligent tools</em>
</div>