# Cybersec CLI

[![Python Version](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

> AI-Powered Cybersecurity Assistant for Security Professionals

Cybersec CLI is a powerful command-line interface that combines AI assistance with essential cybersecurity tools. It's designed to help security professionals, penetration testers, and IT administrators perform security assessments and automate common tasks. The tool features both a command-line interface and a web interface for comprehensive network scanning, vulnerability assessment, and security analysis.

## 🌟 Features

- **Interactive AI Assistant**: Natural language processing for security-related queries
- **Comprehensive Toolset**: Network scanning, vulnerability assessment, and more
- **Adaptive Concurrency Control**: Automatically adjusts scanning speed based on network performance
- **Enhanced Service Detection**: Accurately identifies services using active probing
- **Beautiful Terminal UI**: Rich text formatting, progress bars, and interactive prompts
- **Extensible Architecture**: Easy to add new tools and commands
- **Themes**: Multiple color schemes to match your style
- **Redis Integration**: Caching and job queuing with automatic fallback to in-memory storage
- **Web Interface**: Modern web interface for real-time scanning and monitoring
- **API Access**: RESTful API with WebSocket support for programmatic access
- **Rate Limiting**: Advanced rate limiting with sliding window and abuse detection
- **Caching System**: Intelligent caching to avoid redundant scans
- **Real-time Streaming**: Server-Sent Events for live scan results

## 🚀 Quick Start

### Prerequisites

- Python 3.10 or higher
- pip (Python package manager)
- Docker (for containerized deployment)
- Nmap (for network scanning features)

### Installation

#### Option 1: Pip Installation (Recommended)

```bash
pip install cybersec-cli
```

#### Option 2: Docker Installation

```bash
# Pull the latest image
docker pull cybersec/cli:latest

# Run the CLI
docker run -it cybersec/cli:latest cybersec

# Run the web interface
docker run -p 8000:8000 cybersec/cli:latest web
```

#### Option 3: From Source

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/cybersec-cli.git
   cd cybersec-cli
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   pip install -e .
   ```

3. Set up environment variables:
   ```bash
   export OPENAI_API_KEY=your_openai_api_key
   export REDIS_URL=redis://localhost:6379
   ```

### Basic Usage

Start the interactive shell:
```bash
cybersec
```

Example commands:
```
# Show help
help

# Scan a target
scan example.com

# Scan specific ports
scan example.com --ports 1-1000

# Check SSL certificate
scan example.com --ssl

# Perform OS detection
scan example.com --os

# Get AI assistance
ask "What does an open SSH port mean?"

# Exit the application
exit
```

### Web Interface

Start the web interface:
```bash
# Using the CLI command
cybersec web

# Or directly from the web directory
cd web && python main.py
```

Access the web interface at `http://localhost:8000`

## 🐳 Docker Deployment

### Using Docker Compose (Recommended)

1. Create a `docker-compose.yml` file:
   ```yaml
   version: '3.8'
   services:
     cybersec-cli:
       image: cybersec/cli:latest
       ports:
         - "8000:8000"
       environment:
         - OPENAI_API_KEY=${OPENAI_API_KEY}
         - REDIS_URL=redis://redis:6379
         - DATABASE_URL=postgresql://postgres:password@db:5432/cybersec
       depends_on:
         - redis
         - db
       networks:
         - cybersec-net

     redis:
       image: redis:7-alpine
       volumes:
         - redis_data:/data
       networks:
         - cybersec-net

     db:
       image: postgres:15
       environment:
         - POSTGRES_DB=cybersec
         - POSTGRES_USER=postgres
         - POSTGRES_PASSWORD=password
       volumes:
         - postgres_data:/var/lib/postgresql/data
       networks:
         - cybersec-net

   volumes:
     redis_data:
     postgres_data:

   networks:
     cybersec-net:
       driver: bridge
   ```

2. Run the services:
   ```bash
   docker-compose up -d
   ```

## 🛠️ Configuration

Configuration is stored in `~/.cybersec/config.yaml`. The application will create this file with default settings on first run.

### Environment Variables

- `OPENAI_API_KEY`: Your OpenAI API key (required for AI features)
- `CYBERSEC_THEME`: Default theme (matrix, cyberpunk, minimal)
- `REDIS_URL`: Redis connection URL (default: redis://localhost:6379)
- `REDIS_PASSWORD`: Redis password (optional)
- `REDIS_DB`: Redis database number (default: 0)
- `ENABLE_REDIS`: Enable/disable Redis (default: true)
- `WEBSOCKET_API_KEY`: API key for WebSocket connections (optional)
- `WS_RATE_LIMIT`: Rate limit for WebSocket connections (default: 5)
- `WS_CONCURRENT_LIMIT`: Concurrent connections limit (default: 2)
- `DATABASE_URL`: Database connection string (default: sqlite:///cybersec.db)

## 🧰 Available Commands

### Core Commands
- `help` - Show help message
- `clear` - Clear the screen
- `exit`/`quit` - Exit the application

### Scan Commands
- `scan <target>` - Perform a basic scan
- `scan <target> --ports <ports>` - Scan specific ports
- `scan <target> --ssl` - Check SSL/TLS configuration
- `scan <target> --os` - Attempt OS detection
- `scan <target> --vuln` - Perform vulnerability scan
- `scan <target> --top-ports` - Scan top 1000 ports
- `scan <target> --fast` - Fast scan (top ports only)

### AI Commands
- `ask <question>` - Ask a cybersecurity question
- `explain <concept>` - Get an explanation of a security concept
- `suggest <tool> <target>` - Get tool usage suggestions
- `report <target>` - Generate a security report for the target

### Utility Commands
- `history` - Show command history
- `theme set <theme_name>` - Change the UI theme
- `config show` - Show current configuration
- `config edit` - Edit configuration interactively
- `export <target> <format>` - Export scan results

## 🌐 Web Interface

The CyberSec-CLI also provides a modern web interface with:

- Real-time scan results via Server-Sent Events
- WebSocket-based command execution
- Interactive dashboard for scan history
- Advanced filtering and export capabilities
- API access with comprehensive documentation
- Responsive design for desktop and mobile

### Web Interface Features
- Live scan progress monitoring
- Historical scan results
- Export results in multiple formats (JSON, CSV, PDF)
- API key management
- Rate limiting controls
- Performance metrics and monitoring

## 🎨 Themes

Change the look and feel with different themes:

1. `matrix` - Green-on-black terminal theme (default)
2. `cyberpunk` - Vibrant purple and blue theme
3. `minimal` - Clean and simple monochrome theme

Change theme with:
```
theme set <theme_name>
```

## 📚 Documentation

For detailed usage instructions and advanced features, see our documentation:

- [User Guide](docs/user-guide.md) - Complete CLI and web interface usage
- [Deployment Guide](docs/deployment.md) - Docker, Kubernetes, and cloud deployment
- [API Documentation](docs/api.md) - RESTful API and WebSocket interface
- [Troubleshooting Guide](docs/troubleshooting.md) - Common issues and solutions

## 🤝 Contributing

Contributions are welcome! Please read our [Contributing Guidelines](CONTRIBUTING.md) for details on how to get started.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built with ❤️ and Python
- Inspired by various open-source security tools
- Powered by OpenAI and other amazing libraries

## 📞 Support

For support, please open an issue on GitHub or contact the maintainers.

---

<div align="center">
  Made with 💻 by Your Name | 2023
</div>