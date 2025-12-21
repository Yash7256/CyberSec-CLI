# Cybersec CLI

[![Python Version](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

> AI-Powered Cybersecurity Assistant for Security Professionals

Cybersec CLI is a powerful command-line interface that combines AI assistance with essential cybersecurity tools. It's designed to help security professionals, penetration testers, and IT administrators perform security assessments and automate common tasks.

## 🌟 Features

- **Interactive AI Assistant**: Natural language processing for security-related queries
- **Comprehensive Toolset**: Network scanning, vulnerability assessment, and more
- **Adaptive Concurrency Control**: Automatically adjusts scanning speed based on network performance
- **Beautiful Terminal UI**: Rich text formatting, progress bars, and interactive prompts
- **Extensible Architecture**: Easy to add new tools and commands
- **Themes**: Multiple color schemes to match your style

## 🚀 Quick Start

### Prerequisites

- Python 3.10 or higher
- pip (Python package manager)

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/cybersec-cli.git
   cd cybersec-cli
   ```

2. Install the package in development mode:
   ```bash
   pip install -e .
   ```

   Or install directly from source:
   ```bash
   pip install -r requirements.txt
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

# Check SSL certificate
scan example.com --ssl

# Exit the application
exit
```

## 🛠️ Configuration

Configuration is stored in `~/.cybersec/config.yaml`. The application will create this file with default settings on first run.

### Environment Variables

- `OPENAI_API_KEY`: Your OpenAI API key (required for AI features)
- `CYBERSEC_THEME`: Default theme (matrix, cyberpunk, minimal)

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

### AI Commands
- `ask <question>` - Ask a cybersecurity question
- `explain <concept>` - Get an explanation of a security concept
- `suggest <tool> <target>` - Get tool usage suggestions

## 🎨 Themes

Change the look and feel with different themes:

1. `matrix` - Green-on-black terminal theme (default)
2. `cyberpunk` - Vibrant purple and blue theme
3. `minimal` - Clean and simple monochrome theme

Change theme with:
```
theme set <theme_name>
```

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
