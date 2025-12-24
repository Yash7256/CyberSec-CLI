from setuptools import find_packages, setup

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="cybersec-cli",
    version="0.1.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="AI-Powered Cybersecurity Assistant CLI",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/cybersec-cli",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    python_requires=">=3.10",
    install_requires=[
        "click>=8.1.0",
        "rich>=13.0.0",
        "python-dotenv>=1.0.0",
        "requests>=2.28.0",
        "python-nmap>=0.7.1",
        "scapy>=2.5.0",
        "cryptography>=41.0.0",
        "tqdm>=4.65.0",
        "pyfiglet>=1.0.0",
        "prompt-toolkit>=3.0.0",
        "colorama>=0.4.0",
        "sqlalchemy>=2.0.0",
        "aiohttp>=3.8.0",
        "python-jose>=3.3.0",
        "tabulate>=0.9.0",
        "pydantic>=2.0.0",
    ],
    entry_points={
        "console_scripts": [
            "cybersec=cybersec_cli.main:cli",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: System :: Systems Administration",
        "Environment :: Console",
    ],
    keywords="cybersecurity cli security-tools penetration-testing infosec",
    project_urls={
        "Bug Reports": "https://github.com/yourusername/cybersec-cli/issues",
        "Source": "https://github.com/yourusername/cybersec-cli",
    },
)
