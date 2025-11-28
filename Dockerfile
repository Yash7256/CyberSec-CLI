FROM python:3.10-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    libffi-dev \
    nmap \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements
COPY requirements.txt web/requirements.txt ./requirements_web.txt ./

# Combine requirements and install
RUN cat requirements.txt requirements_web.txt | sort -u > combined_requirements.txt && \
    pip install --upgrade pip setuptools wheel && \
    pip install -r combined_requirements.txt

# Copy application code
COPY src/ src/
COPY web/ web/
COPY setup.py .
COPY README.md .

# Install the package in editable mode
RUN pip install -e .

# Create necessary directories
RUN mkdir -p ~/.cybersec/models && \
    mkdir -p reports && \
    mkdir -p logs

# Expose ports
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8000/api/status || exit 1

# Default command (can be overridden)
CMD ["python", "web/main.py"]
