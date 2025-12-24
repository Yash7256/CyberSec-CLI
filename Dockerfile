FROM python:3.10.14-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Create non-root user
RUN useradd -m -u 1000 cybersec && \
    mkdir -p /app /app/reports && \
    chown -R cybersec:cybersec /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    libffi-dev \
    libpcap-dev \
    nmap \
    curl \
    git \
    gcc \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Set working directory
WORKDIR /app

# Copy requirements
COPY requirements.txt ./
COPY web/requirements.txt ./web_requirements.txt

# Combine requirements and install
RUN if [ -f web_requirements.txt ]; then \
    cat requirements.txt web_requirements.txt | sort -u > combined_requirements.txt; \
    else \
    cp requirements.txt combined_requirements.txt; \
    fi && \
    pip install --upgrade pip setuptools wheel && \
    pip install -r combined_requirements.txt

# Copy application code
COPY src/ src/
COPY web/ web/
COPY core/ core/
COPY setup.py .
COPY README.md .

# Install the package in editable mode
RUN pip install -e .

# Run database migrations
RUN python scripts/init_db.py || echo "Database migration will run on first start"

# Create necessary directories
RUN mkdir -p ~/.cybersec/models && \
    mkdir -p reports && \
    mkdir -p logs && \
    chown -R cybersec:cybersec /app

# Switch to non-root user
USER cybersec

# Expose ports
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8000/api/status || exit 1

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8000/api/status')"

# Default command (web interface)
CMD ["python", "-m", "uvicorn", "web.main:app", "--host", "0.0.0.0", "--port", "8000"]