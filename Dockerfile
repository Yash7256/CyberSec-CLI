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
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Set working directory
WORKDIR /app

# Copy application code
COPY src/ src/
COPY web/ web/
COPY setup.py .
COPY README.md .

# Copy requirements
COPY requirements.txt ./
COPY web/requirements.txt ./web_requirements.txt

# Install requirements separately to avoid conflicts
RUN pip install --upgrade pip setuptools wheel && \
    pip install -r requirements.txt && \
    pip install -r web_requirements.txt

# Install the package in editable mode
RUN pip install -e .

# Create startup scripts
RUN echo '#!/bin/bash\n\n# Determine DB host: prefer DB_HOST, fallback to host extracted from DATABASE_URL, default to "postgres"\nif [ -z "${DB_HOST}" ]; then\n  if [ -n "${DATABASE_URL}" ]; then\n    DB_HOST=$(echo "$DATABASE_URL" | sed -E "s#^[^:]+://([^@]+@)?([^:/]+).*#\\2#")\n  else\n    DB_HOST=postgres\n  fi\nfi\n\n# Wait for database to be ready\nuntil nc -z $DB_HOST 5432; do\n  echo "Waiting for PostgreSQL at $DB_HOST..."\n  sleep 2\ndone\n\n# Run database migrations\npython scripts/init_db.py || echo "Database migration failed, will retry on next start"\n\n# Start the application\nexec "$@"' > /app/web-startup.sh && chmod +x /app/web-startup.sh && \
    echo '#!/bin/bash\n\n# Determine DB host: prefer DB_HOST, fallback to host extracted from DATABASE_URL, default to "postgres"\nif [ -z "${DB_HOST}" ]; then\n  if [ -n "${DATABASE_URL}" ]; then\n    DB_HOST=$(echo "$DATABASE_URL" | sed -E "s#^[^:]+://([^@]+@)?([^:/]+).*#\\2#")\n  else\n    DB_HOST=postgres\n  fi\nfi\n\nREDIS_HOST=${REDIS_HOST:-redis}\n\n# Wait for services to be ready\nuntil nc -z $DB_HOST 5432; do\n  echo "Waiting for PostgreSQL at $DB_HOST..."\n  sleep 2\ndone\n\nuntil nc -z $REDIS_HOST 6379; do\n  echo "Waiting for Redis at $REDIS_HOST..."\n  sleep 2\ndone\n\n# Start the application\nexec "$@"' > /app/worker-startup.sh && chmod +x /app/worker-startup.sh

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

# Default command (web interface)
CMD ["/app/web-startup.sh", "python", "-m", "uvicorn", "web.main:app", "--host", "0.0.0.0", "--port", "8000"]