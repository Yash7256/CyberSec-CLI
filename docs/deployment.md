# Deployment Guide

This guide provides comprehensive instructions for deploying CyberSec-CLI in various environments, from local development to production-scale deployments.

## Table of Contents

1. [Docker Deployment](#docker-deployment)
2. [Docker Compose Setup](#docker-compose-setup)
3. [Kubernetes Deployment](#kubernetes-deployment)
4. [Cloud Deployment](#cloud-deployment)
5. [Environment Configuration](#environment-configuration)
6. [Scaling Considerations](#scaling-considerations)
7. [Monitoring Setup](#monitoring-setup)

## Docker Deployment

### Prerequisites

- Docker Engine 20.10 or higher
- Docker Compose (for multi-container deployments)
- Sufficient system resources (4GB RAM recommended)

### Single Container Deployment

#### Pull the Image

```bash
docker pull cybersec/cli:latest
```

#### Run the CLI

```bash
# Run interactively
docker run -it cybersec/cli:latest cybersec

# Run with environment variables
docker run -it \
  -e OPENAI_API_KEY=your_openai_api_key \
  -e REDIS_URL=redis://host.docker.internal:6379 \
  cybersec/cli:latest cybersec
```

#### Run the Web Interface

```bash
# Basic web interface
docker run -p 8000:8000 cybersec/cli:latest web

# Web interface with environment variables
docker run -p 8000:8000 \
  -e OPENAI_API_KEY=your_openai_api_key \
  -e REDIS_URL=redis://host.docker.internal:6379 \
  -e DATABASE_URL=postgresql://user:pass@host:5432/db \
  cybersec/cli:latest web
```

#### Persistent Data

```bash
# Mount volumes for persistent data
docker run -p 8000:8000 \
  -v cybersec-config:/root/.cybersec \
  -v cybersec-logs:/app/logs \
  -e OPENAI_API_KEY=your_openai_api_key \
  cybersec/cli:latest web
```

### Building from Source

```bash
# Clone the repository
git clone https://github.com/yourusername/cybersec-cli.git
cd cybersec-cli

# Build the Docker image
docker build -t cybersec/cli:latest .

# Run the built image
docker run -p 8000:8000 cybersec/cli:latest web
```

## Docker Compose Setup

### Basic Docker Compose

Create a `docker-compose.yml` file:

```yaml
version: '3.8'

services:
  web:
    image: cybersec/cli:latest
    ports:
      - "8000:8000"
    environment:
      - OPENAI_API_KEY=${OPENAI_API_KEY}
      - REDIS_URL=redis://redis:6379
      - DATABASE_URL=postgresql://postgres:password@db:5432/cybersec
      - LOG_LEVEL=INFO
    depends_on:
      - redis
      - db
    networks:
      - cybersec-net
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    command: redis-server --appendonly yes
    volumes:
      - redis_data:/data
    networks:
      - cybersec-net
    restart: unless-stopped

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
    restart: unless-stopped

volumes:
  redis_data:
  postgres_data:

networks:
  cybersec-net:
    driver: bridge
```

### Environment File

Create a `.env` file:

```env
OPENAI_API_KEY=your_openai_api_key_here
POSTGRES_PASSWORD=your_secure_password
```

### Running with Docker Compose

```bash
# Start services
docker-compose up -d

# View logs
docker-compose logs -f web

# Stop services
docker-compose down

# Scale web services (if needed)
docker-compose up -d --scale web=2
```

### Production Docker Compose

For production environments, use this enhanced configuration:

```yaml
version: '3.8'

services:
  web:
    image: cybersec/cli:latest
    ports:
      - "8000:8000"
    environment:
      - OPENAI_API_KEY=${OPENAI_API_KEY}
      - REDIS_URL=redis://redis:6379
      - DATABASE_URL=postgresql://postgres:${POSTGRES_PASSWORD}@db:5432/cybersec
      - LOG_LEVEL=WARNING
      - ALLOWED_ORIGINS=${ALLOWED_ORIGINS:-http://localhost:8000,https://yourdomain.com}
      - WS_RATE_LIMIT=${WS_RATE_LIMIT:-5}
      - WS_CONCURRENT_LIMIT=${WS_CONCURRENT_LIMIT:-2}
    depends_on:
      - redis
      - db
    networks:
      - cybersec-net
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

  redis:
    image: redis:7-alpine
    command: redis-server --requirepass ${REDIS_PASSWORD:-} --appendonly yes
    volumes:
      - redis_data:/data
      - ./redis.conf:/usr/local/etc/redis/redis.conf
    networks:
      - cybersec-net
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 3s
      retries: 3

  db:
    image: postgres:15
    environment:
      - POSTGRES_DB=cybersec
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./init.sql:/docker-entrypoint-initdb.d/init.sql
    networks:
      - cybersec-net
    restart: unless-stopped
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 10s
      timeout: 5s
      retries: 5

volumes:
  redis_data:
    driver: local
  postgres_data:
    driver: local

networks:
  cybersec-net:
    driver: bridge
```

## Kubernetes Deployment

### Prerequisites

- Kubernetes cluster (v1.19 or higher)
- kubectl configured
- Helm (optional, for easier deployment)

### Basic Kubernetes Manifests

#### Namespace

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: cybersec-cli
```

#### ConfigMap

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: cybersec-config
  namespace: cybersec-cli
data:
  settings.yaml: |
    general:
      theme: "matrix"
      language: "en"
      log_level: "INFO"
    scanning:
      default_timeout: 1.0
      max_concurrent: 10
      default_ports: "top-ports"
    api:
      websocket_rate_limit: 5
      websocket_concurrent_limit: 2
```

#### Secret

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: cybersec-secrets
  namespace: cybersec-cli
type: Opaque
data:
  openai-api-key: <base64-encoded-api-key>
  postgres-password: <base64-encoded-password>
  redis-password: <base64-encoded-password>
```

#### PostgreSQL Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: postgres
  namespace: cybersec-cli
spec:
  replicas: 1
  selector:
    matchLabels:
      app: postgres
  template:
    metadata:
      labels:
        app: postgres
    spec:
      containers:
      - name: postgres
        image: postgres:15
        env:
        - name: POSTGRES_DB
          value: "cybersec"
        - name: POSTGRES_USER
          value: "postgres"
        - name: POSTGRES_PASSWORD
          valueFrom:
            secretKeyRef:
              name: cybersec-secrets
              key: postgres-password
        ports:
        - containerPort: 5432
        volumeMounts:
        - name: postgres-storage
          mountPath: /var/lib/postgresql/data
        livenessProbe:
          exec:
            command:
            - pg_isready
            - -U
            - postgres
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          exec:
            command:
            - pg_isready
            - -U
            - postgres
          initialDelaySeconds: 5
          periodSeconds: 5
      volumes:
      - name: postgres-storage
        persistentVolumeClaim:
          claimName: postgres-pvc
---
apiVersion: v1
kind: Service
metadata:
  name: postgres
  namespace: cybersec-cli
spec:
  selector:
    app: postgres
  ports:
    - protocol: TCP
      port: 5432
      targetPort: 5432
  type: ClusterIP
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: postgres-pvc
  namespace: cybersec-cli
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 10Gi
```

#### Redis Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: redis
  namespace: cybersec-cli
spec:
  replicas: 1
  selector:
    matchLabels:
      app: redis
  template:
    metadata:
      labels:
        app: redis
    spec:
      containers:
      - name: redis
        image: redis:7-alpine
        command:
        - redis-server
        - --requirepass
        - $(REDIS_PASSWORD)
        - --appendonly
        - "yes"
        env:
        - name: REDIS_PASSWORD
          valueFrom:
            secretKeyRef:
              name: cybersec-secrets
              key: redis-password
        ports:
        - containerPort: 6379
        volumeMounts:
        - name: redis-storage
          mountPath: /data
        livenessProbe:
          exec:
            command:
            - redis-cli
            - ping
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          exec:
            command:
            - redis-cli
            - ping
          initialDelaySeconds: 5
          periodSeconds: 5
      volumes:
      - name: redis-storage
        persistentVolumeClaim:
          claimName: redis-pvc
---
apiVersion: v1
kind: Service
metadata:
  name: redis
  namespace: cybersec-cli
spec:
  selector:
    app: redis
  ports:
    - protocol: TCP
      port: 6379
      targetPort: 6379
  type: ClusterIP
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: redis-pvc
  namespace: cybersec-cli
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 5Gi
```

#### Web Application Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cybersec-web
  namespace: cybersec-cli
spec:
  replicas: 2
  selector:
    matchLabels:
      app: cybersec-web
  template:
    metadata:
      labels:
        app: cybersec-web
    spec:
      containers:
      - name: web
        image: cybersec/cli:latest
        command: ["python", "web/main.py"]
        env:
        - name: OPENAI_API_KEY
          valueFrom:
            secretKeyRef:
              name: cybersec-secrets
              key: openai-api-key
        - name: REDIS_URL
          value: "redis://redis:6379"
        - name: DATABASE_URL
          value: "postgresql://postgres:$(POSTGRES_PASSWORD)@postgres:5432/cybersec"
        - name: POSTGRES_PASSWORD
          valueFrom:
            secretKeyRef:
              name: cybersec-secrets
              key: postgres-password
        - name: LOG_LEVEL
          value: "INFO"
        ports:
        - containerPort: 8000
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 60
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 10
          periodSeconds: 5
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "1Gi"
            cpu: "500m"
---
apiVersion: v1
kind: Service
metadata:
  name: cybersec-web
  namespace: cybersec-cli
spec:
  selector:
    app: cybersec-web
  ports:
    - protocol: TCP
      port: 80
      targetPort: 8000
  type: LoadBalancer
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: cybersec-ingress
  namespace: cybersec-cli
  annotations:
    nginx.ingress.kubernetes.io/rewrite-target: /
spec:
  rules:
  - host: cybersec.yourdomain.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: cybersec-web
            port:
              number: 80
```

### Helm Chart (Alternative)

For easier Kubernetes deployment, you can use a Helm chart:

```yaml
# Chart.yaml
apiVersion: v2
name: cybersec-cli
description: A Helm chart for CyberSec-CLI
type: application
version: 1.0.0
appVersion: "1.0.0"
```

```yaml
# values.yaml
# Default values for cybersec-cli
replicaCount: 2

image:
  repository: cybersec/cli
  pullPolicy: IfNotPresent
  tag: "latest"

service:
  type: LoadBalancer
  port: 80

ingress:
  enabled: false
  className: ""
  annotations: {}
  hosts:
    - host: cybersec.local
      paths:
        - path: /
          pathType: ImplementationSpecific

resources:
  limits:
    cpu: 500m
    memory: 1Gi
  requests:
    cpu: 250m
    memory: 512Mi

env:
  OPENAI_API_KEY: ""
  LOG_LEVEL: "INFO"
```

## Cloud Deployment

### Render.com Deployment

1. Create a `render.yaml` file:

```yaml
services:
  - type: web
    name: cybersec-cli
    env: python
    buildCommand: pip install -r requirements.txt && pip install -e .
    startCommand: python web/main.py
    envVars:
      - key: OPENAI_API_KEY
        sync: false
      - key: REDIS_URL
        sync: false
      - key: DATABASE_URL
        sync: false
    autoDeploy: false
```

2. Push to Render.com using Git or direct deployment

### AWS Deployment

#### Using Elastic Beanstalk

1. Create a `Procfile`:
```
web: python web/main.py
```

2. Deploy using the AWS CLI:
```bash
eb init
eb create cybersec-env
eb deploy
```

#### Using ECS/Fargate

Create task definition and service with the Docker image.

### Google Cloud Platform

#### Using Cloud Run

```bash
gcloud run deploy cybersec-cli \
  --image cybersec/cli:latest \
  --platform managed \
  --port 8000 \
  --set-env-vars OPENAI_API_KEY=your_key \
  --allow-unauthenticated
```

## Environment Configuration

### Required Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `OPENAI_API_KEY` | OpenAI API key for AI features | - | Yes |
| `REDIS_URL` | Redis connection URL | redis://localhost:6379 | No* |
| `DATABASE_URL` | Database connection string | sqlite:///cybersec.db | No* |

*Required if Redis or database is used

### Optional Environment Variables

| Variable | Description | Default | Notes |
|----------|-------------|---------|-------|
| `LOG_LEVEL` | Logging level | INFO | DEBUG, INFO, WARNING, ERROR |
| `REDIS_PASSWORD` | Redis password | - | If using password authentication |
| `REDIS_DB` | Redis database number | 0 | Database index |
| `ENABLE_REDIS` | Enable Redis | true | Set to false to disable |
| `WS_RATE_LIMIT` | WebSocket rate limit | 5 | Requests per minute |
| `WS_CONCURRENT_LIMIT` | WebSocket concurrent limit | 2 | Concurrent connections |
| `ALLOWED_ORIGINS` | CORS allowed origins | http://localhost:8000 | Comma-separated list |

### Configuration Best Practices

#### Security

- Never commit secrets to version control
- Use environment variables for sensitive data
- Implement proper access controls
- Use HTTPS in production

#### Performance

- Configure appropriate resource limits
- Use a production database (PostgreSQL/MySQL)
- Set up Redis for caching and rate limiting
- Monitor resource usage

#### Reliability

- Implement health checks
- Use persistent storage for data
- Set up proper logging
- Configure appropriate restart policies

## Scaling Considerations

### Horizontal Scaling

CyberSec-CLI can be scaled horizontally by running multiple instances:

1. **Stateless Application**: The web interface is stateless
2. **Shared Storage**: Use external Redis and database
3. **Load Balancing**: Distribute requests across instances
4. **Rate Limiting**: Centralized rate limiting with Redis

### Vertical Scaling

For single-instance scaling:

1. **CPU**: Increase for intensive scanning
2. **Memory**: Increase for large result sets
3. **Network**: Ensure sufficient bandwidth
4. **Storage**: For persistent logs and results

### Resource Requirements

#### Minimum Requirements
- CPU: 1 core
- Memory: 512MB
- Storage: 1GB

#### Recommended Requirements
- CPU: 2-4 cores
- Memory: 2-4GB
- Storage: 10GB+

#### Production Requirements
- CPU: 4+ cores
- Memory: 8GB+
- Storage: 50GB+

### Load Testing

Perform load testing to determine optimal scaling:

```bash
# Example using Apache Bench
ab -n 1000 -c 10 http://your-cybersec-cli/health

# Example using wrk
wrk -t12 -c400 -d30s http://your-cybersec-cli/api/status
```

## Monitoring Setup

### Application Metrics

CyberSec-CLI exposes metrics at `/metrics` endpoint in Prometheus format:

- `cybersec_scans_total`: Total number of scans
- `cybersec_scan_duration_seconds`: Scan duration histogram
- `cybersec_active_connections`: Active WebSocket connections
- `cybersec_rate_limit_exceeded_total`: Rate limit violations

### Logging Configuration

#### Log Levels

- DEBUG: Detailed diagnostic information
- INFO: General operational information
- WARNING: Potential issues
- ERROR: Errors that don't stop execution
- CRITICAL: Critical errors

#### Log Locations

- **Docker**: stdout/stderr
- **Kubernetes**: Cluster logging system
- **File**: `~/.cybersec/logs/`

### Monitoring Stack

#### Prometheus + Grafana

1. Deploy Prometheus to scrape metrics
2. Configure Grafana dashboard
3. Set up alerting rules

#### Example Prometheus Configuration

```yaml
scrape_configs:
  - job_name: 'cybersec-cli'
    static_configs:
      - targets: ['cybersec-web:8000']
    scrape_interval: 15s
```

### Health Checks

#### Liveness Probe
```
GET /health
```

#### Readiness Probe
```
GET /ready
```

### Alerting

Set up alerts for:

- High error rates
- Slow response times
- Resource exhaustion
- Service unavailability
- Rate limit violations