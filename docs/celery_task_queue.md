# Celery Task Queue Implementation

This document describes the Celery task queue implementation for the CyberSec-CLI project, which enables asynchronous job processing to separate scanning from web requests.

## Overview

The Celery implementation provides:

1. Asynchronous scan processing using Redis as broker and result backend
2. Task prioritization and routing
3. Progress tracking and status reporting
4. Error handling and automatic retries
5. Horizontal scaling through multiple workers

## Architecture

```
[Web API] → [Redis Broker] → [Celery Worker] → [Redis Results] → [Web API]
```

## Components

### 1. Celery App (`tasks/celery_app.py`)

- Configures Celery with Redis as broker and result backend
- Sets up task routing and queues
- Configures worker behavior

### 2. Scan Tasks (`tasks/scan_tasks.py`)

- Implements `perform_scan_task` for network scanning
- Tracks progress using Celery's update_state
- Stores results in database when complete
- Handles errors and retries (max 3 attempts)

### 3. Worker Entry Point (`worker.py`)

- Starts the Celery worker process
- Configures logging and worker parameters

### 4. Web API Integration (`web/main.py`)

- New endpoints for async scanning:
  - `POST /api/scan` - Queue a new scan task
  - `GET /api/scan/{task_id}` - Check task status

## Setup and Configuration

### Environment Variables

```bash
# Redis connection (already configured)
REDIS_URL=redis://localhost:6379

# Optional: Celery-specific settings
CELERY_BROKER_URL=redis://localhost:6379
CELERY_RESULT_BACKEND=redis://localhost:6379
```

### Dependencies

The following packages are required (already added to requirements.txt):

```txt
celery==5.3.4
redis==4.5.4
```

## Running the System

### Using Docker Compose (Recommended)

```bash
# Start all services including Celery worker
docker-compose up -d

# Scale workers if needed
docker-compose up -d --scale celery-worker=3
```

### Manual Setup

1. **Start Redis server:**
   ```bash
   redis-server
   ```

2. **Start Celery worker:**
   ```bash
   cd /path/to/cybersec-cli
   python worker.py
   ```

3. **Start web application:**
   ```bash
   cd /path/to/cybersec-cli
   python web/main.py
   ```

## Using the API

### Queue a Scan

```bash
curl -X POST http://localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{
    "target": "example.com",
    "ports": "1-1000",
    "config": {
      "scan_type": "TCP",
      "timeout": 1.0,
      "max_concurrent": 50
    }
  }'
```

Response:
```json
{
  "task_id": "123e4567-e89b-12d3-a456-426614174000",
  "scan_id": "123e4567-e89b-12d3-a456-426614174000",
  "status": "queued",
  "message": "Scan queued for target example.com"
}
```

### Check Scan Status

```bash
curl http://localhost:8000/api/scan/123e4567-e89b-12d3-a456-426614174000
```

During processing:
```json
{
  "state": "PROGRESS",
  "status": "Scanning critical priority ports",
  "progress": 25,
  "current_group": "critical",
  "group_size": 15
}
```

When complete:
```json
{
  "state": "SUCCESS",
  "result": {
    "scan_id": "123e4567-e89b-12d3-a456-426614174000",
    "target": "example.com",
    "ports": "1-1000",
    "total_ports_scanned": 1000,
    "open_ports": [...],
    "status": "completed",
    "progress": 100
  }
}
```

## Production Deployment

### Systemd Service

A systemd service file is provided at `systemd/celery-worker.service`:

```ini
[Unit]
Description=CyberSec-CLI Celery Worker
After=network.target redis.service

[Service]
Type=forking
User=cybersec
Group=cybersec
WorkingDirectory=/opt/cybersec-cli
ExecStart=/opt/cybersec-cli/venv/bin/celery -A worker worker --loglevel=info --queues=scans --hostname=cybersec-worker@%h --concurrency=4 --prefetch-multiplier=1
ExecReload=/bin/kill -HUP $MAINPID
KillSignal=SIGTERM
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

### Supervisor Configuration

Alternatively, use Supervisor:

```ini
[program:cybersec-worker]
command=/opt/cybersec-cli/venv/bin/celery -A worker worker --loglevel=info --queues=scans
directory=/opt/cybersec-cli
user=cybersec
numprocs=1
stdout_logfile=/var/log/cybersec-worker.log
stderr_logfile=/var/log/cybersec-worker.log
autostart=true
autorestart=true
startsecs=10
stopwaitsecs=600
killasgroup=true
priority=998
```

## Monitoring and Management

### Flower (Optional)

Install Flower for web-based monitoring:

```bash
pip install flower
celery -A tasks.celery_app flower
```

### Command Line Tools

```bash
# List active workers
celery -A tasks.celery_app inspect active

# Check worker stats
celery -A tasks.celery_app inspect stats

# List registered tasks
celery -A tasks.celery_app inspect registered

# Purge task queue
celery -A tasks.celery_app purge
```

## Error Handling and Retries

The scan task is configured to automatically retry up to 3 times on failure with a 60-second delay between retries. Failed tasks are logged for investigation.

## Scaling

To scale the worker capacity:

1. **Horizontal scaling:** Start additional worker processes
2. **Vertical scaling:** Increase concurrency per worker
3. **Queue separation:** Route different task types to different queues

## Security Considerations

1. **Network isolation:** Workers should only accept connections from trusted sources
2. **Authentication:** Use Redis authentication if exposed to network
3. **Resource limits:** Configure worker concurrency to prevent resource exhaustion
4. **Input validation:** Validate all scan parameters before queuing tasks

## Troubleshooting

### Common Issues

1. **Workers not starting:**
   - Check Redis connectivity
   - Verify Python path and dependencies
   - Check logs for import errors

2. **Tasks stuck in PENDING:**
   - Verify workers are running
   - Check Redis connectivity
   - Review task routing configuration

3. **High memory usage:**
   - Reduce worker concurrency
   - Optimize scan result serialization
   - Implement result expiration

### Log Locations

- Worker logs: `/var/log/cybersec-worker.log` (when using systemd/supervisor)
- Application logs: As configured in web application
- Redis logs: As configured in Redis installation

## Performance Tuning

1. **Worker concurrency:** Adjust based on CPU cores and I/O characteristics
2. **Prefetch multiplier:** Set to 1 for better load distribution
3. **Result expiration:** Configure appropriate TTL for scan results
4. **Queue routing:** Separate long-running tasks from quick ones