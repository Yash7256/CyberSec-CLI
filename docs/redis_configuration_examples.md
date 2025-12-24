# Redis Configuration Examples

This document provides various configuration examples for setting up Redis with the CyberSec-CLI application.

## Basic Configuration

### Environment Variables (.env file)

```bash
# Basic Redis configuration
REDIS_URL=redis://localhost:6379
REDIS_DB=0
ENABLE_REDIS=true

# Optional password (if Redis requires authentication)
# REDIS_PASSWORD=your_secure_password
```

### Docker Compose Configuration

The application already includes Redis in the `docker-compose.yml` file:

```yaml
version: '3.8'

services:
  redis:
    image: redis:7-alpine
    container_name: cybersec-redis
    ports:
      - "6379:6379"
    restart: unless-stopped
    networks:
      - cybersec-network
    volumes:
      - redis-data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 3s
      retries: 3
    command: redis-server --appendonly yes

  cybersec-web:
    # ... other configuration
    environment:
      # ... other environment variables
      REDIS_URL: redis://redis:6379
    depends_on:
      redis:
        condition: service_healthy
    # ... rest of configuration

volumes:
  redis-data:
    driver: local

networks:
  cybersec-network:
    driver: bridge
```

## Advanced Configurations

### 1. External Redis Server

To connect to an external Redis server:

```bash
# In .env file
REDIS_URL=redis://external-redis-server:6379
REDIS_PASSWORD=external_server_password
REDIS_DB=1
```

### 2. Redis with TLS

For secure connections to Redis:

```bash
# In .env file
REDIS_URL=rediss://secure-redis-server:6379
REDIS_PASSWORD=secure_password
REDIS_DB=0
```

### 3. Multiple Redis Instances

For applications requiring multiple Redis instances:

```bash
# Primary Redis for caching
PRIMARY_REDIS_URL=redis://primary-redis:6379
PRIMARY_REDIS_DB=0

# Secondary Redis for job queues
QUEUE_REDIS_URL=redis://queue-redis:6379
QUEUE_REDIS_DB=1
```

Then modify the Redis client to support multiple instances:

```python
# In core/redis_client.py
class RedisClient:
    def __init__(self, url=None, db=0, password=None):
        # Allow custom configuration
        redis_url = url or os.getenv('REDIS_URL', 'redis://localhost:6379')
        redis_password = password or os.getenv('REDIS_PASSWORD')
        redis_db = int(os.getenv('REDIS_DB', db))
        # ... rest of initialization
```

## Configuration Validation

### Testing Redis Connection

Use the built-in health check endpoint:

```bash
# Test Redis health
curl http://localhost:8000/health/redis
```

Expected response:
```json
{
  "status": "healthy",
  "latency_ms": 0.5,
  "message": "Redis connection is healthy"
}
```

### Manual Testing Script

Create a simple test script `test_redis_config.py`:

```python
#!/usr/bin/env python3
"""
Test Redis configuration
"""

import os
import sys
sys.path.insert(0, os.path.abspath('.'))

from core.redis_client import redis_client

def test_redis_config():
    print("Testing Redis Configuration...")
    
    # Check if Redis is enabled
    enabled = os.getenv('ENABLE_REDIS', 'true').lower() == 'true'
    print(f"Redis Enabled: {enabled}")
    
    # Check Redis URL
    redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379')
    print(f"Redis URL: {redis_url}")
    
    # Test connection
    print(f"Redis Available: {redis_client.is_redis_available()}")
    
    # Test basic operations
    if redis_client.is_redis_available():
        print("Testing basic operations...")
        redis_client.set("test_key", "test_value", ttl=60)
        value = redis_client.get("test_key")
        print(f"Retrieved value: {value}")
        redis_client.delete("test_key")
        print("Basic operations successful!")
    else:
        print("Redis not available, using in-memory cache")

if __name__ == "__main__":
    test_redis_config()
```

## Monitoring and Metrics

### Redis Stats Dashboard

You can monitor Redis using the built-in `redis-cli`:

```bash
# Connect to Redis
redis-cli

# Get info
info

# Get memory stats
info memory

# Get keyspace stats
info keyspace
```

### Custom Metrics Endpoint

Extend the health check to include more metrics in `web/main.py`:

```python
@app.get("/health/redis")
async def redis_health_check():
    """Enhanced health check with metrics."""
    if not HAS_REDIS or redis_client is None:
        return {
            "status": "disabled",
            "message": "Redis is not available or not configured"
        }
    
    try:
        start_time = time.time()
        # Test Redis connectivity
        redis_client.redis_client.ping()
        latency = (time.time() - start_time) * 1000
        
        # Get additional metrics if available
        try:
            info = redis_client.redis_client.info()
            memory_used = info.get('used_memory_human', 'N/A')
            connected_clients = info.get('connected_clients', 'N/A')
        except:
            memory_used = "N/A"
            connected_clients = "N/A"
        
        return {
            "status": "healthy",
            "latency_ms": round(latency, 2),
            "memory_used": memory_used,
            "connected_clients": connected_clients,
            "message": "Redis connection is healthy"
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e),
            "message": "Redis connection failed"
        }
```

## Security Considerations

### 1. Network Security

When deploying in production:

```yaml
# docker-compose.yml
redis:
  image: redis:7-alpine
  container_name: cybersec-redis
  # Don't expose Redis port publicly
  # ports:
  #   - "6379:6379"
  expose:
    - "6379"
  restart: unless-stopped
  networks:
    - cybersec-network
  volumes:
    - redis-data:/data
  # Require password authentication
  command: redis-server --requirepass ${REDIS_PASSWORD}
```

### 2. Environment Variable Security

Store sensitive information in a secure way:

```bash
# Use Docker secrets or Kubernetes secrets in production
# .env file for development only
REDIS_PASSWORD_FILE=/run/secrets/redis_password
```

## Backup and Recovery

### Automated Backups

Add backup configuration to docker-compose.yml:

```yaml
redis:
  image: redis:7-alpine
  # ... other configuration
  volumes:
    - redis-data:/data
    - ./backups:/backups
  # Add backup cron job
  command: >
    sh -c "
      redis-server --appendonly yes &
      sleep 5 &&
      crontab -l | { cat; echo '0 2 * * * redis-cli bgrewriteaof && cp /data/appendonly.aof /backups/'; } | crontab - &&
      tail -f /dev/null
    "
```

This configuration provides comprehensive examples for configuring Redis with the CyberSec-CLI application in various environments and use cases.