# Redis Migration Guide

This guide explains how to migrate from in-memory caching to Redis for the CyberSec-CLI application.

## Overview

The CyberSec-CLI application now supports Redis as a caching and job queue backend with graceful fallback to in-memory cache if Redis is unavailable.

## Prerequisites

Ensure you have the following installed:
- Redis server (version 6.0 or higher)
- Python packages: `redis` and `aioredis`

## Configuration

### Environment Variables

The following environment variables can be used to configure Redis:

| Variable | Default | Description |
|----------|---------|-------------|
| `REDIS_URL` | `redis://localhost:6379` | Redis server URL |
| `REDIS_PASSWORD` | None | Password for Redis authentication |
| `REDIS_DB` | `0` | Redis database number |
| `ENABLE_REDIS` | `true` | Enable/disable Redis integration |

### Docker Configuration

If using Docker, the `docker-compose.yml` file already includes a Redis service:

```yaml
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
```

## Migration Steps

### 1. Install Dependencies

Ensure Redis dependencies are installed:

```bash
pip install redis aioredis
```

Or if using the project's requirements:

```bash
pip install -r requirements.txt
```

### 2. Configure Environment

Set the appropriate environment variables in your `.env` file:

```bash
REDIS_URL=redis://localhost:6379
REDIS_PASSWORD=your_password  # Optional
REDIS_DB=0
ENABLE_REDIS=true
```

### 3. Update Application Code

The Redis client is already integrated into the application. You can use it by importing:

```python
from core.redis_client import redis_client
```

### 4. Using Redis Methods

The Redis client provides the following methods:

- `get(key)` - Get value by key
- `set(key, value, ttl=3600)` - Set key-value pair with optional TTL
- `delete(key)` - Delete key
- `exists(key)` - Check if key exists
- `increment(key, amount=1)` - Increment key by amount
- `expire(key, seconds)` - Set expiration time for a key

Example usage:

```python
# Set a value with 1 hour TTL
redis_client.set("my_key", "my_value", ttl=3600)

# Get a value
value = redis_client.get("my_key")

# Check if key exists
if redis_client.exists("my_key"):
    print("Key exists")

# Increment a counter
count = redis_client.increment("counter_key")

# Delete a key
redis_client.delete("my_key")
```

### 5. Health Check

A health check endpoint is available at `/health/redis` which returns:

```json
{
  "status": "healthy",
  "latency_ms": 0.5,
  "message": "Redis connection is healthy"
}
```

## Fallback Behavior

If Redis is unavailable or disabled, the application will automatically fall back to in-memory caching. All functionality will continue to work, but data will not be persisted across application restarts.

## Testing

To test the Redis integration, run:

```bash
python test_redis_health.py
```

This will verify that the Redis client is working correctly and test all available methods.

## Troubleshooting

### Common Issues

1. **Connection Refused**: Ensure Redis server is running and accessible
2. **Authentication Failed**: Check `REDIS_PASSWORD` environment variable
3. **Database Not Found**: Verify `REDIS_DB` is a valid database number

### Logs

Check application logs for Redis-related messages:
- `INFO` level for successful connections
- `WARNING` level for fallbacks to in-memory cache
- `ERROR` level for connection failures

## Best Practices

1. Always set appropriate TTL values for cache entries
2. Use descriptive key names to avoid conflicts
3. Monitor Redis memory usage
4. Regularly backup Redis data if persistence is critical
5. Use connection pooling for efficient resource usage

## Rollback

To disable Redis and revert to in-memory caching only:

```bash
ENABLE_REDIS=false
```

This will completely disable Redis integration and use only in-memory caching.