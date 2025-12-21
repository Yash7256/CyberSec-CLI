# Redis Integration Guide

This document explains how to set up and use Redis with CyberSec-CLI for caching and job queuing.

## Overview

Redis integration provides:

1. **Caching Layer**: Speed up repeated operations by caching results
2. **Job Queue**: Process background tasks efficiently
3. **Rate Limiting**: Track and enforce rate limits across instances
4. **Session Storage**: Store user sessions for web interface
5. **Graceful Fallback**: Automatically falls back to in-memory cache if Redis is unavailable

## Configuration

### Environment Variables

The following environment variables control Redis behavior:

```bash
# Redis connection URL (default: redis://localhost:6379)
REDIS_URL=redis://localhost:6379

# Redis password (optional)
REDIS_PASSWORD=

# Redis database number (default: 0)
REDIS_DB=0

# Enable/disable Redis (default: true)
ENABLE_REDIS=true
```

### Docker Configuration

When using Docker Compose, Redis is automatically configured:

- Service name: `redis`
- Container name: `cybersec-redis`
- Port: `6379`
- Data persistence: Volume-mounted to `redis-data`

## Redis Client API

The Redis client provides a simple interface with automatic fallback:

### Methods

1. **get(key)** - Retrieve value by key
   ```python
   from core.redis_client import redis_client
   value = redis_client.get("my_key")
   ```

2. **set(key, value, ttl=3600)** - Set key-value pair with TTL
   ```python
   redis_client.set("my_key", "my_value", ttl=1800)  # 30 minutes
   ```

3. **delete(key)** - Delete a key
   ```python
   redis_client.delete("my_key")
   ```

4. **exists(key)** - Check if key exists
   ```python
   if redis_client.exists("my_key"):
       print("Key exists")
   ```

5. **increment(key, amount=1)** - Increment numeric value
   ```python
   count = redis_client.increment("visitor_count", 1)
   ```

6. **expire(key, seconds)** - Set expiration time
   ```python
   redis_client.expire("my_key", 3600)  # Expire in 1 hour
   ```

### Health Check Endpoint

A health check endpoint is available at `/health/redis`:

```bash
curl http://localhost:8000/health/redis
```

Response examples:
```json
// Healthy
{
  "status": "healthy",
  "latency_ms": 0.5,
  "message": "Redis connection is healthy"
}

// Unhealthy
{
  "status": "unhealthy",
  "error": "Connection refused",
  "message": "Redis connection failed"
}

// Disabled
{
  "status": "disabled",
  "message": "Redis is not available or not configured"
}
```

## Migration from In-Memory to Redis

### 1. Update Environment Variables

Set the following in your `.env` file:
```bash
ENABLE_REDIS=true
REDIS_URL=redis://localhost:6379
```

### 2. Docker Deployment

With Docker Compose, Redis is automatically included:
```bash
docker-compose up -d
```

### 3. Manual Installation

Install Redis server:
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install redis-server

# CentOS/RHEL
sudo yum install redis

# macOS
brew install redis
```

Start Redis:
```bash
redis-server
```

### 4. Verify Connection

Check Redis health:
```bash
curl http://localhost:8000/health/redis
```

## Best Practices

### Key Naming Convention

Use descriptive key prefixes:
- `cache:user:{user_id}` for user data
- `session:{session_id}` for session data
- `job:scan:{target}` for scan jobs
- `rate:{ip_address}` for rate limiting

### TTL Management

Set appropriate TTL values:
- Short-lived cache: 5-30 minutes
- Session data: 24 hours
- Configuration: 1 hour
- Job queues: Process-based (no TTL until completion)

### Error Handling

The Redis client automatically falls back to in-memory cache if Redis is unavailable, but you should still handle potential errors:

```python
from core.redis_client import redis_client

try:
    result = redis_client.get("important_key")
    if result is None:
        # Handle cache miss
        result = compute_expensive_operation()
        redis_client.set("important_key", result, ttl=3600)
except Exception as e:
    # Handle any Redis-related errors
    logger.warning(f"Redis operation failed: {e}")
    result = compute_expensive_operation()
```

## Troubleshooting

### Connection Issues

1. Check if Redis server is running:
   ```bash
   redis-cli ping
   ```

2. Verify connection settings in `.env` file

3. Check Docker service status:
   ```bash
   docker-compose ps
   ```

### Performance Issues

1. Monitor Redis memory usage:
   ```bash
   redis-cli info memory
   ```

2. Check for slow operations:
   ```bash
   redis-cli slowlog get
   ```

3. Optimize key sizes and TTL values

## Security Considerations

1. **Network Security**: Bind Redis to localhost or use protected networks
2. **Authentication**: Set a strong password using `REDIS_PASSWORD`
3. **Database Isolation**: Use separate databases for different environments
4. **Encryption**: Use TLS in production environments

Example secure configuration:
```bash
REDIS_URL=rediss://:your_password@redis.example.com:6380/1
REDIS_PASSWORD=your_strong_password
```