"""
Redis client for CyberSec CLI.
"""
import redis
import logging
import json
from typing import Optional, Any
import os
from urllib.parse import urlparse
from functools import wraps
import sys
from typing import Dict

# Try to import redis, but don't fail if it's not available
try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    redis = None

# Import structured logging
try:
    from core.logging_config import get_logger
    HAS_STRUCTURED_LOGGING = True
except ImportError:
    HAS_STRUCTURED_LOGGING = False

logger = get_logger('database') if HAS_STRUCTURED_LOGGING else logging.getLogger(__name__)


class RedisClient:
    """Singleton Redis client with connection pooling and in-memory fallback."""
    
    _instance = None
    _initialized = False
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(RedisClient, cls).__new__(cls)
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
            
        self.redis_client = None
        self.in_memory_cache: Dict[str, Any] = {}
        self.enabled = os.getenv('ENABLE_REDIS', 'true').lower() == 'true'
        
        if self.enabled and REDIS_AVAILABLE:
            try:
                redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379')
                redis_password = os.getenv('REDIS_PASSWORD')
                redis_db = int(os.getenv('REDIS_DB', '0'))
                
                # Parse the URL to extract host and port
                parsed = urlparse(redis_url)
                host = parsed.hostname or 'localhost'
                port = parsed.port or 6379
                
                # Create connection pool
                connection_pool = redis.ConnectionPool(
                    host=host,
                    port=port,
                    password=redis_password,
                    db=redis_db,
                    max_connections=20,
                    retry_on_timeout=True
                )
                
                self.redis_client = redis.Redis(connection_pool=connection_pool)
                # Test connection
                self.redis_client.ping()
                logger.info("Redis connection established successfully")
            except Exception as e:
                logger.warning(f"Failed to connect to Redis, falling back to in-memory cache: {e}")
                self.redis_client = None
        else:
            logger.info("Redis is disabled or not available, using in-memory cache")
            
        self._initialized = True
    
    def _ensure_redis(self, func):
        """Decorator to ensure Redis is available, fallback to in-memory if not."""
        @wraps(func)
        def wrapper(*args, **kwargs):
            if self.redis_client is not None:
                try:
                    return func(self, *args, **kwargs)
                except Exception as e:
                    logger.warning(f"Redis operation failed, falling back to in-memory: {e}")
                    self.redis_client = None
            
            # Fallback to in-memory implementation
            in_memory_func = getattr(self, f"_in_memory_{func.__name__}")
            return in_memory_func(*args, **kwargs)
        return wrapper
    
    def _in_memory_get(self, key: str) -> Optional[str]:
        """In-memory implementation of get."""
        return self.in_memory_cache.get(key)
    
    def get(self, key: str) -> Optional[str]:
        """Get value by key from Redis or in-memory cache."""
        if self.redis_client:
            try:
                return self.redis_client.get(key)
            except Exception as e:
                logger.warning(f"Redis operation failed, falling back to in-memory: {e}")
                self.redis_client = None
        return self._in_memory_get(key)
    
    def _in_memory_set(self, key: str, value: str, ttl: int = 3600) -> bool:
        """In-memory implementation of set."""
        self.in_memory_cache[key] = value
        # Note: In a production implementation, we would implement TTL for in-memory cache
        return True
    
    def set(self, key: str, value: str, ttl: int = 3600) -> bool:
        """Set key-value pair with optional TTL."""
        if self.redis_client:
            try:
                return self.redis_client.setex(key, ttl, value)
            except Exception as e:
                logger.warning(f"Redis operation failed, falling back to in-memory: {e}")
                self.redis_client = None
        return self._in_memory_set(key, value, ttl)
    
    def _in_memory_delete(self, key: str) -> bool:
        """In-memory implementation of delete."""
        if key in self.in_memory_cache:
            del self.in_memory_cache[key]
            return True
        return False
    
    def delete(self, key: str) -> bool:
        """Delete key from Redis or in-memory cache."""
        if self.redis_client:
            try:
                return self.redis_client.delete(key) > 0
            except Exception as e:
                logger.warning(f"Redis operation failed, falling back to in-memory: {e}")
                self.redis_client = None
        return self._in_memory_delete(key)
    
    def _in_memory_exists(self, key: str) -> bool:
        """In-memory implementation of exists."""
        return key in self.in_memory_cache
    
    def exists(self, key: str) -> bool:
        """Check if key exists in Redis or in-memory cache."""
        if self.redis_client:
            try:
                return self.redis_client.exists(key) > 0
            except Exception as e:
                logger.warning(f"Redis operation failed, falling back to in-memory: {e}")
                self.redis_client = None
        return self._in_memory_exists(key)
    
    def _in_memory_increment(self, key: str, amount: int = 1) -> int:
        """In-memory implementation of increment."""
        current = self.in_memory_cache.get(key, 0)
        try:
            current = int(current)
        except (ValueError, TypeError):
            current = 0
        new_value = current + amount
        self.in_memory_cache[key] = str(new_value)
        return new_value
    
    def increment(self, key: str, amount: int = 1) -> int:
        """Increment key by amount."""
        if self.redis_client:
            try:
                return self.redis_client.incrby(key, amount)
            except Exception as e:
                logger.warning(f"Redis operation failed, falling back to in-memory: {e}")
                self.redis_client = None
        return self._in_memory_increment(key, amount)
    
    def _in_memory_expire(self, key: str, seconds: int) -> bool:
        """In-memory implementation of expire.
        
        Note: This is a simplified implementation. A full implementation would
        require a background task to clean up expired keys.
        """
        # In a real implementation, we would track expiration times
        return key in self.in_memory_cache
    
    def expire(self, key: str, seconds: int) -> bool:
        """Set expiration time for a key."""
        if self.redis_client:
            try:
                return self.redis_client.expire(key, seconds)
            except Exception as e:
                logger.warning(f"Redis operation failed, falling back to in-memory: {e}")
                self.redis_client = None
        return self._in_memory_expire(key, seconds)
    
    def is_redis_available(self) -> bool:
        """Check if Redis is available and connected."""
        if self.redis_client is None:
            return False
        try:
            self.redis_client.ping()
            return True
        except Exception:
            return False


# Create a global instance
redis_client = RedisClient()