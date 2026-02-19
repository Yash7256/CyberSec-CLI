"""
Redis client for CyberSec CLI.
"""

import logging
import os
import time
from functools import wraps
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse

# Try to import redis, but don't fail if it's not available
try:
    import redis

    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    redis = None

# Import structured logging
try:
    from cybersec_cli.core.logging_config import get_logger

    HAS_STRUCTURED_LOGGING = True
except ImportError:
    HAS_STRUCTURED_LOGGING = False

logger = (
    get_logger("database") if HAS_STRUCTURED_LOGGING else logging.getLogger(__name__)
)


class RedisClient:
    """Singleton Redis client with connection pooling and in-memory fallback."""

    _instance = None
    _initialized = False

    # Maximum size for in-memory cache (default 1000 entries)
    MAX_CACHE_SIZE = int(os.getenv("REDIS_CACHE_MAX_SIZE", "1000"))
    # Maximum value size in bytes (default 1MB)
    MAX_VALUE_SIZE = int(os.getenv("REDIS_CACHE_MAX_VALUE_SIZE", "1048576"))

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(RedisClient, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        self.redis_client = None
        # In-memory cache stores (value, expiration_timestamp) tuples
        self.in_memory_cache: Dict[str, Tuple[Any, Optional[float]]] = {}
        self._cleanup_counter = 0
        self._cleanup_threshold = 100  # Clean up expired entries every N operations
        self.enabled = os.getenv("ENABLE_REDIS", "true").lower() == "true"
        self._cache_hits = 0
        self._cache_misses = 0

        if self.enabled and REDIS_AVAILABLE:
            try:
                redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")
                redis_password = os.getenv("REDIS_PASSWORD")
                redis_db = int(os.getenv("REDIS_DB", "0"))

                # Parse the URL to extract host and port
                parsed = urlparse(redis_url)
                host = parsed.hostname or "localhost"
                port = parsed.port or 6379

                # Create connection pool
                connection_pool = redis.ConnectionPool(
                    host=host,
                    port=port,
                    password=redis_password,
                    db=redis_db,
                    max_connections=20,
                    retry_on_timeout=True,
                )

                self.redis_client = redis.Redis(connection_pool=connection_pool)
                # Test connection
                self.redis_client.ping()
                logger.info("Redis connection established successfully")
            except Exception as e:
                logger.warning(
                    f"Failed to connect to Redis, falling back to in-memory cache: {e}"
                )
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
                    logger.warning(
                        f"Redis operation failed, falling back to in-memory: {e}"
                    )
                    self.redis_client = None

            # Fallback to in-memory implementation
            in_memory_func = getattr(self, f"_in_memory_{func.__name__}")
            return in_memory_func(*args, **kwargs)

        return wrapper

    def _cleanup_expired(self) -> None:
        """Remove expired entries from in-memory cache (lazy cleanup)."""
        now = time.time()
        expired_keys = [
            key for key, (_, exp_time) in self.in_memory_cache.items()
            if exp_time is not None and exp_time <= now
        ]
        for key in expired_keys:
            del self.in_memory_cache[key]
        if expired_keys:
            logger.debug(f"Cleaned up {len(expired_keys)} expired cache entries")

    def _maybe_cleanup(self) -> None:
        """Periodically clean up expired entries."""
        self._cleanup_counter += 1
        if self._cleanup_counter >= self._cleanup_threshold:
            self._cleanup_expired()
            self._cleanup_counter = 0

    def _in_memory_get(self, key: str) -> Optional[str]:
        """In-memory implementation of get with TTL support."""
        self._maybe_cleanup()
        if key in self.in_memory_cache:
            value, exp_time = self.in_memory_cache[key]
            if exp_time is None or exp_time > time.time():
                return value
            else:
                # Entry has expired, remove it
                del self.in_memory_cache[key]
        return None

    def get(self, key: str) -> Optional[str]:
        """Get value by key from Redis or in-memory cache."""
        if self.redis_client:
            try:
                return self.redis_client.get(key)
            except Exception as e:
                logger.warning(
                    f"Redis operation failed, falling back to in-memory: {e}"
                )
                self.redis_client = None
        return self._in_memory_get(key)

    def _in_memory_set(self, key: str, value: str, ttl: int = 3600) -> bool:
        """In-memory implementation of set with TTL support and size limits."""
        self._maybe_cleanup()
        
        # Check value size limit
        if len(value) > self.MAX_VALUE_SIZE:
            logger.warning(f"Value for key {key} exceeds max size ({len(value)} > {self.MAX_VALUE_SIZE})")
            return False
        
        # Check cache size limit - evict oldest if at capacity
        if len(self.in_memory_cache) >= self.MAX_CACHE_SIZE:
            # Remove oldest expired entry, or oldest entry if none expired
            if self.in_memory_cache:
                oldest_key = min(
                    self.in_memory_cache.keys(),
                    key=lambda k: self.in_memory_cache[k][1] or float('inf')
                )
                del self.in_memory_cache[oldest_key]
                logger.debug(f"Evicted oldest cache entry to make room")
        
        exp_time = time.time() + ttl if ttl > 0 else None
        self.in_memory_cache[key] = (value, exp_time)
        return True

    def set(self, key: str, value: str, ttl: int = 3600) -> bool:
        """Set key-value pair with optional TTL."""
        if self.redis_client:
            try:
                return self.redis_client.setex(key, ttl, value)
            except Exception as e:
                logger.warning(
                    f"Redis operation failed, falling back to in-memory: {e}"
                )
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
                logger.warning(
                    f"Redis operation failed, falling back to in-memory: {e}"
                )
                self.redis_client = None
        return self._in_memory_delete(key)

    def _in_memory_exists(self, key: str) -> bool:
        """In-memory implementation of exists with TTL support."""
        if key in self.in_memory_cache:
            value, exp_time = self.in_memory_cache[key]
            if exp_time is None or exp_time > time.time():
                return True
            else:
                # Entry has expired, remove it
                del self.in_memory_cache[key]
        return False

    def exists(self, key: str) -> bool:
        """Check if key exists in Redis or in-memory cache."""
        if self.redis_client:
            try:
                return self.redis_client.exists(key) > 0
            except Exception as e:
                logger.warning(
                    f"Redis operation failed, falling back to in-memory: {e}"
                )
                self.redis_client = None
        return self._in_memory_exists(key)

    def _in_memory_increment(self, key: str, amount: int = 1) -> int:
        """In-memory implementation of increment with TTL preservation."""
        self._maybe_cleanup()
        current = 0
        exp_time = None  # Preserve expiration time if key exists
        
        if key in self.in_memory_cache:
            value, exp_time = self.in_memory_cache[key]
            # Check if not expired
            if exp_time is None or exp_time > time.time():
                try:
                    current = int(value)
                except (ValueError, TypeError):
                    current = 0
            else:
                # Expired, start fresh
                exp_time = None
        
        new_value = current + amount
        self.in_memory_cache[key] = (str(new_value), exp_time)
        return new_value

    def increment(self, key: str, amount: int = 1) -> int:
        """Increment key by amount."""
        if self.redis_client:
            try:
                return self.redis_client.incrby(key, amount)
            except Exception as e:
                logger.warning(
                    f"Redis operation failed, falling back to in-memory: {e}"
                )
                self.redis_client = None
        return self._in_memory_increment(key, amount)

    def _in_memory_expire(self, key: str, seconds: int) -> bool:
        """In-memory implementation of expire with proper TTL tracking."""
        if key not in self.in_memory_cache:
            return False
        
        value, _ = self.in_memory_cache[key]
        # Check if current value is expired  
        if self._in_memory_exists(key):  # This also cleans up if expired
            new_exp_time = time.time() + seconds
            self.in_memory_cache[key] = (value, new_exp_time)
            return True
        return False

    def expire(self, key: str, seconds: int) -> bool:
        """Set expiration time for a key."""
        if self.redis_client:
            try:
                return self.redis_client.expire(key, seconds)
            except Exception as e:
                logger.warning(
                    f"Redis operation failed, falling back to in-memory: {e}"
                )
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

    def get_cache_stats(self) -> Dict[str, Any]:
        """Get statistics about the in-memory cache."""
        return {
            "entries": len(self.in_memory_cache),
            "max_entries": self.MAX_CACHE_SIZE,
            "max_value_size": self.MAX_VALUE_SIZE,
            "hits": self._cache_hits,
            "misses": self._cache_misses,
            "hit_rate": (
                self._cache_hits / (self._cache_hits + self._cache_misses)
                if (self._cache_hits + self._cache_misses) > 0
                else 0.0
            ),
        }


# Create a global instance
redis_client = RedisClient()
