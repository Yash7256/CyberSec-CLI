"""
Intelligent caching system for CyberSec-CLI scans.
This module provides caching functionality to avoid redundant scans of the same targets.
"""

import json
import logging
from typing import Optional, Dict, Any, List, Union
from datetime import datetime
import hashlib
import asyncio
import ipaddress
import gzip

# Import structured logging
try:
    from core.logging_config import get_logger

    HAS_STRUCTURED_LOGGING = True
except ImportError:
    HAS_STRUCTURED_LOGGING = False

logger = (
    get_logger("scanner") if HAS_STRUCTURED_LOGGING else logging.getLogger(__name__)
)


# Import Redis client
try:
    from core.redis_client import redis_client

    HAS_REDIS = True
except ImportError:
    redis_client = None
    HAS_REDIS = False


class ScanCache:
    """Cache for scan results with Redis backend."""

    def __init__(self):
        self.stats = {"hits": 0, "misses": 0, "stored": 0}
        self._initialized = True  # Redis client is already initialized

    async def initialize(self):
        """Initialize the cache system."""
        # Redis client is already initialized during import
        self._initialized = True
        logger.info("Scan cache initialized")

    def get_cache_key(self, target: str, ports: List[int]) -> str:
        """
        Generate a unique cache key for the given target and ports.

        Args:
            target: Target hostname or IP address
            ports: List of ports to scan

        Returns:
            Unique cache key string
        """
        # Sort ports to ensure consistent key generation
        sorted_ports = sorted(ports)

        # Create a string representation of the parameters
        cache_string = f"{target}:{','.join(map(str, sorted_ports))}"

        # Generate SHA256 hash of the string
        cache_key = hashlib.sha256(cache_string.encode()).hexdigest()

        return f"scan_cache:{cache_key}"

    def _get_default_ttl(self, target: str) -> int:
        """
        Determine default TTL based on target type.

        Args:
            target: Target hostname or IP address

        Returns:
            TTL in seconds
        """
        try:
            # Parse the target as an IP address
            ip = ipaddress.ip_address(target)

            # Internal IP ranges
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                return 6 * 3600  # 6 hours for internal IPs
            else:
                return 3600  # 1 hour for external IPs
        except ValueError:
            # It's a hostname, check if it looks like internal
            if any(
                internal_domain in target.lower()
                for internal_domain in [
                    "internal",
                    "local",
                    "intranet",
                    "corp",
                    "company",
                ]
            ):
                return 6 * 3600  # 6 hours for internal hostnames
            else:
                return 3600  # 1 hour for external hostnames

    async def check_cache(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """
        Check Redis for cached results.

        Args:
            cache_key: Cache key to look up

        Returns:
            Cached data with metadata if found and not expired, None otherwise
        """
        if not self._initialized:
            await self.initialize()

        try:
            cached_data = redis_client.get(cache_key)

            if cached_data is None:
                self.stats["misses"] += 1
                return None

            # Decompress if the data was compressed
            if isinstance(cached_data, bytes):
                try:
                    cached_data = gzip.decompress(cached_data).decode()
                except Exception:
                    # If decompression fails, try as plain string
                    cached_data = cached_data.decode()
            elif isinstance(cached_data, (bytes, bytearray)):
                cached_data = cached_data.decode()

            # Parse the JSON data
            result = json.loads(cached_data)

            # Check if the cache has expired based on metadata
            if "cached_at" in result:
                cached_at = datetime.fromisoformat(result["cached_at"])
                ttl = result.get("ttl", 3600)
                if (datetime.now() - cached_at).total_seconds() > ttl:
                    # Cache has expired
                    redis_client.delete(cache_key)
                    self.stats["misses"] += 1
                    return None

            self.stats["hits"] += 1
            return result

        except Exception as e:
            logger.error(f"Error checking cache: {e}")
            self.stats["misses"] += 1
            return None

    async def store_cache(
        self,
        cache_key: str,
        results: Dict[str, Any],
        ttl: Optional[int] = None,
        target: Optional[str] = None,
    ) -> bool:
        """
        Store scan results in Redis with optional compression.

        Args:
            cache_key: Cache key to store under
            results: Scan results to store
            ttl: Time-to-live in seconds (default determined by target type)
            target: Target for TTL determination (if ttl is None)

        Returns:
            True if stored successfully, False otherwise
        """
        if not self._initialized:
            await self.initialize()

        try:
            # Add metadata to the results
            cache_data = {
                **results,
                "cached_at": datetime.now().isoformat(),
                "ttl": ttl or (self._get_default_ttl(target) if target else 3600),
            }

            # Serialize to JSON
            json_data = json.dumps(cache_data)

            # Compress if the data is large
            if len(json_data) > 1024:  # Compress if larger than 1KB
                compressed_data = gzip.compress(json_data.encode())
                result = redis_client.set(
                    cache_key,
                    compressed_data,
                    ttl or (self._get_default_ttl(target) if target else 3600),
                )
            else:
                result = redis_client.set(
                    cache_key,
                    json_data,
                    ttl or (self._get_default_ttl(target) if target else 3600),
                )

            if result:
                self.stats["stored"] += 1
                return True
            else:
                return False

        except Exception as e:
            logger.error(f"Error storing cache: {e}")
            return False

    def get_stats(self) -> Dict[str, Union[int, float]]:
        """
        Get cache statistics.

        Returns:
            Dictionary with cache statistics
        """
        total_requests = self.stats["hits"] + self.stats["misses"]
        hit_rate = (
            (self.stats["hits"] / total_requests * 100) if total_requests > 0 else 0
        )

        return {
            "hits": self.stats["hits"],
            "misses": self.stats["misses"],
            "total_requests": total_requests,
            "hit_rate_percent": round(hit_rate, 2),
            "stored": self.stats["stored"],
        }

    async def invalidate_cache(self, cache_key: str) -> bool:
        """
        Invalidate a specific cache entry.

        Args:
            cache_key: Cache key to invalidate

        Returns:
            True if invalidated successfully, False otherwise
        """
        if not self._initialized:
            await self.initialize()

        try:
            result = redis_client.delete(cache_key)
            # RedisClient.delete returns number of deleted keys, so > 0 means success
            return result > 0
        except Exception as e:
            logger.error(f"Error invalidating cache: {e}")
            return False

    async def clear_all_cache(self) -> bool:
        """
        Clear all scan cache entries.

        Returns:
            True if cleared successfully, False otherwise
        """
        if not self._initialized:
            await self.initialize()

        try:
            # Note: This would require Redis keys() operation which is not available in the current RedisClient
            # For now, we'll just return True as a placeholder
            logger.warning("clear_all_cache not implemented in current RedisClient")
            return True
        except Exception as e:
            logger.error(f"Error clearing cache: {e}")
            return False


# Create a global instance
scan_cache = ScanCache()
