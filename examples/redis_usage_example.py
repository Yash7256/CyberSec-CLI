#!/usr/bin/env python3
"""
Redis Usage Example

This script demonstrates how to use the Redis client in the CyberSec-CLI application.
"""

import sys
import os
import time

# Add the project root to the path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.redis_client import redis_client


def main():
    """Demonstrate Redis client usage."""
    print("Redis Usage Example")
    print("=" * 50)

    # Check if Redis is available
    print(f"Redis Available: {redis_client.is_redis_available()}")

    # Test basic operations
    print("\n1. Testing SET operation...")
    result = redis_client.set("example_key", "Hello, Redis!", ttl=300)  # 5 minute TTL
    print(f"SET result: {result}")

    print("\n2. Testing GET operation...")
    value = redis_client.get("example_key")
    print(f"GET result: {value}")

    print("\n3. Testing EXISTS operation...")
    exists = redis_client.exists("example_key")
    print(f"EXISTS result: {exists}")

    print("\n4. Testing INCREMENT operation...")
    # Increment a counter
    count = redis_client.increment("page_views")
    print(f"Page views: {count}")

    # Increment by a specific amount
    count = redis_client.increment("page_views", 5)
    print(f"Page views after incrementing by 5: {count}")

    print("\n5. Testing EXPIRE operation...")
    expire_result = redis_client.expire("example_key", 60)  # Expire in 1 minute
    print(f"EXPIRE result: {expire_result}")

    print("\n6. Testing DELETE operation...")
    delete_result = redis_client.delete("example_key")
    print(f"DELETE result: {delete_result}")

    # Verify deletion
    value = redis_client.get("example_key")
    print(f"Value after deletion: {value}")

    print("\n7. Testing in-memory fallback...")
    # Disable Redis to test fallback
    original_client = redis_client.redis_client
    redis_client.redis_client = None

    # Now operations should use in-memory cache
    redis_client.set("fallback_key", "This is cached in memory", ttl=300)
    fallback_value = redis_client.get("fallback_key")
    print(f"Fallback GET result: {fallback_value}")

    # Restore Redis client
    redis_client.redis_client = original_client

    print("\n8. Performance comparison...")
    # Measure Redis performance
    start_time = time.time()
    for i in range(100):
        redis_client.set(f"perf_key_{i}", f"value_{i}")
    redis_set_time = time.time() - start_time

    start_time = time.time()
    for i in range(100):
        redis_client.get(f"perf_key_{i}")
    redis_get_time = time.time() - start_time

    print(f"Time to set 100 keys in Redis: {redis_set_time:.4f} seconds")
    print(f"Time to get 100 keys from Redis: {redis_get_time:.4f} seconds")

    # Clean up
    for i in range(100):
        redis_client.delete(f"perf_key_{i}")

    print("\nExample completed successfully!")


if __name__ == "__main__":
    main()
