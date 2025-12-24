#!/usr/bin/env python3
"""
Test script to verify Redis health check functionality.
"""

import asyncio
import os
import sys

# Add the project root to the path so we can import our modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), ".")))

try:
    from core.redis_client import RedisClient

    print("✅ Redis client imported successfully")
except ImportError as e:
    print(f"❌ Failed to import Redis client: {e}")
    sys.exit(1)


async def test_redis_health():
    """Test Redis health check functionality."""
    print("\n=== Redis Health Check Test ===")

    # Initialize Redis client
    client = RedisClient()
    print(f"✅ Redis client initialized")

    # Check if Redis is available
    is_available = client.is_redis_available()
    print(f"📊 Redis availability: {is_available}")

    # Test basic operations
    print("\n--- Testing basic operations ---")

    # Set a test key
    set_result = client.set("health_test_key", "health_test_value", ttl=60)
    print(f"📝 Set operation result: {set_result}")

    # Get the test key
    get_result = client.get("health_test_key")
    # Handle bytes vs string return types
    if isinstance(get_result, bytes):
        get_result = get_result.decode("utf-8")
    print(f"📖 Get operation result: {get_result}")

    # Check if key exists
    exists_result = client.exists("health_test_key")
    print(f"🔍 Exists operation result: {exists_result}")

    # Increment a counter
    incr_result = client.increment("health_test_counter")
    print(f"➕ Increment operation result: {incr_result}")

    # Delete the test key
    delete_result = client.delete("health_test_key")
    print(f"🗑️ Delete operation result: {delete_result}")

    print("\n=== Test Summary ===")
    if (
        set_result
        and get_result == "health_test_value"
        and exists_result
        and incr_result >= 1
    ):
        print("✅ All Redis operations passed")
    else:
        print("❌ Some operations failed")


if __name__ == "__main__":
    asyncio.run(test_redis_health())
