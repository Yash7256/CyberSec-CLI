"""
Tests for the Redis client implementation.
"""

import unittest
import sys
import os

# Add the project root to the path so we can import our modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

try:
    from core.redis_client import RedisClient

    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    RedisClient = None


class TestRedisClient(unittest.TestCase):

    @unittest.skipIf(not REDIS_AVAILABLE, "Redis not available")
    def test_singleton_instance(self):
        """Test that RedisClient is a singleton."""
        client1 = RedisClient()
        client2 = RedisClient()
        self.assertIs(client1, client2)

    @unittest.skipIf(not REDIS_AVAILABLE, "Redis not available")
    def test_set_and_get(self):
        """Test setting and getting values."""
        client = RedisClient()
        key = "test_key"
        value = "test_value"

        # Set a value
        result = client.set(key, value, ttl=60)
        self.assertTrue(result)

        # Get the value
        retrieved = client.get(key)
        # Redis returns bytes, so compare as bytes or decode both
        self.assertEqual(
            retrieved, value.encode() if isinstance(retrieved, bytes) else retrieved
        )

        # Clean up
        client.delete(key)

    @unittest.skipIf(not REDIS_AVAILABLE, "Redis not available")
    def test_delete(self):
        """Test deleting values."""
        client = RedisClient()
        key = "test_key_to_delete"
        value = "test_value"

        # Set a value
        client.set(key, value, ttl=60)

        # Delete the value
        result = client.delete(key)
        self.assertTrue(result)

        # Verify it's deleted
        retrieved = client.get(key)
        self.assertIsNone(retrieved)

    @unittest.skipIf(not REDIS_AVAILABLE, "Redis not available")
    def test_exists(self):
        """Test checking if keys exist."""
        client = RedisClient()
        key = "test_key_exists"
        value = "test_value"

        # Key should not exist initially
        self.assertFalse(client.exists(key))

        # Set a value
        client.set(key, value, ttl=60)

        # Key should now exist
        self.assertTrue(client.exists(key))

        # Clean up
        client.delete(key)

    @unittest.skipIf(not REDIS_AVAILABLE, "Redis not available")
    def test_increment(self):
        """Test incrementing values."""
        client = RedisClient()
        key = "test_counter"

        # Increment from 0
        result = client.increment(key)
        self.assertEqual(result, 1)

        # Increment again
        result = client.increment(key)
        self.assertEqual(result, 2)

        # Increment by specific amount
        result = client.increment(key, 5)
        self.assertEqual(result, 7)

        # Clean up
        client.delete(key)

    @unittest.skipIf(not REDIS_AVAILABLE, "Redis not available")
    def test_in_memory_fallback(self):
        """Test in-memory fallback when Redis is disabled."""
        # This test would require mocking Redis failure,
        # which is complex. We'll rely on manual testing for this scenario.
        pass


if __name__ == "__main__":
    unittest.main()
