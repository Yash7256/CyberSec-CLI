"""
Tests for the Redis client implementation.
"""

import os
import sys

import pytest

# Add the project root to the path so we can import our modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from cybersec_cli.core import redis_client as redis_module
from cybersec_cli.core.redis_client import RedisClient


@pytest.fixture
def mock_redis(mocker):
    async_redis = mocker.patch("redis.asyncio.Redis", autospec=True, create=True)
    mocker.patch("redis.ConnectionPool", autospec=True)
    sync_redis = mocker.patch("redis.Redis", autospec=True)
    sync_instance = sync_redis.return_value
    sync_instance.ping.return_value = True
    mocker.patch.object(redis_module, "REDIS_AVAILABLE", True)
    return sync_instance


@pytest.fixture
def redis_client_instance(mock_redis):
    redis_module.RedisClient._instance = None
    redis_module.RedisClient._initialized = False
    return RedisClient()


def test_singleton_instance(redis_client_instance):
    """Test that RedisClient is a singleton."""
    client2 = RedisClient()
    assert redis_client_instance is client2


def test_set_and_get(redis_client_instance, mock_redis):
    """Test setting and getting values."""
    key = "test_key"
    value = "test_value"

    mock_redis.setex.return_value = True
    mock_redis.get.return_value = value.encode()

    result = redis_client_instance.set(key, value, ttl=60)
    assert result is True

    retrieved = redis_client_instance.get(key)
    assert retrieved == value.encode()


def test_delete(redis_client_instance, mock_redis):
    """Test deleting values."""
    key = "test_key_to_delete"

    mock_redis.delete.return_value = 1

    result = redis_client_instance.delete(key)
    assert result is True


def test_exists(redis_client_instance, mock_redis):
    """Test checking if keys exist."""
    key = "test_key_exists"

    mock_redis.exists.side_effect = [0, 1]

    assert redis_client_instance.exists(key) is False
    assert redis_client_instance.exists(key) is True


def test_increment(redis_client_instance, mock_redis):
    """Test incrementing values."""
    key = "test_counter"

    mock_redis.incrby.side_effect = [1, 2, 7]

    result = redis_client_instance.increment(key)
    assert result == 1

    result = redis_client_instance.increment(key)
    assert result == 2

    result = redis_client_instance.increment(key, 5)
    assert result == 7


def test_in_memory_fallback(redis_client_instance):
    """Test in-memory fallback when Redis is disabled."""
    redis_client_instance.redis_client = None
    key = "fallback_key"

    assert redis_client_instance.set(key, "value", ttl=60) is True
    retrieved = redis_client_instance.get(key)
    assert retrieved == "value"
