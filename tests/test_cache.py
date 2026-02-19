import json
from datetime import datetime
from unittest.mock import patch

import pytest

from cybersec_cli.core.scan_cache import ScanCache


class TestCacheKeyGeneration:
    """Test cache key generation logic."""

    @pytest.fixture
    def scan_cache(self):
        """Create a ScanCache instance for testing."""
        cache = ScanCache()
        return cache

    def test_cache_key_generation_consistency(self, scan_cache):
        """Test that the same input always generates the same key."""
        key1 = scan_cache.get_cache_key("192.168.1.1", [22, 80, 443])
        key2 = scan_cache.get_cache_key("192.168.1.1", [22, 80, 443])

        assert key1 == key2
        assert key1.startswith("scan_cache:")

    def test_cache_key_generation_different_inputs(self, scan_cache):
        """Test that different inputs generate different keys."""
        key1 = scan_cache.get_cache_key("192.168.1.1", [22, 80])
        key2 = scan_cache.get_cache_key("192.168.1.2", [22, 80])
        key3 = scan_cache.get_cache_key("192.168.1.1", [22, 443])

        assert key1 != key2
        assert key1 != key3
        assert key2 != key3

    def test_cache_key_generation_port_order_independence(self, scan_cache):
        """Test that port order doesn't affect the cache key."""
        key1 = scan_cache.get_cache_key("192.168.1.1", [22, 80, 443])
        key2 = scan_cache.get_cache_key("192.168.1.1", [443, 22, 80])

        assert key1 == key2


class TestCacheHitMissLogic:
    """Test cache hit/miss logic."""

    @pytest.mark.anyio
    async def test_cache_miss(self, mock_redis_client):
        """Test cache miss behavior."""
        cache = ScanCache()
        cache._initialized = True  # Bypass initialization

        # Patch the global redis_client
        with patch("cybersec_cli.core.scan_cache.redis_client", mock_redis_client):
            mock_redis_client.get.return_value = None

            cache_key = cache.get_cache_key("192.168.1.1", [22, 80])
            result = await cache.check_cache(cache_key)

            assert result is None
            mock_redis_client.get.assert_called_once_with(cache_key)

    @pytest.mark.anyio
    async def test_cache_hit(self, mock_redis_client):
        """Test cache hit behavior."""
        cache = ScanCache()
        cache._initialized = True  # Bypass initialization

        expected_result = {
            "host": "192.168.1.1",
            "ports": [{"port": 22, "state": "open"}],
            "cached_at": datetime.now().isoformat(),
            "ttl": 3600,
        }
        serialized_result = json.dumps(expected_result)

        with patch("cybersec_cli.core.scan_cache.redis_client", mock_redis_client):
            mock_redis_client.get.return_value = serialized_result.encode()

            cache_key = cache.get_cache_key("192.168.1.1", [22, 80])
            result = await cache.check_cache(cache_key)

            assert result["host"] == expected_result["host"]
            assert result["ports"] == expected_result["ports"]
            mock_redis_client.get.assert_called_once_with(cache_key)

    @pytest.mark.anyio
    async def test_cache_store(self, mock_redis_client):
        """Test storing scan results in cache."""
        cache = ScanCache()
        cache._initialized = True  # Bypass initialization

        scan_result = {"host": "192.168.1.1", "ports": [{"port": 22, "state": "open"}]}

        with patch("cybersec_cli.core.scan_cache.redis_client", mock_redis_client):
            cache_key = cache.get_cache_key("192.168.1.1", [22, 80])
            success = await cache.store_cache(
                cache_key, scan_result, target="192.168.1.1"
            )

            assert success is True
            assert (
                mock_redis_client.set.called
            )  # Check that set was called at least once

    @pytest.mark.anyio
    async def test_cache_store_and_retrieve(self, mock_redis_client):
        """Test storing and retrieving cached results."""
        cache = ScanCache()
        cache._initialized = True  # Bypass initialization

        storage = {}

        def _fake_set(key, value, ttl=None):
            storage[key] = value
            return True

        def _fake_get(key):
            return storage.get(key)

        mock_redis_client.set.side_effect = _fake_set
        mock_redis_client.get.side_effect = _fake_get

        with patch("cybersec_cli.core.scan_cache.redis_client", mock_redis_client):
            # Arrange
            cache_key = cache.get_cache_key("192.168.1.1", [22, 80])
            expected_data = {
                "host": "192.168.1.1",
                "ports": [{"port": 22, "state": "open"}],
            }

            # Act
            await cache.store_cache(cache_key, expected_data, target="192.168.1.1")
            result = await cache.check_cache(cache_key)

            # Assert
            assert result["host"] == expected_data["host"]
            assert result["ports"] == expected_data["ports"]

    @pytest.mark.anyio
    async def test_cache_store_with_compression(self, mock_redis_client):
        """Test that large stored results are compressed."""
        cache = ScanCache()
        cache._initialized = True  # Bypass initialization

        # Create a large result to trigger compression
        large_result = {"data": "x" * 2000}  # Larger than 1KB threshold

        with patch("cybersec_cli.core.scan_cache.redis_client", mock_redis_client):
            cache_key = cache.get_cache_key("192.168.1.1", [22, 80])
            success = await cache.store_cache(
                cache_key, large_result, target="192.168.1.1"
            )

            assert success is True
            # Verify that the value passed to set is compressed (bytes)
            assert mock_redis_client.set.called
            call_args = mock_redis_client.set.call_args
            if call_args:
                stored_value = call_args[0][1]  # Second argument is the value
                assert isinstance(stored_value, bytes)  # Should be compressed data


class TestTTLExpiration:
    """Test TTL expiration functionality."""

    @pytest.mark.anyio
    async def test_cache_ttl_set_correctly(self, mock_redis_client):
        """Test that TTL is set correctly when storing results."""
        cache = ScanCache()
        cache._initialized = True  # Bypass initialization

        scan_result = {"host": "192.168.1.1", "ports": [{"port": 22, "state": "open"}]}
        expected_ttl = 3600  # Default TTL

        with patch("cybersec_cli.core.scan_cache.redis_client", mock_redis_client):
            cache_key = cache.get_cache_key("192.168.1.1", [22, 80])
            await cache.store_cache(
                cache_key, scan_result, ttl=expected_ttl, target="192.168.1.1"
            )

            # Check that set was called with the correct TTL
            assert mock_redis_client.set.called
            call_args = mock_redis_client.set.call_args
            if call_args and len(call_args[1]) >= 1:  # Use kwargs for TTL
                ttl_value = (
                    call_args[1]["ttl"]
                    if "ttl" in call_args[1]
                    else (call_args[0][2] if len(call_args[0]) > 2 else None)
                )
                assert ttl_value == expected_ttl

    @pytest.mark.anyio
    async def test_cache_ttl_custom(self, mock_redis_client):
        """Test that custom TTL can be set."""
        cache = ScanCache()
        cache._initialized = True  # Bypass initialization

        scan_result = {"host": "192.168.1.1", "ports": [{"port": 22, "state": "open"}]}
        custom_ttl = 7200

        with patch("cybersec_cli.core.scan_cache.redis_client", mock_redis_client):
            cache_key = cache.get_cache_key("192.168.1.1", [22, 80])
            await cache.store_cache(
                cache_key, scan_result, ttl=custom_ttl, target="192.168.1.1"
            )

            # Check that set was called with the custom TTL
            assert mock_redis_client.set.called
            call_args = mock_redis_client.set.call_args
            if call_args and len(call_args[1]) >= 1:  # Use kwargs for TTL
                ttl_value = (
                    call_args[1]["ttl"]
                    if "ttl" in call_args[1]
                    else (call_args[0][2] if len(call_args[0]) > 2 else None)
                )
                assert ttl_value == custom_ttl


class TestCacheStatistics:
    """Test cache statistics functionality."""

    def test_cache_statistics(self, mock_cache):
        """Test retrieving cache statistics."""
        # Use the mock_cache fixture that has the proper Redis client setup
        stats = mock_cache.get_stats()

        assert "hits" in stats
        assert "misses" in stats
        assert "total_requests" in stats
        assert "hit_rate_percent" in stats
        assert "stored" in stats

        # Initially all should be 0
        assert stats["hits"] == 0
        assert stats["misses"] == 0
        assert stats["stored"] == 0
        assert stats["total_requests"] == 0
        assert stats["hit_rate_percent"] == 0


class TestCacheInvalidate:
    """Test cache invalidation functionality."""

    @pytest.mark.anyio
    async def test_invalidate_specific_key(self, mock_redis_client):
        """Test invalidating a specific cache key."""
        cache = ScanCache()
        cache._initialized = True  # Bypass initialization

        # Mock the Redis delete method to return 1 (indicating successful deletion)
        mock_redis_client.delete.return_value = 1

        with patch("cybersec_cli.core.scan_cache.redis_client", mock_redis_client):
            cache_key = cache.get_cache_key("192.168.1.1", [22, 80])
            result = await cache.invalidate_cache(cache_key)

            # The Redis delete method returns number of deleted keys, so if it's > 0,
            # invalidate should return True
            mock_redis_client.delete.assert_called_once_with(cache_key)
            assert (
                result is True
            )  # We expect the return value to be True based on the Redis result
