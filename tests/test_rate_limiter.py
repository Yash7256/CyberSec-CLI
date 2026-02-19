from unittest.mock import MagicMock, patch

import pytest
import asyncio
from fastapi import HTTPException

import web.main as main

from cybersec_cli.core.rate_limiter import SmartRateLimiter


class TestClientLimits:
    """Test client-based rate limiting."""

    @pytest.fixture
    def rate_limiter(self):
        """Create a SmartRateLimiter instance for testing."""
        redis_client = MagicMock()
        config = {
            "CLIENT_RATE_LIMIT": 10,
            "CLIENT_RATE_WINDOW": 3600,
            "TARGET_RATE_LIMIT": 100,
            "TARGET_RATE_WINDOW": 3600,
            "PORT_LIMIT_PER_SCAN": 1000,
            "GLOBAL_CONCURRENT_LIMIT": 1000,
            "PORT_WARN_THRESHOLD": 100,
        }
        return SmartRateLimiter(redis_client, config)

    def test_client_limit_initial_state(self, rate_limiter):
        """Test initial state of client rate limiter."""
        assert rate_limiter.client_limit == 10
        assert rate_limiter.client_window == 3600

    def test_client_within_limit(self, rate_limiter):
        """Test that requests within limit are allowed."""
        client_id = "client1"

        with patch.object(rate_limiter.redis, "zcard", return_value=5), patch.object(
            rate_limiter.redis, "zremrangebyscore"
        ), patch.object(rate_limiter.redis, "zadd"), patch.object(
            rate_limiter.redis, "expire"
        ):
            result = rate_limiter.check_client_limit(client_id)
            assert result is True

    def test_client_exceeds_limit(self, rate_limiter):
        """Test that requests exceeding limit are blocked."""
        client_id = "client1"

        with patch.object(rate_limiter.redis, "zcard", return_value=15), patch.object(
            rate_limiter.redis, "zremrangebyscore"
        ):
            result = rate_limiter.check_client_limit(client_id)
            assert result is False


class TestTargetLimits:
    """Test target-based rate limiting."""

    @pytest.fixture
    def rate_limiter(self):
        """Create a SmartRateLimiter instance for testing."""
        redis_client = MagicMock()
        config = {
            "CLIENT_RATE_LIMIT": 10,
            "CLIENT_RATE_WINDOW": 3600,
            "TARGET_RATE_LIMIT": 100,
            "TARGET_RATE_WINDOW": 3600,
            "PORT_LIMIT_PER_SCAN": 1000,
            "GLOBAL_CONCURRENT_LIMIT": 1000,
            "PORT_WARN_THRESHOLD": 100,
        }
        return SmartRateLimiter(redis_client, config)

    def test_target_within_limit(self, rate_limiter):
        """Test that requests to target within limit are allowed."""
        target = "192.168.1.1"

        with patch.object(rate_limiter.redis, "zcard", return_value=50), patch.object(
            rate_limiter.redis, "zremrangebyscore"
        ), patch.object(rate_limiter.redis, "zadd"), patch.object(
            rate_limiter.redis, "expire"
        ):
            result = rate_limiter.check_target_limit(target)
            assert result is True

    def test_target_exceeds_limit(self, rate_limiter):
        """Test that requests to target exceeding limit are blocked."""
        target = "192.168.1.1"

        with patch.object(rate_limiter.redis, "zcard", return_value=150), patch.object(
            rate_limiter.redis, "zremrangebyscore"
        ):
            result = rate_limiter.check_target_limit(target)
            assert result is False


class TestPortRangeLimits:
    """Test port range limiting functionality."""

    @pytest.fixture
    def rate_limiter(self):
        """Create a SmartRateLimiter instance for testing."""
        redis_client = MagicMock()
        config = {
            "CLIENT_RATE_LIMIT": 10,
            "CLIENT_RATE_WINDOW": 3600,
            "TARGET_RATE_LIMIT": 100,
            "TARGET_RATE_WINDOW": 3600,
            "PORT_LIMIT_PER_SCAN": 1000,
            "GLOBAL_CONCURRENT_LIMIT": 1000,
            "PORT_WARN_THRESHOLD": 100,
        }
        return SmartRateLimiter(redis_client, config)

    def test_port_range_within_limit(self, rate_limiter):
        """Test port ranges within the allowed limit."""
        ports = list(range(1, 100))  # 99 ports, below warning threshold
        is_valid, warning = rate_limiter.check_port_range_limit(ports)

        assert is_valid is True
        assert warning == ""  # Should not have warning for 99 ports

    def test_port_range_warning_threshold(self, rate_limiter):
        """Test port ranges that trigger warnings."""
        ports = list(range(1, 200))  # 199 ports, above warning threshold
        is_valid, warning = rate_limiter.check_port_range_limit(ports)

        assert is_valid is True  # Still valid but with warning
        assert "Warning" in warning

    def test_port_range_exceeds_limit(self, rate_limiter):
        """Test port ranges that exceed the maximum limit."""
        ports = list(range(1, 2000))  # 1999 ports, exceeds limit
        is_valid, warning = rate_limiter.check_port_range_limit(ports)

        assert is_valid is False
        assert "Port range too large" in warning


class TestGlobalConcurrentLimits:
    """Test global concurrent scan limiting."""

    @pytest.fixture
    def rate_limiter(self):
        """Create a SmartRateLimiter instance for testing."""
        redis_client = MagicMock()
        config = {
            "CLIENT_RATE_LIMIT": 10,
            "CLIENT_RATE_WINDOW": 3600,
            "TARGET_RATE_LIMIT": 100,
            "TARGET_RATE_WINDOW": 3600,
            "PORT_LIMIT_PER_SCAN": 1000,
            "GLOBAL_CONCURRENT_LIMIT": 1000,
            "PORT_WARN_THRESHOLD": 100,
        }
        return SmartRateLimiter(redis_client, config)

    def test_global_limit_within_bounds(self, rate_limiter):
        """Test global concurrent limit when within bounds."""
        with patch.object(rate_limiter.redis, "get", return_value="500"):
            is_allowed, available_slots = rate_limiter.check_global_limit()
            assert is_allowed is True
            assert available_slots == 500  # 1000 - 500

    def test_global_limit_exceeded(self, rate_limiter):
        """Test global concurrent limit when exceeded."""
        with patch.object(rate_limiter.redis, "get", return_value="1500"):
            is_allowed, available_slots = rate_limiter.check_global_limit()
            assert is_allowed is False
            assert available_slots == 0

    def test_increment_concurrent_scan(self, rate_limiter):
        """Test incrementing concurrent scan counter."""
        with patch.object(rate_limiter.redis, "incr", return_value=100), patch.object(
            rate_limiter.redis, "expire"
        ):
            result = rate_limiter.increment_concurrent_scan()
            assert result is True  # Within limit

    def test_increment_concurrent_scan_exceeds(self, rate_limiter):
        """Test incrementing concurrent scan counter when it exceeds limit."""
        with patch.object(rate_limiter.redis, "incr", return_value=1500), patch.object(
            rate_limiter.redis, "expire"
        ):
            result = rate_limiter.increment_concurrent_scan()
            assert result is False  # Exceeds limit


class TestExponentialBackoff:
    """Test exponential backoff functionality."""

    @pytest.fixture
    def rate_limiter(self):
        """Create a SmartRateLimiter instance for testing."""
        redis_client = MagicMock()
        config = {
            "CLIENT_RATE_LIMIT": 10,
            "CLIENT_RATE_WINDOW": 3600,
            "TARGET_RATE_LIMIT": 100,
            "TARGET_RATE_WINDOW": 3600,
            "PORT_LIMIT_PER_SCAN": 1000,
            "GLOBAL_CONCURRENT_LIMIT": 1000,
            "PORT_WARN_THRESHOLD": 100,
        }
        return SmartRateLimiter(redis_client, config)

    def test_violation_recording(self, rate_limiter):
        """Test recording rate limit violations."""
        client_id = "client1"

        with patch.object(rate_limiter.redis, "get", return_value="0"), patch.object(
            rate_limiter.redis, "incr", return_value=1
        ):
            violation_count = rate_limiter.record_violation(client_id)
            assert violation_count == 1

    def test_cooldown_period_calculation(self, rate_limiter):
        """Test cooldown period calculation based on violation count."""
        client_id = "client1"

        # First violation - no cooldown
        with patch.object(rate_limiter.redis, "get", return_value="0"):
            period = rate_limiter.get_cooldown_period(client_id)
            assert period == 0  # First violation has no cooldown

        # Second violation - 5 minute cooldown
        with patch.object(rate_limiter.redis, "get", return_value="1"):
            period = rate_limiter.get_cooldown_period(client_id)
            assert period == 300  # 5 minutes

    def test_cooldown_application(self, rate_limiter):
        """Test applying cooldown to a client."""
        client_id = "client1"

        with patch.object(rate_limiter.redis, "get", return_value="2"), patch.object(
            rate_limiter.redis, "setex"
        ) as mock_setex:
            rate_limiter.apply_cooldown(client_id)
            # Should call setex with the appropriate cooldown period
            mock_setex.assert_called_once()
            # Verify cooldown period is 3600 (3rd violation)
            call_args = mock_setex.call_args
            assert call_args[0][1] == 3600


class TestRateLimitMetrics:
    """Test rate limit metrics and statistics."""

    @pytest.fixture
    def rate_limiter(self):
        """Create a SmartRateLimiter instance for testing."""
        redis_client = MagicMock()
        config = {
            "CLIENT_RATE_LIMIT": 10,
            "CLIENT_RATE_WINDOW": 3600,
            "TARGET_RATE_LIMIT": 100,
            "TARGET_RATE_WINDOW": 3600,
            "PORT_LIMIT_PER_SCAN": 1000,
            "GLOBAL_CONCURRENT_LIMIT": 1000,
            "PORT_WARN_THRESHOLD": 100,
        }
        return SmartRateLimiter(redis_client, config)

    def test_get_violation_count(self, rate_limiter):
        """Test retrieving violation count for a client."""
        client_id = "client1"

        with patch.object(rate_limiter.redis, "get", return_value="3"):
            count = rate_limiter.get_violation_count(client_id)
            assert count == 3

        # Test with no violations (None returned)
        with patch.object(rate_limiter.redis, "get", return_value=None):
            count = rate_limiter.get_violation_count(client_id)
            assert count == 0

    def test_get_all_violations(self, rate_limiter):
        """Test retrieving all violation counts."""
        with patch.object(
            rate_limiter.redis,
            "keys",
            return_value=[
                b"rate_limit:violations:client1",
                b"rate_limit:violations:client2",
            ],
        ), patch.object(rate_limiter.redis, "get", side_effect=["2", "1"]):
            violations = rate_limiter.get_all_violations()
            assert "client1" in violations
            assert "client2" in violations
            assert violations["client1"] == 2
            assert violations["client2"] == 1


class TestRateLimitReset:
    """Test rate limit reset functionality."""

    @pytest.fixture
    def rate_limiter(self):
        """Create a SmartRateLimiter instance for testing."""
        redis_client = MagicMock()
        config = {
            "CLIENT_RATE_LIMIT": 10,
            "CLIENT_RATE_WINDOW": 3600,
            "TARGET_RATE_LIMIT": 100,
            "TARGET_RATE_WINDOW": 3600,
            "PORT_LIMIT_PER_SCAN": 1000,
            "GLOBAL_CONCURRENT_LIMIT": 1000,
            "PORT_WARN_THRESHOLD": 100,
        }
        return SmartRateLimiter(redis_client, config)

    def test_reset_client_limits(self, rate_limiter):
        """Test resetting limits for a specific client."""
        client_id = "client1"

        with patch.object(rate_limiter.redis, "delete") as mock_delete, patch.object(
            rate_limiter.redis, "get", return_value=None
        ), patch.object(rate_limiter.redis, "exists", return_value=0):
            rate_limiter.reset_client_limits(client_id)

            # Should delete the relevant keys - verify specific keys are deleted
            assert mock_delete.call_count >= 3
            # Verify the client key pattern is included
            called_keys = [call[0][0] for call in mock_delete.call_args_list]
            key_patterns = [str(k) for k in called_keys]
            assert any("client:client1" in k or "violation" in k or "cooldown" in k for k in key_patterns)
            assert rate_limiter.get_violation_count(client_id) == 0
            assert rate_limiter.is_on_cooldown(client_id) is False


class TestApiRateLimiting:
    """Test API rate limiting behavior."""

    def test_rate_limit_triggers_http_429(self, monkeypatch):
        class DummyLimiter:
            def is_on_cooldown(self, client_id):
                return False

            def check_client_limit(self, client_id):
                return False

            def record_violation(self, client_id):
                return None

            def apply_cooldown(self, client_id):
                return None

        monkeypatch.setattr(main, "HAS_RATE_LIMITER", True)
        monkeypatch.setattr(main, "rate_limiter", DummyLimiter())

        scope = {
            "type": "http",
            "method": "GET",
            "path": "/api/scans",
            "headers": [],
            "client": ("127.0.0.1", 12345),
            "server": ("testserver", 80),
        }
        request = main.Request(scope)

        try:
            asyncio.run(main.rate_limit_dependency(request))
            assert False, "Expected rate limiting to raise HTTPException"
        except HTTPException as exc:
            assert exc.status_code == 429
            assert "rate limit" in str(exc.detail).lower()
