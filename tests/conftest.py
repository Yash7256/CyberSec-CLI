import os
import sys
from unittest.mock import MagicMock, patch

import pytest

# Add the src directory to the Python path to make cybersec_cli importable
# This ensures that the package can be imported when not installed in editable mode
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
src_path = os.path.join(project_root, "src")
sys.path.insert(0, src_path)

# Also add the project root to the Python path to allow importing from cybersec_cli.core directory
sys.path.insert(0, project_root)

# Now import modules after adding paths to sys.path
from cybersec_cli.core.scan_cache import ScanCache  # noqa: E402
from cybersec_cli.config import RateLimitConfig, ScanningConfig  # noqa: E402
try:
    from cybersec_cli.tools.network.port_scanner import PortScanner  # noqa: E402
except ImportError:
    pytest.skip("module not available", allow_module_level=True)

@pytest.fixture
def mocker():
    """Minimal pytest-mock compatible fixture using unittest.mock.patch."""
    active_patches = []

    def _start_patch(patcher):
        started = patcher.start()
        active_patches.append(patcher)
        return started

    class _PatchProxy:
        def __call__(self, *args, **kwargs):
            return _start_patch(patch(*args, **kwargs))

        def object(self, *args, **kwargs):
            return _start_patch(patch.object(*args, **kwargs))

    class _Mocker:
        patch = _PatchProxy()

    yield _Mocker()

    for patcher in reversed(active_patches):
        patcher.stop()

@pytest.fixture
def anyio_backend():
    """Force anyio to use asyncio backend only."""
    return "asyncio"


@pytest.fixture
def mock_redis_client():
    """Mock Redis client for testing."""
    # Create a mock that simulates the synchronous Redis client behavior
    mock_client = MagicMock()
    mock_client.get = MagicMock(return_value=None)
    mock_client.set = MagicMock(return_value=True)
    mock_client.exists = MagicMock(return_value=False)
    mock_client.delete = MagicMock(return_value=1)  # Return 1 for successful deletion
    mock_client.keys = MagicMock(return_value=[])
    mock_client.flushdb = MagicMock(return_value=None)
    mock_client.zcard = MagicMock(return_value=5)  # For rate limiter tests
    mock_client.zremrangebyscore = MagicMock()
    mock_client.zadd = MagicMock()
    mock_client.expire = MagicMock()
    mock_client.incr = MagicMock(return_value=1)
    return mock_client


@pytest.fixture
def mock_config():
    """Mock configuration object."""
    config = MagicMock()
    config.scanning = ScanningConfig(
        default_timeout=30,
        max_threads=10,
        rate_limit=10,
        adaptive_scanning=True,
        enhanced_service_detection=True,
    )
    config.rate_limit = RateLimitConfig(
        client_rate_limit=10, target_rate_limit=100, port_limit_per_scan=1000
    )
    return config


@pytest.fixture
def mock_scan_result():
    """Mock scan result data."""

    return {
        "host": "127.0.0.1",
        "ports": [
            {"port": 22, "service": "ssh", "state": "open"},
            {"port": 80, "service": "http", "state": "open"},
            {"port": 443, "service": "https", "state": "closed"},
        ],
        "timestamp": "2023-01-01T00:00:00Z",
        "scan_type": "nmap",
    }


@pytest.fixture
def mock_cache(mock_redis_client, mocker):
    """Mock ScanCache instance."""
    with mocker.patch("cybersec_cli.core.scan_cache.redis_client", mock_redis_client):
        cache = ScanCache()
        cache._initialized = True  # Bypass initialization
        cache.redis_client = mock_redis_client
        return cache


@pytest.fixture
def mock_rate_limiter():
    """Mock RateLimiter instance."""
    # Since we don't have the actual SmartRateLimiter implementation in the expected location,
    # we'll create a mock directly
    rate_limiter = MagicMock()
    rate_limiter.check_client_limit = MagicMock(return_value=True)
    rate_limiter.check_target_limit = MagicMock(return_value=True)
    rate_limiter.check_port_range_limit = MagicMock(return_value=(True, ""))
    rate_limiter.check_global_limit = MagicMock(return_value=(True, 100))
    rate_limiter.increment_concurrent_scan = MagicMock(return_value=True)
    rate_limiter.decrement_concurrent_scan = MagicMock()
    rate_limiter.record_violation = MagicMock()
    rate_limiter.get_cooldown_period = MagicMock(return_value=0)
    rate_limiter.is_on_cooldown = MagicMock(return_value=False)
    rate_limiter.apply_cooldown = MagicMock()
    rate_limiter.get_rate_limit_headers = MagicMock(return_value={})
    rate_limiter.reset_client_limits = MagicMock()
    rate_limiter.get_all_violations = MagicMock(return_value={})
    rate_limiter.get_abuse_patterns = MagicMock(return_value=[])
    rate_limiter.get_violation_count = MagicMock(return_value=0)
    return rate_limiter


@pytest.fixture
def mock_scanner(mock_config, mock_cache, mock_rate_limiter):
    """Mock Scanner instance."""
    # Create a PortScanner with mocked dependencies
    with patch("cybersec_cli.tools.network.port_scanner.scan_cache", mock_cache), patch(
        "cybersec_cli.tools.network.port_scanner.HAS_SCAN_CACHE", True
    ):
        scanner = PortScanner(
            target="127.0.0.1", ports=[22, 80, 443], timeout=1.0, max_concurrent=10
        )
        # Replace the cache with our mock
        scanner.scan_cache = mock_cache
        yield scanner


@pytest.fixture
def sample_ip():
    """Sample IP address for testing."""
    return "192.168.1.1"


@pytest.fixture
def sample_domain():
    """Sample domain name for testing."""
    return "example.com"


@pytest.fixture
def sample_port_range():
    """Sample port range for testing."""
    return [1, 80, 443]
