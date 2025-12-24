import pytest

import web.main as main


@pytest.mark.asyncio
async def test_redis_helpers_fallback_when_none():
    # ensure _redis is None and helpers return False or no-op
    orig = main._redis
    main._redis = None
    try:
        ok = await main._redis_check_and_increment_rate("test-client")
        assert ok is False
        ok2 = await main._redis_increment_active("test-client")
        assert ok2 is False
        # should not raise
        await main._redis_decrement_active("test-client")
    finally:
        main._redis = orig


class DummyRedis:
    def __init__(self):
        self._store = {}

    async def incr(self, key):
        v = self._store.get(key, 0) + 1
        self._store[key] = v
        return v

    async def decr(self, key):
        v = self._store.get(key, 0) - 1
        v = max(0, v)
        self._store[key] = v
        return v

    async def expire(self, key, ttl):
        # no-op for testing
        self._store[f"{key}:ttl"] = ttl
        return True


@pytest.mark.asyncio
async def test_redis_helpers_with_dummy():
    orig = main._redis
    dummy = DummyRedis()
    main._redis = dummy
    try:
        # Rate: WS_RATE_LIMIT default is small (5) in module; allow up to that
        for i in range(1, main.WS_RATE_LIMIT + 1):
            ok = await main._redis_check_and_increment_rate("c1")
            assert ok is True
        # next should fail
        ok = await main._redis_check_and_increment_rate("c1")
        assert ok is False

        # Active concurrency: allow upto WS_CONCURRENT_LIMIT
        for i in range(1, main.WS_CONCURRENT_LIMIT + 1):
            ok = await main._redis_increment_active("c2")
            assert ok is True
        ok = await main._redis_increment_active("c2")
        assert ok is False

        # decrement should not raise and should reduce counter
        await main._redis_decrement_active("c2")
        # now we can increment again (one slot freed)
        ok = await main._redis_increment_active("c2")
        assert ok is True
    finally:
        main._redis = orig


@pytest.mark.asyncio
async def test_check_and_record_rate_limit_in_memory():
    """Test _check_and_record_rate_limit fallback to in-memory when Redis is None."""
    orig_redis = main._redis
    main._redis = None
    orig_counters = main._rate_counters.copy()
    main._rate_counters.clear()
    try:
        # First few should pass
        for i in range(main.WS_RATE_LIMIT):
            ok = await main._check_and_record_rate_limit("test-client")
            assert ok is True
        # Next should fail (rate limit exceeded)
        ok = await main._check_and_record_rate_limit("test-client")
        assert ok is False
    finally:
        main._redis = orig_redis
        main._rate_counters = orig_counters


@pytest.mark.asyncio
async def test_record_scan_start_end_in_memory():
    """Test _record_scan_start and _record_scan_end fallback to in-memory when Redis is None."""
    orig_redis = main._redis
    main._redis = None
    orig_active = main._active_scans.copy()
    main._active_scans.clear()
    try:
        # First few should pass
        for i in range(main.WS_CONCURRENT_LIMIT):
            ok = await main._record_scan_start("test-client-2")
            assert ok is True
        # Next should fail
        ok = await main._record_scan_start("test-client-2")
        assert ok is False
        # Decrement one
        await main._record_scan_end("test-client-2")
        # now we can start again
        ok = await main._record_scan_start("test-client-2")
        assert ok is True
    finally:
        main._redis = orig_redis
        main._active_scans = orig_active
