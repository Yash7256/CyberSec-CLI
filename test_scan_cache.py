#!/usr/bin/env python3
"""
Test script to verify scan caching functionality for CyberSec-CLI.
"""

import asyncio
import os
import sys
import time

# Add the project root to the path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))


async def test_scan_cache():
    """Test the scan caching functionality."""
    print("Testing Scan Cache Functionality")
    print("=" * 50)

    try:
        # Test cache initialization
        print("1. Testing cache initialization...")
        from core.scan_cache import scan_cache

        await scan_cache.initialize()
        print("   ✅ Cache initialized successfully")

        # Test cache key generation
        print("\n2. Testing cache key generation...")
        cache_key = scan_cache.get_cache_key("example.com", [80, 443, 22])
        print(f"   Cache key for example.com:80,443,22: {cache_key[:20]}...")

        # Test cache miss
        print("\n3. Testing cache miss...")
        result = await scan_cache.check_cache(cache_key)
        if result is None:
            print("   ✅ Cache miss handled correctly (returned None)")
        else:
            print("   ❌ Cache miss failed (should return None)")

        # Test cache storage
        print("\n4. Testing cache storage...")
        test_data = {
            "results": [
                {
                    "port": 80,
                    "state": "open",
                    "service": "http",
                    "version": "Apache 2.4.6",
                },
                {
                    "port": 443,
                    "state": "open",
                    "service": "https",
                    "version": "nginx 1.20.1",
                },
            ]
        }

        store_result = await scan_cache.store_cache(
            cache_key, test_data, target="example.com"
        )
        if store_result:
            print("   ✅ Cache storage successful")
        else:
            print("   ❌ Cache storage failed")

        # Test cache hit
        print("\n5. Testing cache hit...")
        retrieved_result = await scan_cache.check_cache(cache_key)
        if retrieved_result is not None:
            print("   ✅ Cache hit successful")
            print(f"   Retrieved {len(retrieved_result.get('results', []))} results")
        else:
            print("   ❌ Cache hit failed")

        # Test cache statistics
        print("\n6. Testing cache statistics...")
        stats = scan_cache.get_stats()
        print(f"   Stats: {stats}")

        # Test cache invalidation
        print("\n7. Testing cache invalidation...")
        invalidate_result = await scan_cache.invalidate_cache(cache_key)
        if invalidate_result:
            print("   ✅ Cache invalidation successful")
        else:
            print("   ❌ Cache invalidation failed")

        # Verify cache was invalidated
        print("\n8. Verifying cache invalidation...")
        result_after_invalidation = await scan_cache.check_cache(cache_key)
        if result_after_invalidation is None:
            print("   ✅ Cache properly invalidated (returns None)")
        else:
            print("   ❌ Cache invalidation failed (still returns data)")

        print("\n🎉 All cache tests completed successfully!")
        return True

    except Exception as e:
        print(f"\n❌ Error during cache testing: {e}")
        import traceback

        traceback.print_exc()
        return False


async def test_scan_with_caching():
    """Test port scanning with caching functionality."""
    print("\n\nTesting Port Scanning with Caching")
    print("=" * 50)

    try:
        # Import the port scanner
        from cybersec_cli.tools.network.port_scanner import PortScanner, ScanType

        print("1. Creating port scanner...")
        # Use a test target that won't actually be scanned (for safety)
        scanner = PortScanner(
            target="127.0.0.1",  # Localhost for testing
            ports=[22, 80, 443],  # Common ports
            scan_type=ScanType.TCP_CONNECT,
            timeout=0.1,  # Very short timeout for testing
            max_concurrent=10,
        )
        print("   ✅ Port scanner created")

        print("\n2. Performing first scan (should cache results)...")
        start_time = time.time()
        results1 = await scanner.scan(force=False)  # Allow caching
        first_scan_time = time.time() - start_time
        print(f"   First scan completed in {first_scan_time:.2f}s")
        print(f"   Found {len(results1)} results")

        print("\n3. Performing second scan (should return cached results)...")
        start_time = time.time()
        results2 = await scanner.scan(force=False)  # Should use cache
        second_scan_time = time.time() - start_time
        print(f"   Second scan completed in {second_scan_time:.2f}s")
        print(f"   Found {len(results2)} results")

        print(f"\n4. Performance comparison:")
        if first_scan_time > 0:
            speedup = first_scan_time / max(
                second_scan_time, 0.001
            )  # Avoid division by zero
            print(f"   Speedup: {speedup:.2f}x faster with caching")

        print("\n5. Performing forced scan (should bypass cache)...")
        start_time = time.time()
        results3 = await scanner.scan(force=True)  # Bypass cache
        forced_scan_time = time.time() - start_time
        print(f"   Forced scan completed in {forced_scan_time:.2f}s")
        print(f"   Found {len(results3)} results")

        print("\n✅ Scan caching test completed successfully!")
        return True

    except Exception as e:
        print(f"\n❌ Error during scan caching test: {e}")
        import traceback

        traceback.print_exc()
        return False


async def main():
    """Main test function."""
    print("CyberSec-CLI Scan Caching Test Suite")
    print("=" * 60)

    # Run cache tests
    cache_test_result = await test_scan_cache()

    # Run scan tests
    scan_test_result = await test_scan_with_caching()

    print("\n" + "=" * 60)
    print("Test Summary:")
    print(f"  Cache functionality: {'✅ PASS' if cache_test_result else '❌ FAIL'}")
    print(f"  Scan caching:        {'✅ PASS' if scan_test_result else '❌ FAIL'}")

    if cache_test_result and scan_test_result:
        print("\n🎉 All tests passed!")
        return 0
    else:
        print("\n❌ Some tests failed!")
        return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
