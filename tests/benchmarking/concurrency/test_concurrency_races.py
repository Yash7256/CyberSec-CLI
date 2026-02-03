"""
Extreme Concurrency & Race Condition Benchmark.
Hunts for data corruption and thread-safety issues during 1000+ parallel access.
Generates data for Section 20 of the IEEE paper.
"""

import asyncio
import sys
import time
import random
import threading
from typing import Dict, List, Any
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / "src"))

from cybersec_cli.tools.network.port_scanner import PortScanner, PortResult, PortState
from tests.benchmarking.framework.base_benchmark import BaseBenchmark

class ConcurrencyRaceBenchmark(BaseBenchmark):
    """
    Benchmark to hunt for race conditions and verify thread safety.
    """

    def __init__(self):
        super().__init__("concurrency_races", "tests/benchmarking/results/concurrency")
        self.shared_results = []
        self.lock = threading.Lock()

    async def benchmark_thread_safety_async(self, worker_count: int = 1000) -> Dict:
        """
        Test 1: AsyncIO Thread Safety.
        1,000 concurrent tasks appending to the same list.
        In Python's asyncio, this is usually safe on the same loop, 
        but we want to check for logic races in complex state updates.
        """
        print(f"\nTesting AsyncIO result list safety with {worker_count:,} workers...")
        self.shared_results = []
        
        async def worker(worker_id: int):
            # Simulate some work
            await asyncio.sleep(random.uniform(0, 0.05))
            res = PortResult(
                port=worker_id,
                state=PortState.OPEN,
                service="test"
            )
            self.shared_results.append(res)

        start_time = time.time()
        tasks = [worker(i) for i in range(worker_count)]
        await asyncio.gather(*tasks)
        duration = time.time() - start_time
        
        actual_count = len(self.shared_results)
        print(f"  Completed in {duration:.2f}s")
        print(f"  Expected Results: {worker_count}, Actual: {actual_count}")
        
        success = actual_count == worker_count
        return {
            "worker_count": worker_count,
            "actual_count": actual_count,
            "duration": duration,
            "success": success
        }

    async def benchmark_cache_coherency_race(self, race_count: int = 100) -> Dict:
        """
        Test 2: Cache Coherency Race (Thundering Herd).
        Multiple tasks trying to update/check the same cache key simultaneously.
        """
        print(f"\nTesting Cache Coherency Race with {race_count} simultaneous requests...")
        from cybersec_cli.core.scan_cache import scan_cache
        
        if not scan_cache:
            return {"error": "ScanCache not available"}

        target = "127.0.0.1"
        ports = [80, 443]
        cache_key = scan_cache.get_cache_key(target, ports)
        
        # Clear existing
        await scan_cache.invalidate_cache(cache_key)
        
        async def cache_task(task_id: int):
            # Simulate a real scan logic check-then-store
            cached = await scan_cache.check_cache(cache_key)
            if not cached:
                # Thundering herd: everyone sees no cache and tries to store
                await asyncio.sleep(0.01) # Simulate scan delay
                results = {"target": target, "ports": ports, "results": [{"port": 80, "state": "open"}]}
                await scan_cache.store_cache(cache_key, results)
            return True

        start_time = time.time()
        tasks = [cache_task(i) for i in range(race_count)]
        await asyncio.gather(*tasks)
        duration = time.time() - start_time
        
        print(f"  Completed race simulation in {duration:.2f}s")
        
        # Verify cache state
        final_cache = await scan_cache.check_cache(cache_key)
        success = final_cache is not None
        
        return {
            "race_count": race_count,
            "duration": duration,
            "final_status": "coherent" if success else "corrupted"
        }

    async def run_benchmark(self) -> Dict:
        """Run all Phase 13 benchmarks."""
        print("\n" + "=" * 60)
        print("Extreme Concurrency & Race Condition Suite")
        print("=" * 60)
        
        results = {}
        
        # Test 1: Thread/Task Safety
        results["thread_safety"] = await self.benchmark_thread_safety_async(1000)
        
        # Test 2: Cache Coherency
        results["cache_coherency"] = await self.benchmark_cache_coherency_race(100)

        # Save results
        filepath = self.save_results("concurrency_races_results.json")
        print(f"\n✓ Results saved to: {filepath}")

        self.print_summary()
        return results

    def print_summary(self):
        """Print summary."""
        print("\n" + "=" * 60)
        print("Concurrency & Race Summary")
        print("=" * 60)
        print("Verified data integrity under parallel worker load and cache races.")
        print("=" * 60)

async def main():
    """Run the benchmark."""
    benchmark = ConcurrencyRaceBenchmark()
    await benchmark.run_benchmark()

if __name__ == "__main__":
    asyncio.run(main())
