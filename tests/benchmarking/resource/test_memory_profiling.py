"""
Memory profiling for CyberSec-CLI.
Analyzes memory usage patterns and detects leaks.
"""

import asyncio
import gc
import sys
import tracemalloc
from pathlib import Path
from typing import Dict, Tuple

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from tests.benchmarking.framework.base_benchmark import BaseBenchmark


class MemoryProfilingBenchmark(BaseBenchmark):
    """
    Profile memory usage of CyberSec-CLI operations.
    
    Tests:
    - Baseline memory consumption
    - Memory per operation
    - Memory leak detection
    - Peak memory usage
    """

    def __init__(self):
        """Initialize memory profiling benchmark."""
        super().__init__("memory_profiling", "tests/benchmarking/results/resource")

    def get_memory_snapshot(self) -> Tuple[float, float]:
        """
        Get current memory snapshot.
        
        Returns:
            Tuple of (current_mb, peak_mb)
        """
        current, peak = tracemalloc.get_traced_memory()
        return current / 1024 / 1024, peak / 1024 / 1024

    async def benchmark_baseline_memory(self) -> Dict:
        """
        Measure baseline memory consumption.
        
        Returns:
            Dictionary with baseline metrics
        """
        print("Measuring baseline memory consumption...")

        # Force garbage collection
        gc.collect()

        # Start tracing
        tracemalloc.start()

        # Measure idle memory
        await asyncio.sleep(1.0)

        current, peak = self.get_memory_snapshot()
        tracemalloc.stop()

        result = {
            "test": "baseline_memory",
            "current_mb": current,
            "peak_mb": peak,
            "process_memory_mb": self.measure_memory_usage(),
        }

        print(f"  Baseline: {result['process_memory_mb']:.2f} MB")

        return result

    async def benchmark_memory_per_scan(self, iterations: int = 10) -> Dict:
        """
        Measure memory usage per scan operation.
        
        Args:
            iterations: Number of scans to perform
            
        Returns:
            Dictionary with per-scan memory metrics
        """
        print(f"\nMeasuring memory per scan ({iterations} iterations)...")

        gc.collect()
        tracemalloc.start()

        memory_snapshots = []
        initial_memory = self.measure_memory_usage()

        try:
            from cybersec_cli.tools.network.port_scanner import PortScanner

            for i in range(iterations):
                # Use different targets to avoid cache
                target = f"127.0.0.{(i % 254) + 1}"

                scanner = PortScanner(
                    target=target,
                    ports=list(range(1, 101)),
                    timeout=0.5,
                    max_concurrent=10,
                )
                await scanner.scan()

                # Measure memory after each scan
                memory_snapshots.append(self.measure_memory_usage())

                if (i + 1) % 5 == 0:
                    print(f"  Progress: {i+1}/{iterations}")

        except ImportError:
            # Mock for testing
            for i in range(iterations):
                await asyncio.sleep(0.1)
                memory_snapshots.append(initial_memory + (i * 0.1))

        final_memory = self.measure_memory_usage()
        current, peak = self.get_memory_snapshot()
        tracemalloc.stop()

        # Calculate statistics
        import statistics

        memory_diffs = [m - initial_memory for m in memory_snapshots]

        result = {
            "test": "memory_per_scan",
            "iterations": iterations,
            "initial_memory_mb": initial_memory,
            "final_memory_mb": final_memory,
            "total_increase_mb": final_memory - initial_memory,
            "mean_increase_per_scan_mb": statistics.mean(memory_diffs),
            "max_increase_mb": max(memory_diffs),
            "peak_traced_mb": peak,
        }

        print(f"  Memory increase: {result['total_increase_mb']:.2f} MB")
        print(f"  Per scan: {result['mean_increase_per_scan_mb']:.3f} MB")

        return result

    async def benchmark_memory_leak_detection(self, duration: int = 60) -> Dict:
        """
        Detect memory leaks over time.
        
        Args:
            duration: Duration to run test in seconds
            
        Returns:
            Dictionary with leak detection results
        """
        print(f"\nDetecting memory leaks (running for {duration}s)...")

        gc.collect()
        tracemalloc.start()

        memory_samples = []
        start_time = asyncio.get_event_loop().time()
        sample_interval = 5  # Sample every 5 seconds

        try:
            from cybersec_cli.tools.network.port_scanner import PortScanner

            scan_count = 0

            while (asyncio.get_event_loop().time() - start_time) < duration:
                # Perform scan
                target = f"127.0.0.{(scan_count % 254) + 1}"
                scanner = PortScanner(
                    target=target,
                    ports=[80, 443],
                    timeout=0.5,
                    max_concurrent=5,
                )
                await scanner.scan()

                scan_count += 1

                # Sample memory periodically
                if scan_count % 10 == 0:
                    memory_samples.append({
                        "time": asyncio.get_event_loop().time() - start_time,
                        "memory_mb": self.measure_memory_usage(),
                        "scans": scan_count,
                    })
                    print(f"  {len(memory_samples)} samples, {scan_count} scans")

                # Small delay
                await asyncio.sleep(0.1)

        except ImportError:
            # Mock for testing
            for i in range(duration // sample_interval):
                await asyncio.sleep(sample_interval)
                memory_samples.append({
                    "time": i * sample_interval,
                    "memory_mb": 100 + (i * 0.5),  # Simulated growth
                    "scans": i * 10,
                })

        current, peak = self.get_memory_snapshot()
        tracemalloc.stop()

        # Analyze for leaks using linear regression
        if len(memory_samples) > 1:
            times = [s["time"] for s in memory_samples]
            memories = [s["memory_mb"] for s in memory_samples]

            # Simple linear regression
            import statistics

            mean_time = statistics.mean(times)
            mean_memory = statistics.mean(memories)

            numerator = sum((times[i] - mean_time) * (memories[i] - mean_memory) for i in range(len(times)))
            denominator = sum((times[i] - mean_time) ** 2 for i in range(len(times)))

            slope = numerator / denominator if denominator != 0 else 0

            # Leak detected if slope is significantly positive
            leak_detected = slope > 0.1  # More than 0.1 MB/second growth

            result = {
                "test": "memory_leak_detection",
                "duration_seconds": duration,
                "samples": len(memory_samples),
                "initial_memory_mb": memory_samples[0]["memory_mb"] if memory_samples else 0,
                "final_memory_mb": memory_samples[-1]["memory_mb"] if memory_samples else 0,
                "memory_growth_rate_mb_per_sec": slope,
                "leak_detected": leak_detected,
                "peak_traced_mb": peak,
            }

            print(f"  Growth rate: {slope:.4f} MB/sec")
            print(f"  Leak detected: {'YES' if leak_detected else 'NO'}")

        else:
            result = {"test": "memory_leak_detection", "error": "Insufficient samples"}

        return result

    async def run_benchmark(self) -> Dict:
        """Run all memory profiling benchmarks."""
        print("\n" + "=" * 60)
        print("Memory Profiling Benchmark Suite")
        print("=" * 60 + "\n")

        results = {}

        # Baseline memory
        results["baseline"] = await self.benchmark_baseline_memory()

        # Memory per scan
        results["per_scan"] = await self.benchmark_memory_per_scan(iterations=20)

        # Memory leak detection (shorter duration for testing)
        results["leak_detection"] = await self.benchmark_memory_leak_detection(duration=30)

        # Save results
        filepath = self.save_results("memory_profiling_results.json")
        print(f"\n✓ Results saved to: {filepath}")
        
        self.print_summary()

        return results

    def print_summary(self):
        """Print summary of memory profiling."""
        print(f"\n{'=' * 60}")
        print(f"Benchmark: {self.name}")
        print(f"{'=' * 60}")
        print("Memory profiling generates custom result structures.")
        print("See detailed output above for specific metrics.")
        print(f"{'=' * 60}\n")



async def main():
    """Run the memory profiling benchmark suite."""
    benchmark = MemoryProfilingBenchmark()
    results = await benchmark.run_benchmark()

    print("\n" + "=" * 60)
    print("Memory Profiling Complete!")
    print("=" * 60)

    return results


if __name__ == "__main__":
    asyncio.run(main())
