"""
Endurance testing suite for CyberSec-CLI.
Tests long-running operations for memory leaks and performance degradation.
"""

import asyncio
import sys
import time
from pathlib import Path
from typing import Dict

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from tests.benchmarking.framework.base_benchmark import BaseBenchmark
from tests.benchmarking.framework.metrics_collector import PerformanceMonitor

try:
    import psutil
except ImportError:
    psutil = None


class EnduranceBenchmark(BaseBenchmark):
    """
    Endurance testing benchmark for CyberSec-CLI.
    
    Tests:
    - 24-hour continuous scanning
    - 48-hour stress test
    - 7-day reliability test
    - Memory leak detection
    - Performance degradation monitoring
    """

    def __init__(self):
        """Initialize endurance benchmark."""
        super().__init__("endurance_test", "tests/benchmarking/results/reliability")
        self.performance_monitor = PerformanceMonitor()

    async def benchmark_continuous_scanning(
        self, duration_hours: float = 1.0, scan_interval: int = 60
    ) -> Dict:
        """
        Test continuous scanning over extended period.
        
        Args:
            duration_hours: Duration in hours (default: 1 hour for testing)
            scan_interval: Interval between scans in seconds
            
        Returns:
            Dictionary with endurance test results
        """
        duration_seconds = int(duration_hours * 3600)
        print(f"Benchmarking continuous scanning ({duration_hours}h = {duration_seconds}s)...")
        print(f"  Scan interval: {scan_interval}s")
        print(f"  Expected scans: {duration_seconds // scan_interval}")

        start_time = time.time()
        end_time = start_time + duration_seconds
        
        scan_count = 0
        scan_times = []
        memory_samples = []
        errors = []

        async def continuous_scan_loop():
            nonlocal scan_count, scan_times, memory_samples, errors

            while time.time() < end_time:
                scan_start = time.time()

                try:
                    # Perform a scan
                    from cybersec_cli.tools.network.port_scanner import PortScanner

                    scanner = PortScanner(
                        target="127.0.0.1",
                        ports=[80, 443, 22, 21, 25],
                        timeout=1.0,
                        max_concurrent=5,
                    )
                    await scanner.scan()

                    scan_duration = time.time() - scan_start
                    scan_times.append(scan_duration)
                    scan_count += 1

                    # Record performance metrics
                    self.performance_monitor.record(
                        "scan_duration", scan_duration
                    )

                    # Sample memory
                    if psutil:
                        process = psutil.Process()
                        mem_mb = process.memory_info().rss / (1024 * 1024)
                        memory_samples.append(mem_mb)
                        self.performance_monitor.record("memory_mb", mem_mb)

                    # Progress update
                    if scan_count % 10 == 0:
                        elapsed = time.time() - start_time
                        remaining = end_time - time.time()
                        print(
                            f"    Scans: {scan_count}, "
                            f"Elapsed: {elapsed/60:.1f}m, "
                            f"Remaining: {remaining/60:.1f}m, "
                            f"Memory: {mem_mb:.1f}MB"
                        )

                except ImportError:
                    # Mock for testing without scanner
                    await asyncio.sleep(0.1)
                    scan_times.append(0.1)
                    scan_count += 1
                    memory_samples.append(100.0)

                except Exception as e:
                    errors.append(str(e))
                    print(f"    ✗ Scan error: {e}")

                # Wait for next scan interval
                await asyncio.sleep(scan_interval)

        # Run continuous scanning
        await continuous_scan_loop()

        # Analyze results
        total_duration = time.time() - start_time
        avg_scan_time = sum(scan_times) / len(scan_times) if scan_times else 0
        
        # Memory leak detection
        memory_leak_detected = False
        memory_growth_rate = 0.0
        
        if len(memory_samples) > 10:
            # Compare first 10% vs last 10%
            split_point = len(memory_samples) // 10
            initial_avg = sum(memory_samples[:split_point]) / split_point
            final_avg = sum(memory_samples[-split_point:]) / split_point
            memory_growth_rate = (final_avg - initial_avg) / initial_avg if initial_avg > 0 else 0
            
            # Consider it a leak if memory grew > 20%
            memory_leak_detected = memory_growth_rate > 0.20

        # Performance degradation detection
        degradation_detected = self.performance_monitor.detect_regression(
            "scan_duration", threshold=0.10, window=20
        )

        results = {
            "duration_hours": duration_hours,
            "duration_seconds": total_duration,
            "scan_interval": scan_interval,
            "total_scans": scan_count,
            "successful_scans": scan_count - len(errors),
            "failed_scans": len(errors),
            "success_rate": (scan_count - len(errors)) / scan_count if scan_count > 0 else 0,
            "avg_scan_time": avg_scan_time,
            "min_scan_time": min(scan_times) if scan_times else 0,
            "max_scan_time": max(scan_times) if scan_times else 0,
            "memory_samples": len(memory_samples),
            "memory_initial_mb": memory_samples[0] if memory_samples else 0,
            "memory_final_mb": memory_samples[-1] if memory_samples else 0,
            "memory_peak_mb": max(memory_samples) if memory_samples else 0,
            "memory_growth_rate": memory_growth_rate,
            "memory_leak_detected": memory_leak_detected,
            "performance_degradation_detected": degradation_detected,
            "errors": errors[:10],  # First 10 errors
        }

        print("\n  Results:")
        print(f"    Total scans: {results['total_scans']}")
        print(f"    Success rate: {results['success_rate']:.1%}")
        print(f"    Avg scan time: {results['avg_scan_time']:.3f}s")
        print(f"    Memory growth: {results['memory_growth_rate']:.1%}")
        print(f"    Memory leak: {'✗ DETECTED' if memory_leak_detected else '✓ None'}")
        print(f"    Performance degradation: {'✗ DETECTED' if degradation_detected else '✓ None'}")

        return results

    async def benchmark_repeated_operations(
        self, iterations: int = 1000, operation_type: str = "scan"
    ) -> Dict:
        """
        Test repeated operations for memory leaks.
        
        Args:
            iterations: Number of iterations
            operation_type: Type of operation to repeat
            
        Returns:
            Dictionary with repeated operation results
        """
        print(f"Benchmarking repeated operations ({iterations} iterations)...")

        memory_samples = []
        durations = []

        for i in range(iterations):
            iter_start = time.time()

            try:
                from cybersec_cli.tools.network.port_scanner import PortScanner

                scanner = PortScanner(
                    target="127.0.0.1",
                    ports=[80],
                    timeout=0.5,
                    max_concurrent=1,
                )
                await scanner.scan()

            except ImportError:
                await asyncio.sleep(0.001)

            durations.append(time.time() - iter_start)

            # Sample memory every 100 iterations
            if psutil and i % 100 == 0:
                process = psutil.Process()
                mem_mb = process.memory_info().rss / (1024 * 1024)
                memory_samples.append(mem_mb)

                if i % 500 == 0:
                    print(f"    Iteration: {i}/{iterations}, Memory: {mem_mb:.1f}MB")

        # Analyze memory trend
        memory_leak_detected = False
        if len(memory_samples) > 2:
            initial = memory_samples[0]
            final = memory_samples[-1]
            growth = (final - initial) / initial if initial > 0 else 0
            memory_leak_detected = growth > 0.10  # 10% growth threshold

        results = {
            "iterations": iterations,
            "operation_type": operation_type,
            "total_duration": sum(durations),
            "avg_duration": sum(durations) / len(durations) if durations else 0,
            "memory_samples": len(memory_samples),
            "memory_initial_mb": memory_samples[0] if memory_samples else 0,
            "memory_final_mb": memory_samples[-1] if memory_samples else 0,
            "memory_leak_detected": memory_leak_detected,
        }

        print(f"  Avg duration: {results['avg_duration']:.4f}s")
        print(f"  Memory leak: {'✗ DETECTED' if memory_leak_detected else '✓ None'}")

        return results

    async def run_benchmark(self, duration_hours: float = 1.0) -> Dict:
        """
        Run endurance benchmarks.
        
        Args:
            duration_hours: Duration for continuous scanning test
        """
        print("\n" + "=" * 60)
        print("Endurance Testing Benchmark Suite")
        print("=" * 60 + "\n")

        print("⚠ Note: Full endurance tests (24h, 48h, 7d) take significant time.")
        print(f"  Running abbreviated test: {duration_hours}h")
        print()

        results = {}

        # Continuous scanning test
        results["continuous_scanning"] = await self.benchmark_continuous_scanning(
            duration_hours=duration_hours, scan_interval=30
        )

        # Repeated operations test
        results["repeated_operations"] = await self.benchmark_repeated_operations(
            iterations=1000
        )

        # Save results
        filepath = self.save_results("endurance_test_results.json")
        print(f"\n✓ Results saved to: {filepath}")

        # Print summary
        self.print_summary()

        return results

    def print_summary(self):
        """Print summary of endurance tests."""
        print(f"\n{'=' * 60}")
        print(f"Benchmark: {self.name}")
        print(f"{'=' * 60}")
        print("Endurance tests generate custom result structures.")
        print("See detailed output above for specific metrics.")
        print(f"{'=' * 60}\n")

async def main():
    """Run the endurance testing benchmark suite."""
    import argparse

    parser = argparse.ArgumentParser(description="Run endurance tests")
    parser.add_argument(
        "--duration",
        type=float,
        default=1.0,
        help="Duration in hours (default: 1.0)",
    )

    args = parser.parse_args()

    benchmark = EnduranceBenchmark()
    results = await benchmark.run_benchmark(duration_hours=args.duration)

    print("\n" + "=" * 60)
    print("Endurance Testing Complete!")
    print("=" * 60)
    print("\nFor full tests, run:")
    print(f"  24h test: python {__file__} --duration=24")
    print(f"  48h test: python {__file__} --duration=48")
    print(f"  7d test:  python {__file__} --duration=168")

    return results


if __name__ == "__main__":
    asyncio.run(main())
