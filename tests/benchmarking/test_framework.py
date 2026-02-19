#!/usr/bin/env python3
"""
Quick test runner for benchmarking framework.
Runs a subset of benchmarks to verify functionality.
"""

import asyncio
import sys
from pathlib import Path

import pytest

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

pytestmark = pytest.mark.anyio


async def test_framework():
    """Test the benchmarking framework."""
    print("=" * 70)
    print("CyberSec-CLI Benchmarking Framework - Quick Test")
    print("=" * 70)
    print()

    # Test 1: Import framework components
    print("1. Testing framework imports...")
    try:
        from tests.benchmarking.framework.base_benchmark import BaseBenchmark, BenchmarkMetrics
        from tests.benchmarking.framework.metrics_collector import MetricsCollector
        from tests.benchmarking.framework.statistical_analysis import StatisticalAnalyzer
        from tests.benchmarking.framework.visualization import BenchmarkVisualizer

        print("   ✓ All framework components imported successfully")
    except ImportError as e:
        print(f"   ✗ Import error: {e}")
        return False

    # Test 2: Create a simple benchmark
    print("\n2. Testing BaseBenchmark class...")
    try:
        class SimpleBenchmark(BaseBenchmark):
            def __init__(self):
                super().__init__("simple_test")

            async def run_benchmark(self):
                # Simple test function
                async def test_func():
                    await asyncio.sleep(0.1)
                    return "test"

                metrics = await self.run_with_metrics(
                    test_func, operations=1, metadata={"test": "simple"}
                )

                return {"duration": metrics.duration, "success": True}

        benchmark = SimpleBenchmark()
        result = await benchmark.run_benchmark()

        if result.get("success"):
            print(f"   ✓ Benchmark ran successfully (duration: {result['duration']:.3f}s)")
        else:
            print("   ✗ Benchmark failed")
            return False

    except Exception as e:
        print(f"   ✗ Benchmark error: {e}")
        import traceback
        traceback.print_exc()
        return False

    # Test 3: Test metrics collector
    print("\n3. Testing MetricsCollector...")
    try:
        collector = MetricsCollector(interval=0.05)

        async def sample_work():
            await asyncio.sleep(0.2)

        result = await collector.collect_during(sample_work)

        if "metrics" in result:
            print(f"   ✓ Metrics collected: {len(collector.metrics)} snapshots")
        else:
            print("   ✗ Metrics collection failed")
            return False

    except Exception as e:
        print(f"   ✗ Metrics collector error: {e}")
        return False

    # Test 4: Test statistical analysis
    print("\n4. Testing StatisticalAnalyzer...")
    try:
        analyzer = StatisticalAnalyzer()

        # Test confidence interval
        data = [1.0, 2.0, 3.0, 4.0, 5.0]
        mean, lower, upper = analyzer.calculate_confidence_interval(data)
        print(f"   ✓ Confidence interval: {mean:.2f} [{lower:.2f}, {upper:.2f}]")

        # Test t-test
        sample1 = [1.0, 2.0, 3.0, 4.0, 5.0]
        sample2 = [2.0, 3.0, 4.0, 5.0, 6.0]
        t_test = analyzer.t_test_independent(sample1, sample2)
        print(f"   ✓ T-test p-value: {t_test['p_value']:.4f}")

    except Exception as e:
        print(f"   ✗ Statistical analysis error: {e}")
        return False

    # Test 5: Test visualization (without actually saving)
    print("\n5. Testing BenchmarkVisualizer...")
    try:
        visualizer = BenchmarkVisualizer()
        print(f"   ✓ Visualizer initialized (output: {visualizer.output_dir})")

    except Exception as e:
        print(f"   ✗ Visualization error: {e}")
        return False

    # Test 6: Save and load results
    print("\n6. Testing result persistence...")
    try:
        benchmark = SimpleBenchmark()
        await benchmark.run_benchmark()

        # Save results
        filepath = benchmark.save_results("test_results.json")
        print(f"   ✓ Results saved to: {filepath}")

        # Load results
        loaded = benchmark.load_results(filepath)
        print(f"   ✓ Loaded {len(loaded)} result(s)")

        # Clean up
        filepath.unlink()

    except Exception as e:
        print(f"   ✗ Persistence error: {e}")
        return False

    print("\n" + "=" * 70)
    print("✓ All framework tests passed!")
    print("=" * 70)
    print()

    return True


async def run_quick_benchmark():
    """Run a quick performance benchmark."""
    print("\nRunning quick performance benchmark...")
    print("-" * 70)

    try:
        from tests.benchmarking.performance.test_speed_throughput import SpeedThroughputBenchmark

        benchmark = SpeedThroughputBenchmark()

        # Run only the quick tests
        print("\nRunning single port scan test (10 iterations)...")
        result = await benchmark.benchmark_single_port_scan(iterations=10)
        print(f"Mean latency: {result.get('mean_latency_ms', 0):.2f}ms")

        print("\nRunning cache operations test (100 ops)...")
        cache_result = await benchmark.benchmark_cache_operations(operations=100)
        if not cache_result.get("skipped"):
            print(f"Read ops/sec: {cache_result.get('read_ops_per_sec', 0):.0f}")

        print("\n✓ Quick benchmark complete!")

    except Exception as e:
        print(f"✗ Benchmark error: {e}")
        import traceback
        traceback.print_exc()


async def main():
    """Main test runner."""
    # Test framework
    framework_ok = await test_framework()

    if not framework_ok:
        print("\n✗ Framework tests failed. Please check the errors above.")
        return 1

    # Run quick benchmark
    try:
        await run_quick_benchmark()
    except Exception as e:
        print(f"\nWarning: Quick benchmark failed: {e}")
        print("This is expected if dependencies are not installed.")

    print("\n" + "=" * 70)
    print("Framework verification complete!")
    print("=" * 70)
    print("\nNext steps:")
    print("1. Install dependencies: pip install -r requirements-dev.txt")
    print("2. Run full benchmarks: python tests/benchmarking/performance/test_speed_throughput.py")
    print("3. Run comparative tests: python tests/benchmarking/comparative/test_nmap_comparison.py")
    print("4. Check README: tests/benchmarking/README.md")
    print()

    return 0


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
