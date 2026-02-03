#!/usr/bin/env python3
"""
Master benchmark runner for CyberSec-CLI.
Runs all benchmarks and generates comprehensive report.
"""

import asyncio
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))


async def run_all_benchmarks():
    """Run all available benchmarks."""
    print("=" * 70)
    print("CyberSec-CLI - Comprehensive Benchmark Suite")
    print("=" * 70)
    print()

    results = {}
    errors = []

    # 1. Speed & Throughput
    print("\n[1/5] Running Speed & Throughput Benchmarks...")
    print("-" * 70)
    try:
        from tests.benchmarking.performance.test_speed_throughput import SpeedThroughputBenchmark

        benchmark = SpeedThroughputBenchmark()
        results["speed_throughput"] = await benchmark.run_benchmark()
        print("✓ Speed & Throughput complete")
    except Exception as e:
        print(f"✗ Speed & Throughput failed: {e}")
        errors.append(("Speed & Throughput", str(e)))

    # 2. Scalability
    print("\n[2/5] Running Scalability Benchmarks...")
    print("-" * 70)
    try:
        from tests.benchmarking.performance.test_scalability import ScalabilityBenchmark

        benchmark = ScalabilityBenchmark()
        results["scalability"] = await benchmark.run_benchmark()
        print("✓ Scalability complete")
    except Exception as e:
        print(f"✗ Scalability failed: {e}")
        errors.append(("Scalability", str(e)))

    # 3. Memory Profiling
    print("\n[3/5] Running Memory Profiling...")
    print("-" * 70)
    try:
        from tests.benchmarking.resource.test_memory_profiling import MemoryProfilingBenchmark

        benchmark = MemoryProfilingBenchmark()
        results["memory_profiling"] = await benchmark.run_benchmark()
        print("✓ Memory Profiling complete")
    except Exception as e:
        print(f"✗ Memory Profiling failed: {e}")
        errors.append(("Memory Profiling", str(e)))

    # 4. Nmap Comparison
    print("\n[4/5] Running Nmap Comparison...")
    print("-" * 70)
    try:
        from tests.benchmarking.comparative.test_nmap_comparison import NmapComparison

        benchmark = NmapComparison()
        results["nmap_comparison"] = await benchmark.run_benchmark()
        print("✓ Nmap Comparison complete")
    except Exception as e:
        print(f"✗ Nmap Comparison failed: {e}")
        errors.append(("Nmap Comparison", str(e)))

    # 5. Generate Report
    print("\n[5/5] Generating Comprehensive Report...")
    print("-" * 70)
    try:
        from tests.benchmarking.tools.generate_report import BenchmarkReportGenerator

        generator = BenchmarkReportGenerator()
        all_results = generator.load_benchmark_results(Path("tests/benchmarking/results"))

        if all_results:
            report_path = generator.generate_markdown_report(all_results)
            print(f"✓ Report generated: {report_path}")
        else:
            print("⚠ No results to report")
    except Exception as e:
        print(f"✗ Report generation failed: {e}")
        errors.append(("Report Generation", str(e)))

    # Summary
    print("\n" + "=" * 70)
    print("Benchmark Suite Complete!")
    print("=" * 70)
    print()

    successful = len(results)
    failed = len(errors)
    total = successful + failed

    print(f"Results: {successful}/{total} benchmarks successful")

    if errors:
        print("\nErrors encountered:")
        for name, error in errors:
            print(f"  - {name}: {error}")

    print("\nResults saved to: tests/benchmarking/results/")
    print("View report: tests/benchmarking/results/reports/benchmark_report.md")
    print()

    return results


async def run_quick_benchmarks():
    """Run quick subset of benchmarks for testing."""
    print("=" * 70)
    print("CyberSec-CLI - Quick Benchmark Suite")
    print("=" * 70)
    print()

    # Just run speed & throughput with reduced iterations
    print("Running Speed & Throughput (quick mode)...")
    try:
        from tests.benchmarking.performance.test_speed_throughput import SpeedThroughputBenchmark

        benchmark = SpeedThroughputBenchmark()

        # Run subset
        result = await benchmark.benchmark_single_port_scan(iterations=10)
        print(f"✓ Single port latency: {result.get('mean_latency_ms', 0):.2f}ms")

        result = await benchmark.benchmark_cache_operations(operations=100)
        if not result.get("skipped"):
            print(f"✓ Cache read ops/sec: {result.get('read_ops_per_sec', 0):.0f}")

        print("\n✓ Quick benchmark complete!")

    except Exception as e:
        print(f"✗ Quick benchmark failed: {e}")


def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="CyberSec-CLI Benchmark Runner")
    parser.add_argument(
        "--quick",
        action="store_true",
        help="Run quick benchmark subset (for testing)",
    )
    parser.add_argument(
        "--category",
        choices=["performance", "comparative", "resource", "all"],
        default="all",
        help="Benchmark category to run",
    )

    args = parser.parse_args()

    if args.quick:
        asyncio.run(run_quick_benchmarks())
    else:
        asyncio.run(run_all_benchmarks())


if __name__ == "__main__":
    main()
