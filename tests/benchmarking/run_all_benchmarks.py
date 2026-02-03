#!/usr/bin/env python3
"""
Master benchmark runner for CyberSec-CLI.
Runs all available benchmarks and generates comprehensive report.
"""

import asyncio
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))


async def run_comprehensive_benchmarks():
    """Run all available benchmarks."""
    print("=" * 70)
    print("CyberSec-CLI - Comprehensive Benchmark Suite")
    print("Running ALL benchmarks for extreme testing")
    print("=" * 70)
    print()

    results = {}
    errors = []

    # 1. Speed & Throughput
    print("\n[1/10] Running Speed & Throughput Benchmarks...")
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
    print("\n[2/10] Running Scalability Benchmarks...")
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
    print("\n[3/10] Running Memory Profiling...")
    print("-" * 70)
    try:
        from tests.benchmarking.resource.test_memory_profiling import MemoryProfilingBenchmark

        benchmark = MemoryProfilingBenchmark()
        results["memory_profiling"] = await benchmark.run_benchmark()
        print("✓ Memory Profiling complete")
    except Exception as e:
        print(f"✗ Memory Profiling failed: {e}")
        errors.append(("Memory Profiling", str(e)))

    # 4. Network Conditions
    print("\n[4/10] Running Network Conditions Benchmarks...")
    print("-" * 70)
    try:
        from tests.benchmarking.performance.test_network_conditions import NetworkConditionBenchmark

        benchmark = NetworkConditionBenchmark()
        results["network_conditions"] = await benchmark.run_benchmark()
        print("✓ Network Conditions complete")
    except Exception as e:
        print(f"✗ Network Conditions failed: {e}")
        errors.append(("Network Conditions", str(e)))

    # 5. Stress Testing
    print("\n[5/10] Running Stress Testing...")
    print("-" * 70)
    try:
        from tests.benchmarking.reliability.test_stress import StressBenchmark

        benchmark = StressBenchmark()
        results["stress_testing"] = await benchmark.run_benchmark()
        print("✓ Stress Testing complete")
    except Exception as e:
        print(f"✗ Stress Testing failed: {e}")
        errors.append(("Stress Testing", str(e)))

    # 6. Endurance Testing
    print("\n[6/10] Running Endurance Testing...")
    print("-" * 70)
    try:
        from tests.benchmarking.reliability.test_endurance import EnduranceBenchmark

        benchmark = EnduranceBenchmark()
        results["endurance_testing"] = await benchmark.run_benchmark()
        print("✓ Endurance Testing complete")
    except Exception as e:
        print(f"✗ Endurance Testing failed: {e}")
        errors.append(("Endurance Testing", str(e)))

    # 7. Chaos Engineering
    print("\n[7/10] Running Chaos Engineering...")
    print("-" * 70)
    try:
        from tests.benchmarking.reliability.test_chaos import ChaosBenchmark

        benchmark = ChaosBenchmark()
        results["chaos_engineering"] = await benchmark.run_benchmark()
        print("✓ Chaos Engineering complete")
    except Exception as e:
        print(f"✗ Chaos Engineering failed: {e}")
        errors.append(("Chaos Engineering", str(e)))

    # 8. Accuracy Analysis
    print("\n[8/10] Running Accuracy Analysis...")
    print("-" * 70)
    try:
        from tests.benchmarking.accuracy.test_accuracy_analysis import AccuracyAnalysisBenchmark

        benchmark = AccuracyAnalysisBenchmark()
        results["accuracy_analysis"] = await benchmark.run_benchmark()
        print("✓ Accuracy Analysis complete")
    except Exception as e:
        print(f"✗ Accuracy Analysis failed: {e}")
        errors.append(("Accuracy Analysis", str(e)))

    # 9. AI Integration
    print("\n[9/10] Running AI Integration Testing...")
    print("-" * 70)
    try:
        from tests.benchmarking.performance.test_ai_integration import AIIntegrationBenchmark

        benchmark = AIIntegrationBenchmark()
        results["ai_integration"] = await benchmark.run_benchmark()
        print("✓ AI Integration Testing complete")
    except Exception as e:
        print(f"✗ AI Integration Testing failed: {e}")
        errors.append(("AI Integration", str(e)))

    # 10. Comparative Analysis (Nmap, Masscan, Zmap, Rustscan)
    print("\n[10/10] Running Comparative Analysis...")
    print("-" * 70)
    
    # Nmap
    try:
        from tests.benchmarking.comparative.test_nmap_comparison import NmapComparison

        benchmark = NmapComparison()
        results["nmap_comparison"] = await benchmark.run_benchmark()
        print("✓ Nmap Comparison complete")
    except Exception as e:
        print(f"✗ Nmap Comparison failed: {e}")
        errors.append(("Nmap Comparison", str(e)))

    # Masscan
    try:
        from tests.benchmarking.comparative.test_masscan_comparison import MasscanComparison

        benchmark = MasscanComparison()
        results["masscan_comparison"] = await benchmark.run_benchmark()
        print("✓ Masscan Comparison complete")
    except Exception as e:
        print(f"✗ Masscan Comparison failed: {e}")
        errors.append(("Masscan Comparison", str(e)))

    # Zmap
    try:
        from tests.benchmarking.comparative.test_zmap_comparison import ZmapComparison

        benchmark = ZmapComparison()
        results["zmap_comparison"] = await benchmark.run_benchmark()
        print("✓ Zmap Comparison complete")
    except Exception as e:
        print(f"✗ Zmap Comparison failed: {e}")
        errors.append(("Zmap Comparison", str(e)))

    # Rustscan
    try:
        from tests.benchmarking.comparative.test_rustscan_comparison import RustscanComparison

        benchmark = RustscanComparison()
        results["rustscan_comparison"] = await benchmark.run_benchmark()
        print("✓ Rustscan Comparison complete")
    except Exception as e:
        print(f"✗ Rustscan Comparison failed: {e}")
        errors.append(("Rustscan Comparison", str(e)))

    # Generate Report
    print("\nGenerating Comprehensive Report...")
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
    print("Comprehensive Benchmark Suite Complete!")
    print("=" * 70)
    print()

    successful = len(results)
    failed = len(errors)
    total = successful + len([x for x in ['nmap_comparison', 'masscan_comparison', 'zmap_comparison', 'rustscan_comparison'] if x in results]) + 6  # Add comparative tests

    print(f"Results: {successful}/{total} benchmark categories successful")

    if errors:
        print("\nErrors encountered:")
        for name, error in errors:
            print(f"  - {name}: {error}")

    print("\nResults saved to: tests/benchmarking/results/")
    print("View report: tests/benchmarking/results/reports/benchmark_report.md")
    print()

    return results


async def run_extreme_benchmarks():
    """Run the most extreme and rigorous benchmarks."""
    print("=" * 70)
    print("CyberSec-CLI - EXTREME BENCHMARKING SUITE")
    print("Running most rigorous tests for stress testing")
    print("=" * 70)
    print()

    results = {}
    errors = []

    # Focus on the most intensive tests
    extreme_categories = [
        ("Stress Testing", "tests.benchmarking.reliability.test_stress", "StressBenchmark"),
        ("Chaos Engineering", "tests.benchmarking.reliability.test_chaos", "ChaosBenchmark"),
        ("Network Conditions", "tests.benchmarking.performance.test_network_conditions", "NetworkConditionBenchmark"),
        ("Accuracy Analysis", "tests.benchmarking.accuracy.test_accuracy_analysis", "AccuracyAnalysisBenchmark"),
        ("AI Integration", "tests.benchmarking.performance.test_ai_integration", "AIIntegrationBenchmark"),
    ]

    for i, (name, module_path, class_name) in enumerate(extreme_categories, 1):
        print(f"\n[{i}/{len(extreme_categories)}] Running {name} (EXTREME)...")
        print("-" * 70)
        try:
            module = __import__(module_path, fromlist=[class_name])
            BenchmarkClass = getattr(module, class_name)
            
            benchmark = BenchmarkClass()
            result = await benchmark.run_benchmark()
            results[name.lower().replace(' ', '_')] = result
            print(f"✓ {name} complete")
        except Exception as e:
            print(f"✗ {name} failed: {e}")
            errors.append((name, str(e)))

    # Summary
    print("\n" + "=" * 70)
    print("EXTREME BENCHMARKING SUITE Complete!")
    print("=" * 70)
    print()

    successful = len(results)
    failed = len(errors)
    total = successful + failed

    print(f"Extreme Results: {successful}/{total} benchmark categories successful")

    if errors:
        print("\nErrors encountered:")
        for name, error in errors:
            print(f"  - {name}: {error}")

    print("\nExtreme results saved to: tests/benchmarking/results/extreme/")
    print()

    return results


def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="CyberSec-CLI Extreme Benchmark Runner")
    parser.add_argument(
        "--extreme",
        action="store_true",
        help="Run only extreme/rigorous benchmarks",
    )
    parser.add_argument(
        "--category",
        choices=[
            "performance", "reliability", "accuracy", "comparative", 
            "resource", "security", "adaptive", "ai", "all"
        ],
        default="all",
        help="Specific category to run",
    )

    args = parser.parse_args()

    if args.extreme:
        print("Running EXTREME benchmark suite...")
        asyncio.run(run_extreme_benchmarks())
    else:
        print("Running COMPREHENSIVE benchmark suite...")
        asyncio.run(run_comprehensive_benchmarks())


if __name__ == "__main__":
    main()