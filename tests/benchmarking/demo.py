#!/usr/bin/env python3
"""
Quick demo script to showcase the comprehensive testing infrastructure.
Runs a subset of tests to demonstrate capabilities.
"""

import asyncio
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))


async def main():
    """Run demo tests."""
    print("\n" + "=" * 70)
    print("CYBERSEC-CLI COMPREHENSIVE TESTING INFRASTRUCTURE - DEMO")
    print("=" * 70)
    print("\nThis demo showcases the testing infrastructure capabilities.")
    print("For full tests, use: python run_all_benchmarks.py")
    print("\n" + "=" * 70 + "\n")

    results = {}

    # 1. Framework Verification
    print("1️⃣  FRAMEWORK VERIFICATION")
    print("-" * 70)
    try:
        from tests.benchmarking.framework.base_benchmark import BaseBenchmark
        from tests.benchmarking.framework.metrics_collector import MetricsCollector
        from tests.benchmarking.framework.statistical_analysis import StatisticalAnalyzer
        
        print("✓ Framework components loaded successfully")
        results["framework"] = "PASS"
    except Exception as e:
        print(f"✗ Framework error: {e}")
        results["framework"] = "FAIL"
    
    print()

    # 2. Performance Test Sample
    print("2️⃣  PERFORMANCE BENCHMARK SAMPLE")
    print("-" * 70)
    try:
        from tests.benchmarking.performance.test_speed_throughput import SpeedThroughputBenchmark
        
        benchmark = SpeedThroughputBenchmark()
        print("Running single port scan benchmark (10 iterations)...")
        result = await benchmark.benchmark_single_port_scan(iterations=10)
        print(f"✓ Mean latency: {result.get('mean_latency_ms', 0):.2f}ms")
        results["performance"] = "PASS"
    except Exception as e:
        print(f"✗ Performance test error: {e}")
        results["performance"] = "FAIL"
    
    print()

    # 3. Scalability Test Sample
    print("3️⃣  SCALABILITY TEST SAMPLE")
    print("-" * 70)
    try:
        from tests.benchmarking.performance.test_scalability import ScalabilityBenchmark
        
        benchmark = ScalabilityBenchmark()
        print("Running horizontal scaling test (1, 10 targets)...")
        result = await benchmark.benchmark_horizontal_scaling([1, 10])
        print(f"✓ Scalability test completed")
        results["scalability"] = "PASS"
    except Exception as e:
        print(f"✗ Scalability test error: {e}")
        results["scalability"] = "FAIL"
    
    print()

    # 4. Accuracy Test Sample
    print("4️⃣  ACCURACY TEST SAMPLE")
    print("-" * 70)
    try:
        from tests.benchmarking.accuracy.test_port_detection import AccuracyBenchmark
        
        benchmark = AccuracyBenchmark()
        print("Running port detection accuracy test...")
        result = await benchmark.benchmark_port_detection_accuracy(
            target="127.0.0.1",
            expected_open_ports={22, 80, 443},
            port_range="1-100"
        )
        print(f"✓ Accuracy: {result.get('accuracy', 0):.2%}")
        print(f"✓ Precision: {result.get('precision', 0):.2%}")
        print(f"✓ Recall: {result.get('recall', 0):.2%}")
        results["accuracy"] = "PASS"
    except Exception as e:
        print(f"✗ Accuracy test error: {e}")
        results["accuracy"] = "FAIL"
    
    print()

    # 5. Stress Test Sample
    print("5️⃣  STRESS TEST SAMPLE")
    print("-" * 70)
    try:
        from tests.benchmarking.reliability.test_stress import StressBenchmark
        
        benchmark = StressBenchmark()
        print("Running memory stress test (100MB, 5s)...")
        result = await benchmark.benchmark_memory_stress(target_mb=100, duration=5)
        print(f"✓ Memory stress test completed")
        print(f"  Peak memory: {result.get('memory_peak_mb', 0):.1f}MB")
        results["stress"] = "PASS"
    except Exception as e:
        print(f"✗ Stress test error: {e}")
        results["stress"] = "FAIL"
    
    print()

    # Summary
    print("=" * 70)
    print("DEMO SUMMARY")
    print("=" * 70)
    
    passed = sum(1 for r in results.values() if r == "PASS")
    total = len(results)
    
    print(f"\nTests Passed: {passed}/{total} ({passed/total*100:.0f}%)")
    print("\nTest Results:")
    for test, result in results.items():
        status = "✓" if result == "PASS" else "✗"
        print(f"  {status} {test.capitalize()}: {result}")
    
    print("\n" + "=" * 70)
    print("AVAILABLE TEST SUITES")
    print("=" * 70)
    print("\n📊 Performance Benchmarking:")
    print("  • python tests/benchmarking/performance/test_speed_throughput.py")
    print("  • python tests/benchmarking/performance/test_scalability.py")
    print("  • sudo python tests/benchmarking/performance/test_network_conditions.py")
    
    print("\n🔍 Comparative Analysis:")
    print("  • python tests/benchmarking/comparative/test_nmap_comparison.py")
    print("  • sudo python tests/benchmarking/comparative/test_masscan_comparison.py")
    print("  • python tests/benchmarking/comparative/test_rustscan_comparison.py")
    
    print("\n💪 Reliability & Stability:")
    print("  • python tests/benchmarking/reliability/test_stress.py")
    print("  • python tests/benchmarking/reliability/test_endurance.py --duration=1")
    print("  • python tests/benchmarking/reliability/test_chaos.py")
    
    print("\n🎯 Accuracy & Correctness:")
    print("  • python tests/benchmarking/accuracy/test_port_detection.py")
    
    print("\n🚀 Run All Tests:")
    print("  • python tests/benchmarking/run_all_benchmarks.py")
    print("  • python tests/benchmarking/run_all_benchmarks.py --phases performance reliability")
    
    print("\n" + "=" * 70)
    print("For more information, see:")
    print("  • tests/benchmarking/QUICKSTART.md")
    print("  • tests/benchmarking/SUMMARY.md")
    print("  • tests/benchmarking/README.md")
    print("=" * 70 + "\n")
    
    return 0 if passed == total else 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
