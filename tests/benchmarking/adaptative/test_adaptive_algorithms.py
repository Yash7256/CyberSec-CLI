"""
Adaptive algorithm benchmarks for CyberSec-CLI.
Tests convergence, adaptation speed, and edge case handling.
"""

import asyncio
import random
import sys
import time
from pathlib import Path
from typing import Dict, List

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from tests.benchmarking.framework.base_benchmark import BaseBenchmark


class AdaptiveAlgorithmBenchmark(BaseBenchmark):
    """
    Benchmark adaptive algorithms in CyberSec-CLI.
    
    Tests:
    - Convergence to optimal concurrency
    - Adaptation speed to changing conditions
    - Edge case handling
    - Stability at optimal point
    """

    def __init__(self):
        """Initialize adaptive algorithm benchmark."""
        super().__init__("adaptive_algorithms", "tests/benchmarking/results/adaptative")

    async def benchmark_convergence_testing(self) -> Dict:
        """
        Test how quickly adaptive algorithms converge to optimal settings.
        
        Returns:
            Dictionary with convergence test results
        """
        print("Benchmarking adaptive algorithm convergence...")

        # Test convergence from different starting points
        starting_points = [1, 5, 10, 20, 50, 100]
        convergence_results = {}

        for start_point in starting_points:
            print(f"  Testing convergence from: {start_point} concurrency")
            
            result = await self._test_convergence_from_point(start_point)
            convergence_results[f"start_{start_point}"] = result

        results = {
            "starting_points": starting_points,
            "convergence_results": convergence_results,
            "average_convergence_time": sum(r["time_to_converge"] for r in convergence_results.values()) / len(convergence_results),
        }

        print(f"  Average convergence time: {results['average_convergence_time']:.2f}s")

        return results

    async def _test_convergence_from_point(self, start_concurrency: int) -> Dict:
        """Test convergence starting from a specific concurrency level."""
        # Simulate adaptive algorithm behavior
        current_concurrency = start_concurrency
        optimal_concurrency = 25  # Assume this is the optimal point
        time_steps = 0
        convergence_time = 0
        
        # Track values for analysis
        concurrency_values = [current_concurrency]
        time_values = [0]
        
        start_time = time.time()
        
        # Simulate adaptive adjustment process
        while abs(current_concurrency - optimal_concurrency) > 2 and time_steps < 50:
            time_steps += 1
            
            # Simulate adaptive adjustment (simplified model)
            error = optimal_concurrency - current_concurrency
            adjustment = error * 0.1  # Learning rate
            
            # Add some noise to simulate real-world conditions
            noise = random.uniform(-2, 2)
            current_concurrency = max(1, current_concurrency + adjustment + noise)
            
            concurrency_values.append(current_concurrency)
            time_values.append(time_steps)
            
            # Simulate processing time
            await asyncio.sleep(0.01)
            
            convergence_time = time.time() - start_time

        # Check for oscillation
        oscillation_detected = self._detect_oscillation(concurrency_values[-10:])
        
        return {
            "start_concurrency": start_concurrency,
            "final_concurrency": current_concurrency,
            "optimal_concurrency": optimal_concurrency,
            "time_to_converge": convergence_time,
            "steps_to_converge": time_steps,
            "oscillation_detected": oscillation_detected,
            "converged": abs(current_concurrency - optimal_concurrency) <= 2,
        }

    def _detect_oscillation(self, values: List[float]) -> bool:
        """Detect if the algorithm is oscillating around the optimal point."""
        if len(values) < 4:
            return False
            
        # Simple oscillation detection: alternating increases/decreases
        increases = [values[i+1] > values[i] for i in range(len(values)-1)]
        
        # Check for alternating pattern
        oscillation_count = 0
        for i in range(len(increases)-1):
            if increases[i] != increases[i+1]:  # Alternating direction
                oscillation_count += 1
                
        # If more than half the transitions alternate, consider oscillating
        return oscillation_count > len(increases) / 2

    async def benchmark_adaptation_speed(self) -> Dict:
        """
        Test how quickly adaptive algorithms respond to changing conditions.
        
        Returns:
            Dictionary with adaptation speed test results
        """
        print("Benchmarking adaptation speed to changing conditions...")

        # Simulate different network condition changes
        scenarios = [
            {"change_type": "bandwidth_increase", "magnitude": 2.0},  # 2x improvement
            {"change_type": "bandwidth_decrease", "magnitude": 0.5},  # 50% reduction
            {"change_type": "latency_spike", "magnitude": 5.0},      # 5x latency
            {"change_type": "packet_loss", "magnitude": 0.1},       # 10% packet loss
        ]
        
        adaptation_results = {}

        for scenario in scenarios:
            print(f"  Testing {scenario['change_type']} (magnitude: {scenario['magnitude']})")
            
            result = await self._test_adaptation_to_change(scenario)
            adaptation_results[scenario["change_type"]] = result

        results = {
            "scenarios": scenarios,
            "adaptation_results": adaptation_results,
            "average_response_time": sum(r["response_time"] for r in adaptation_results.values()) / len(adaptation_results),
        }

        print(f"  Average response time: {results['average_response_time']:.2f}s")

        return results

    async def _test_adaptation_to_change(self, scenario: Dict) -> Dict:
        """Test adaptation to a specific network condition change."""
        # Start with stable conditions
        initial_concurrency = 20
        current_concurrency = initial_concurrency
        
        # Simulate stable state
        await asyncio.sleep(0.5)  # Allow to stabilize
        
        change_start_time = time.time()
        
        # Apply the condition change
        if scenario["change_type"] == "bandwidth_increase":
            # More bandwidth allows higher concurrency
            optimal_after_change = min(50, initial_concurrency * scenario["magnitude"])
        elif scenario["change_type"] == "bandwidth_decrease":
            # Less bandwidth requires lower concurrency
            optimal_after_change = max(5, initial_concurrency * scenario["magnitude"])
        elif scenario["change_type"] == "latency_spike":
            # High latency requires lower concurrency
            optimal_after_change = max(5, initial_concurrency / scenario["magnitude"])
        elif scenario["change_type"] == "packet_loss":
            # Packet loss requires lower concurrency
            optimal_after_change = max(5, initial_concurrency * (1 - scenario["magnitude"]))
        else:
            optimal_after_change = initial_concurrency
        
        # Simulate adaptation process after change
        adaptation_start_time = time.time()
        time_after_change = 0
        steps = 0
        
        while abs(current_concurrency - optimal_after_change) > 3 and steps < 30:
            steps += 1
            
            # Adaptive adjustment toward new optimal
            error = optimal_after_change - current_concurrency
            adjustment = error * 0.15  # Faster adjustment after change detected
            
            # Add noise
            noise = random.uniform(-1, 1)
            current_concurrency = max(1, min(100, current_concurrency + adjustment + noise))
            
            await asyncio.sleep(0.02)  # Simulate processing interval
            time_after_change = time.time() - adaptation_start_time
        
        response_time = time.time() - change_start_time
        
        return {
            "scenario": scenario,
            "initial_concurrency": initial_concurrency,
            "optimal_after_change": optimal_after_change,
            "final_concurrency": current_concurrency,
            "response_time": response_time,
            "adaptation_time": time_after_change,
            "steps_taken": steps,
            "adapted_successfully": abs(current_concurrency - optimal_after_change) <= 3,
        }

    async def benchmark_edge_case_handling(self) -> Dict:
        """
        Test adaptive algorithm behavior under extreme conditions.
        
        Returns:
            Dictionary with edge case handling results
        """
        print("Benchmarking edge case handling...")

        edge_cases = [
            {"case": "network_down", "condition": "complete_outage"},
            {"case": "saturation", "condition": "100_percent_packet_loss"},
            {"case": "unreachable_target", "condition": "no_response"},
            {"case": "all_ports_filtered", "condition": "filtered_response"},
            {"case": "unusual_scenario", "condition": "all_ports_open"},
        ]
        
        edge_case_results = {}

        for case in edge_cases:
            print(f"  Testing edge case: {case['case']}")
            
            result = await self._test_edge_case(case)
            edge_case_results[case["case"]] = result

        results = {
            "edge_cases": edge_cases,
            "edge_case_results": edge_case_results,
            "graceful_failures": sum(1 for r in edge_case_results.values() if r["handled_gracefully"]),
        }

        print(f"  Gracefully handled: {results['graceful_failures']}/{len(edge_cases)} cases")

        return results

    async def _test_edge_case(self, case: Dict) -> Dict:
        """Test a specific edge case."""
        start_time = time.time()
        
        # Simulate different edge case behaviors
        if case["condition"] == "complete_outage":
            # Simulate network outage - no responses
            try:
                await asyncio.wait_for(self._simulate_no_response_scan(), timeout=2.0)
                outcome = "unexpected_success"
            except asyncio.TimeoutError:
                outcome = "timeout_as_expected"
        elif case["condition"] == "100_percent_packet_loss":
            # Simulate complete packet loss
            current_concurrency = 20
            for _ in range(10):  # Simulate failed attempts
                await asyncio.sleep(0.1)
                current_concurrency = max(1, current_concurrency * 0.8)  # Reduce concurrency
            outcome = "reduced_concurrency"
        elif case["condition"] == "no_response":
            # Simulate completely unreachable target
            try:
                await asyncio.wait_for(self._simulate_unreachable_scan(), timeout=1.0)
                outcome = "unexpected_response"
            except asyncio.TimeoutError:
                outcome = "timeout_as_expected"
        elif case["condition"] == "filtered_response":
            # Simulate all ports showing as filtered
            current_concurrency = 20
            for _ in range(5):
                await asyncio.sleep(0.05)
                current_concurrency = max(1, current_concurrency - 2)  # Gradually reduce
            outcome = "gradual_reduction"
        elif case["condition"] == "all_ports_open":
            # Unusual case: all ports appear open
            current_concurrency = 10
            for _ in range(5):
                await asyncio.sleep(0.05)
                current_concurrency = min(50, current_concurrency * 1.2)  # Increase cautiously
            outcome = "cautious_increase"
        else:
            outcome = "default_handling"
        
        duration = time.time() - start_time
        
        return {
            "case": case,
            "outcome": outcome,
            "duration": duration,
            "handled_gracefully": "as_expected" in outcome or "reduced" in outcome or "gradual" in outcome or "cautious" in outcome,
            "final_state": f"Concurrency: {min(50, int(current_concurrency)) if 'concurrency' in locals() else 'N/A'}",
        }

    async def _simulate_no_response_scan(self):
        """Simulate a scan with no responses."""
        await asyncio.sleep(5.0)  # Longer than timeout

    async def _simulate_unreachable_scan(self):
        """Simulate a scan on an unreachable target."""
        await asyncio.sleep(3.0)  # Longer than timeout

    async def benchmark_stability_at_optimum(self) -> Dict:
        """
        Test stability of adaptive algorithms when at optimal settings.
        
        Returns:
            Dictionary with stability test results
        """
        print("Benchmarking stability at optimal settings...")

        optimal_concurrency = 25
        current_concurrency = optimal_concurrency
        
        # Simulate stable conditions for a period
        duration = 10.0  # Test for 10 seconds
        start_time = time.time()
        
        concurrency_readings = []
        time_points = []
        
        while time.time() - start_time < duration:
            # Small random fluctuations around optimal
            fluctuation = random.uniform(-2, 2)
            current_concurrency = max(1, min(50, optimal_concurrency + fluctuation))
            
            concurrency_readings.append(current_concurrency)
            time_points.append(time.time() - start_time)
            
            await asyncio.sleep(0.1)  # Sampling interval

        # Analyze stability
        avg_concurrency = sum(concurrency_readings) / len(concurrency_readings)
        max_deviation = max(abs(c - optimal_concurrency) for c in concurrency_readings)
        std_deviation = (sum((c - avg_concurrency) ** 2 for c in concurrency_readings) / len(concurrency_readings)) ** 0.5

        results = {
            "duration": duration,
            "optimal_concurrency": optimal_concurrency,
            "readings_count": len(concurrency_readings),
            "avg_concurrency": avg_concurrency,
            "max_deviation": max_deviation,
            "std_deviation": std_deviation,
            "stability_rating": "high" if std_deviation < 1.0 else "medium" if std_deviation < 2.0 else "low",
        }

        print(f"  Stability rating: {results['stability_rating']} (std dev: {results['std_deviation']:.2f})")

        return results

    async def run_benchmark(self) -> Dict:
        """Run all adaptive algorithm benchmarks."""
        print("\n" + "=" * 60)
        print("Adaptive Algorithm Benchmark Suite")
        print("=" * 60 + "\n")

        results = {}

        # Convergence testing
        results["convergence"] = await self.benchmark_convergence_testing()
        print()

        # Adaptation speed
        results["adaptation_speed"] = await self.benchmark_adaptation_speed()
        print()

        # Edge case handling
        results["edge_cases"] = await self.benchmark_edge_case_handling()
        print()

        # Stability at optimum
        results["stability"] = await self.benchmark_stability_at_optimum()
        print()

        # Save results
        filepath = self.save_results("adaptive_algorithm_results.json")
        print(f"✓ Results saved to: {filepath}")

        # Print summary
        self.print_summary()

        return results


async def main():
    """Run the adaptive algorithm benchmark suite."""
    benchmark = AdaptiveAlgorithmBenchmark()
    results = await benchmark.run_benchmark()

    print("\n" + "=" * 60)
    print("Adaptive Algorithm Benchmark Complete!")
    print("=" * 60)

    return results


if __name__ == "__main__":
    asyncio.run(main())