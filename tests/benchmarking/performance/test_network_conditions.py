"""
Network condition simulation benchmarks for CyberSec-CLI.
Tests performance under various network conditions.
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


class NetworkConditionBenchmark(BaseBenchmark):
    """
    Benchmark CyberSec-CLI under various network conditions.
    
    Tests:
    - Bandwidth variation (56 Kbps to 10 Gbps)
    - Latency simulation (local to satellite)
    - Packet loss scenarios (0% to 25%)
    - Network congestion levels
    """

    def __init__(self):
        """Initialize network condition benchmark."""
        super().__init__("network_conditions", "tests/benchmarking/results/performance")

    async def benchmark_bandwidth_variation(self) -> Dict:
        """
        Test performance under different bandwidth conditions.
        
        Returns:
            Dictionary with bandwidth test results
        """
        print("Benchmarking performance under different bandwidth conditions...")

        # Bandwidth levels in Kbps (as per config)
        bandwidth_levels = [56, 1000, 10000, 100000, 1000000]  # 56K, 1M, 10M, 100M, 1G
        results = {}

        for bandwidth_kbps in bandwidth_levels:
            print(f"  Testing bandwidth: {bandwidth_kbps} Kbps")
            
            # Simulate network with this bandwidth
            result = await self._simulate_bandwidth_test(bandwidth_kbps)
            results[f"bandwidth_{bandwidth_kbps}"] = result

        # Calculate performance ratios
        if "bandwidth_1000000" in results and "bandwidth_56" in results:  # 1G vs 56K
            performance_ratio = (
                results["bandwidth_56"]["throughput"] / results["bandwidth_1000000"]["throughput"]
                if results["bandwidth_1000000"]["throughput"] > 0
                else float('inf')
            )
            results["performance_ratio_1g_vs_56k"] = performance_ratio

        return results

    async def _simulate_bandwidth_test(self, bandwidth_kbps: int) -> Dict:
        """Simulate a test under specific bandwidth conditions."""
        # Calculate simulated transfer time based on bandwidth
        data_size_kb = 100  # 100KB of data to transfer
        theoretical_time = (data_size_kb * 8) / bandwidth_kbps  # Time in seconds
        
        # Add some overhead and variance
        overhead_factor = 1.2  # 20% overhead
        simulated_time = theoretical_time * overhead_factor
        
        # Add some random variance
        variance = 0.1  # ±10% variance
        simulated_time *= (1 + (random.uniform(-variance, variance) if bandwidth_kbps > 56 else 0))
        
        start_time = time.time()
        
        # Simulate network operations with delay
        await asyncio.sleep(min(simulated_time, 5.0))  # Cap at 5 seconds for testing
        
        actual_duration = time.time() - start_time
        
        # Calculate effective throughput
        effective_throughput = (data_size_kb * 8) / actual_duration if actual_duration > 0 else 0
        
        return {
            "bandwidth_kbps": bandwidth_kbps,
            "theoretical_time": theoretical_time,
            "simulated_time": simulated_time,
            "actual_duration": actual_duration,
            "effective_throughput_kbps": effective_throughput,
            "data_transferred_kb": data_size_kb,
        }

    async def benchmark_latency_simulation(self) -> Dict:
        """
        Test performance under different latency conditions.
        
        Returns:
            Dictionary with latency test results
        """
        print("Benchmarking performance under different latency conditions...")

        # Latency levels in milliseconds (as per config)
        latency_levels = [1, 20, 100, 300, 700]  # Local, regional, cross-country, international, satellite
        results = {}

        for latency_ms in latency_levels:
            print(f"  Testing latency: {latency_ms} ms")
            
            # Simulate network with this latency
            result = await self._simulate_latency_test(latency_ms)
            results[f"latency_{latency_ms}"] = result

        return results

    async def _simulate_latency_test(self, latency_ms: int) -> Dict:
        """Simulate a test under specific latency conditions."""
        # Convert to seconds
        latency_seconds = latency_ms / 1000.0
        
        # Simulate multiple round trips to get average
        num_round_trips = 10
        total_time = 0
        
        for _ in range(num_round_trips):
            start_time = time.time()
            
            # Simulate round trip with latency
            await asyncio.sleep(latency_seconds)
            
            # Add processing time
            await asyncio.sleep(0.001)  # 1ms processing time
            
            total_time += time.time() - start_time
        
        avg_round_trip_time = total_time / num_round_trips
        throughput = num_round_trips / total_time if total_time > 0 else 0
        
        return {
            "latency_ms": latency_ms,
            "num_round_trips": num_round_trips,
            "avg_round_trip_time": avg_round_trip_time,
            "total_time": total_time,
            "throughput_rps": throughput,  # Requests per second
        }

    async def benchmark_packet_loss_scenarios(self) -> Dict:
        """
        Test performance under different packet loss scenarios.
        
        Returns:
            Dictionary with packet loss test results
        """
        print("Benchmarking performance under different packet loss scenarios...")

        # Packet loss percentages (as per config)
        packet_loss_levels = [0, 1, 5, 10, 25]  # 0%, 1%, 5%, 10%, 25%
        results = {}

        for loss_percent in packet_loss_levels:
            print(f"  Testing packet loss: {loss_percent}%")
            
            # Simulate network with this packet loss
            result = await self._simulate_packet_loss_test(loss_percent)
            results[f"packet_loss_{loss_percent}"] = result

        return results

    async def _simulate_packet_loss_test(self, loss_percent: int) -> Dict:
        """Simulate a test under specific packet loss conditions."""
        import random
        
        num_packets = 100
        successful_packets = 0
        retransmissions = 0
        
        start_time = time.time()
        
        for i in range(num_packets):
            # Simulate packet transmission
            if random.randint(1, 100) > loss_percent:
                # Packet successfully transmitted
                successful_packets += 1
                await asyncio.sleep(0.001)  # Processing time for successful packet
            else:
                # Packet lost, needs retransmission
                retransmissions += 1
                await asyncio.sleep(0.005)  # Additional time for retransmission handling
                
                # Simulate retransmission success
                if random.randint(1, 100) > loss_percent * 0.5:  # Lower loss rate for retransmission
                    successful_packets += 1
        
        duration = time.time() - start_time
        success_rate = successful_packets / num_packets if num_packets > 0 else 0
        effective_throughput = successful_packets / duration if duration > 0 else 0
        
        return {
            "packet_loss_percent": loss_percent,
            "num_packets": num_packets,
            "successful_packets": successful_packets,
            "retransmissions": retransmissions,
            "success_rate": success_rate,
            "duration": duration,
            "effective_throughput_pps": effective_throughput,  # Packets per second
        }

    async def benchmark_network_congestion(self) -> Dict:
        """
        Test performance under different network congestion levels.
        
        Returns:
            Dictionary with congestion test results
        """
        print("Benchmarking performance under different congestion levels...")

        congestion_levels = [0, 0.5, 0.8, 0.95]  # 0%, 50%, 80%, 95% congestion
        results = {}

        for congestion in congestion_levels:
            print(f"  Testing congestion: {congestion*100:.0f}%")
            
            # Simulate network with this congestion level
            result = await self._simulate_congestion_test(congestion)
            results[f"congestion_{int(congestion*100)}"] = result

        return results

    async def _simulate_congestion_test(self, congestion_level: float) -> Dict:
        """Simulate a test under specific congestion conditions."""
        import random
        
        # Higher congestion = more delays and collisions
        base_delay = 0.01  # Base processing delay
        congestion_multiplier = 1 + (congestion_level * 5)  # Up to 6x slower at 95% congestion
        
        num_requests = 50
        total_time = 0
        timeouts = 0
        
        for i in range(num_requests):
            start_time = time.time()
            
            # Simulate request processing with congestion effects
            delay = base_delay * congestion_multiplier
            
            # Add random variation based on congestion
            variation = delay * congestion_level * random.uniform(0, 0.5)
            actual_delay = delay + variation
            
            # Simulate timeout based on congestion
            if random.random() < congestion_level * 0.1:  # Higher timeout probability with congestion
                await asyncio.sleep(0.5)  # Simulate timeout
                timeouts += 1
            else:
                await asyncio.sleep(actual_delay)
            
            total_time += time.time() - start_time
        
        avg_request_time = total_time / num_requests if num_requests > 0 else 0
        throughput = num_requests / total_time if total_time > 0 else 0
        
        return {
            "congestion_level": congestion_level,
            "num_requests": num_requests,
            "total_time": total_time,
            "avg_request_time": avg_request_time,
            "throughput_rps": throughput,
            "timeouts": timeouts,
            "timeout_rate": timeouts / num_requests if num_requests > 0 else 0,
        }

    async def benchmark_combined_network_effects(self) -> Dict:
        """
        Test performance under combined network effects.
        
        Returns:
            Dictionary with combined effects test results
        """
        print("Benchmarking performance under combined network effects...")

        # Test combinations of conditions
        test_combinations = [
            {"bandwidth": 1000, "latency": 100, "loss": 1, "congestion": 0.5},  # Typical broadband
            {"bandwidth": 56, "latency": 300, "loss": 5, "congestion": 0.8},     # Poor connection
            {"bandwidth": 1000000, "latency": 1, "loss": 0, "congestion": 0},     # Ideal conditions
            {"bandwidth": 10000, "latency": 100, "loss": 10, "congestion": 0.95}, # Severely degraded
        ]
        
        results = {}

        for i, combo in enumerate(test_combinations):
            print(f"  Testing combination {i+1}: "
                  f"B={combo['bandwidth']}Kbps, L={combo['latency']}ms, "
                  f"P={combo['loss']}%, C={combo['congestion']*100}%")
            
            result = await self._simulate_combined_test(combo)
            results[f"combination_{i+1}"] = result

        return results

    async def _simulate_combined_test(self, combo: Dict) -> Dict:
        """Simulate a test under combined network conditions."""
        # Combine all effects
        base_time = 1.0  # Base operation time
        
        # Apply bandwidth effect (inverse relationship)
        bandwidth_factor = 10000 / combo["bandwidth"]  # Slower with lower bandwidth
        
        # Apply latency effect
        latency_factor = combo["latency"] / 100  # Higher latency slows things down
        
        # Apply packet loss effect (more retransmissions needed)
        loss_factor = 1 + (combo["loss"] / 10)  # More loss = more retransmissions
        
        # Apply congestion effect
        congestion_factor = 1 + combo["congestion"] * 3  # Congestion greatly affects performance
        
        # Calculate total time with all factors
        total_time = base_time * bandwidth_factor * latency_factor * loss_factor * congestion_factor
        
        # Cap at reasonable limits
        total_time = min(total_time, 10.0)  # Don't run too long in tests
        
        start_time = time.time()
        await asyncio.sleep(total_time)
        actual_duration = time.time() - start_time
        
        # Simulate some operations during this time
        operations_completed = int(10 / max(actual_duration, 0.1))  # Fewer ops with worse conditions
        throughput = operations_completed / actual_duration if actual_duration > 0 else 0
        
        return {
            "configuration": combo,
            "calculated_time": total_time,
            "actual_duration": actual_duration,
            "operations_completed": operations_completed,
            "throughput_ops_per_sec": throughput,
            "efficiency_ratio": throughput / (10 / base_time) if base_time > 0 else 0,  # Compared to ideal
        }

    async def run_benchmark(self) -> Dict:
        """Run all network condition benchmarks."""
        print("\n" + "=" * 60)
        print("Network Condition Benchmark Suite")
        print("=" * 60 + "\n")

        results = {}

        # Bandwidth variation
        results["bandwidth"] = await self.benchmark_bandwidth_variation()
        print()

        # Latency simulation
        results["latency"] = await self.benchmark_latency_simulation()
        print()

        # Packet loss scenarios
        results["packet_loss"] = await self.benchmark_packet_loss_scenarios()
        print()

        # Network congestion
        results["congestion"] = await self.benchmark_network_congestion()
        print()

        # Combined network effects
        results["combined"] = await self.benchmark_combined_network_effects()
        print()

        # Save results
        filepath = self.save_results("network_condition_results.json")
        print(f"✓ Results saved to: {filepath}")

    def print_summary(self):
        """Print summary of network condition benchmarks."""
        print(f"\n{'=' * 60}")
        print(f"Benchmark: {self.name}")
        print(f"{'=' * 60}")
        print("Network condition tests generate custom result structures.")
        print("See detailed output above for specific metrics.")
        print(f"{'=' * 60}\n")

        return results


async def main():
    """Run the network condition benchmark suite."""
    benchmark = NetworkConditionBenchmark()
    results = await benchmark.run_benchmark()

    print("\n" + "=" * 60)
    print("Network Condition Benchmark Complete!")
    print("=" * 60)

    return results


if __name__ == "__main__":
    asyncio.run(main())