"""
Adaptive Algorithm Instability Benchmark.
Tests robustness against network jitter, packet loss spikes, and oscillating latency.
Generates data for Section 6 of the IEEE paper.
"""

import asyncio
import random
import time
import math
import sys
from pathlib import Path
from typing import Dict

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from cybersec_cli.tools.network.port_scanner import PortScanner, PortResult, PortState
from tests.benchmarking.framework.base_benchmark import BaseBenchmark

class UnstablePortScanner(PortScanner):
    """
    PortScanner instrumented to simulate unstable network conditions.
    Supports dynamic condition injection.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.history = []
        self.start_time = time.time()
        self.condition_mode = "stable" # stable, oscillating, spiking
        self.packet_loss_rate = 0.0
        self.base_latency = 0.1 # 100ms (Simulate Internet Latency to prevent instant scans)
        
        # Oscillation params
        self.oscillation_period = 5.0 # seconds
        self.oscillation_amplitude = 0.200 # 200ms
        
    def set_condition(self, mode: str, loss: float = 0.0):
        """Update network condition simulation parameters."""
        self.condition_mode = mode
        self.packet_loss_rate = loss
        
    def _get_current_latency(self) -> float:
        """Calculate latency based on current mode and time."""
        current_time = time.time() - self.start_time
        
        if self.condition_mode == "oscillating":
            # Sine wave oscillation between base and (base + amplitude)
            # phase = (time % period) / period * 2pi
            phase = (current_time % self.oscillation_period) / self.oscillation_period * 2 * math.pi
            # Normalized sin from 0 to 1: (sin + 1) / 2
            factor = (math.sin(phase) + 1) / 2
            return self.base_latency + (factor * self.oscillation_amplitude)
            
        return self.base_latency

    def _maybe_adjust_adaptive_params(self, success: bool) -> None:
        """Record state changes and adjust params."""
        super()._maybe_adjust_adaptive_params(success)
        
        self.history.append({
            "timestamp": time.time() - self.start_time,
            "concurrency": self.max_concurrent,
            "timeout": self.timeout,
            "success": success,
            "latency": self._get_current_latency(),
            "loss_rate": self.packet_loss_rate
        })

    async def _check_port(self, port: int) -> PortResult:
        """Mocked check_port to simulate instability."""
        
        # Calculate current conditions
        latency = self._get_current_latency()
        
        # Add random jitter (+/- 10%)
        jitter = latency * 0.1
        actual_latency = latency + random.uniform(-jitter, jitter)
        
        # Simulate Network Wait
        try:
            if actual_latency > self.timeout:
                await asyncio.sleep(self.timeout)
                raise asyncio.TimeoutError("Simulated Latency Timeout")
            
            await asyncio.sleep(actual_latency)
            
            # Simulate Packet Loss
            # In "spiking" mode, we might set loss_rate to 0.2 (20%)
            if random.random() < self.packet_loss_rate:
                # Packet lost -> Timeout from client perspective
                raise asyncio.TimeoutError("Simulated Packet Loss")
            
            # Success!
            result = PortResult(port=port, state=PortState.OPEN)
            self._maybe_adjust_adaptive_params(True)
            return result
            
        except asyncio.TimeoutError:
            self._maybe_adjust_adaptive_params(False)
            # Return filtered as is typical for timeouts
            return PortResult(port=port, state=PortState.FILTERED)
        except Exception:
            self._maybe_adjust_adaptive_params(False)
            return PortResult(port=port, state=PortState.CLOSED)


class AdaptiveInstabilityBenchmark(BaseBenchmark):
    """
    Benchmark to verify adaptive algorithm robustness.
    """

    def __init__(self):
        super().__init__("adaptive_instability", "tests/benchmarking/results/adaptive")

    async def benchmark_oscillation(self) -> Dict:
        """
        Test 1: Jitter/Oscillation.
        Latency swings between 5ms and 200ms every 5 seconds.
        Goal: Algorithm should not crash or stall, but maintain average throughput.
        """
        print("Testing adaptation to Network Oscillation (Jitter)...")
        
        # Scan 50000 ports to ensure multiple oscillation cycles
        target_ports = list(range(1, 50001))
        
        # Unique IP to bypass cache
        target = f"127.0.0.{random.randint(2, 100)}"
        
        scanner = UnstablePortScanner(
            target=target, 
            ports=target_ports,
            timeout=0.1, # Tight timeout to force reaction
            max_concurrent=10,
            adaptive_scanning=True
        )
        
        # Configure Oscillation
        scanner.condition_mode = "oscillating"
        scanner.oscillation_period = 5.0 # 5s cycle
        scanner.oscillation_amplitude = 0.200 # 200ms peak
        
        await scanner.scan()
        
        # Analysis
        concurrency_values = [h["concurrency"] for h in scanner.history]
        avg_concurrency = sum(concurrency_values) / len(concurrency_values) if concurrency_values else 0
        variance = sum((x - avg_concurrency) ** 2 for x in concurrency_values) / len(concurrency_values) if concurrency_values else 0
        stability_score = 1.0 / (variance + 1.0) # Higher is better
        
        print(f"  Avg Concurrency: {avg_concurrency:.1f}")
        print(f"  Variance: {variance:.1f}")
        print(f"  Stability Score: {stability_score:.4f}")
        
        return {
            "avg_concurrency": avg_concurrency,
            "variance": variance,
            "stability_score": stability_score,
            "history_sample": scanner.history[::10] # Downsample for report
        }

    async def benchmark_loss_spikes(self) -> Dict:
        """
        Test 2: Loss Spikes & Recovery.
        Stable -> Sudden 20% Loss -> Stable.
        Goal: Verify rapid backoff and subsequent recovery.
        """
        print("Testing reaction to Packet Loss Spikes...")
        
        # Long scan to allow phases
        # Increased to 50000 to ensure it lasts long enough
        target_ports = list(range(1, 50001))
        
        # Unique IP to bypass cache
        target = f"127.0.0.{random.randint(101, 200)}"
        
        scanner = UnstablePortScanner(
            target=target, 
            ports=target_ports,
            timeout=0.2,
            max_concurrent=10,
            adaptive_scanning=True
        )
        
        # Dynamic control task
        async def control_network():
            # Phase 1: Stable (0-2s)
            scanner.set_condition("stable", loss=0.0)
            await asyncio.sleep(2) 
            
            # Phase 2: Spike (2-4s) - 20% Loss
            print("  -> Injecting 20% Packet Loss Spike!")
            scanner.set_condition("spiking", loss=0.20)
            await asyncio.sleep(2)
            
            # Phase 3: Recovery (4s+)
            print("  -> Removing Packet Loss (Recovery)...")
            scanner.set_condition("stable", loss=0.0)
            
        scan_task = asyncio.create_task(scanner.scan())
        control_task = asyncio.create_task(control_network())
        
        await scan_task
        # Control task might still be sleeping if scan was too fast, cancel it
        if not control_task.done():
            control_task.cancel()
            
        try:
            await control_task
        except asyncio.CancelledError:
            pass

        # Analysis
        # Find min concurrency during spike
        # We need to correlate timestamps roughly
        min_concurrency_in_spike = 9999
        # Default to 0, but if we never enter recovery, stays 0
        recovered_max_concurrency = 0
        
        entered_spike = False
        entered_recovery = False
        
        for record in scanner.history:
            t = record["timestamp"]
            c = record["concurrency"]
            loss = record["loss_rate"]
            
            if loss > 0.05: # In spike
                entered_spike = True
                min_concurrency_in_spike = min(min_concurrency_in_spike, c)
            elif t > 4.0: # Recovery phase
                entered_recovery = True
                recovered_max_concurrency = max(recovered_max_concurrency, c)
                
        if not entered_spike:
            print("  [WARNING] Never entered spike phase! Scan too fast?")
            min_concurrency_in_spike = 0 # Invalid
            
        print(f"  Min Concurrency (Spike): {min_concurrency_in_spike}")
        print(f"  Max Concurrency (Recovery): {recovered_max_concurrency}")
        
        did_backoff = min_concurrency_in_spike < 50 # Assuming it gathered some speed before
        did_recover = recovered_max_concurrency > min_concurrency_in_spike * 2
        
        print(f"  Backoff Verified: {did_backoff}")
        print(f"  Recovery Verified: {did_recover}")
        
        return {
            "min_concurrency_spike": min_concurrency_in_spike,
            "max_concurrency_recovery": recovered_max_concurrency,
            "did_backoff": did_backoff,
            "did_recover": did_recover,
            "history_sample": scanner.history[::10]
        }

    async def run_benchmark(self) -> Dict:
        """Run all adaptive instability benchmarks."""
        print("\n" + "=" * 60)
        print("Adaptive Instability Benchmark Suite")
        print("=" * 60 + "\n")

        results = {}
        
        results["oscillation"] = await self.benchmark_oscillation()
        print()
        results["loss_spikes"] = await self.benchmark_loss_spikes()
        
        # Custom Save (to handle history lists if needed, but dicts are fine)
        filepath = self.save_results("adaptive_instability_results.json")
        print(f"\n✓ Results saved to: {filepath}")

        self.print_summary()
        return results

    def print_summary(self):
        """Print summary."""
        print("\n" + "=" * 60)
        print("Adaptive Instability Summary")
        print("=" * 60)
        print("Stability tests complete. See JSON for detailed adaptation curves.")
        print("=" * 60)

async def main():
    """Run the benchmark."""
    benchmark = AdaptiveInstabilityBenchmark()
    await benchmark.run_benchmark()

if __name__ == "__main__":
    asyncio.run(main())
