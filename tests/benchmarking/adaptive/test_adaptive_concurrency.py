"""
Adaptive Algorithm Benchmark for CyberSec-CLI.
Generates data for Figure 2: Adaptive Concurrency Over Time.
"""

import asyncio
import random
import time
import json
import sys
from pathlib import Path
from typing import Dict, List, Any

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from cybersec_cli.tools.network.port_scanner import PortScanner, PortResult, PortState
from tests.benchmarking.framework.base_benchmark import BaseBenchmark


class InstrumentedPortScanner(PortScanner):
    """
    PortScanner instrumented to track concurrency changes and simulate network conditions.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.history = []
        self.start_time = time.time()
        self.network_condition = "good"  # good, bad, degraded

    def _maybe_adjust_adaptive_params(self, success: bool) -> None:
        """Override to record state changes."""
        super()._maybe_adjust_adaptive_params(success)
        
        # Record state
        timestamp = time.time() - self.start_time
        
        # Only record if state changed or periodically
        self.history.append({
            "timestamp": timestamp,
            "concurrency": self.max_concurrent,
            "timeout": self.timeout,
            "success": success,
            "condition": self.network_condition
        })

    async def _check_port(self, port: int) -> PortResult:
        """
        Mocked check_port to simulate network conditions.
        """
        # Simulate network delay based on condition
        delay = 0.001
        success_prob = 1.0
        
        if self.network_condition == "good":
            delay = random.uniform(0.001, 0.01)
            success_prob = 1.0 # All success (Open ports for max ramp up)
        elif self.network_condition == "degraded":
            delay = random.uniform(0.05, 0.2)
            success_prob = 0.8 # Occasional failures
        elif self.network_condition == "bad":
            delay = random.uniform(0.5, 1.5) # High latency
            success_prob = 0.1 # Mostly failures (Timeouts/Closed)
            
        # Simulate wait
        try:
            # Check if we should timeout (if delay > timeout in bad conditions)
            if delay > self.timeout:
                await asyncio.sleep(self.timeout)
                raise asyncio.TimeoutError()
                
            await asyncio.sleep(delay)
            
            # Determine success/failure
            if random.random() < success_prob:
                result = PortResult(port=port, state=PortState.OPEN)
                success = True
            else:
                # Simulate timeout or closed port (both treated as failure by adaptive config currently)
                # But we want to trigger backoff, which reacts to failures.
                raise asyncio.TimeoutError("Simulated Network Timeout")

            # Record attempt (usually done in parent, but we mocked it out)
            # IMPORTANT: Parent _check_port logic calls _maybe_adjust_adaptive_params
            # Since we override _check_port completely, we MUST call it here!
            self._maybe_adjust_adaptive_params(True)
            return result
            
        except asyncio.TimeoutError:
            self._maybe_adjust_adaptive_params(False)
            return PortResult(port=port, state=PortState.FILTERED)
        except Exception:
            self._maybe_adjust_adaptive_params(False)
            return PortResult(port=port, state=PortState.CLOSED)


class AdaptiveConcurrencyBenchmark(BaseBenchmark):
    """
    Benchmark to test adaptive concurrency algorithm.
    """

    def __init__(self):
        super().__init__("adaptive_concurrency", "tests/benchmarking/results/adaptive")

    def save_results(self, filename: str) -> Path:
        """Save adaptive benchmark results."""
        filepath = self.output_dir / filename
        
        # Collect results from the scanner history if available
        # We need to access the results dictionary created in run_benchmark
        # But save_results is called from run_benchmark
        # customized save for this benchmark
        
        # We will pass results to this method in our override
        # But since signature must match or we just use custom logic in run_benchmark
        pass
        return filepath
        
    async def run_benchmark(self) -> Dict:
        print("\n" + "=" * 60)
        print("Adaptive Algorithm Performance Benchmark")
        print("=" * 60 + "\n")

        results = {}

        # 1. Concurrency Adaptation Test
        results["adaptation_curve"] = await self.benchmark_adaptation_curve()
        
        # Manual Save
        filepath = self.output_dir / "adaptive_concurrency_results.json"
        with open(filepath, "w") as f:
            json.dump(results, f, indent=2)
            
        print(f"\n✓ Results saved to: {filepath}")
        
        self.print_summary()
        return results

    async def benchmark_adaptation_curve(self) -> List[Dict]:
        """
        Simulate a long scan with varying network conditions to generate Figure 2 data.
        """
        print("Benchmarking concurrency adaptation over time...")
        
        # Initialize scanner with adaptive scanning ENABLED
        scanner = InstrumentedPortScanner(
            target="127.0.0.1",
            ports=list(range(1, 5001)), # 5000 ports to allow time for adaptation
            adaptive_scanning=True,
            service_detection=False, # Disable to isolate concurrency logic
        )
        
        # Start scan in background
        scan_task = asyncio.create_task(scanner.scan(force=True))
        
        # Control network conditions
        print("  0s-10s: Good network (Expect ramp up)")
        scanner.network_condition = "good"
        await asyncio.sleep(10)
        
        print("  10s-20s: Bad network (Expect drop)")
        scanner.network_condition = "bad"
        await asyncio.sleep(10)
        
        print("  20s-30s: Degraded network (Expect stabilization)")
        scanner.network_condition = "degraded"
        await asyncio.sleep(10)
        
        print("  30s+: Good network (Expect recovery)")
        scanner.network_condition = "good"
        
        # Wait for scan to complete
        await scan_task
        
        print(f"  Scan complete. History points: {len(scanner.history)}")
        return scanner.history

    def print_summary(self):
        print(f"\n{'=' * 60}")
        print(f"Benchmark: {self.name}")
        print(f"{'=' * 60}")
        print("Adaptive algorithm data generated.")
        print("See results/adaptive/adaptive_concurrency_results.json for plotting.")
        print(f"{'=' * 60}\n")

async def main():
    benchmark = AdaptiveConcurrencyBenchmark()
    await benchmark.run_benchmark()

if __name__ == "__main__":
    asyncio.run(main())
