"""
CPU Profiling Benchmark.
Tests CPU usage patterns and identifies hotspots.
"""

import asyncio
import cProfile
import pstats
import io
import sys
import time
import psutil
from pathlib import Path
from typing import Dict, List

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from tests.benchmarking.framework.base_benchmark import BaseBenchmark

class CpuProfilingBenchmark(BaseBenchmark):
    """
    Benchmark to profile CPU usage.
    
    Tests:
    - Idle CPU usage
    - Load CPU usage (scan 1000 ports)
    - Hotspot analysis (cProfile)
    """

    def __init__(self):
        """Initialize CPU profiling benchmark."""
        super().__init__("cpu_profiling", "tests/benchmarking/results/resource")
        self.process = psutil.Process()

    async def benchmark_idle_usage(self, duration: int = 5) -> Dict:
        """
        Measure CPU usage when idle.
        
        Args:
            duration: measure duration in seconds
        """
        print(f"Benchmarking idle CPU usage for {duration}s...")
        
        # Reset CPU counter
        self.process.cpu_percent()
        
        start_time = time.time()
        cpu_readings = []
        
        while time.time() - start_time < duration:
            await asyncio.sleep(0.1)
            cpu = self.process.cpu_percent()
            cpu_readings.append(cpu)
            
        avg_cpu = sum(cpu_readings) / len(cpu_readings) if cpu_readings else 0
        max_cpu = max(cpu_readings) if cpu_readings else 0
        
        print(f"  Idle CPU: Avg {avg_cpu:.1f}%, Max {max_cpu:.1f}%")
        
        return {
            "avg_cpu_percent": avg_cpu,
            "max_cpu_percent": max_cpu,
            "samples": len(cpu_readings)
        }

    async def benchmark_load_usage(self) -> Dict:
        """
        Measure CPU usage under load (scanning).
        """
        print("Benchmarking CPU usage under load...")
        
        from cybersec_cli.tools.network.port_scanner import PortScanner
        
        # Reset CPU counter
        self.process.cpu_percent()
        
        cpu_readings = []
        scanning = True
        
        async def monitor_cpu():
            while scanning:
                cpu = self.process.cpu_percent(interval=0.1)
                cpu_readings.append(cpu)
                await asyncio.sleep(0.01) # fast sample
        
        # Start monitoring task
        monitor_task = asyncio.create_task(monitor_cpu())
        
        target = "127.0.0.1" # Use localhost for speed/CPU focus
        ports = list(range(1, 1001)) # 1000 ports
        
        start_time = time.time()
        
        try:
            scanner = PortScanner(
                target=target,
                ports=ports,
                timeout=0.1,
                max_concurrent=50
            )
            await scanner.scan()
        finally:
            scanning = False
            await monitor_task
            
        duration = time.time() - start_time
        avg_cpu = sum(cpu_readings) / len(cpu_readings) if cpu_readings else 0
        max_cpu = max(cpu_readings) if cpu_readings else 0
        
        print(f"  Load CPU: Avg {avg_cpu:.1f}%, Max {max_cpu:.1f}% over {duration:.2f}s")
        
        return {
             "avg_cpu_percent": avg_cpu,
             "max_cpu_percent": max_cpu,
             "duration": duration,
             "ports_scanned": 1000
        }

    async def benchmark_hotspots(self) -> Dict:
        """
        Identify CPU hotspots using cProfile.
        """
        print("Identifying CPU hotspots...")
        
        pr = cProfile.Profile()
        pr.enable()
        
        # Run a short intensive scan
        from cybersec_cli.tools.network.port_scanner import PortScanner
        scanner = PortScanner(
            target="127.0.0.1",
            ports=list(range(1, 10001)), 
            timeout=0.01,
            max_concurrent=50
        )
        await scanner.scan()
        
        pr.disable()
        
        s = io.StringIO()
        sortby = 'cumulative'
        ps = pstats.Stats(pr, stream=s).sort_stats(sortby)
        ps.print_stats(20) # Top 20 functions
        
        print(s.getvalue())
        
        return {
            "profile_output": s.getvalue()
        }

    async def run_benchmark(self) -> Dict:
        """Run all CPU profiling benchmarks."""
        print("\n" + "=" * 60)
        print("CPU Profiling Suite")
        print("=" * 60 + "\n")

        results = {}
        results["idle"] = await self.benchmark_idle_usage()
        results["load"] = await self.benchmark_load_usage()
        results["hotspots"] = await self.benchmark_hotspots()
        
        self.results = results
        
        # Save results
        filepath = self.save_results("cpu_profiling_results.json")
        print(f"\n✓ Results saved to: {filepath}")

        self.print_summary()
        return results
    
    def save_results(self, filename: str) -> Path:
        """Override save_results to handle custom dictionary."""
        filepath = self.output_dir / filename
        import json
        with open(filepath, "w") as f:
            json.dump(self.results, f, indent=2)
        return filepath
    
    def print_summary(self):
        """Print summary manually to avoid KeyError if metrics missing."""
        print("\n" + "=" * 60)
        print("CPU Profiling Summary")
        print("=" * 60)
        print("Refer to output log for cProfile data.")
        print("=" * 60)

async def main():
    """Run the CPU profiling benchmark suite."""
    benchmark = CpuProfilingBenchmark()
    await benchmark.run_benchmark()

if __name__ == "__main__":
    asyncio.run(main())
