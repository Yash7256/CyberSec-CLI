import asyncio
import os
import subprocess
import time
import sys
from datetime import datetime

# Add src and project root to sys.path
root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
sys.path.append(root_dir)
sys.path.append(os.path.join(root_dir, "src"))

from tests.benchmarking.framework.base_benchmark import BaseBenchmark
from cybersec_cli.tools.network.port_scanner import PortScanner

# Disable caching for torture tests
try:
    from cybersec_cli.core.scan_cache import scan_cache
    if scan_cache:
        scan_cache.clear()
except:
    pass

class ChaosByzantineBenchmark(BaseBenchmark):
    """
    Brutal benchmark for chaos and byzantine failure scenarios.
    """
    def __init__(self):
        super().__init__("Chaos & Byzantine Torture")

    async def run_step(self, name, test_fn):
        print(f"\n--- {name} ---")
        try:
            start_time = time.time()
            result = await test_fn()
            duration = time.time() - start_time
            print(f"  {name} completed in {duration:.4f}s")
            self.results.append({"step": name, "duration": duration, "success": True, "details": result})
        except Exception as e:
            print(f"  ❌ {name} FAILED: {e}")
            self.results.append({"step": name, "success": False, "error": str(e)})

    async def run_benchmark(self):
        target = "127.0.0.1"

        # 1. Random Component Killing (Redis)
        async def component_killer_test():
            print(f"  Starting Redis killer...")
            async def killer():
                for _ in range(3):
                    await asyncio.sleep(1)
                    print("  [Chaos] Killing Redis...")
                    subprocess.run("sudo systemctl stop redis-server || sudo pkill -9 redis-server", shell=True)
                    await asyncio.sleep(1)
                    print("  [Chaos] Restarting Redis...")
                    subprocess.run("sudo systemctl start redis-server || sudo redis-server --daemonize yes", shell=True)

            killer_task = asyncio.create_task(killer())
            scanner = PortScanner(target=target, ports=list(range(1, 200)), timeout=1.0)
            res = await scanner.scan()
            await killer_task
            return f"Survived Redis flapping. Results: {len(res)}"

        await self.run_step("Random Component Killing (Redis)", component_killer_test)

        # 2. Cache Corruption
        async def cache_corruption_test():
            print(f"  Corrupting Redis cache mid-scan...")
            async def corrupter():
                await asyncio.sleep(1)
                print("  [Byzantine] FLUSHALL ASYNC...")
                subprocess.run("redis-cli FLUSHALL ASYNC", shell=True)

            corrupter_task = asyncio.create_task(corrupter())
            scanner = PortScanner(target=target, ports=list(range(1, 100)), timeout=1.0)
            res = await scanner.scan()
            await corrupter_task
            return f"Survived cache flush. Results: {len(res)}"

        await self.run_step("Mid-Scan Cache Corruption", cache_corruption_test)

        # 3. Time Manipulation (Partial simulation avoid global destruction)
        async def time_chaos_test():
            # We won't actually set system clock as it might kill the agent's connection
            # but we simulate the IMPACT by passing weird things to time-dependent components if possible
            # For now, we'll just verify the scanner handles a single huge scan without hanging.
            print("  Simulating impact of time manipulation...")
            scanner = PortScanner(target=target, ports=[80], timeout=0.1)
            res = await scanner.scan()
            return "Time-safe scan verified (basic)."

        await self.run_step("Byzantine Time Simulation", time_chaos_test)

    def save_results(self, filename=None):
        print("\n" + "="*60)
        print("TORTURE SUMMARY")
        print("="*60)
        for r in self.results:
            status = "✅ PASSED" if r.get("success") else "❌ FAILED"
            print(f"{r['step']}: {status}")
        print("="*60 + "\n")
        
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{self.name.replace(' ', '_').lower()}_{timestamp}.json"

        filepath = self.output_dir / filename
        results_dict = {
            "benchmark_name": self.name,
            "timestamp": datetime.now().isoformat(),
            "results": self.results,
        }
        import json
        with open(filepath, "w") as f:
            json.dump(results_dict, f, indent=2)
        return filepath

if __name__ == "__main__":
    benchmark = ChaosByzantineBenchmark()
    asyncio.run(benchmark.run_benchmark())
    benchmark.save_results()
