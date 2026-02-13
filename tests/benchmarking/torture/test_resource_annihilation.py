import asyncio
import os
import subprocess
import time
import sys
import resource
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

class ResourceAnnihilationBenchmark(BaseBenchmark):
    """
    Brutal benchmark for resource starvation scenarios.
    """
    def __init__(self):
        super().__init__("Resource Annihilation Torture")

    async def run_step(self, name, setup_fn, cleanup_fn, test_fn):
        print(f"\n--- {name} ---")
        if setup_fn:
            setup_fn()
        
        try:
            start_time = time.time()
            result = await test_fn()
            duration = time.time() - start_time
            print(f"  {name} completed in {duration:.4f}s")
            self.results.append({"step": name, "duration": duration, "success": True, "details": result})
        except Exception as e:
            print(f"  ❌ {name} FAILED: {e}")
            self.results.append({"step": name, "success": False, "error": str(e)})
        finally:
            if cleanup_fn:
                cleanup_fn()

    async def run_benchmark(self):
        target = "127.0.0.1"

        # 1. Memory Starvation via stress-ng (easier than systemd-run in this environment)
        async def memory_starvation_test():
            print("  Allocating 1204MB of pressure...")
            stress_proc = subprocess.Popen("stress-ng --vm 1 --vm-bytes 1G", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                # Give some time to allocate
                await asyncio.sleep(2)
                scanner = PortScanner(target=target, ports=list(range(1, 100)), timeout=1.0)
                res = await scanner.scan()
                return f"Scan survived. Results: {len(res)}"
            finally:
                subprocess.run("pkill -9 stress-ng", shell=True)

        await self.run_step("Memory Starvation Simulation", None, None, memory_starvation_test)

        # 2. CPU Starvation
        async def cpu_starvation_test():
            print("  CPU eaters active. Running scan...")
            # Pin cores and load them
            stress_proc = subprocess.Popen("stress-ng --cpu 0 --cpu-load 95", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                await asyncio.sleep(1)
                scanner = PortScanner(target=target, ports=list(range(1, 500)), timeout=1.0)
                res = await scanner.scan()
                return "Scan finished under CPU pressure."
            finally:
                subprocess.run("pkill -9 stress-ng", shell=True)

        await self.run_step("CPU Starvation Simulation", None, None, cpu_starvation_test)

        # 3. File Descriptor Exhaustion
        async def fd_exhaustion_test():
            # Set soft limit
            soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
            print("  Setting FD soft limit to 64...")
            resource.setrlimit(resource.RLIMIT_NOFILE, (64, hard))
            try:
                scanner = PortScanner(target=target, ports=list(range(1, 100)), timeout=0.1)
                res = await scanner.scan()
                return f"Scan survived FD pressure. Results: {len(res)}"
            finally:
                resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))

        await self.run_step("File Descriptor Exhaustion", None, None, fd_exhaustion_test)

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
    benchmark = ResourceAnnihilationBenchmark()
    asyncio.run(benchmark.run_benchmark())
    benchmark.save_results()
