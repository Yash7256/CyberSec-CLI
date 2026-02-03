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

class NetworkWarfareBenchmark(BaseBenchmark):
    """
    Brutal benchmark for hostile network conditions.
    """
    def __init__(self):
        super().__init__("Hostile Network Warfare Torture")
        self.interface = self._get_default_interface()

    def _get_default_interface(self):
        try:
            res = subprocess.check_output("ip route list default", shell=True).decode()
            return res.split("dev")[1].split()[0]
        except:
            return "eth0"

    async def run_step(self, name, cmd_setup, cmd_cleanup, test_fn):
        print(f"\n--- {name} ---")
        if cmd_setup:
            print(f"  Executing: {cmd_setup}")
            subprocess.run(f"sudo {cmd_setup}", shell=True, check=True)
        
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
            if cmd_cleanup:
                subprocess.run(f"sudo {cmd_cleanup}", shell=True)

    async def run_benchmark(self):
        target = "127.0.0.1"
        
        # 1. SYN Flood Survival
        async def syn_flood_test():
            print(f"  Scanning {target} while being flooded...")
            # Start flood in background
            flood_proc = subprocess.Popen(f"sudo hping3 -S --flood -p 80 {target}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                scanner = PortScanner(target=target, ports=[80, 443, 22], timeout=1.0)
                res = await scanner.scan()
                return f"Results found: {len(res)}"
            finally:
                subprocess.run(f"sudo pkill -9 hping3", shell=True)

        await self.run_step("Active Attack Simulation (SYN Flood)", None, None, syn_flood_test)

        # 2. Combined Chaos (Netem)
        async def chaos_test():
            print(f"  Chaos enabled. Running scan...")
            scanner = PortScanner(target=target, ports=list(range(1, 81)), timeout=2.0)
            res = await scanner.scan()
            return f"Results: {len(res)}"

        chaos_cmd = f"tc qdisc add dev {self.interface} root netem delay 100ms 50ms loss 10% corrupt 5% duplicate 5% reorder 25%"
        cleanup_cmd = f"tc qdisc del dev {self.interface} root netem"
        await self.run_step("Combined Chaos Netem Torture", chaos_cmd, cleanup_cmd, chaos_test)

        # 3. Network Flapping
        async def flapping_test():
            print(f"  Starting scan while network flaps...")
            
            async def flapper():
                for _ in range(5):
                    subprocess.run("sudo iptables -A OUTPUT -d 127.0.0.1 -j DROP", shell=True)
                    print("  [Flap] Network DOWN")
                    await asyncio.sleep(0.5)
                    subprocess.run("sudo iptables -D OUTPUT -d 127.0.0.1 -j DROP", shell=True)
                    print("  [Flap] Network UP")
                    await asyncio.sleep(0.5)

            flapper_task = asyncio.create_task(flapper())
            scanner = PortScanner(target=target, ports=list(range(1, 200)), timeout=1.0)
            res = await scanner.scan()
            await flapper_task
            return f"Results: {len(res)}"

        await self.run_step("Network Flapping Torture", None, "iptables -D OUTPUT -d 127.0.0.1 -j DROP", flapping_test)

    def save_results(self, filename=None):
        # Specific override for torture reporting
        print("\n" + "="*60)
        print("TORTURE SUMMARY")
        print("="*60)
        for r in self.results:
            status = "✅ PASSED" if r.get("success") else "❌ FAILED"
            print(f"{r['step']}: {status}")
        print("="*60 + "\n")
        
        # Manually save to avoid BaseBenchmark.save_results trying to call .to_dict() on dicts
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
    benchmark = NetworkWarfareBenchmark()
    asyncio.run(benchmark.run_benchmark())
    benchmark.save_results()
