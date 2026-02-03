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
from tests.benchmarking.torture.test_malicious_battery import MaliciousInputBenchmark

# Disable caching for torture tests
try:
    from cybersec_cli.core.scan_cache import scan_cache
    if scan_cache:
        scan_cache.clear()
except:
    pass

class FinalBossBenchmark(BaseBenchmark):
    """
    THE FINAL BOSS: Combinatorial Hell.
    Simultaneous activation of all torture conditions.
    """
    def __init__(self):
        super().__init__("The Final Boss: Combinatorial Hell")
        self.mi = MaliciousInputBenchmark() # For inputs

    async def run_benchmark(self):
        print("\n" + "💀" * 30)
        print("THE FINAL BOSS: COMBINATORIAL HELL")
        print("💀" * 30 + "\n")

        # 1. SETUP CHAOS (Network)
        print("🔥 Step 1: Activating Combined Network Chaos...")
        try:
            interface = subprocess.check_output("ip route list default", shell=True).decode().split("dev")[1].split()[0]
            chaos_cmd = f"sudo tc qdisc add dev {interface} root netem delay 100ms 50ms loss 10% corrupt 5% duplicate 5% reorder 25%"
            subprocess.run(chaos_cmd, shell=True)
        except:
            print("  ⚠️ Network chaos setup failed (skipping netem)")
            interface = None

        # 2. SETUP STARVATION (CPU)
        print("🔥 Step 2: Activating CPU Starvation...")
        cpu_stress = subprocess.Popen("stress-ng --cpu 4 --cpu-load 80", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # 3. SETUP COMPONENT FAILURE (Redis)
        print("🔥 Step 3: Starting Component Killer (Redis)...")
        async def redis_killer():
            while True:
                subprocess.run("sudo systemctl stop redis-server || sudo pkill -9 redis-server", shell=True)
                await asyncio.sleep(2)
                subprocess.run("sudo systemctl start redis-server || sudo redis-server --daemonize yes", shell=True)
                await asyncio.sleep(5)

        killer_task = asyncio.create_task(redis_killer())

        # 4. RUN THE SCAN (The Ordeal)
        print("\n" + "⚔️ " * 15)
        print("THE ORDEAL BEGINS")
        print("⚔️ " * 15 + "\n")
        
        target = self.mi.malicious_inputs[0] # Test with malicious input under chaos!
        print(f"  Target: {repr(target)}")
        
        start_time = time.time()
        success = False
        error = None
        
        try:
            scanner = PortScanner(target=target, ports=list(range(1, 100)), timeout=2.0)
            await scanner.scan()
            success = True
            print(f"  SURVIVED! (Graceful rejection/No execution)")
        except ValueError as e:
            success = True
            print(f"  SURVIVED VIA VALIDATION! ({e})")
        except Exception as e:
            error = str(e)
            print(f"  ❌ COLLAPSED: {e}")

        duration = time.time() - start_time

        # 5. CLEANUP
        print("\n🔥 Cleaning up wreckage...")
        killer_task.cancel()
        if interface:
            subprocess.run(f"sudo tc qdisc del dev {interface} root netem", shell=True)
        subprocess.run("pkill -9 stress-ng", shell=True)
        subprocess.run("sudo systemctl start redis-server || sudo redis-server --daemonize yes", shell=True)

        print("\n" + "💀" * 30)
        print("FINAL BOSS RESULT")
        print("💀" * 30)
        print(f"Status: {'✅ BULLETPROOF' if success else '❌ ANNIHILATED'}")
        print(f"Duration: {duration:.2f}s")
        print("💀" * 30 + "\n")
        
        self.results.append({
            "step": "final_boss",
            "success": success,
            "duration": duration,
            "error": error
        })

    def save_results(self, filename=None):
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
    benchmark = FinalBossBenchmark()
    asyncio.run(benchmark.run_benchmark())
    benchmark.save_results()
