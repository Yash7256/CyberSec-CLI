"""
CLI Fuzzing Benchmark.
Tests tool robustness against malformed CLI arguments and inputs.
"""

import asyncio
import sys
import random
import string
from pathlib import Path
from typing import Dict

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from tests.benchmarking.framework.base_benchmark import BaseBenchmark

class FuzzingBenchmark(BaseBenchmark):
    """
    Benchmark to fuzz the CLI interface.
    
    Tests:
    - Random garbage arguments
    - Extremely long argument strings
    - SQL injection patterns in target fields
    - Malformed IP addresses
    """

    def __init__(self):
        """Initialize fuzzing benchmark."""
        super().__init__("cli_fuzzing", "tests/benchmarking/results/security")
        self.cli_path = [sys.executable, "-m", "cybersec_cli.main"]

    def _generate_garbage(self, length: int = 100) -> str:
        """Generate random garbage string."""
        return ''.join(random.choice(string.printable) for _ in range(length))

    async def benchmark_cli_robustness(self, iterations: int = 20) -> Dict:
        """
        Fuzz the CLI with random arguments.
        
        Args:
            iterations: Number of fuzzing attempts
            
        Returns:
            Dictionary with fuzzing results
        """
        print(f"Fuzzing CLI with {iterations} random garbage inputs...")
        results = {}
        
        crashes = 0
        handled_errors = 0
        
        for i in range(iterations):
            # Generate random garbage args
            fuzz_arg = self._generate_garbage(random.randint(10, 1000))
            
            # Construct command: python -m cybersec_cli.main [GARBAGE]
            cmd = self.cli_path + [fuzz_arg]
            
            start_time = asyncio.get_event_loop().time()
            
            try:
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await process.communicate()
                exit_code = process.returncode
                
            except Exception as e:
                exit_code = -1
                stderr = str(e).encode()

            duration = asyncio.get_event_loop().time() - start_time
            
            # Categorize result
            # 0: Success (Unexpected for garbage)
            # 1: Error (Expected)
            # 2: Argument Error (Expected)
            # < 0: Crash/Signal (BAD)
            
            status = "UNKNOWN"
            if exit_code in [1, 2]:
                status = "HANDLED"
                handled_errors += 1
            elif exit_code == 0:
                status = "SUCCESS_UNEXPECTED"
            else:
                status = "CRASH"
                crashes += 1
                print(f"  [CRASH] Input len {len(fuzz_arg)} caused exit code {exit_code}")

            results[f"fuzz_{i}"] = {
                "input_length": len(fuzz_arg),
                "exit_code": exit_code,
                "status": status,
                "duration": duration
            }
            
            # Don't print every iteration to keep output clean, just every 5
            if (i+1) % 5 == 0:
                print(f"  Iteration {i+1}: {status}")

        print(f"  Robustness Result: {crashes} crashes in {iterations} attempts.")
        return {
            "crashes": crashes,
            "handled_errors": handled_errors,
            "iterations": iterations,
            "details": results
        }

    async def benchmark_target_fuzzing(self) -> Dict:
        """
        Fuzz the target argument specifically with common attack vectors.
        """
        print("\nFuzzing Target Argument with Attack Vectors...")
        
        vectors = [
            "' OR '1'='1",
            "; ls -la",
            "$(reboot)",
            "1.2.3.4.5", # Invalid IP
            "999.999.999.999",
            "http://example.com/ malicious",
            "A" * 5000 # Buffer overflow attempt
        ]
        
        results = {}
        crashes = 0
        
        for vector in vectors:
            # cmd: python -m cybersec_cli.main scan -t [VECTOR]
            # Assuming 'scan' subcommand and '-t' or target pos arg
            cmd = self.cli_path + ["scan", "-t", vector]
            
            try:
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await process.communicate()
                exit_code = process.returncode
            except Exception:
                exit_code = -1
            
            status = "HANDLED" if exit_code in [1, 2] else "CRASH" if exit_code != 0 else "ACCEPTED"
            
            if status == "CRASH": 
                crashes += 1
                
            results[vector[:20]] = {
                "vector": vector,
                "exit_code": exit_code,
                "status": status
            }
            print(f"  Vector '{vector[:20]}...': {status} (Exit {exit_code})")

        return {"crashes": crashes, "details": results}

    async def run_benchmark(self) -> Dict:
        """Run all fuzzing benchmarks."""
        print("\n" + "=" * 60)
        print("CLI Fuzzing Benchmark Suite")
        print("=" * 60 + "\n")

        results = {}
        
        results["cli_random"] = await self.benchmark_cli_robustness()
        results["target_vectors"] = await self.benchmark_target_fuzzing()

        # Save results
        filepath = self.save_results("cli_fuzzing_results.json")
        print(f"\n✓ Results saved to: {filepath}")

        self.print_summary()
        return results

    def print_summary(self):
        """Print summary of fuzzing results."""
        print("\n" + "=" * 60)
        print("Fuzzing Summary")
        print("=" * 60)
        print("See detailed JSON output for crash reports.")
        print("=" * 60)


async def main():
    """Run the fuzzing benchmark suite."""
    benchmark = FuzzingBenchmark()
    await benchmark.run_benchmark()

if __name__ == "__main__":
    asyncio.run(main())
