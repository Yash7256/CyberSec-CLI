"""
CLI UX Audit Benchmark.
Automates verification of help-text consistency and error clarity across CLI commands.
Generates data for Section 10 of the IEEE paper.
"""

import sys
import subprocess
import asyncio
from typing import Dict, List
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from tests.benchmarking.framework.base_benchmark import BaseBenchmark

class CLIUXBenchmark(BaseBenchmark):
    """
    Benchmark to audit CLI usability and error handling.
    """

    def __init__(self):
        super().__init__("cli_ux", "tests/benchmarking/results/ux")
        self.cli_path = "cybersec" # Assuming it's installed or available as an entry point

    def _run_cmd(self, args: List[str]) -> subprocess.CompletedProcess:
        """Helper to run CLI command."""
        try:
            return subprocess.run(
                ["python3", "-m", "cybersec_cli.main"] + args,
                capture_output=True,
                text=True,
                timeout=10
            )
        except subprocess.TimeoutExpired:
            return subprocess.CompletedProcess(args, -1, "", "Timeout")

    async def benchmark_help_consistency(self) -> Dict:
        """
        Check if all major commands have consistent and informative help text.
        """
        print("\nAuditing CLI Help-Text Consistency...")
        commands = [
            [], # Root
            ["scan"],
            ["ai"],
            ["results"],
            ["config"]
        ]
        
        results = []
        for cmd in commands:
            name = " ".join(cmd) if cmd else "root"
            print(f"  Checking '{name}' --help...")
            cp = self._run_cmd(cmd + ["--help"])
            
            has_help = "usage:" in cp.stdout.lower() or "options:" in cp.stdout.lower()
            word_count = len(cp.stdout.split())
            
            results.append({
                "command": name,
                "exit_code": cp.returncode,
                "informative": has_help and word_count > 20,
                "word_count": word_count
            })
            
        success_rate = sum(1 for r in results if r["informative"]) / len(results)
        return {
            "commands_checked": len(commands),
            "success_rate": success_rate,
            "details": results
        }

    async def benchmark_error_clarity(self) -> Dict:
        """
        Check if invalid inputs trigger helpful hints.
        """
        print("\nAuditing CLI Error Clarity...")
        scenarios = [
            {"args": ["scan", "--target", "invalid_ip"], "expected_hint": "invalid"},
            {"args": ["scan", "--ports", "99999"], "expected_hint": "port"},
            {"args": ["ai", "nonexistent_result"], "expected_hint": "not found"}
        ]
        
        results = []
        for s in scenarios:
            print(f"  Testing invalid input: {' '.join(s['args'])}...")
            cp = self._run_cmd(s["args"])
            
            # We expect a non-zero exit code and a hint in stderr
            has_hint = s["expected_hint"].lower() in cp.stderr.lower() or s["expected_hint"].lower() in cp.stdout.lower()
            
            results.append({
                "args": s["args"],
                "exit_code": cp.returncode,
                "has_hint": has_hint,
                "stderr_snippet": cp.stderr[:100].replace("\n", " ")
            })
            
        clarity_score = sum(1 for r in results if r["has_hint"]) / len(results)
        return {
            "scenarios_tested": len(scenarios),
            "clarity_score": clarity_score,
            "details": results
        }

    async def run_benchmark(self) -> Dict:
        """Run all Phase 18 UX benchmarks."""
        print("\n" + "=" * 60)
        print("CLI UX Audit Suite")
        print("=" * 60)
        
        results = {}
        results["help_consistency"] = await self.benchmark_help_consistency()
        results["error_clarity"] = await self.benchmark_error_clarity()

        # Save results
        import json
        self.results = results
        filepath = self.output_dir / "cli_ux_results.json"
        with open(filepath, "w") as f:
            json.dump(results, f, indent=2)
            
        print(f"\n✓ Results saved to: {filepath}")

        self.print_summary()
        return results

    def print_summary(self):
        """Print summary."""
        print("\n" + "=" * 60)
        print("CLI UX Summary")
        print("=" * 60)
        print("Verified help-text consistency and error message clarity.")
        print("=" * 60)

async def main():
    """Run the benchmark."""
    benchmark = CLIUXBenchmark()
    await benchmark.run_benchmark()

if __name__ == "__main__":
    asyncio.run(main())
