"""
Real Accuracy Benchmark for CyberSec-CLI.
Generates data for Table II: Accuracy Metrics.
Scans scanme.nmap.org and compares with Nmap ground truth.
"""

import asyncio
import json
import sys
import subprocess
import re
import time
from pathlib import Path
from typing import Dict, List, Set, Tuple

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from tests.benchmarking.framework.base_benchmark import BaseBenchmark
from cybersec_cli.tools.network.port_scanner import PortScanner, PortState

class RealAccuracyBenchmark(BaseBenchmark):
    """
    Benchmark accuracy against real internet targets.
    """

    def __init__(self):
        super().__init__("real_accuracy", "tests/benchmarking/results/accuracy")
        self.target = "scanme.nmap.org"
        # Use top 100 ports for speed, or 1000 for better coverage
        self.ports = list(range(1, 1001)) 
        self.port_str = "1-1000"

    async def run_benchmark(self) -> Dict:
        print("\n" + "=" * 60)
        print("Real Accuracy Benchmark (Table II)")
        print(f"Target: {self.target}")
        print("=" * 60 + "\n")

        results = {}

        # 1. Establish Ground Truth (Nmap)
        print(f"1. Establishing Ground Truth (Nmap {self.port_str})...")
        nmap_ports = self._get_nmap_ground_truth()
        results["nmap_open_ports"] = list(nmap_ports)
        print(f"   Nmap found {len(nmap_ports)} open ports: {sorted(list(nmap_ports))}")

        if not nmap_ports:
            print("⚠ Warning: Nmap found no ports. Check internet connection.")
            # Continue anyway to see if we find anything (false positives?)

        # 2. Run CyberSec-CLI Scan
        print(f"\n2. Running CyberSec-CLI Scan ({self.port_str})...")
        cybersec_ports, duration = await self._run_cybersec_scan()
        results["cybersec_open_ports"] = list(cybersec_ports)
        results["scan_duration"] = duration
        print(f"   CyberSec-CLI found {len(cybersec_ports)} open ports: {sorted(list(cybersec_ports))}")
        print(f"   Duration: {duration:.2f}s")

        # 3. Calculate Metrics
        print("\n3. Calculating Accuracy Metrics...")
        metrics = self._calculate_metrics(nmap_ports, cybersec_ports)
        results["metrics"] = metrics
        
        self._print_metrics(metrics)

        # Save results
        filepath = self.output_dir / "real_accuracy_results.json"
        with open(filepath, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\n✓ Results saved to: {filepath}")

        return results

    def _get_nmap_ground_truth(self) -> Set[int]:
        """Run Nmap to get ground truth open ports."""
        try:
            # -Pn: Treat host as online
            # -n: No DNS resolution
            # -T4: Aggressive timing
            cmd = ["nmap", "-p", self.port_str, "-n", "-Pn", "-T4", "-oX", "-", self.target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode != 0:
                print(f"Error running Nmap: {result.stderr}")
                return set()

            # Parse XML output
            port_pattern = r'<port protocol="tcp" portid="(\d+)"><state state="open"'
            matches = re.findall(port_pattern, result.stdout)
            return set(int(p) for p in matches)
            
        except Exception as e:
            print(f"Exception running Nmap: {e}")
            return set()

    async def _run_cybersec_scan(self) -> Tuple[Set[int], float]:
        """Run CyberSec-CLI scan."""
        start_time = time.time()
        
        scanner = PortScanner(
            target=self.target,
            ports=self.ports,
            timeout=2.0,
            max_concurrent=100,
            service_detection=False # Focus on port state accuracy first
        )
        # Force bypass cache for accuracy test
        results = await scanner.scan(force=True)
        
        duration = time.time() - start_time
        
        open_ports = set()
        for res in results:
            if res.state == PortState.OPEN:
                open_ports.add(res.port)
                
        return open_ports, duration

    def _calculate_metrics(self, ground_truth: Set[int], detected: Set[int]) -> Dict:
        """Calculate Precision, Recall, F1."""
        tp = len(ground_truth & detected)
        fp = len(detected - ground_truth)
        fn = len(ground_truth - detected)
        
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        
        return {
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "precision": precision,
            "recall": recall,
            "f1_score": f1
        }

    def _print_metrics(self, metrics: Dict):
        print("-" * 40)
        print(f"True Positives:  {metrics['true_positives']}")
        print(f"False Positives: {metrics['false_positives']}")
        print(f"False Negatives: {metrics['false_negatives']}")
        print("-" * 40)
        print(f"Precision: {metrics['precision']:.4f}")
        print(f"Recall:    {metrics['recall']:.4f}")
        print(f"F1 Score:  {metrics['f1_score']:.4f}")
        print("-" * 40)

def main():
    benchmark = RealAccuracyBenchmark()
    asyncio.run(benchmark.run_benchmark())

if __name__ == "__main__":
    main()
