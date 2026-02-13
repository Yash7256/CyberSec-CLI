"""
Comparative benchmark: CyberSec-CLI vs Nmap.
Tests performance, accuracy, and feature parity.
"""

import asyncio
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, Tuple

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from tests.benchmarking.framework.base_benchmark import ComparativeBenchmark


class NmapComparison(ComparativeBenchmark):
    """
    Compare CyberSec-CLI against Nmap.
    
    Tests:
    - Speed comparison (all timing templates T0-T5)
    - Accuracy comparison
    - Resource usage
    - Feature parity
    """

    def __init__(self):
        """Initialize Nmap comparison benchmark."""
        super().__init__("nmap_comparison", "nmap", "tests/benchmarking/results/comparative")
        self.nmap_available = self._check_nmap_available()

    def _check_nmap_available(self) -> bool:
        """Check if Nmap is installed."""
        try:
            result = subprocess.run(
                ["nmap", "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    async def _run_cybersec_scan(
        self, target: str, ports: str, timeout: float = 1.0
    ) -> Tuple[float, Dict]:
        """
        Run CyberSec-CLI scan.
        
        Args:
            target: Target to scan
            ports: Port specification
            timeout: Timeout per port
            
        Returns:
            Tuple of (duration, results)
        """
        try:
            from cybersec_cli.tools.network.port_scanner import PortScanner

            # Parse port range
            if "-" in ports:
                start, end = map(int, ports.split("-"))
                port_list = list(range(start, end + 1))
            else:
                port_list = [int(p) for p in ports.split(",")]

            start_time = time.time()

            scanner = PortScanner(
                target=target,
                ports=port_list,
                timeout=timeout,
                max_concurrent=20,
            )
            results = await scanner.scan()

            duration = time.time() - start_time

            # Convert results to standard format
            open_ports = []
            if isinstance(results, list):
                for res in results:
                    # Handle both objects and dictionaries (cached results)
                    if hasattr(res, "state"):
                        if str(res.state.value) == "open":
                            open_ports.append(res.port)
                    elif isinstance(res, dict):
                        if res.get("state") == "open":
                            open_ports.append(res.get("port"))

            return duration, {"open_ports": open_ports}

        except ImportError:
            # Mock for testing
            await asyncio.sleep(1.0)
            return 1.0, {"open_ports": []}

    def _run_nmap_scan(
        self, target: str, ports: str, timing: str = "T3"
    ) -> Tuple[float, Dict]:
        """
        Run Nmap scan.
        
        Args:
            target: Target to scan
            ports: Port specification
            timing: Timing template (T0-T5)
            
        Returns:
            Tuple of (duration, results)
        """
        if not self.nmap_available:
            return 0, {"error": "Nmap not available"}

        try:
            start_time = time.time()

            # Run Nmap
            result = subprocess.run(
                [
                    "nmap",
                    "-p", ports,
                    f"-{timing}",
                    "-oX", "-",  # XML output to stdout
                    target,
                ],
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout
            )

            duration = time.time() - start_time

            # Parse results
            open_ports = []
            if result.returncode == 0:
                # Simple regex parsing of XML output
                port_pattern = r'<port protocol="tcp" portid="(\d+)"><state state="open"'
                matches = re.findall(port_pattern, result.stdout)
                open_ports = [int(p) for p in matches]

            return duration, {"open_ports": open_ports, "raw_output": result.stdout}

        except subprocess.TimeoutExpired:
            return 0, {"error": "Timeout"}
        except Exception as e:
            return 0, {"error": str(e)}

    async def benchmark_speed_comparison(
        self, target: str = "127.0.0.1", ports: str = "1-100"
    ) -> Dict:
        """
        Compare scan speed between CyberSec-CLI and Nmap.
        
        Args:
            target: Target to scan
            ports: Port range
            
        Returns:
            Dictionary with comparison results
        """
        print(f"Benchmarking speed comparison: {target} ports {ports}")

        results = {}

        # CyberSec-CLI scan
        print("  Running CyberSec-CLI scan...")
        cybersec_duration, cybersec_results = await self._run_cybersec_scan(target, ports)

        cybersec_metrics = await self.run_with_metrics(
            lambda: None,  # Already ran the scan
            operations=1,
            metadata={"tool": "cybersec_cli", "target": target, "ports": ports},
        )
        cybersec_metrics.duration = cybersec_duration

        self.add_comparison_result("cybersec_cli", cybersec_metrics)

        results["cybersec_cli"] = {
            "duration": cybersec_duration,
            "open_ports_found": len(cybersec_results.get("open_ports", [])),
        }

        # Nmap scans with different timing templates
        # Expanded for IEEE paper requirements (T0-T5)
        timing_templates = ["T0", "T1", "T2", "T3", "T4", "T5"]

        for timing in timing_templates:
            print(f"  Running Nmap scan ({timing})...")
            # For T0/T1, we reduce port count significantly as they are extremely slow
            scan_ports = ports
            if timing in ["T0", "T1"]:
                 # Just scan top 5 ports for very slow modes to avoid 24h+ execution
                 print(f"    Note: Limiting {timing} scan to 5 ports for feasibility")
                 if "-" in ports: 
                    # Assuming format "1-100". Take first 5.
                    start = int(ports.split("-")[0])
                    scan_ports = f"{start}-{start+4}"
                 else:
                    # Comma separated
                    p_list = ports.split(",")
                    scan_ports = ",".join(p_list[:5])


            nmap_duration, nmap_results = self._run_nmap_scan(target, scan_ports, timing)

            if "error" in nmap_results:
                print(f"    Nmap {timing} error: {nmap_results['error']}")
                continue

            nmap_metrics = await self.run_with_metrics(
                lambda: None,
                operations=1,
                metadata={"tool": f"nmap_{timing}", "target": target, "ports": ports},
            )
            nmap_metrics.duration = nmap_duration

            self.add_comparison_result("nmap", nmap_metrics)

            results[f"nmap_{timing}"] = {
                "duration": nmap_duration,
                "open_ports_found": len(nmap_results.get("open_ports", [])),
            }

        return results

    async def benchmark_network_conditions(self) -> Dict:
        """
        Compare performance under simulated network conditions (Table I).
        Requires 'tc' (traffic control) and sudo privileges.
        """
        print("\nBenchmarking Network Conditions (Table I)...")
        conditions = [
            ("Ideal", None, None), 
            ("Good", "5ms", None),
            ("Degraded", "50ms", None), 
            ("Poor", "100ms", None),
            ("Packet Loss", "5ms", "5%")
        ]
        
        target = "127.0.0.1" 
        ports = "1-100"
        results = {}

        for name, latency, loss in conditions:
            print(f"\nCondition: {name} (Latency: {latency}, Loss: {loss})")
            
            # Apply network conditions (using sudo tc)
            # CAUTION: This might fail without passwordless sudo
            try:
                if latency or loss:
                    cmd = ["sudo", "tc", "qdisc", "add", "dev", "lo", "root", "netem"]
                    if latency:
                        cmd.extend(["delay", latency])
                    if loss:
                        cmd.extend(["loss", loss])
                    
                    subprocess.run(cmd, check=True, capture_output=True)
            except Exception as e:
                print(f"  Warning: Failed to apply network conditions (sudo required): {e}")
                print("  Skipping restricted tests...")
                # We can't proceed with meaningful data for this condition if setup failed
                # But we can run 'Ideal' (no condition) or fallback
                if name != "Ideal":
                    continue

            try:
                # Run CyberSec-CLI
                print("  Running CyberSec-CLI...")
                cs_dur, _ = await self._run_cybersec_scan(target, ports)
                
                # Run Nmap (T3, T4)
                print("  Running Nmap T3...")
                n3_dur, _ = self._run_nmap_scan(target, ports, "T3")
                
                print("  Running Nmap T4...")
                n4_dur, _ = self._run_nmap_scan(target, ports, "T4")
                
                results[name] = {
                    "cybersec": cs_dur,
                    "nmap_t3": n3_dur,
                    "nmap_t4": n4_dur
                }
                
            finally:
                # Clean up network conditions
                if latency or loss:
                    try:
                        subprocess.run(["sudo", "tc", "qdisc", "del", "dev", "lo", "root"], 
                                      capture_output=True)
                    except:
                        pass
        
        return results

    async def benchmark_accuracy_comparison(
        self, target: str = "scanme.nmap.org", ports: str = "1-1000"
    ) -> Dict:
        """
        Compare accuracy between tools.
        
        Args:
            target: Target to scan (should be a known test target)
            ports: Port range
            
        Returns:
            Dictionary with accuracy comparison
        """
        print(f"Benchmarking accuracy: {target} ports {ports}")
        print("  Note: Using scanme.nmap.org as reference target")

        # Run both scans
        print("  Running CyberSec-CLI scan...")
        _, cybersec_results = await self._run_cybersec_scan(target, ports, timeout=2.0)
        cybersec_ports = set(cybersec_results.get("open_ports", []))

        print("  Running Nmap scan...")
        _, nmap_results = self._run_nmap_scan(target, ports, "T4")
        nmap_ports = set(nmap_results.get("open_ports", []))

        # Calculate accuracy metrics
        if not nmap_ports:
            print("  Warning: Nmap found no open ports (may not be available)")
            return {"error": "Nmap scan failed or found no ports"}

        # Use Nmap as ground truth
        true_positives = len(cybersec_ports & nmap_ports)
        false_positives = len(cybersec_ports - nmap_ports)
        false_negatives = len(nmap_ports - cybersec_ports)

        precision = (
            true_positives / (true_positives + false_positives)
            if (true_positives + false_positives) > 0
            else 0
        )
        recall = (
            true_positives / (true_positives + false_negatives)
            if (true_positives + false_negatives) > 0
            else 0
        )
        f1_score = (
            2 * (precision * recall) / (precision + recall)
            if (precision + recall) > 0
            else 0
        )

        return {
            "cybersec_ports_found": len(cybersec_ports),
            "nmap_ports_found": len(nmap_ports),
            "true_positives": true_positives,
            "false_positives": false_positives,
            "false_negatives": false_negatives,
            "precision": precision,
            "recall": recall,
            "f1_score": f1_score,
            "accuracy": (
                (true_positives) / len(nmap_ports) if nmap_ports else 0
            ),
        }

    async def run_benchmark(self) -> Dict:
        """Run all Nmap comparison benchmarks."""
        print("\n" + "=" * 60)
        print("Nmap Comparison Benchmark Suite")
        print("=" * 60 + "\n")

        if not self.nmap_available:
            print("⚠ Nmap is not installed. Install with:")
            print("  sudo apt-get install nmap  (Debian/Ubuntu)")
            print("  sudo yum install nmap      (RHEL/CentOS)")
            print("  brew install nmap          (macOS)")
            print("\nSkipping Nmap comparison benchmarks.\n")
            return {"error": "Nmap not available"}

        results = {}

        # Speed comparison on localhost
        print("1. Speed Comparison (localhost, ports 1-100)")
        results["speed_local"] = await self.benchmark_speed_comparison(
            "127.0.0.1", "1-100"
        )
        print()

        # Speed comparison with larger range
        print("2. Speed Comparison (localhost, ports 1-1000)")
        results["speed_local_large"] = await self.benchmark_speed_comparison(
            "127.0.0.1", "1-1000"
        )
        print()

        # Network Conditions (Table I)
        results["network_conditions"] = await self.benchmark_network_conditions()
        print()

        # Accuracy comparison (requires internet)
        print("3. Accuracy Comparison (scanme.nmap.org)")
        print("   Note: This requires internet connection")
        try:
            results["accuracy"] = await self.benchmark_accuracy_comparison()
            print()
        except Exception as e:
            print(f"   Accuracy test failed: {e}")
            results["accuracy"] = {"error": str(e)}

        # Print comparison summary
        self.print_comparison()

        # Save results
        filepath = self.save_results("nmap_comparison_results.json")
        print(f"\n✓ Results saved to: {filepath}")

        return results


async def main():
    """Run the Nmap comparison benchmark suite."""
    benchmark = NmapComparison()
    results = await benchmark.run_benchmark()

    print("\n" + "=" * 60)
    print("Benchmark Complete!")
    print("=" * 60)

    return results


if __name__ == "__main__":
    asyncio.run(main())
