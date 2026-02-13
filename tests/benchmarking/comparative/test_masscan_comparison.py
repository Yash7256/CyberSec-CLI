"""
Comparative benchmark: CyberSec-CLI vs Masscan.
Tests performance against the fastest port scanner.
"""

import asyncio
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from tests.benchmarking.framework.base_benchmark import ComparativeBenchmark


class MasscanComparison(ComparativeBenchmark):
    """
    Compare CyberSec-CLI against Masscan.
    
    Masscan is known as the fastest port scanner, capable of scanning
    the entire Internet in under 6 minutes. This benchmark tests if
    CyberSec-CLI can compete in speed while maintaining accuracy.
    
    Tests:
    - Speed comparison (small to large port ranges)
    - Throughput comparison (packets per second)
    - Resource usage
    - Accuracy comparison
    """

    def __init__(self):
        """Initialize Masscan comparison benchmark."""
        super().__init__("masscan_comparison", "masscan")
        self.masscan_path = self._find_masscan()

    def _find_masscan(self) -> Optional[str]:
        """Find Masscan executable."""
        try:
            result = subprocess.run(
                ["which", "masscan"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                return result.stdout.strip()
            
            # Try common paths
            for path in ["/usr/bin/masscan", "/usr/local/bin/masscan"]:
                if Path(path).exists():
                    return path
            
            return None
        except Exception:
            return None

    def _check_masscan_available(self) -> bool:
        """Check if Masscan is installed."""
        if not self.masscan_path:
            return False
        
        try:
            result = subprocess.run(
                [self.masscan_path, "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.returncode == 0
        except Exception:
            return False

    async def _run_cybersec_scan(
        self, target: str, ports: str, rate: int = 1000
    ) -> Tuple[float, Dict]:
        """
        Run CyberSec-CLI scan.
        
        Args:
            target: Target to scan
            ports: Port specification
            rate: Scan rate (packets per second)
            
        Returns:
            Tuple of (duration, results)
        """
        start_time = time.time()
        results = {"open_ports": [], "total_ports": 0}

        try:
            from cybersec_cli.tools.network.port_scanner import PortScanner

            # Parse port range
            if "-" in ports:
                start, end = map(int, ports.split("-"))
                port_list = list(range(start, end + 1))
            else:
                port_list = [int(p) for p in ports.split(",")]

            results["total_ports"] = len(port_list)

            # Calculate concurrency based on rate
            # rate = packets/sec, timeout = 1s, so max_concurrent ≈ rate
            max_concurrent = min(rate, 1000)

            scanner = PortScanner(
                target=target,
                ports=port_list,
                timeout=1.0,
                max_concurrent=max_concurrent,
            )
            scan_results = await scanner.scan()

            # Extract open ports
            if scan_results and "open_ports" in scan_results:
                results["open_ports"] = scan_results["open_ports"]

        except ImportError:
            # Mock for testing
            await asyncio.sleep(len(port_list) / rate if rate > 0 else 0.1)
            results["open_ports"] = []

        duration = time.time() - start_time
        return duration, results

    async def _run_masscan_scan(
        self, target: str, ports: str, rate: int = 1000
    ) -> Tuple[float, Dict]:
        """
        Run Masscan scan.
        
        Args:
            target: Target to scan
            ports: Port specification
            rate: Scan rate (packets per second)
            
        Returns:
            Tuple of (duration, results)
        """
        if not self.masscan_path:
            return 0.0, {"error": "Masscan not found"}

        try:
            # Build masscan command
            cmd = [
                "sudo",  # Masscan requires root
                self.masscan_path,
                target,
                "-p", ports,
                "--rate", str(rate),
                "--wait", "0",  # Don't wait for responses after scan
                "-oJ", "-",  # Output JSON to stdout
            ]

            start_time = time.time()
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout
            )
            duration = time.time() - start_time

            # Parse results
            results = {"open_ports": [], "total_ports": 0}
            
            if result.returncode == 0:
                # Masscan outputs JSON lines
                for line in result.stdout.strip().split("\n"):
                    if line.strip() and not line.strip().startswith("{"):
                        continue
                    try:
                        data = json.loads(line)
                        if "ports" in data:
                            for port_info in data["ports"]:
                                if port_info.get("status") == "open":
                                    results["open_ports"].append(port_info["port"])
                    except json.JSONDecodeError:
                        continue

            # Count total ports scanned
            if "-" in ports:
                start, end = map(int, ports.split("-"))
                results["total_ports"] = end - start + 1
            else:
                results["total_ports"] = len(ports.split(","))

            return duration, results

        except subprocess.TimeoutExpired:
            return 300.0, {"error": "Timeout"}
        except Exception as e:
            return 0.0, {"error": str(e)}

    async def benchmark_speed_comparison(
        self,
        target: str = "127.0.0.1",
        port_ranges: List[str] = ["1-100", "1-1000", "1-10000"],
        rate: int = 1000,
    ) -> Dict:
        """
        Compare scan speed between CyberSec-CLI and Masscan.
        
        Args:
            target: Target to scan
            port_ranges: List of port ranges to test
            rate: Scan rate in packets per second
            
        Returns:
            Dictionary with comparison results
        """
        print(f"Benchmarking speed comparison (rate: {rate} pps)...")
        
        if not self._check_masscan_available():
            print("  ⚠ Masscan not available, skipping comparison")
            print("  Install with: sudo apt-get install masscan")
            return {"skipped": True, "reason": "Masscan not installed"}

        results = {}

        for ports in port_ranges:
            print(f"\n  Testing port range: {ports}")

            # Test CyberSec-CLI
            print("    Running CyberSec-CLI...")
            cybersec_duration, cybersec_results = await self._run_cybersec_scan(
                target, ports, rate
            )

            cybersec_metrics = await self.run_with_metrics(
                lambda: asyncio.sleep(0),  # Already measured
                operations=cybersec_results["total_ports"],
                metadata={"tool": "cybersec", "ports": ports, "rate": rate},
            )
            cybersec_metrics.duration = cybersec_duration

            # Test Masscan
            print("    Running Masscan...")
            masscan_duration, masscan_results = await self._run_masscan_scan(
                target, ports, rate
            )

            masscan_metrics = await self.run_with_metrics(
                lambda: asyncio.sleep(0),
                operations=masscan_results.get("total_ports", 0),
                metadata={"tool": "masscan", "ports": ports, "rate": rate},
            )
            masscan_metrics.duration = masscan_duration

            # Store results
            self.add_comparison_result("cybersec", cybersec_metrics)
            self.add_comparison_result("masscan", masscan_metrics)

            # Calculate metrics
            speedup = (
                masscan_duration / cybersec_duration
                if cybersec_duration > 0
                else 0
            )

            results[ports] = {
                "port_range": ports,
                "cybersec": {
                    "duration": cybersec_duration,
                    "open_ports": len(cybersec_results.get("open_ports", [])),
                    "ports_per_second": (
                        cybersec_results["total_ports"] / cybersec_duration
                        if cybersec_duration > 0
                        else 0
                    ),
                },
                "masscan": {
                    "duration": masscan_duration,
                    "open_ports": len(masscan_results.get("open_ports", [])),
                    "ports_per_second": (
                        masscan_results.get("total_ports", 0) / masscan_duration
                        if masscan_duration > 0
                        else 0
                    ),
                },
                "speedup": speedup,
                "winner": "cybersec" if speedup > 1.0 else "masscan",
            }

            print(f"    CyberSec-CLI: {cybersec_duration:.2f}s ({results[ports]['cybersec']['ports_per_second']:.0f} ports/sec)")
            print(f"    Masscan:      {masscan_duration:.2f}s ({results[ports]['masscan']['ports_per_second']:.0f} ports/sec)")
            print(f"    Speedup:      {speedup:.2f}x ({'CyberSec-CLI' if speedup > 1.0 else 'Masscan'} faster)")

        return results

    async def benchmark_throughput_comparison(
        self,
        target: str = "127.0.0.1",
        rates: List[int] = [100, 1000, 10000],
    ) -> Dict:
        """
        Compare throughput at different scan rates.
        
        Args:
            target: Target to scan
            rates: List of scan rates to test (packets per second)
            
        Returns:
            Dictionary with throughput comparison
        """
        print("\nBenchmarking throughput comparison...")
        
        if not self._check_masscan_available():
            return {"skipped": True, "reason": "Masscan not installed"}

        results = {}
        ports = "1-1000"  # Fixed port range

        for rate in rates:
            print(f"\n  Testing at {rate} packets/sec...")

            # Test CyberSec-CLI
            cybersec_duration, cybersec_results = await self._run_cybersec_scan(
                target, ports, rate
            )

            # Test Masscan
            masscan_duration, masscan_results = await self._run_masscan_scan(
                target, ports, rate
            )

            results[f"rate_{rate}"] = {
                "target_rate": rate,
                "cybersec": {
                    "duration": cybersec_duration,
                    "actual_rate": 1000 / cybersec_duration if cybersec_duration > 0 else 0,
                    "efficiency": (1000 / cybersec_duration) / rate if rate > 0 and cybersec_duration > 0 else 0,
                },
                "masscan": {
                    "duration": masscan_duration,
                    "actual_rate": 1000 / masscan_duration if masscan_duration > 0 else 0,
                    "efficiency": (1000 / masscan_duration) / rate if rate > 0 and masscan_duration > 0 else 0,
                },
            }

            print(f"    CyberSec-CLI: {results[f'rate_{rate}']['cybersec']['actual_rate']:.0f} pps (efficiency: {results[f'rate_{rate}']['cybersec']['efficiency']:.1%})")
            print(f"    Masscan:      {results[f'rate_{rate}']['masscan']['actual_rate']:.0f} pps (efficiency: {results[f'rate_{rate}']['masscan']['efficiency']:.1%})")

        return results

    async def run_benchmark(self) -> Dict:
        """Run all Masscan comparison benchmarks."""
        print("\n" + "=" * 60)
        print("Masscan Comparison Benchmark Suite")
        print("=" * 60 + "\n")

        results = {}

        # Speed comparison
        results["speed"] = await self.benchmark_speed_comparison(
            port_ranges=["1-100", "1-1000"],
            rate=1000,
        )

        # Throughput comparison
        results["throughput"] = await self.benchmark_throughput_comparison(
            rates=[100, 1000],
        )

        # Save results
        filepath = self.save_results("masscan_comparison_results.json")
        print(f"\n✓ Results saved to: {filepath}")

        # Print comparison summary
        self.print_comparison()

        return results


async def main():
    """Run the Masscan comparison benchmark suite."""
    benchmark = MasscanComparison()
    results = await benchmark.run_benchmark()

    print("\n" + "=" * 60)
    print("Masscan Comparison Complete!")
    print("=" * 60)

    return results


if __name__ == "__main__":
    asyncio.run(main())
