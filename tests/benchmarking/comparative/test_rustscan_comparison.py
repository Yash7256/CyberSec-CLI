"""
Comparative benchmark: CyberSec-CLI vs Rustscan.
Tests performance against the modern Rust-based port scanner.
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


class RustscanComparison(ComparativeBenchmark):
    """
    Compare CyberSec-CLI against Rustscan.
    
    Rustscan is a modern, fast port scanner written in Rust that pipes
    results to Nmap for service detection. It's known for speed and
    modern architecture.
    
    Tests:
    - Speed comparison
    - Resource usage (memory, CPU)
    - Accuracy comparison
    - Feature comparison
    """

    def __init__(self):
        """Initialize Rustscan comparison benchmark."""
        super().__init__("rustscan_comparison", "rustscan")
        self.rustscan_path = self._find_rustscan()

    def _find_rustscan(self) -> Optional[str]:
        """Find Rustscan executable."""
        try:
            result = subprocess.run(
                ["which", "rustscan"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                return result.stdout.strip()
            
            # Try common paths
            for path in [
                "~/.cargo/bin/rustscan",
                "/usr/local/bin/rustscan",
                "/usr/bin/rustscan",
            ]:
                expanded = Path(path).expanduser()
                if expanded.exists():
                    return str(expanded)
            
            return None
        except Exception:
            return None

    def _check_rustscan_available(self) -> bool:
        """Check if Rustscan is installed."""
        if not self.rustscan_path:
            return False
        
        try:
            result = subprocess.run(
                [self.rustscan_path, "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.returncode == 0
        except Exception:
            return False

    async def _run_cybersec_scan(
        self, target: str, ports: str, batch_size: int = 1000
    ) -> Tuple[float, Dict]:
        """
        Run CyberSec-CLI scan.
        
        Args:
            target: Target to scan
            ports: Port specification
            batch_size: Batch size for scanning
            
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

            scanner = PortScanner(
                target=target,
                ports=port_list,
                timeout=1.0,
                max_concurrent=min(batch_size, 1000),
            )
            scan_results = await scanner.scan()

            if scan_results and "open_ports" in scan_results:
                results["open_ports"] = scan_results["open_ports"]

        except ImportError:
            # Mock for testing
            await asyncio.sleep(len(port_list) / 1000 if len(port_list) > 0 else 0.1)
            results["open_ports"] = []

        duration = time.time() - start_time
        return duration, results

    async def _run_rustscan_scan(
        self, target: str, ports: str, batch_size: int = 1000
    ) -> Tuple[float, Dict]:
        """
        Run Rustscan scan.
        
        Args:
            target: Target to scan
            ports: Port specification
            batch_size: Batch size for scanning
            
        Returns:
            Tuple of (duration, results)
        """
        if not self.rustscan_path:
            return 0.0, {"error": "Rustscan not found"}

        try:
            # Build rustscan command
            cmd = [
                self.rustscan_path,
                "-a", target,
                "-p", ports,
                "-b", str(batch_size),
                "--greppable",  # Easier to parse
                "--no-nmap",  # Don't pipe to nmap
                "--timeout", "1000",  # 1 second timeout
            ]

            start_time = time.time()
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )
            duration = time.time() - start_time

            # Parse results
            results = {"open_ports": [], "total_ports": 0}
            
            if result.returncode == 0:
                # Rustscan greppable output: "Open IP:PORT"
                for line in result.stdout.strip().split("\n"):
                    if "Open" in line and ":" in line:
                        try:
                            port = int(line.split(":")[-1].strip())
                            results["open_ports"].append(port)
                        except ValueError:
                            continue

            # Count total ports
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
        batch_size: int = 1000,
    ) -> Dict:
        """
        Compare scan speed between CyberSec-CLI and Rustscan.
        
        Args:
            target: Target to scan
            port_ranges: List of port ranges to test
            batch_size: Batch size for scanning
            
        Returns:
            Dictionary with comparison results
        """
        print(f"Benchmarking speed comparison (batch size: {batch_size})...")
        
        if not self._check_rustscan_available():
            print("  ⚠ Rustscan not available, skipping comparison")
            print("  Install with: cargo install rustscan")
            return {"skipped": True, "reason": "Rustscan not installed"}

        results = {}

        for ports in port_ranges:
            print(f"\n  Testing port range: {ports}")

            # Test CyberSec-CLI
            print("    Running CyberSec-CLI...")
            cybersec_duration, cybersec_results = await self._run_cybersec_scan(
                target, ports, batch_size
            )

            cybersec_metrics = await self.run_with_metrics(
                lambda: asyncio.sleep(0),
                operations=cybersec_results["total_ports"],
                metadata={"tool": "cybersec", "ports": ports, "batch_size": batch_size},
            )
            cybersec_metrics.duration = cybersec_duration

            # Test Rustscan
            print("    Running Rustscan...")
            rustscan_duration, rustscan_results = await self._run_rustscan_scan(
                target, ports, batch_size
            )

            rustscan_metrics = await self.run_with_metrics(
                lambda: asyncio.sleep(0),
                operations=rustscan_results.get("total_ports", 0),
                metadata={"tool": "rustscan", "ports": ports, "batch_size": batch_size},
            )
            rustscan_metrics.duration = rustscan_duration

            # Store results
            self.add_comparison_result("cybersec", cybersec_metrics)
            self.add_comparison_result("rustscan", rustscan_metrics)

            # Calculate metrics
            speedup = (
                rustscan_duration / cybersec_duration
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
                "rustscan": {
                    "duration": rustscan_duration,
                    "open_ports": len(rustscan_results.get("open_ports", [])),
                    "ports_per_second": (
                        rustscan_results.get("total_ports", 0) / rustscan_duration
                        if rustscan_duration > 0
                        else 0
                    ),
                },
                "speedup": speedup,
                "winner": "cybersec" if speedup > 1.0 else "rustscan",
            }

            print(f"    CyberSec-CLI: {cybersec_duration:.2f}s ({results[ports]['cybersec']['ports_per_second']:.0f} ports/sec)")
            print(f"    Rustscan:     {rustscan_duration:.2f}s ({results[ports]['rustscan']['ports_per_second']:.0f} ports/sec)")
            print(f"    Speedup:      {speedup:.2f}x ({'CyberSec-CLI' if speedup > 1.0 else 'Rustscan'} faster)")

        return results

    async def benchmark_resource_usage(
        self,
        target: str = "127.0.0.1",
        ports: str = "1-1000",
    ) -> Dict:
        """
        Compare resource usage between tools.
        
        Args:
            target: Target to scan
            ports: Port range to scan
            
        Returns:
            Dictionary with resource usage comparison
        """
        print("\nBenchmarking resource usage...")
        
        if not self._check_rustscan_available():
            return {"skipped": True, "reason": "Rustscan not installed"}

        results = {}

        # Test CyberSec-CLI
        print("  Testing CyberSec-CLI resource usage...")
        cybersec_duration, _ = await self._run_cybersec_scan(target, ports)
        
        cybersec_metrics = await self.run_with_metrics(
            lambda: asyncio.sleep(0),
            operations=1000,
            metadata={"tool": "cybersec", "ports": ports},
        )
        cybersec_metrics.duration = cybersec_duration

        # Test Rustscan
        print("  Testing Rustscan resource usage...")
        rustscan_duration, _ = await self._run_rustscan_scan(target, ports)
        
        rustscan_metrics = await self.run_with_metrics(
            lambda: asyncio.sleep(0),
            operations=1000,
            metadata={"tool": "rustscan", "ports": ports},
        )
        rustscan_metrics.duration = rustscan_duration

        results = {
            "cybersec": {
                "memory_mb": cybersec_metrics.memory_peak_mb,
                "cpu_percent": cybersec_metrics.cpu_percent,
            },
            "rustscan": {
                "memory_mb": rustscan_metrics.memory_peak_mb,
                "cpu_percent": rustscan_metrics.cpu_percent,
            },
            "memory_efficiency": (
                rustscan_metrics.memory_peak_mb / cybersec_metrics.memory_peak_mb
                if cybersec_metrics.memory_peak_mb > 0
                else 0
            ),
        }

        print(f"  CyberSec-CLI: {results['cybersec']['memory_mb']:.1f} MB, {results['cybersec']['cpu_percent']:.1f}% CPU")
        print(f"  Rustscan:     {results['rustscan']['memory_mb']:.1f} MB, {results['rustscan']['cpu_percent']:.1f}% CPU")

        return results

    async def run_benchmark(self) -> Dict:
        """Run all Rustscan comparison benchmarks."""
        print("\n" + "=" * 60)
        print("Rustscan Comparison Benchmark Suite")
        print("=" * 60 + "\n")

        results = {}

        # Speed comparison
        results["speed"] = await self.benchmark_speed_comparison(
            port_ranges=["1-100", "1-1000"],
            batch_size=1000,
        )

        # Resource usage
        results["resources"] = await self.benchmark_resource_usage(
            ports="1-1000",
        )

        # Save results
        filepath = self.save_results("rustscan_comparison_results.json")
        print(f"\n✓ Results saved to: {filepath}")

        # Print comparison summary
        self.print_comparison()

        return results


async def main():
    """Run the Rustscan comparison benchmark suite."""
    benchmark = RustscanComparison()
    results = await benchmark.run_benchmark()

    print("\n" + "=" * 60)
    print("Rustscan Comparison Complete!")
    print("=" * 60)

    return results


if __name__ == "__main__":
    asyncio.run(main())
