"""
Speed and throughput benchmarks for CyberSec-CLI.
Tests micro and macro performance characteristics.
"""

import asyncio
import sys
import time
from pathlib import Path
from typing import Dict, List

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from tests.benchmarking.framework.base_benchmark import BaseBenchmark


class SpeedThroughputBenchmark(BaseBenchmark):
    """
    Benchmark speed and throughput of port scanning operations.
    
    Includes:
    - Micro-benchmarks (single port, connection establishment)
    - Macro-benchmarks (full port ranges, large IP ranges)
    - Throughput measurements
    """

    def __init__(self):
        """Initialize speed/throughput benchmark."""
        super().__init__("speed_throughput", "tests/benchmarking/results/performance")

    async def benchmark_single_port_scan(self, iterations: int = 100) -> Dict:
        """
        Benchmark single port scan latency.
        
        Args:
            iterations: Number of iterations to run
            
        Returns:
            Dictionary with benchmark results
        """
        print(f"Benchmarking single port scan ({iterations} iterations)...")

        try:
            from cybersec_cli.tools.network.port_scanner import PortScanner
        except ImportError:
            # Fallback for testing
            print("Warning: PortScanner not available, using mock")
            return await self._mock_single_port_scan(iterations)

        latencies = []

        for i in range(iterations):
            start = time.perf_counter()

            try:
                scanner = PortScanner(
                    target="127.0.0.1",
                    ports=[80],
                    timeout=0.5,
                    max_concurrent=1,
                )
                await scanner.scan()
            except Exception as e:
                print(f"Scan error: {e}")
                continue

            latency = (time.perf_counter() - start) * 1000  # Convert to milliseconds
            latencies.append(latency)

            if (i + 1) % 20 == 0:
                print(f"  Progress: {i+1}/{iterations}")

        if not latencies:
            return {"error": "No successful scans"}

        import statistics

        return {
            "test": "single_port_scan",
            "iterations": len(latencies),
            "mean_latency_ms": statistics.mean(latencies),
            "median_latency_ms": statistics.median(latencies),
            "min_latency_ms": min(latencies),
            "max_latency_ms": max(latencies),
            "stdev_latency_ms": statistics.stdev(latencies) if len(latencies) > 1 else 0,
        }

    async def _mock_single_port_scan(self, iterations: int) -> Dict:
        """Mock single port scan for testing."""
        latencies = []
        for _ in range(iterations):
            start = time.perf_counter()
            await asyncio.sleep(0.001)  # Simulate scan
            latency = (time.perf_counter() - start) * 1000
            latencies.append(latency)

        import statistics

        return {
            "test": "single_port_scan_mock",
            "iterations": len(latencies),
            "mean_latency_ms": statistics.mean(latencies),
            "median_latency_ms": statistics.median(latencies),
            "min_latency_ms": min(latencies),
            "max_latency_ms": max(latencies),
            "stdev_latency_ms": statistics.stdev(latencies) if len(latencies) > 1 else 0,
        }

    async def benchmark_100_ports(self) -> Dict:
        """Benchmark scanning 100 ports."""
        print("Benchmarking 100-port scan...")

        async def scan_100_ports():
            try:
                from cybersec_cli.tools.network.port_scanner import PortScanner

                scanner = PortScanner(
                    target="127.0.0.1",
                    ports=list(range(1, 101)),
                    timeout=0.5,
                    max_concurrent=10,
                )
                await scanner.scan()
            except ImportError:
                # Mock scan
                await asyncio.sleep(0.5)

        metrics = await self.run_with_metrics(
            scan_100_ports, operations=100, metadata={"ports": 100, "target": "127.0.0.1"}
        )

        return {
            "test": "100_port_scan",
            "duration": metrics.duration,
            "throughput": metrics.throughput,
            "memory_diff_mb": metrics.memory_diff_mb,
            "ports_per_second": 100 / metrics.duration if metrics.duration > 0 else 0,
        }

    async def benchmark_1000_ports(self) -> Dict:
        """Benchmark scanning 1000 ports."""
        print("Benchmarking 1000-port scan...")

        async def scan_1000_ports():
            try:
                from cybersec_cli.tools.network.port_scanner import PortScanner

                scanner = PortScanner(
                    target="127.0.0.1",
                    ports=list(range(1, 1001)),
                    timeout=0.5,
                    max_concurrent=20,
                )
                await scanner.scan()
            except ImportError:
                # Mock scan
                await asyncio.sleep(2.0)

        metrics = await self.run_with_metrics(
            scan_1000_ports, operations=1000, metadata={"ports": 1000, "target": "127.0.0.1"}
        )

        return {
            "test": "1000_port_scan",
            "duration": metrics.duration,
            "throughput": metrics.throughput,
            "memory_diff_mb": metrics.memory_diff_mb,
            "ports_per_second": 1000 / metrics.duration if metrics.duration > 0 else 0,
        }

    async def benchmark_full_port_range(self) -> Dict:
        """Benchmark scanning full port range (1-65535)."""
        print("Benchmarking full port range scan (1-65535)...")
        print("  Warning: This may take several minutes...")

        async def scan_full_range():
            try:
                from cybersec_cli.tools.network.port_scanner import PortScanner

                scanner = PortScanner(
                    target="127.0.0.1",
                    ports=list(range(1, 65536)),
                    timeout=0.3,
                    max_concurrent=50,
                )
                await scanner.scan()
            except ImportError:
                # Mock scan
                await asyncio.sleep(10.0)

        metrics = await self.run_with_metrics(
            scan_full_range,
            operations=65535,
            metadata={"ports": 65535, "target": "127.0.0.1"},
        )

        return {
            "test": "full_port_range_scan",
            "duration": metrics.duration,
            "throughput": metrics.throughput,
            "memory_diff_mb": metrics.memory_diff_mb,
            "ports_per_second": 65535 / metrics.duration if metrics.duration > 0 else 0,
        }

    async def benchmark_cache_operations(self, operations: int = 1000) -> Dict:
        """
        Benchmark cache hit/miss performance.
        
        Args:
            operations: Number of cache operations to test
            
        Returns:
            Dictionary with cache performance metrics
        """
        print(f"Benchmarking cache operations ({operations} ops)...")

        try:
            from cybersec_cli.core.scan_cache import ScanCache

            cache = ScanCache()
            await cache.initialize()

            # Benchmark cache writes
            async def cache_write_test():
                for i in range(operations):
                    cache_key = cache.get_cache_key(f"192.168.1.{i % 255}", [80, 443])
                    await cache.store_cache(
                        cache_key, {"ports": [{"port": 80, "state": "open"}]}
                    )

            write_metrics = await self.run_with_metrics(
                cache_write_test, operations=operations, metadata={"operation": "write"}
            )

            # Benchmark cache reads (hits)
            async def cache_read_test():
                for i in range(operations):
                    cache_key = cache.get_cache_key(f"192.168.1.{i % 255}", [80, 443])
                    await cache.check_cache(cache_key)

            read_metrics = await self.run_with_metrics(
                cache_read_test, operations=operations, metadata={"operation": "read"}
            )

            return {
                "test": "cache_operations",
                "write_ops_per_sec": write_metrics.throughput,
                "read_ops_per_sec": read_metrics.throughput,
                "write_duration": write_metrics.duration,
                "read_duration": read_metrics.duration,
            }

        except ImportError:
            print("Warning: ScanCache not available, skipping")
            return {"test": "cache_operations", "skipped": True}

    async def benchmark_database_queries(self, queries: int = 100) -> Dict:
        """
        Benchmark database query performance.
        
        Args:
            queries: Number of queries to execute
            
        Returns:
            Dictionary with database performance metrics
        """
        print(f"Benchmarking database queries ({queries} queries)...")

        try:
            import sqlite3
            import tempfile

            # Create temporary database
            temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
            temp_db.close()

            conn = sqlite3.connect(temp_db.name)
            c = conn.cursor()

            # Create table
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY,
                    target TEXT,
                    timestamp TEXT,
                    results TEXT
                )
            """
            )
            conn.commit()

            # Benchmark inserts
            async def insert_test():
                for i in range(queries):
                    c.execute(
                        "INSERT INTO scans (target, timestamp, results) VALUES (?, ?, ?)",
                        (f"192.168.1.{i % 255}", "2024-01-01", "{}"),
                    )
                conn.commit()

            insert_metrics = await self.run_with_metrics(
                insert_test, operations=queries, metadata={"operation": "insert"}
            )

            # Benchmark selects
            async def select_test():
                for i in range(queries):
                    c.execute("SELECT * FROM scans WHERE target = ?", (f"192.168.1.{i % 255}",))
                    c.fetchall()

            select_metrics = await self.run_with_metrics(
                select_test, operations=queries, metadata={"operation": "select"}
            )

            conn.close()

            import os

            os.unlink(temp_db.name)

            return {
                "test": "database_queries",
                "insert_ops_per_sec": insert_metrics.throughput,
                "select_ops_per_sec": select_metrics.throughput,
                "insert_duration": insert_metrics.duration,
                "select_duration": select_metrics.duration,
            }

        except Exception as e:
            print(f"Database benchmark error: {e}")
            return {"test": "database_queries", "error": str(e)}

    async def run_benchmark(self) -> Dict:
        """Run all speed/throughput benchmarks."""
        print("\n" + "=" * 60)
        print("Speed & Throughput Benchmark Suite")
        print("=" * 60 + "\n")

        results = {}

        # Micro-benchmarks
        results["single_port"] = await self.benchmark_single_port_scan(iterations=50)
        print(f"✓ Single port latency: {results['single_port'].get('mean_latency_ms', 0):.2f}ms\n")

        # Macro-benchmarks
        results["100_ports"] = await self.benchmark_100_ports()
        print(f"✓ 100 ports: {results['100_ports']['duration']:.2f}s ({results['100_ports']['ports_per_second']:.1f} ports/sec)\n")

        results["1000_ports"] = await self.benchmark_1000_ports()
        print(f"✓ 1000 ports: {results['1000_ports']['duration']:.2f}s ({results['1000_ports']['ports_per_second']:.1f} ports/sec)\n")

        # Cache operations
        results["cache"] = await self.benchmark_cache_operations(operations=500)
        if not results["cache"].get("skipped"):
            print(f"✓ Cache: {results['cache']['read_ops_per_sec']:.0f} reads/sec, {results['cache']['write_ops_per_sec']:.0f} writes/sec\n")

        # Database queries
        results["database"] = await self.benchmark_database_queries(queries=100)
        if "error" not in results["database"]:
            print(f"✓ Database: {results['database']['select_ops_per_sec']:.0f} selects/sec, {results['database']['insert_ops_per_sec']:.0f} inserts/sec\n")

        # Save results
        filepath = self.save_results("speed_throughput_results.json")
        print(f"\n✓ Results saved to: {filepath}")

        # Print summary
        self.print_summary()

        return results


async def main():
    """Run the speed/throughput benchmark suite."""
    benchmark = SpeedThroughputBenchmark()
    results = await benchmark.run_benchmark()

    print("\n" + "=" * 60)
    print("Benchmark Complete!")
    print("=" * 60)

    return results


if __name__ == "__main__":
    asyncio.run(main())
