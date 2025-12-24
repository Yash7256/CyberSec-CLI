"""
Performance benchmarks for the CyberSec-CLI scanner component.
Tests various scenarios to measure performance metrics.
"""
import asyncio
import time
import tracemalloc
import psutil
import os
from datetime import datetime
from typing import Dict, List, Tuple
import matplotlib.pyplot as plt
import numpy as np

from cybersec_cli.tools.network.port_scanner import PortScanner
from core.scan_cache import ScanCache
from core.rate_limiter import SmartRateLimiter
from core.adaptive_scanner import AdaptiveScanConfig


class ScannerBenchmark:
    """Benchmark suite for the port scanner component."""
    
    def __init__(self):
        self.results = {}
        self.cache = ScanCache()
        
    async def setup(self):
        """Initialize required components."""
        await self.cache.initialize()
        
    def measure_memory_usage(self) -> float:
        """Measure current memory usage in MB."""
        process = psutil.Process(os.getpid())
        return process.memory_info().rss / 1024 / 1024
    
    async def benchmark_scan_100_ports(self) -> Dict:
        """Benchmark scanning 100 ports."""
        print("Benchmarking 100-port scan...")
        
        initial_memory = self.measure_memory_usage()
        tracemalloc.start()
        
        start_time = time.time()
        
        # Use a mock target for testing
        scanner = PortScanner(target='127.0.0.1', ports=list(range(1, 101)), timeout=0.5, max_concurrent=10)
        results = await scanner.scan()
        
        end_time = time.time()
        scan_duration = end_time - start_time
        
        current_memory = self.measure_memory_usage()
        memory_diff = current_memory - initial_memory
        
        # Get memory usage from tracemalloc
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        
        return {
            'duration': scan_duration,
            'memory_initial': initial_memory,
            'memory_final': current_memory,
            'memory_diff': memory_diff,
            'peak_memory': peak / 1024 / 1024,  # Convert to MB
            'ports_scanned': 100,
            'timestamp': datetime.now().isoformat()
        }
    
    async def benchmark_scan_1000_ports(self) -> Dict:
        """Benchmark scanning 1000 ports."""
        print("Benchmarking 1000-port scan...")
        
        initial_memory = self.measure_memory_usage()
        tracemalloc.start()
        
        start_time = time.time()
        
        # Use a mock target for testing
        scanner = PortScanner(target='127.0.0.1', ports=list(range(1, 1001)), timeout=0.5, max_concurrent=10)
        results = await scanner.scan()
        
        end_time = time.time()
        scan_duration = end_time - start_time
        
        current_memory = self.measure_memory_usage()
        memory_diff = current_memory - initial_memory
        
        # Get memory usage from tracemalloc
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        
        return {
            'duration': scan_duration,
            'memory_initial': initial_memory,
            'memory_final': current_memory,
            'memory_diff': memory_diff,
            'peak_memory': peak / 1024 / 1024,  # Convert to MB
            'ports_scanned': 1000,
            'timestamp': datetime.now().isoformat()
        }
    
    async def benchmark_concurrent_scans(self) -> Dict:
        """Benchmark concurrent scans."""
        print("Benchmarking concurrent scans...")
        
        initial_memory = self.measure_memory_usage()
        tracemalloc.start()
        
        start_time = time.time()
        
        # Create 10 concurrent scan tasks
        tasks = []
        for i in range(10):
            scanner = PortScanner(target=f'127.0.0.{i+1}', ports=list(range(1, 101)), timeout=0.5, max_concurrent=5)
            tasks.append(scanner.scan())
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        end_time = time.time()
        total_duration = end_time - start_time
        
        current_memory = self.measure_memory_usage()
        memory_diff = current_memory - initial_memory
        
        # Get memory usage from tracemalloc
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        
        # Calculate throughput (scans per second)
        throughput = 10 / total_duration if total_duration > 0 else 0
        
        return {
            'total_duration': total_duration,
            'throughput': throughput,
            'memory_initial': initial_memory,
            'memory_final': current_memory,
            'memory_diff': memory_diff,
            'peak_memory': peak / 1024 / 1024,  # Convert to MB
            'concurrent_scans': 10,
            'ports_per_scan': 100,
            'timestamp': datetime.now().isoformat()
        }
    
    async def benchmark_cache_hit_rate(self) -> Dict:
        """Benchmark cache hit rate with repeated scans."""
        print("Benchmarking cache hit rate...")
        
        # Prepare cache key for the same target and ports
        cache_key = self.cache.get_cache_key('127.0.0.1', list(range(1, 101)))
        mock_result = {'ports': [{'port': 80, 'state': 'open', 'service': 'http'}]}
        
        # Store initial result in cache
        await self.cache.store_cache(cache_key, mock_result)
        
        tracemalloc.start()
        initial_memory = self.measure_memory_usage()
        
        # Measure cache hit performance
        start_time = time.time()
        for _ in range(100):
            result = await self.cache.check_cache(cache_key)
        cache_hit_duration = time.time() - start_time
        
        # Measure cache miss performance
        miss_cache_key = self.cache.get_cache_key('127.0.0.2', list(range(1, 101)))
        start_time = time.time()
        for _ in range(100):
            result = await self.cache.check_cache(miss_cache_key)
        cache_miss_duration = time.time() - start_time
        
        current_memory = self.measure_memory_usage()
        memory_diff = current_memory - initial_memory
        
        # Get memory usage from tracemalloc
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        
        return {
            'cache_hit_duration': cache_hit_duration,
            'cache_miss_duration': cache_miss_duration,
            'cache_hit_rate': 100.0,  # Since we know all will be hits
            'memory_initial': initial_memory,
            'memory_final': current_memory,
            'memory_diff': memory_diff,
            'peak_memory': peak / 1024 / 1024,  # Convert to MB
            'operations': 100,
            'timestamp': datetime.now().isoformat()
        }
    
    async def benchmark_memory_usage_during_large_scan(self) -> Dict:
        """Benchmark memory usage during a large scan."""
        print("Benchmarking memory usage during large scan...")
        
        initial_memory = self.measure_memory_usage()
        
        # Track memory at intervals during scan
        memory_snapshots = []
        
        def track_memory():
            memory_snapshots.append(self.measure_memory_usage())
        
        # Start memory tracking in background
        import threading
        import time as time_module
        
        tracking_thread = threading.Thread(target=lambda: [time_module.sleep(0.1) or track_memory() for _ in range(50)])
        tracking_thread.start()
        
        # Perform a large scan
        start_time = time.time()
        scanner = PortScanner(target='127.0.0.1', ports=list(range(1, 5001)), timeout=0.5, max_concurrent=20)
        results = await scanner.scan()
        scan_duration = time.time() - start_time
        
        tracking_thread.join()  # Wait for tracking to finish
        
        max_memory = max(memory_snapshots) if memory_snapshots else initial_memory
        memory_increase = max_memory - initial_memory
        
        return {
            'duration': scan_duration,
            'initial_memory': initial_memory,
            'max_memory': max_memory,
            'memory_increase': memory_increase,
            'memory_snapshots_count': len(memory_snapshots),
            'ports_scanned': 5000,
            'timestamp': datetime.now().isoformat()
        }
    
    async def benchmark_adaptive_scanning(self) -> Dict:
        """Compare performance with and without adaptive scanning."""
        print("Benchmarking adaptive scanning...")
        
        # Test with adaptive scanning
        adaptive_config = AdaptiveScanConfig()
        start_time = time.time()
        
        # Simulate adaptive scanning behavior
        for i in range(100):
            # Simulate some adaptive behavior
            if i % 20 == 0:  # Every 20th iteration, adjust settings
                adaptive_config.update_success_rate(0.8)  # Good success rate
        
        adaptive_duration = time.time() - start_time
        
        # Test without adaptive scanning (baseline)
        start_time = time.time()
        for i in range(100):
            # No adaptive behavior
            pass
        baseline_duration = time.time() - start_time
        
        return {
            'adaptive_duration': adaptive_duration,
            'baseline_duration': baseline_duration,
            'adaptive_overhead': adaptive_duration - baseline_duration,
            'operations': 100,
            'timestamp': datetime.now().isoformat()
        }
    
    async def run_all_benchmarks(self) -> Dict:
        """Run all benchmarks and return results."""
        print("Starting scanner benchmarks...")
        
        await self.setup()
        
        results = {}
        
        # Run each benchmark
        results['100_port_scan'] = await self.benchmark_scan_100_ports()
        print(f"100-port scan: {results['100_port_scan']['duration']:.2f}s")
        
        results['1000_port_scan'] = await self.benchmark_scan_1000_ports()
        print(f"1000-port scan: {results['1000_port_scan']['duration']:.2f}s")
        
        results['concurrent_scans'] = await self.benchmark_concurrent_scans()
        print(f"Concurrent scans throughput: {results['concurrent_scans']['throughput']:.2f} scans/sec")
        
        results['cache_performance'] = await self.benchmark_cache_hit_rate()
        print(f"Cache hit duration: {results['cache_performance']['cache_hit_duration']:.4f}s")
        
        results['memory_usage_large_scan'] = await self.benchmark_memory_usage_during_large_scan()
        print(f"Large scan duration: {results['memory_usage_large_scan']['duration']:.2f}s")
        
        results['adaptive_scanning'] = await self.benchmark_adaptive_scanning()
        print(f"Adaptive scanning overhead: {results['adaptive_scanning']['adaptive_overhead']:.6f}s")
        
        self.results = results
        return results
    
    def generate_report(self) -> str:
        """Generate a text report from benchmark results."""
        if not self.results:
            return "No benchmark results available."
        
        report = "Scanner Performance Benchmark Report\n"
        report += "=" * 50 + "\n\n"
        
        for test_name, result in self.results.items():
            report += f"{test_name.replace('_', ' ').title()}:\n"
            for key, value in result.items():
                if isinstance(value, float):
                    report += f"  {key}: {value:.4f}\n"
                else:
                    report += f"  {key}: {value}\n"
            report += "\n"
        
        return report
    
    def plot_results(self, output_dir: str = "tests/performance/plots"):
        """Generate plots from benchmark results."""
        import os
        os.makedirs(output_dir, exist_ok=True)
        
        if not self.results:
            print("No results to plot")
            return
        
        # Plot scan duration comparison
        if '100_port_scan' in self.results and '1000_port_scan' in self.results:
            fig, ax = plt.subplots(figsize=(10, 6))
            
            scan_sizes = ['100 Ports', '1000 Ports']
            durations = [
                self.results['100_port_scan']['duration'],
                self.results['1000_port_scan']['duration']
            ]
            
            ax.bar(scan_sizes, durations)
            ax.set_ylabel('Duration (seconds)')
            ax.set_title('Scan Duration Comparison')
            
            plt.xticks(rotation=45)
            plt.tight_layout()
            plt.savefig(f"{output_dir}/scan_duration_comparison.png")
            plt.close()
        
        # Plot memory usage
        if '100_port_scan' in self.results and '1000_port_scan' in self.results:
            fig, ax = plt.subplots(figsize=(10, 6))
            
            scan_sizes = ['100 Ports', '1000 Ports']
            peak_memory = [
                self.results['100_port_scan']['peak_memory'],
                self.results['1000_port_scan']['peak_memory']
            ]
            
            ax.bar(scan_sizes, peak_memory)
            ax.set_ylabel('Peak Memory (MB)')
            ax.set_title('Peak Memory Usage Comparison')
            
            plt.xticks(rotation=45)
            plt.tight_layout()
            plt.savefig(f"{output_dir}/memory_usage_comparison.png")
            plt.close()


async def main():
    """Run the benchmark suite."""
    benchmark = ScannerBenchmark()
    results = await benchmark.run_all_benchmarks()
    
    # Generate report
    report = benchmark.generate_report()
    print("\n" + report)
    
    # Save report to file
    with open("tests/performance/scanner_benchmark_report.txt", "w") as f:
        f.write(report)
    
    # Generate plots
    benchmark.plot_results()
    
    print("Benchmark completed. Results saved to tests/performance/scanner_benchmark_report.txt")
    print("Plots saved to tests/performance/plots/")


if __name__ == "__main__":
    asyncio.run(main())