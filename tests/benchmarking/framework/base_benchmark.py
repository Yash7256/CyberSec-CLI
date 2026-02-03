"""
Base benchmark class for CyberSec-CLI benchmarking framework.
Provides standardized metrics collection, result storage, and analysis.
"""

import asyncio
import json
import os
import time
import tracemalloc
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import psutil


@dataclass
class BenchmarkMetrics:
    """Standard metrics collected for all benchmarks."""

    name: str
    timestamp: str
    duration: float
    memory_initial_mb: float
    memory_final_mb: float
    memory_peak_mb: float
    memory_diff_mb: float
    cpu_percent: float
    operations: int
    throughput: float  # operations per second
    metadata: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to dictionary."""
        return asdict(self)

    def to_json(self) -> str:
        """Convert metrics to JSON string."""
        return json.dumps(self.to_dict(), indent=2)


class BaseBenchmark(ABC):
    """
    Base class for all benchmarks.
    
    Provides:
    - Standardized metrics collection
    - Result storage and retrieval
    - Statistical analysis hooks
    - Comparison utilities
    """

    def __init__(self, name: str, output_dir: str = "tests/benchmarking/results"):
        """
        Initialize benchmark.
        
        Args:
            name: Name of the benchmark
            output_dir: Directory to store results
        """
        self.name = name
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.results: List[BenchmarkMetrics] = []
        self.process = psutil.Process(os.getpid())

    def measure_memory_usage(self) -> float:
        """Measure current memory usage in MB."""
        return self.process.memory_info().rss / 1024 / 1024

    def measure_cpu_percent(self, interval: float = 0.1) -> float:
        """Measure CPU usage percentage."""
        return self.process.cpu_percent(interval=interval)

    async def run_with_metrics(
        self,
        func,
        *args,
        operations: int = 1,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> BenchmarkMetrics:
        """
        Run a function and collect metrics.
        
        Args:
            func: Function to benchmark (can be sync or async)
            *args: Positional arguments for func
            operations: Number of operations performed
            metadata: Additional metadata to store
            **kwargs: Keyword arguments for func
            
        Returns:
            BenchmarkMetrics object with collected metrics
        """
        # Initialize metrics
        initial_memory = self.measure_memory_usage()
        tracemalloc.start()
        errors = []

        # Start timing
        start_time = time.time()

        try:
            # Run the function
            if asyncio.iscoroutinefunction(func):
                result = await func(*args, **kwargs)
            else:
                result = func(*args, **kwargs)
        except Exception as e:
            errors.append(f"{type(e).__name__}: {str(e)}")
            result = None

        # End timing
        duration = time.time() - start_time

        # Collect memory metrics
        final_memory = self.measure_memory_usage()
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        # Collect CPU metrics
        cpu_percent = self.measure_cpu_percent()

        # Calculate throughput
        throughput = operations / duration if duration > 0 else 0

        # Create metrics object
        metrics = BenchmarkMetrics(
            name=self.name,
            timestamp=datetime.now().isoformat(),
            duration=duration,
            memory_initial_mb=initial_memory,
            memory_final_mb=final_memory,
            memory_peak_mb=peak / 1024 / 1024,
            memory_diff_mb=final_memory - initial_memory,
            cpu_percent=cpu_percent,
            operations=operations,
            throughput=throughput,
            metadata=metadata or {},
            errors=errors,
        )

        # Store result
        self.results.append(metrics)

        return metrics

    def save_results(self, filename: Optional[str] = None) -> Path:
        """
        Save benchmark results to JSON file.
        
        Args:
            filename: Optional custom filename
            
        Returns:
            Path to saved file
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{self.name}_{timestamp}.json"

        filepath = self.output_dir / filename

        # Convert results to dict
        results_dict = {
            "benchmark_name": self.name,
            "timestamp": datetime.now().isoformat(),
            "total_runs": len(self.results),
            "results": [r.to_dict() for r in self.results],
        }

        # Save to file
        with open(filepath, "w") as f:
            json.dump(results_dict, f, indent=2)

        return filepath

    def load_results(self, filepath: Path) -> List[BenchmarkMetrics]:
        """
        Load benchmark results from JSON file.
        
        Args:
            filepath: Path to results file
            
        Returns:
            List of BenchmarkMetrics objects
        """
        with open(filepath, "r") as f:
            data = json.load(f)

        results = []
        for result_dict in data.get("results", []):
            # Reconstruct BenchmarkMetrics
            metrics = BenchmarkMetrics(**result_dict)
            results.append(metrics)

        return results

    def get_summary_statistics(self) -> Dict[str, Any]:
        """
        Calculate summary statistics for all results.
        
        Returns:
            Dictionary with summary statistics
        """
        if not self.results:
            return {}

        durations = [r.duration for r in self.results]
        throughputs = [r.throughput for r in self.results]
        memory_diffs = [r.memory_diff_mb for r in self.results]
        cpu_percents = [r.cpu_percent for r in self.results]

        import statistics

        return {
            "total_runs": len(self.results),
            "duration": {
                "mean": statistics.mean(durations),
                "median": statistics.median(durations),
                "stdev": statistics.stdev(durations) if len(durations) > 1 else 0,
                "min": min(durations),
                "max": max(durations),
            },
            "throughput": {
                "mean": statistics.mean(throughputs),
                "median": statistics.median(throughputs),
                "stdev": statistics.stdev(throughputs) if len(throughputs) > 1 else 0,
                "min": min(throughputs),
                "max": max(throughputs),
            },
            "memory_diff_mb": {
                "mean": statistics.mean(memory_diffs),
                "median": statistics.median(memory_diffs),
                "stdev": statistics.stdev(memory_diffs) if len(memory_diffs) > 1 else 0,
                "min": min(memory_diffs),
                "max": max(memory_diffs),
            },
            "cpu_percent": {
                "mean": statistics.mean(cpu_percents),
                "median": statistics.median(cpu_percents),
                "stdev": statistics.stdev(cpu_percents) if len(cpu_percents) > 1 else 0,
                "min": min(cpu_percents),
                "max": max(cpu_percents),
            },
            "errors": sum(1 for r in self.results if r.errors),
        }

    @abstractmethod
    async def run_benchmark(self) -> Dict[str, Any]:
        """
        Run the benchmark. Must be implemented by subclasses.
        
        Returns:
            Dictionary with benchmark results
        """
        pass

    def print_summary(self):
        """Print a summary of benchmark results."""
        stats = self.get_summary_statistics()

        print(f"\n{'=' * 60}")
        print(f"Benchmark: {self.name}")
        print(f"{'=' * 60}")
        print(f"Total runs: {stats.get('total_runs', 0)}")
        print(f"\nDuration (seconds):")
        print(f"  Mean:   {stats['duration']['mean']:.4f}")
        print(f"  Median: {stats['duration']['median']:.4f}")
        print(f"  StdDev: {stats['duration']['stdev']:.4f}")
        print(f"  Min:    {stats['duration']['min']:.4f}")
        print(f"  Max:    {stats['duration']['max']:.4f}")
        print(f"\nThroughput (ops/sec):")
        print(f"  Mean:   {stats['throughput']['mean']:.2f}")
        print(f"  Median: {stats['throughput']['median']:.2f}")
        print(f"  StdDev: {stats['throughput']['stdev']:.2f}")
        print(f"\nMemory Diff (MB):")
        print(f"  Mean:   {stats['memory_diff_mb']['mean']:.2f}")
        print(f"  Median: {stats['memory_diff_mb']['median']:.2f}")
        print(f"\nCPU Usage (%):")
        print(f"  Mean:   {stats['cpu_percent']['mean']:.2f}")
        print(f"  Median: {stats['cpu_percent']['median']:.2f}")
        print(f"\nErrors: {stats.get('errors', 0)}")
        print(f"{'=' * 60}\n")


class ComparativeBenchmark(BaseBenchmark):
    """
    Base class for comparative benchmarks (comparing against other tools).
    """

    def __init__(
        self,
        name: str,
        tool_name: str,
        output_dir: str = "tests/benchmarking/results/comparative",
    ):
        """
        Initialize comparative benchmark.
        
        Args:
            name: Name of the benchmark
            tool_name: Name of the tool being compared against
            output_dir: Directory to store results
        """
        super().__init__(name, output_dir)
        self.tool_name = tool_name
        self.comparison_results: Dict[str, List[BenchmarkMetrics]] = {
            "cybersec_cli": [],
            tool_name: [],
        }

    def add_comparison_result(self, tool: str, metrics: BenchmarkMetrics):
        """Add a result for comparison."""
        if tool in self.comparison_results:
            self.comparison_results[tool].append(metrics)

    def get_comparison_summary(self) -> Dict[str, Any]:
        """
        Get summary comparison between tools.
        
        Returns:
            Dictionary with comparison statistics
        """
        summary = {}

        for tool, results in self.comparison_results.items():
            if not results:
                continue

            durations = [r.duration for r in results]
            throughputs = [r.throughput for r in results]

            import statistics

            summary[tool] = {
                "mean_duration": statistics.mean(durations),
                "mean_throughput": statistics.mean(throughputs),
                "total_runs": len(results),
            }

        # Calculate ratios
        if "cybersec_cli" in summary and self.tool_name in summary:
            cybersec = summary["cybersec_cli"]
            other = summary[self.tool_name]

            summary["comparison"] = {
                "speed_ratio": (
                    cybersec["mean_duration"] / other["mean_duration"]
                    if other["mean_duration"] > 0
                    else 0
                ),
                "throughput_ratio": (
                    cybersec["mean_throughput"] / other["mean_throughput"]
                    if other["mean_throughput"] > 0
                    else 0
                ),
            }

        return summary

    def print_comparison(self):
        """Print comparison summary."""
        summary = self.get_comparison_summary()

        print(f"\n{'=' * 60}")
        print(f"Comparative Benchmark: {self.name}")
        print(f"{'=' * 60}")

        for tool, stats in summary.items():
            if tool == "comparison":
                continue
            print(f"\n{tool}:")
            print(f"  Mean Duration:   {stats['mean_duration']:.4f}s")
            print(f"  Mean Throughput: {stats['mean_throughput']:.2f} ops/sec")
            print(f"  Total Runs:      {stats['total_runs']}")

        if "comparison" in summary:
            comp = summary["comparison"]
            print(f"\nComparison (CyberSec-CLI / {self.tool_name}):")
            print(f"  Speed Ratio:      {comp['speed_ratio']:.2f}x")
            print(f"  Throughput Ratio: {comp['throughput_ratio']:.2f}x")

            if comp["speed_ratio"] < 1:
                print(f"  → CyberSec-CLI is {1/comp['speed_ratio']:.2f}x FASTER")
            else:
                print(f"  → CyberSec-CLI is {comp['speed_ratio']:.2f}x SLOWER")

        print(f"{'=' * 60}\n")
