"""
Centralized metrics collection for benchmarking.
Provides utilities for collecting system metrics during benchmark runs.
"""

import asyncio
import os
import time
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

import psutil


@dataclass
class SystemMetrics:
    """System-level metrics at a point in time."""

    timestamp: float
    cpu_percent: float
    memory_mb: float
    memory_percent: float
    disk_io_read_mb: float
    disk_io_write_mb: float
    network_sent_mb: float
    network_recv_mb: float
    open_files: int
    threads: int


class MetricsCollector:
    """
    Collects system metrics during benchmark execution.
    
    Can run in background to collect metrics at regular intervals.
    """

    def __init__(self, interval: float = 0.1):
        """
        Initialize metrics collector.
        
        Args:
            interval: Interval in seconds between metric collections
        """
        self.interval = interval
        self.process = psutil.Process(os.getpid())
        self.metrics: List[SystemMetrics] = []
        self._collecting = False
        self._task: Optional[asyncio.Task] = None

        # Baseline metrics
        self._baseline_disk_io = psutil.disk_io_counters()
        self._baseline_net_io = psutil.net_io_counters()

    def collect_snapshot(self) -> SystemMetrics:
        """Collect a single snapshot of system metrics."""
        # CPU and memory
        cpu_percent = self.process.cpu_percent(interval=0)
        mem_info = self.process.memory_info()
        memory_mb = mem_info.rss / 1024 / 1024
        memory_percent = self.process.memory_percent()

        # Disk I/O
        disk_io = psutil.disk_io_counters()
        if disk_io and self._baseline_disk_io:
            disk_read_mb = (
                disk_io.read_bytes - self._baseline_disk_io.read_bytes
            ) / 1024 / 1024
            disk_write_mb = (
                disk_io.write_bytes - self._baseline_disk_io.write_bytes
            ) / 1024 / 1024
        else:
            disk_read_mb = 0
            disk_write_mb = 0

        # Network I/O
        net_io = psutil.net_io_counters()
        if net_io and self._baseline_net_io:
            net_sent_mb = (
                net_io.bytes_sent - self._baseline_net_io.bytes_sent
            ) / 1024 / 1024
            net_recv_mb = (
                net_io.bytes_recv - self._baseline_net_io.bytes_recv
            ) / 1024 / 1024
        else:
            net_sent_mb = 0
            net_recv_mb = 0

        # Process info
        try:
            open_files = len(self.process.open_files())
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            open_files = 0

        threads = self.process.num_threads()

        return SystemMetrics(
            timestamp=time.time(),
            cpu_percent=cpu_percent,
            memory_mb=memory_mb,
            memory_percent=memory_percent,
            disk_io_read_mb=disk_read_mb,
            disk_io_write_mb=disk_write_mb,
            network_sent_mb=net_sent_mb,
            network_recv_mb=net_recv_mb,
            open_files=open_files,
            threads=threads,
        )

    async def _collect_loop(self):
        """Background loop for collecting metrics."""
        while self._collecting:
            snapshot = self.collect_snapshot()
            self.metrics.append(snapshot)
            await asyncio.sleep(self.interval)

    async def start(self):
        """Start collecting metrics in background."""
        if self._collecting:
            return

        self._collecting = True
        self.metrics = []

        # Reset baselines
        self._baseline_disk_io = psutil.disk_io_counters()
        self._baseline_net_io = psutil.net_io_counters()

        # Start collection task
        self._task = asyncio.create_task(self._collect_loop())

    async def stop(self):
        """Stop collecting metrics."""
        if not self._collecting:
            return

        self._collecting = False

        if self._task:
            await self._task
            self._task = None

    def get_summary(self) -> Dict[str, Dict[str, float]]:
        """
        Get summary statistics of collected metrics.
        
        Returns:
            Dictionary with summary statistics for each metric
        """
        if not self.metrics:
            return {}

        import statistics

        cpu_percents = [m.cpu_percent for m in self.metrics]
        memory_mbs = [m.memory_mb for m in self.metrics]
        disk_reads = [m.disk_io_read_mb for m in self.metrics]
        disk_writes = [m.disk_io_write_mb for m in self.metrics]
        net_sent = [m.network_sent_mb for m in self.metrics]
        net_recv = [m.network_recv_mb for m in self.metrics]

        return {
            "cpu_percent": {
                "mean": statistics.mean(cpu_percents),
                "max": max(cpu_percents),
                "min": min(cpu_percents),
            },
            "memory_mb": {
                "mean": statistics.mean(memory_mbs),
                "max": max(memory_mbs),
                "min": min(memory_mbs),
            },
            "disk_io_read_mb": {
                "total": max(disk_reads) if disk_reads else 0,
                "mean_rate": statistics.mean(disk_reads) if disk_reads else 0,
            },
            "disk_io_write_mb": {
                "total": max(disk_writes) if disk_writes else 0,
                "mean_rate": statistics.mean(disk_writes) if disk_writes else 0,
            },
            "network_sent_mb": {
                "total": max(net_sent) if net_sent else 0,
                "mean_rate": statistics.mean(net_sent) if net_sent else 0,
            },
            "network_recv_mb": {
                "total": max(net_recv) if net_recv else 0,
                "mean_rate": statistics.mean(net_recv) if net_recv else 0,
            },
        }

    async def collect_during(self, func: Callable, *args, **kwargs) -> Dict[str, any]:
        """
        Collect metrics while running a function.
        
        Args:
            func: Function to run (can be sync or async)
            *args: Positional arguments for func
            **kwargs: Keyword arguments for func
            
        Returns:
            Dictionary with function result and metrics summary
        """
        await self.start()

        try:
            if asyncio.iscoroutinefunction(func):
                result = await func(*args, **kwargs)
            else:
                result = func(*args, **kwargs)
        finally:
            await self.stop()

        return {"result": result, "metrics": self.get_summary()}


class PerformanceMonitor:
    """
    Monitor for tracking performance over time.
    Useful for detecting performance degradation.
    """

    def __init__(self):
        """Initialize performance monitor."""
        self.history: List[Dict[str, float]] = []

    def record(self, name: str, value: float, metadata: Optional[Dict] = None):
        """
        Record a performance metric.
        
        Args:
            name: Name of the metric
            value: Value of the metric
            metadata: Optional metadata
        """
        record = {
            "timestamp": time.time(),
            "name": name,
            "value": value,
            "metadata": metadata or {},
        }
        self.history.append(record)

    def get_trend(self, name: str, window: int = 10) -> Dict[str, float]:
        """
        Get trend for a metric over recent measurements.
        
        Args:
            name: Name of the metric
            window: Number of recent measurements to consider
            
        Returns:
            Dictionary with trend statistics
        """
        # Filter records by name
        records = [r for r in self.history if r["name"] == name]

        if not records:
            return {}

        # Get recent window
        recent = records[-window:]
        values = [r["value"] for r in recent]

        import statistics

        # Calculate trend
        if len(values) > 1:
            # Simple linear regression
            x = list(range(len(values)))
            mean_x = statistics.mean(x)
            mean_y = statistics.mean(values)

            numerator = sum((x[i] - mean_x) * (values[i] - mean_y) for i in range(len(x)))
            denominator = sum((x[i] - mean_x) ** 2 for i in range(len(x)))

            slope = numerator / denominator if denominator != 0 else 0
        else:
            slope = 0

        return {
            "current": values[-1],
            "mean": statistics.mean(values),
            "min": min(values),
            "max": max(values),
            "slope": slope,
            "trend": "increasing" if slope > 0 else "decreasing" if slope < 0 else "stable",
        }

    def detect_regression(
        self, name: str, threshold: float = 0.05, window: int = 10
    ) -> bool:
        """
        Detect if there's a performance regression.
        
        Args:
            name: Name of the metric
            threshold: Threshold for regression (e.g., 0.05 = 5% increase)
            window: Number of recent measurements to consider
            
        Returns:
            True if regression detected, False otherwise
        """
        trend = self.get_trend(name, window)

        if not trend:
            return False

        # Check if current value is significantly worse than mean
        if trend["current"] > trend["mean"] * (1 + threshold):
            return True

        # Check if trend is increasing significantly
        if trend["slope"] > threshold:
            return True

        return False
