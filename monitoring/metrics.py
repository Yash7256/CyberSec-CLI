"""
Prometheus metrics for CyberSec CLI
"""

import time

from prometheus_client import (
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)

# Dedicated registry to ensure consistent metric export
REGISTRY = CollectorRegistry()

# Counter metrics
SCANS_TOTAL = Counter(
    "scans_total",
    "Total number of scans performed",
    labelnames=["status", "user_type"],
    registry=REGISTRY,
)

SCAN_ERRORS_TOTAL = Counter(
    "scan_errors_total",
    "Total number of scan errors",
    labelnames=["error_type", "target_type"],
    registry=REGISTRY,
)

CACHE_HITS_TOTAL = Counter(
    "cache_hits_total", "Total number of cache hits", registry=REGISTRY
)

CACHE_MISSES_TOTAL = Counter(
    "cache_misses_total", "Total number of cache misses", registry=REGISTRY
)

RATE_LIMIT_VIOLATIONS_TOTAL = Counter(
    "rate_limit_violations_total",
    "Total number of rate limit violations",
    labelnames=["violation_type"],
    registry=REGISTRY,
)

# Histogram metrics
SCAN_DURATION_SECONDS = Histogram(
    "scan_duration_seconds",
    "Scan duration in seconds",
    buckets=[1, 5, 10, 30, 60, 120, 300],
    registry=REGISTRY,
)

PORTS_SCANNED_COUNT = Histogram(
    "ports_scanned_count",
    "Number of ports scanned per scan",
    buckets=[10, 50, 100, 500, 1000],
    registry=REGISTRY,
)

OPEN_PORTS_FOUND_COUNT = Histogram(
    "open_ports_found_count",
    "Number of open ports found per scan",
    buckets=[1, 5, 10, 20, 50, 100],
    registry=REGISTRY,
)

SERVICE_DETECTION_DURATION_SECONDS = Histogram(
    "service_detection_duration_seconds",
    "Service detection duration in seconds",
    buckets=[0.1, 0.5, 1, 2, 5, 10],
    registry=REGISTRY,
)

# Gauge metrics
ACTIVE_SCANS_CURRENT = Gauge(
    "active_scans_current", "Current number of active scans", registry=REGISTRY
)

CELERY_QUEUE_LENGTH = Gauge(
    "celery_queue_length", "Current length of Celery task queue", registry=REGISTRY
)

REDIS_CONNECTION_POOL_SIZE = Gauge(
    "redis_connection_pool_size",
    "Current size of Redis connection pool",
    registry=REGISTRY,
)

DATABASE_CONNECTIONS_ACTIVE = Gauge(
    "database_connections_active",
    "Number of active database connections",
    registry=REGISTRY,
)


class MetricsCollector:
    """
    Centralized metrics collection and management
    """

    def __init__(self):
        self.registry = REGISTRY

    def increment_scan(self, status: str = "completed", user_type: str = "anonymous"):
        """Increment scan counter"""
        SCANS_TOTAL.labels(status=status, user_type=user_type).inc()

    def increment_scan_error(self, error_type: str, target_type: str = "unknown"):
        """Increment scan error counter"""
        SCAN_ERRORS_TOTAL.labels(error_type=error_type, target_type=target_type).inc()

    def increment_cache_hit(self):
        """Increment cache hit counter"""
        CACHE_HITS_TOTAL.inc()

    def increment_cache_miss(self):
        """Increment cache miss counter"""
        CACHE_MISSES_TOTAL.inc()

    def increment_rate_limit_violation(self, violation_type: str):
        """Increment rate limit violation counter"""
        RATE_LIMIT_VIOLATIONS_TOTAL.labels(violation_type=violation_type).inc()

    def observe_scan_duration(self, duration: float):
        """Observe scan duration"""
        SCAN_DURATION_SECONDS.observe(duration)

    def observe_ports_scanned(self, count: int):
        """Observe number of ports scanned"""
        PORTS_SCANNED_COUNT.observe(count)

    def observe_open_ports_found(self, count: int):
        """Observe number of open ports found"""
        OPEN_PORTS_FOUND_COUNT.observe(count)

    def observe_service_detection_duration(self, duration: float):
        """Observe service detection duration"""
        SERVICE_DETECTION_DURATION_SECONDS.observe(duration)

    def set_active_scans(self, count: int):
        """Set current active scans count"""
        ACTIVE_SCANS_CURRENT.set(count)

    def set_celery_queue_length(self, length: int):
        """Set Celery queue length"""
        CELERY_QUEUE_LENGTH.set(length)

    def set_redis_connection_pool_size(self, size: int):
        """Set Redis connection pool size"""
        REDIS_CONNECTION_POOL_SIZE.set(size)

    def set_database_connections_active(self, count: int):
        """Set active database connections count"""
        DATABASE_CONNECTIONS_ACTIVE.set(count)

    def get_metrics(self) -> str:
        """Get current metrics in Prometheus format"""
        return generate_latest(self.registry).decode("utf-8")


# Global metrics collector instance
metrics_collector = MetricsCollector()


def start_timer() -> float:
    """Start a timer for duration metrics"""
    return time.time()


def stop_timer(start_time: float) -> float:
    """Stop a timer and return the duration"""
    return time.time() - start_time


# Context managers for automatic metric collection
class ScanDurationTimer:
    """Context manager to automatically record scan duration"""

    def __init__(self):
        self.start_time = None

    def __enter__(self):
        self.start_time = start_timer()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.start_time:
            duration = stop_timer(self.start_time)
            metrics_collector.observe_scan_duration(duration)

        # Handle exceptions and increment error counter if needed
        if exc_type is not None:
            error_type = exc_type.__name__
            metrics_collector.increment_scan_error(
                error_type=error_type, target_type="unknown"
            )


class ServiceDetectionTimer:
    """Context manager to automatically record service detection duration"""

    def __init__(self):
        self.start_time = None

    def __enter__(self):
        self.start_time = start_timer()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.start_time:
            duration = stop_timer(self.start_time)
            metrics_collector.observe_service_detection_duration(duration)


# Helper functions for common metric operations
def record_scan(
    start_time: float,
    status: str = "completed",
    user_type: str = "anonymous",
    ports_count: int = 0,
    open_ports_count: int = 0,
):
    """
    Record a completed scan with all relevant metrics
    """
    # Record scan completion
    metrics_collector.increment_scan(status=status, user_type=user_type)

    # Record scan duration
    duration = stop_timer(start_time)
    metrics_collector.observe_scan_duration(duration)

    # Record ports scanned
    if ports_count > 0:
        metrics_collector.observe_ports_scanned(ports_count)

    # Record open ports found
    if open_ports_count > 0:
        metrics_collector.observe_open_ports_found(open_ports_count)
