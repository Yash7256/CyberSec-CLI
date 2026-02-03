# CyberSec-CLI Benchmarking Suite

Comprehensive benchmarking and testing framework for CyberSec-CLI performance evaluation and comparative analysis.

## Overview

This benchmarking suite provides:

- **Performance Benchmarking**: Speed, throughput, scalability, and network condition testing
- **Reliability Testing**: Stress, endurance, and chaos engineering tests
- **Accuracy Testing**: Port detection accuracy and false positive/negative analysis
- **Comparative Analysis**: Benchmarks against Nmap, Masscan, Zmap, and Rustscan
- **Resource Profiling**: Memory, CPU, and network efficiency analysis
- **Statistical Analysis**: Hypothesis testing, confidence intervals, and regression detection
- **Visualization**: Comprehensive plots and dashboards

## Directory Structure

```
tests/benchmarking/
├── framework/              # Core framework components
│   ├── base_benchmark.py          # Base benchmark classes
│   ├── metrics_collector.py       # System metrics collection
│   ├── statistical_analysis.py    # Statistical utilities
│   └── visualization.py            # Plotting and visualization
├── performance/            # Performance benchmarks
│   ├── test_speed_throughput.py   # Speed and throughput tests
│   ├── test_scalability.py        # Scalability tests
│   └── test_network_conditions.py # Network simulation tests
├── reliability/            # Reliability tests
│   ├── test_stress.py              # Stress testing
│   ├── test_endurance.py           # Long-running tests
│   └── test_chaos.py               # Failure injection
├── accuracy/               # Accuracy tests
│   ├── test_port_detection.py      # Detection accuracy
│   └── test_false_positives.py     # False positive analysis
├── comparative/            # Comparative benchmarks
│   ├── test_nmap_comparison.py     # vs Nmap
│   ├── test_masscan_comparison.py  # vs Masscan
│   ├── test_zmap_comparison.py     # vs Zmap
│   └── test_rustscan_comparison.py # vs Rustscan
├── resource/               # Resource profiling
│   ├── test_memory_profiling.py    # Memory analysis
│   ├── test_cpu_profiling.py       # CPU profiling
│   └── test_network_efficiency.py  # Network usage
├── reports/                # Report generation
│   ├── generate_report.py          # Comprehensive reports
│   └── dashboard.py                # Real-time dashboard
└── results/                # Benchmark results (auto-created)
```

## Quick Start

### Prerequisites

```bash
# Install benchmarking dependencies
pip install -r requirements-dev.txt

# For comparative benchmarks, install comparison tools:
sudo apt-get install nmap masscan  # Debian/Ubuntu
cargo install rustscan             # Requires Rust
```

### Running Benchmarks

**Run all benchmarks:**
```bash
pytest tests/benchmarking/ -v
```

**Run specific benchmark category:**
```bash
# Performance benchmarks
python tests/benchmarking/performance/test_speed_throughput.py

# Comparative benchmarks
python tests/benchmarking/comparative/test_nmap_comparison.py
```

**Run with pytest:**
```bash
# Run performance tests
pytest tests/benchmarking/performance/ -v

# Run comparative tests
pytest tests/benchmarking/comparative/ -v

# Run with benchmark plugin
pytest tests/benchmarking/ -v --benchmark-only
```

## Benchmark Categories

### 1. Performance Benchmarking

**Speed & Throughput (`test_speed_throughput.py`)**
- Single port scan latency (microseconds)
- 100, 1000, and 65535 port scans
- Cache operations (read/write performance)
- Database query performance

**Scalability (`test_scalability.py`)**
- Horizontal scaling (1 → 100,000 targets)
- Vertical scaling (different hardware profiles)
- Concurrent operations (1 → 1000 simultaneous scans)

**Network Conditions (`test_network_conditions.py`)**
- Bandwidth variation (56 Kbps → 10 Gbps)
- Latency simulation (< 1ms → 700ms)
- Packet loss (0% → 25%)
- Network congestion

### 2. Reliability Testing

**Stress Testing (`test_stress.py`)**
- CPU stress (100% utilization)
- Memory stress (fill until OOM)
- I/O stress (saturate disk)
- Network stress (max connections)

**Endurance Testing (`test_endurance.py`)**
- 24-hour, 48-hour, 7-day continuous scanning
- Memory leak detection
- Performance degradation monitoring

**Chaos Engineering (`test_chaos.py`)**
- Redis/PostgreSQL failure injection
- Network disconnections
- Resource constraints
- Cascading failures

### 3. Accuracy Testing

**Port Detection (`test_port_detection.py`)**
- Test against known environments
- Service identification accuracy
- Precision, recall, F1 score calculation

**False Positives (`test_false_positives.py`)**
- Test against honeypots
- Slow-responding services
- IDS/IPS protected services

### 4. Comparative Analysis

**Nmap Comparison (`test_nmap_comparison.py`)**
- Speed comparison (T0-T5 timing templates)
- Accuracy comparison
- Resource usage comparison

**Other Tools**
- Masscan (speed-focused)
- Zmap (large-scale scanning)
- Rustscan (modern alternative)

### 5. Resource Profiling

**Memory Profiling (`test_memory_profiling.py`)**
- Baseline memory consumption
- Memory per scan operation
- Memory leak detection
- Peak memory usage

**CPU Profiling (`test_cpu_profiling.py`)**
- Hotspot identification
- Thread utilization
- GIL contention analysis

**Network Efficiency (`test_network_efficiency.py`)**
- Bytes sent/received per scan
- Protocol efficiency
- Connection reuse

## Configuration

Edit `config.yaml` to customize benchmark settings:

```yaml
# Test targets
targets:
  local: "127.0.0.1"
  test_server: "scanme.nmap.org"
  
# Performance budgets
budgets:
  duration:
    max: 10.0  # seconds
    target: 5.0
  memory_mb:
    max: 500
    target: 250
  
# Comparison tool paths
tools:
  nmap: "/usr/bin/nmap"
  masscan: "/usr/bin/masscan"
  rustscan: "~/.cargo/bin/rustscan"
```

## Interpreting Results

### Metrics Collected

Each benchmark collects:
- **Duration**: Time taken to complete
- **Throughput**: Operations per second
- **Memory**: Initial, final, peak, and diff (MB)
- **CPU**: Percentage utilization
- **Errors**: Any errors encountered

### Statistical Analysis

Results include:
- Mean, median, standard deviation
- Confidence intervals (95%)
- Hypothesis testing (t-tests, ANOVA)
- Effect sizes (Cohen's d)
- Outlier detection

### Visualization

Plots generated:
- Bar charts (duration, throughput comparison)
- Box plots (distribution analysis)
- Time series (performance over time)
- Scatter plots (correlation analysis)
- Heatmaps (multi-dimensional comparison)

## Performance Budgets

Define acceptable performance thresholds:

```python
from tests.benchmarking.framework.statistical_analysis import PerformanceBudget

budgets = {
    "duration": {"max": 10.0, "target": 5.0},
    "memory_mb": {"max": 500, "target": 250},
    "throughput": {"min": 100, "target": 200},
}

budget = PerformanceBudget(budgets)
result = budget.check_budget({"duration": 7.5, "memory_mb": 300})
```

## Regression Detection

Automatically detect performance regressions:

```python
from tests.benchmarking.framework.statistical_analysis import BenchmarkComparator

comparison = BenchmarkComparator.detect_regression(
    baseline_file="results/baseline.json",
    current_file="results/current.json",
    threshold=0.05,  # 5% regression threshold
    metric="duration"
)

if comparison["regression_detected"]:
    print(f"Regression detected: {comparison['actual_change_percent']:.1f}% slower")
```

## Continuous Integration

GitHub Actions workflow for automated benchmarking:

```yaml
# .github/workflows/benchmark.yml
name: Performance Benchmarks

on: [push, pull_request]

jobs:
  benchmark:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run benchmarks
        run: pytest tests/benchmarking/ --benchmark-autosave
      - name: Check for regressions
        run: python tests/benchmarking/continuous/regression_detector.py
```

## Best Practices

1. **Isolate Tests**: Run benchmarks in isolated environments
2. **Consistent Hardware**: Use same hardware for comparisons
3. **Multiple Runs**: Run each benchmark multiple times for statistical significance
4. **Warm-up**: Include warm-up iterations to stabilize performance
5. **Monitor System**: Check for background processes affecting results
6. **Document Changes**: Record any system or code changes

## Troubleshooting

**Nmap not found:**
```bash
sudo apt-get install nmap
```

**Permission denied (raw sockets):**
```bash
sudo setcap cap_net_raw+ep /path/to/python
# Or run with sudo (not recommended)
```

**Memory profiling issues:**
```bash
pip install memory-profiler psutil
```

**Visualization errors:**
```bash
pip install matplotlib seaborn plotly
```

## Contributing

To add a new benchmark:

1. Create a new file in the appropriate category directory
2. Inherit from `BaseBenchmark` or `ComparativeBenchmark`
3. Implement the `run_benchmark()` method
4. Use `run_with_metrics()` for automatic metric collection
5. Add documentation and examples

Example:

```python
from tests.benchmarking.framework.base_benchmark import BaseBenchmark

class MyBenchmark(BaseBenchmark):
    def __init__(self):
        super().__init__("my_benchmark")
    
    async def run_benchmark(self):
        metrics = await self.run_with_metrics(
            my_function,
            operations=100,
            metadata={"test": "example"}
        )
        return {"duration": metrics.duration}
```

## License

Same as CyberSec-CLI project (MIT License)

## Support

For issues or questions:
- Open an issue on GitHub
- Check existing benchmark results in `results/` directory
- Review implementation plan in `/home/yash/.gemini/antigravity/brain/*/implementation_plan.md`
