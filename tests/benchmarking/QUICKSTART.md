# Comprehensive Testing Campaign - Quick Start Guide

This guide helps you get started with the comprehensive CyberSec-CLI testing campaign.

## Prerequisites

### System Requirements
- Linux (Ubuntu 20.04+ recommended)
- Python 3.8+
- 8GB+ RAM (16GB recommended for stress tests)
- 20GB+ free disk space
- Root/sudo access (for some tests)

### Install Dependencies

```bash
# Install Python dependencies
pip install -r requirements-dev.txt

# Install comparison tools (optional but recommended)
sudo apt-get update
sudo apt-get install -y nmap masscan iproute2

# Install Rustscan (requires Rust)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
cargo install rustscan
```

## Quick Start

### 1. Verify Framework

First, verify the benchmarking framework is working:

```bash
python tests/benchmarking/test_framework.py
```

You should see:
```
✓ All framework tests passed!
```

### 2. Run Performance Benchmarks

Run the performance benchmarking suite:

```bash
# Speed & Throughput
python tests/benchmarking/performance/test_speed_throughput.py

# Scalability
python tests/benchmarking/performance/test_scalability.py

# Network Conditions (requires sudo for tc)
sudo python tests/benchmarking/performance/test_network_conditions.py
```

### 3. Run Comparative Benchmarks

Compare CyberSec-CLI against industry-standard tools:

```bash
# vs Nmap
python tests/benchmarking/comparative/test_nmap_comparison.py

# vs Masscan (requires sudo)
sudo python tests/benchmarking/comparative/test_masscan_comparison.py

# vs Rustscan
python tests/benchmarking/comparative/test_rustscan_comparison.py
```

### 4. Run All Benchmarks

Run all benchmarks at once:

```bash
# Run all phases
python tests/benchmarking/run_all_benchmarks.py

# Run specific phases
python tests/benchmarking/run_all_benchmarks.py --phases performance comparative

# Quick mode (reduced iterations)
python tests/benchmarking/run_all_benchmarks.py --quick
```

## Understanding Results

### Result Files

All results are saved to `tests/benchmarking/results/`:

```
tests/benchmarking/results/
├── performance/
│   ├── speed_throughput_results.json
│   ├── scalability_results.json
│   └── network_conditions_results.json
├── comparative/
│   ├── nmap_comparison_results.json
│   ├── masscan_comparison_results.json
│   └── rustscan_comparison_results.json
└── plots/
    └── (generated visualizations)
```

### Key Metrics

Each benchmark reports:
- **Duration**: Time taken to complete
- **Throughput**: Operations per second
- **Memory**: Peak memory usage in MB
- **CPU**: CPU utilization percentage
- **Speedup**: Performance relative to comparison tools

### Example Output

```
Speed Comparison:
  CyberSec-CLI: 2.45s (408 ports/sec)
  Nmap:         3.12s (321 ports/sec)
  Speedup:      1.27x (CyberSec-CLI faster)
```

## Common Issues

### Permission Denied

Some tests require root access:

```bash
# Network conditions (uses tc)
sudo python tests/benchmarking/performance/test_network_conditions.py

# Masscan comparison
sudo python tests/benchmarking/comparative/test_masscan_comparison.py
```

### Tool Not Found

If a comparison tool is not installed:

```bash
# Install Nmap
sudo apt-get install nmap

# Install Masscan
sudo apt-get install masscan

# Install Rustscan
cargo install rustscan
```

The benchmarks will skip unavailable tools automatically.

### Out of Memory

For memory-intensive tests, ensure you have enough RAM:

```bash
# Check available memory
free -h

# Reduce test scale if needed
# Edit config.yaml and reduce target counts
```

## Test Phases

### Phase 1: Foundation (Complete)
- ✓ Framework verification
- ✓ Configuration setup

### Phase 2: Performance Benchmarking (In Progress)
- ✓ Speed & Throughput tests
- ✓ Scalability tests
- ✓ Network conditions tests

### Phase 3: Comparative Analysis (In Progress)
- ✓ Nmap comparison
- ✓ Masscan comparison
- ✓ Rustscan comparison
- ⏳ Zmap comparison (pending)

### Phase 4-15: Future Phases
See `implementation_plan.md` for details on:
- Reliability & Stability testing
- Accuracy & Correctness validation
- Security & Safety testing
- Resource Efficiency profiling
- AI Integration testing
- And more...

## Configuration

Edit `tests/benchmarking/config.yaml` to customize:

```yaml
# Test targets
targets:
  local: "127.0.0.1"
  test_server: "scanme.nmap.org"

# Performance budgets
budgets:
  duration:
    max: 10.0
    target: 5.0
  memory_mb:
    max: 500
    target: 250
```

Edit `tests/benchmarking/test_environments.yaml` for test environments:

```yaml
# Known vulnerable VMs
metasploitable2:
  target: "192.168.56.101"
  expected_open_ports: [21, 22, 23, ...]
```

## Next Steps

1. **Review Results**: Check `tests/benchmarking/results/` for detailed metrics

2. **Run Specific Tests**: Focus on areas of interest
   ```bash
   python tests/benchmarking/performance/test_speed_throughput.py
   ```

3. **Compare Tools**: Run comparative benchmarks
   ```bash
   python tests/benchmarking/comparative/test_nmap_comparison.py
   ```

4. **Generate Reports**: Create comprehensive reports
   ```bash
   python tests/benchmarking/tools/generate_report.py
   ```

5. **Continuous Testing**: Set up CI/CD integration
   ```bash
   # See .github/workflows/benchmark.yml
   ```

## Advanced Usage

### Custom Benchmarks

Create custom benchmarks by extending `BaseBenchmark`:

```python
from tests.benchmarking.framework.base_benchmark import BaseBenchmark

class MyBenchmark(BaseBenchmark):
    def __init__(self):
        super().__init__("my_benchmark")
    
    async def run_benchmark(self):
        metrics = await self.run_with_metrics(
            my_function,
            operations=100,
        )
        return {"duration": metrics.duration}
```

### Selective Testing

Run only specific benchmarks:

```python
# In run_all_benchmarks.py
runner = MasterBenchmarkRunner(phases=["performance"])
```

### Performance Budgets

Set acceptance criteria in `config.yaml`:

```yaml
budgets:
  duration:
    max: 10.0  # Fail if > 10s
    target: 5.0  # Warn if > 5s
```

## Getting Help

- **Documentation**: See `tests/benchmarking/README.md`
- **Implementation Plan**: See `implementation_plan.md`
- **Issues**: Check existing benchmark results
- **Configuration**: Review `config.yaml` and `test_environments.yaml`

## Contributing

To add new benchmarks:

1. Create file in appropriate category directory
2. Inherit from `BaseBenchmark` or `ComparativeBenchmark`
3. Implement `run_benchmark()` method
4. Add to `run_all_benchmarks.py`
5. Update documentation

## Summary

You now have a comprehensive testing framework that can:
- ✓ Benchmark performance (speed, scalability, network conditions)
- ✓ Compare against industry tools (Nmap, Masscan, Rustscan)
- ✓ Collect detailed metrics (duration, memory, CPU, throughput)
- ✓ Generate reports and visualizations
- ✓ Support continuous integration

Start with `python tests/benchmarking/test_framework.py` and work your way through the phases!
