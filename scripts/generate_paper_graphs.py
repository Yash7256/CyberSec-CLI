"""
Generate Graphs for IEEE Paper.
Reads benchmark JSON results and produces plots.
"""

import json
import os
import sys
from pathlib import Path
import matplotlib.pyplot as plt

def generate_adaptive_graph():
    """Figure 2: Adaptive Concurrency Over Time."""
    results_path = Path("tests/benchmarking/results/adaptive/adaptive_concurrency_results.json")
    if not results_path.exists():
        print(f"File not found: {results_path}")
        return

    with open(results_path) as f:
        data = json.load(f)

    # Handle different saving structures (BaseBenchmark wrapper vs direct dict)
    history = []
    if "results" in data and isinstance(data["results"], list) and not data["results"]:
        # Potentially caught in the empty results issue observed earlier
        # Try to find if 'adaptation_curve' is at top level if format was fixed
        if "adaptation_curve" in data:
             history = data["adaptation_curve"]
    elif "adaptation_curve" in data:
         history = data["adaptation_curve"]
    
    if not history:
        print("No history data found in results file.")
        return

    timestamps = [d["timestamp"] for d in history]
    concurrency = [d["concurrency"] for d in history]
    
    plt.figure(figsize=(10, 6))
    plt.plot(timestamps, concurrency, label="Concurrency Limit", color="blue")
    
    # Annotate phases
    plt.axvspan(0, 10, alpha=0.1, color='green', label='Good Network')
    plt.axvspan(10, 20, alpha=0.1, color='red', label='Bad Network')
    plt.axvspan(20, 30, alpha=0.1, color='orange', label='Degraded')
    plt.axvspan(30, max(timestamps), alpha=0.1, color='green')

    plt.title("Figure 2: Adaptive Concurrency Over Time")
    plt.xlabel("Time (s)")
    plt.ylabel("Max Concurrent Connections")
    plt.legend()
    plt.grid(True)
    
    output_path = "tests/benchmarking/results/plots/figure2_adaptive_concurrency.png"
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    plt.savefig(output_path)
    print(f"Generated {output_path}")

def generate_comparison_graph():
    """Table I: Performance Comparison (Visual)."""
    results_path = Path("tests/benchmarking/results/comparative/nmap_comparison_results.json")
    if not results_path.exists():
        print(f"File not found: {results_path}")
        return

    with open(results_path) as f:
        data = json.load(f)
    
    labels = []
    durations = []
    
    # Parse flat results list
    if "results" in data:
        for r in data["results"]:
            meta = r.get("metadata", {})
            # Filter for the 1000 port test key
            if meta.get("ports") == "1-1000":
                tool_name = meta.get("tool", "unknown")
                labels.append(tool_name)
                durations.append(r.get("duration", 0))

    if labels:
        # Sort labels to group nmap together
        zipped = sorted(zip(labels, durations))
        labels = [x[0] for x in zipped]
        durations = [x[1] for x in zipped]

        plt.figure(figsize=(10, 6))
        
        # Color Map
        colors = []
        for l in labels:
            if "cybersec" in l: colors.append('blue')
            elif "T0" in l: colors.append('purple') # Slowest
            elif "T1" in l: colors.append('red')
            elif "T2" in l: colors.append('orange')
            elif "T3" in l: colors.append('yellow')
            elif "T4" in l: colors.append('green')
            elif "T5" in l: colors.append('lime')
            else: colors.append('gray')

        plt.bar(labels, durations, color=colors)
        plt.title("Scan Duration Comparison (1000 Ports)")
        plt.ylabel("Duration (s)")
        plt.xlabel("Tool / Timing")
        plt.yscale('log') # Log scale because T0 is huge
        plt.xticks(rotation=45)
        plt.grid(True, axis='y')
        plt.tight_layout()
        
        output_path = "tests/benchmarking/results/plots/figure3_performance_comparison.png"
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        plt.savefig(output_path)
        print(f"Generated {output_path}")

def generate_scalability_graph():
    """Table III: Scalability (Visual)."""
    results_path = Path("tests/benchmarking/results/performance/scalability_results.json")
    if not results_path.exists():
        print(f"File not found: {results_path}")
        return

    with open(results_path) as f:
        data = json.load(f)
    
    targets = []
    throughputs = []
    
    # Parse flat results list for Horizontal Scaling
    if "results" in data:
        for r in data["results"]:
            meta = r.get("metadata", {})
            # Horizontal scaling has target_count
            if "target_count" in meta:
                targets.append(meta["target_count"])
                throughputs.append(r.get("throughput", 0))
    
    if targets:
        # Sort by target count
        zipped = sorted(zip(targets, throughputs))
        targets = [x[0] for x in zipped]
        throughputs = [x[1] for x in zipped]
        
        plt.figure(figsize=(10, 6))
        plt.plot(targets, throughputs, marker='o', linestyle='-', color='purple')
        plt.title("Scalability: Throughput vs Target Count")
        plt.xlabel("Number of Targets")
        plt.ylabel("Throughput (targets/sec)")
        plt.xscale('log')
        plt.grid(True)
        
        output_path = "tests/benchmarking/results/plots/figure4_scalability.png"
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        plt.savefig(output_path)
        print(f"Generated {output_path}")

if __name__ == "__main__":
    generate_adaptive_graph()
    generate_comparison_graph()
    generate_scalability_graph()

