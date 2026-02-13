"""
Visualization utilities for benchmark results.
Generates plots and charts for performance analysis.
"""

from pathlib import Path
from typing import Dict, List, Optional

import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns


# Set style
sns.set_style("whitegrid")
plt.rcParams["figure.figsize"] = (12, 6)
plt.rcParams["font.size"] = 10


class BenchmarkVisualizer:
    """
    Create visualizations for benchmark results.
    """

    def __init__(self, output_dir: str = "tests/benchmarking/results/plots"):
        """
        Initialize visualizer.
        
        Args:
            output_dir: Directory to save plots
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def plot_duration_comparison(
        self,
        data: Dict[str, List[float]],
        title: str = "Duration Comparison",
        ylabel: str = "Duration (seconds)",
        filename: str = "duration_comparison.png",
    ) -> Path:
        """
        Create bar chart comparing durations across different benchmarks.
        
        Args:
            data: Dictionary mapping benchmark name to list of durations
            title: Plot title
            ylabel: Y-axis label
            filename: Output filename
            
        Returns:
            Path to saved plot
        """
        fig, ax = plt.subplots(figsize=(12, 6))

        names = list(data.keys())
        means = [np.mean(values) for values in data.values()]
        stds = [np.std(values) for values in data.values()]

        x_pos = np.arange(len(names))
        ax.bar(x_pos, means, yerr=stds, capsize=5, alpha=0.7)
        ax.set_xticks(x_pos)
        ax.set_xticklabels(names, rotation=45, ha="right")
        ax.set_ylabel(ylabel)
        ax.set_title(title)
        ax.grid(axis="y", alpha=0.3)

        plt.tight_layout()
        filepath = self.output_dir / filename
        plt.savefig(filepath, dpi=300, bbox_inches="tight")
        plt.close()

        return filepath

    def plot_throughput_comparison(
        self,
        data: Dict[str, List[float]],
        title: str = "Throughput Comparison",
        ylabel: str = "Throughput (ops/sec)",
        filename: str = "throughput_comparison.png",
    ) -> Path:
        """
        Create bar chart comparing throughput.
        
        Args:
            data: Dictionary mapping benchmark name to list of throughput values
            title: Plot title
            ylabel: Y-axis label
            filename: Output filename
            
        Returns:
            Path to saved plot
        """
        return self.plot_duration_comparison(data, title, ylabel, filename)

    def plot_box_plot(
        self,
        data: Dict[str, List[float]],
        title: str = "Distribution Comparison",
        ylabel: str = "Value",
        filename: str = "box_plot.png",
    ) -> Path:
        """
        Create box plot showing distribution of values.
        
        Args:
            data: Dictionary mapping benchmark name to list of values
            title: Plot title
            ylabel: Y-axis label
            filename: Output filename
            
        Returns:
            Path to saved plot
        """
        fig, ax = plt.subplots(figsize=(12, 6))

        # Prepare data for box plot
        plot_data = []
        labels = []
        for name, values in data.items():
            plot_data.append(values)
            labels.append(name)

        bp = ax.boxplot(plot_data, labels=labels, patch_artist=True)

        # Color boxes
        for patch in bp["boxes"]:
            patch.set_facecolor("lightblue")
            patch.set_alpha(0.7)

        ax.set_ylabel(ylabel)
        ax.set_title(title)
        ax.grid(axis="y", alpha=0.3)
        plt.xticks(rotation=45, ha="right")

        plt.tight_layout()
        filepath = self.output_dir / filename
        plt.savefig(filepath, dpi=300, bbox_inches="tight")
        plt.close()

        return filepath

    def plot_time_series(
        self,
        timestamps: List[float],
        values: List[float],
        title: str = "Performance Over Time",
        ylabel: str = "Value",
        filename: str = "time_series.png",
    ) -> Path:
        """
        Create time series plot.
        
        Args:
            timestamps: List of timestamps
            values: List of values
            title: Plot title
            ylabel: Y-axis label
            filename: Output filename
            
        Returns:
            Path to saved plot
        """
        fig, ax = plt.subplots(figsize=(14, 6))

        ax.plot(timestamps, values, marker="o", linestyle="-", linewidth=2, markersize=4)
        ax.set_xlabel("Time")
        ax.set_ylabel(ylabel)
        ax.set_title(title)
        ax.grid(True, alpha=0.3)

        plt.tight_layout()
        filepath = self.output_dir / filename
        plt.savefig(filepath, dpi=300, bbox_inches="tight")
        plt.close()

        return filepath

    def plot_scatter(
        self,
        x: List[float],
        y: List[float],
        xlabel: str = "X",
        ylabel: str = "Y",
        title: str = "Scatter Plot",
        filename: str = "scatter.png",
        regression_line: bool = True,
    ) -> Path:
        """
        Create scatter plot with optional regression line.
        
        Args:
            x: X values
            y: Y values
            xlabel: X-axis label
            ylabel: Y-axis label
            title: Plot title
            filename: Output filename
            regression_line: Whether to add regression line
            
        Returns:
            Path to saved plot
        """
        fig, ax = plt.subplots(figsize=(10, 6))

        ax.scatter(x, y, alpha=0.6, s=50)

        if regression_line and len(x) > 1:
            # Add regression line
            z = np.polyfit(x, y, 1)
            p = np.poly1d(z)
            ax.plot(x, p(x), "r--", alpha=0.8, linewidth=2, label=f"y={z[0]:.2f}x+{z[1]:.2f}")
            ax.legend()

        ax.set_xlabel(xlabel)
        ax.set_ylabel(ylabel)
        ax.set_title(title)
        ax.grid(True, alpha=0.3)

        plt.tight_layout()
        filepath = self.output_dir / filename
        plt.savefig(filepath, dpi=300, bbox_inches="tight")
        plt.close()

        return filepath

    def plot_heatmap(
        self,
        data: np.ndarray,
        row_labels: List[str],
        col_labels: List[str],
        title: str = "Heatmap",
        filename: str = "heatmap.png",
        cmap: str = "YlOrRd",
    ) -> Path:
        """
        Create heatmap.
        
        Args:
            data: 2D array of values
            row_labels: Labels for rows
            col_labels: Labels for columns
            title: Plot title
            filename: Output filename
            cmap: Colormap name
            
        Returns:
            Path to saved plot
        """
        fig, ax = plt.subplots(figsize=(12, 8))

        im = ax.imshow(data, cmap=cmap, aspect="auto")

        # Set ticks
        ax.set_xticks(np.arange(len(col_labels)))
        ax.set_yticks(np.arange(len(row_labels)))
        ax.set_xticklabels(col_labels)
        ax.set_yticklabels(row_labels)

        # Rotate x labels
        plt.setp(ax.get_xticklabels(), rotation=45, ha="right", rotation_mode="anchor")

        # Add colorbar
        cbar = plt.colorbar(im, ax=ax)

        # Add values in cells
        for i in range(len(row_labels)):
            for j in range(len(col_labels)):
                text = ax.text(j, i, f"{data[i, j]:.2f}", ha="center", va="center", color="black", fontsize=8)

        ax.set_title(title)
        plt.tight_layout()

        filepath = self.output_dir / filename
        plt.savefig(filepath, dpi=300, bbox_inches="tight")
        plt.close()

        return filepath

    def plot_comparative_bar(
        self,
        categories: List[str],
        cybersec_values: List[float],
        other_tool_values: List[float],
        other_tool_name: str = "Other Tool",
        title: str = "Comparative Performance",
        ylabel: str = "Value",
        filename: str = "comparative_bar.png",
    ) -> Path:
        """
        Create side-by-side bar chart for comparison.
        
        Args:
            categories: List of category names
            cybersec_values: Values for CyberSec-CLI
            other_tool_values: Values for other tool
            other_tool_name: Name of other tool
            title: Plot title
            ylabel: Y-axis label
            filename: Output filename
            
        Returns:
            Path to saved plot
        """
        fig, ax = plt.subplots(figsize=(12, 6))

        x = np.arange(len(categories))
        width = 0.35

        rects1 = ax.bar(x - width / 2, cybersec_values, width, label="CyberSec-CLI", alpha=0.8)
        rects2 = ax.bar(x + width / 2, other_tool_values, width, label=other_tool_name, alpha=0.8)

        ax.set_ylabel(ylabel)
        ax.set_title(title)
        ax.set_xticks(x)
        ax.set_xticklabels(categories, rotation=45, ha="right")
        ax.legend()
        ax.grid(axis="y", alpha=0.3)

        # Add value labels on bars
        def autolabel(rects):
            for rect in rects:
                height = rect.get_height()
                ax.annotate(
                    f"{height:.2f}",
                    xy=(rect.get_x() + rect.get_width() / 2, height),
                    xytext=(0, 3),
                    textcoords="offset points",
                    ha="center",
                    va="bottom",
                    fontsize=8,
                )

        autolabel(rects1)
        autolabel(rects2)

        plt.tight_layout()
        filepath = self.output_dir / filename
        plt.savefig(filepath, dpi=300, bbox_inches="tight")
        plt.close()

        return filepath

    def plot_memory_usage_over_time(
        self,
        timestamps: List[float],
        memory_values: List[float],
        title: str = "Memory Usage Over Time",
        filename: str = "memory_usage.png",
    ) -> Path:
        """
        Create memory usage plot.
        
        Args:
            timestamps: List of timestamps
            memory_values: List of memory values in MB
            title: Plot title
            filename: Output filename
            
        Returns:
            Path to saved plot
        """
        fig, ax = plt.subplots(figsize=(14, 6))

        ax.fill_between(timestamps, memory_values, alpha=0.3)
        ax.plot(timestamps, memory_values, linewidth=2)
        ax.set_xlabel("Time")
        ax.set_ylabel("Memory (MB)")
        ax.set_title(title)
        ax.grid(True, alpha=0.3)

        # Add horizontal line for mean
        mean_memory = np.mean(memory_values)
        ax.axhline(y=mean_memory, color="r", linestyle="--", alpha=0.7, label=f"Mean: {mean_memory:.2f} MB")
        ax.legend()

        plt.tight_layout()
        filepath = self.output_dir / filename
        plt.savefig(filepath, dpi=300, bbox_inches="tight")
        plt.close()

        return filepath

    def create_dashboard(
        self,
        benchmark_name: str,
        duration_data: Dict[str, List[float]],
        throughput_data: Dict[str, List[float]],
        memory_data: Optional[Dict[str, List[float]]] = None,
        filename: str = "dashboard.png",
    ) -> Path:
        """
        Create comprehensive dashboard with multiple plots.
        
        Args:
            benchmark_name: Name of benchmark
            duration_data: Duration data for different runs
            throughput_data: Throughput data
            memory_data: Optional memory data
            filename: Output filename
            
        Returns:
            Path to saved dashboard
        """
        if memory_data:
            fig, axes = plt.subplots(2, 2, figsize=(16, 12))
            fig.suptitle(f"{benchmark_name} - Performance Dashboard", fontsize=16)
        else:
            fig, axes = plt.subplots(1, 2, figsize=(16, 6))
            fig.suptitle(f"{benchmark_name} - Performance Dashboard", fontsize=16)
            axes = [axes[0], axes[1]]

        # Duration comparison
        ax = axes[0] if memory_data else axes[0]
        names = list(duration_data.keys())
        means = [np.mean(values) for values in duration_data.values()]
        stds = [np.std(values) for values in duration_data.values()]
        x_pos = np.arange(len(names))
        ax.bar(x_pos, means, yerr=stds, capsize=5, alpha=0.7)
        ax.set_xticks(x_pos)
        ax.set_xticklabels(names, rotation=45, ha="right")
        ax.set_ylabel("Duration (seconds)")
        ax.set_title("Duration Comparison")
        ax.grid(axis="y", alpha=0.3)

        # Throughput comparison
        ax = axes[1] if memory_data else axes[1]
        names = list(throughput_data.keys())
        means = [np.mean(values) for values in throughput_data.values()]
        stds = [np.std(values) for values in throughput_data.values()]
        x_pos = np.arange(len(names))
        ax.bar(x_pos, means, yerr=stds, capsize=5, alpha=0.7, color="green")
        ax.set_xticks(x_pos)
        ax.set_xticklabels(names, rotation=45, ha="right")
        ax.set_ylabel("Throughput (ops/sec)")
        ax.set_title("Throughput Comparison")
        ax.grid(axis="y", alpha=0.3)

        if memory_data:
            # Memory box plot
            ax = axes[1][0]
            plot_data = list(memory_data.values())
            labels = list(memory_data.keys())
            bp = ax.boxplot(plot_data, labels=labels, patch_artist=True)
            for patch in bp["boxes"]:
                patch.set_facecolor("lightcoral")
                patch.set_alpha(0.7)
            ax.set_ylabel("Memory (MB)")
            ax.set_title("Memory Usage Distribution")
            ax.grid(axis="y", alpha=0.3)
            plt.setp(ax.get_xticklabels(), rotation=45, ha="right")

            # Summary statistics table
            ax = axes[1][1]
            ax.axis("off")
            table_data = []
            for name in names:
                dur_mean = np.mean(duration_data[name])
                thr_mean = np.mean(throughput_data[name])
                table_data.append([name, f"{dur_mean:.3f}s", f"{thr_mean:.1f} ops/s"])

            table = ax.table(
                cellText=table_data,
                colLabels=["Benchmark", "Avg Duration", "Avg Throughput"],
                cellLoc="center",
                loc="center",
            )
            table.auto_set_font_size(False)
            table.set_fontsize(10)
            table.scale(1, 2)
            ax.set_title("Summary Statistics")

        plt.tight_layout()
        filepath = self.output_dir / filename
        plt.savefig(filepath, dpi=300, bbox_inches="tight")
        plt.close()

        return filepath
