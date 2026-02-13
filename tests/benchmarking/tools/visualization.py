"""
Visualization tools for CyberSec-CLI benchmark results.
Generates plots and charts for comprehensive analysis.
"""

import json
import matplotlib.pyplot as plt
import numpy as np
from pathlib import Path
from typing import Dict, List, Union
import seaborn as sns
import plotly.graph_objects as go
from plotly.subplots import make_subplots


class BenchmarkVisualizer:
    """
    Visualization tools for benchmark results.
    
    Creates various types of plots:
    - Bar charts for comparisons
    - Box plots for distribution analysis
    - Time series for performance over time
    - Scatter plots for correlations
    - Heatmaps for multi-dimensional analysis
    """
    
    def __init__(self, output_dir: str = "tests/benchmarking/results/plots"):
        """Initialize visualizer with output directory."""
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Set up plotting styles
        plt.style.use('seaborn-v0_8')
        sns.set_palette("husl")
    
    def create_performance_comparison_bar_chart(
        self, 
        data: Dict[str, float], 
        title: str = "Performance Comparison",
        filename: str = "performance_comparison.png"
    ) -> str:
        """
        Create a bar chart comparing performance metrics.
        
        Args:
            data: Dictionary with labels as keys and values as performance metrics
            title: Chart title
            filename: Output filename
            
        Returns:
            Path to saved image
        """
        fig, ax = plt.subplots(figsize=(12, 6))
        
        tools = list(data.keys())
        values = list(data.values())
        
        bars = ax.bar(tools, values, color=plt.cm.viridis(np.linspace(0, 1, len(tools))))
        
        # Add value labels on bars
        for bar, value in zip(bars, values):
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height,
                   f'{value:.2f}',
                   ha='center', va='bottom')
        
        ax.set_title(title, fontsize=16, fontweight='bold')
        ax.set_ylabel('Performance Metric', fontsize=12)
        ax.tick_params(axis='x', rotation=45)
        
        plt.tight_layout()
        
        filepath = self.output_dir / filename
        plt.savefig(filepath, dpi=300, bbox_inches='tight')
        plt.close()
        
        return str(filepath)
    
    def create_distribution_box_plot(
        self,
        datasets: Dict[str, List[float]], 
        title: str = "Performance Distribution",
        filename: str = "distribution_boxplot.png"
    ) -> str:
        """
        Create box plots to show distribution of performance metrics.
        
        Args:
            datasets: Dictionary with labels as keys and lists of values as data
            title: Chart title
            filename: Output filename
            
        Returns:
            Path to saved image
        """
        fig, ax = plt.subplots(figsize=(12, 6))
        
        labels = list(datasets.keys())
        data = [datasets[label] for label in labels]
        
        box_plot = ax.boxplot(data, labels=labels, patch_artist=True)
        
        # Color the boxes
        colors = plt.cm.Set3(np.linspace(0, 1, len(labels)))
        for patch, color in zip(box_plot['boxes'], colors):
            patch.set_facecolor(color)
        
        ax.set_title(title, fontsize=16, fontweight='bold')
        ax.set_ylabel('Value', fontsize=12)
        ax.tick_params(axis='x', rotation=45)
        
        plt.tight_layout()
        
        filepath = self.output_dir / filename
        plt.savefig(filepath, dpi=300, bbox_inches='tight')
        plt.close()
        
        return str(filepath)
    
    def create_time_series_plot(
        self,
        timestamps: List[str], 
        values: List[float], 
        title: str = "Performance Over Time",
        ylabel: str = "Metric Value",
        filename: str = "time_series.png"
    ) -> str:
        """
        Create a time series plot showing performance over time.
        
        Args:
            timestamps: List of time labels
            values: List of metric values
            title: Chart title
            ylabel: Y-axis label
            filename: Output filename
            
        Returns:
            Path to saved image
        """
        fig, ax = plt.subplots(figsize=(14, 6))
        
        ax.plot(timestamps, values, marker='o', linewidth=2, markersize=6)
        
        ax.set_title(title, fontsize=16, fontweight='bold')
        ax.set_xlabel('Time', fontsize=12)
        ax.set_ylabel(ylabel, fontsize=12)
        ax.grid(True, alpha=0.3)
        
        # Rotate x-axis labels for better readability
        plt.xticks(rotation=45, ha='right')
        
        plt.tight_layout()
        
        filepath = self.output_dir / filename
        plt.savefig(filepath, dpi=300, bbox_inches='tight')
        plt.close()
        
        return str(filepath)
    
    def create_scatter_plot(
        self,
        x_data: List[float], 
        y_data: List[float], 
        title: str = "Correlation Analysis",
        xlabel: str = "X Values",
        ylabel: str = "Y Values",
        filename: str = "scatter_plot.png"
    ) -> str:
        """
        Create a scatter plot to analyze correlation between metrics.
        
        Args:
            x_data: X-axis values
            y_data: Y-axis values
            title: Chart title
            xlabel: X-axis label
            ylabel: Y-axis label
            filename: Output filename
            
        Returns:
            Path to saved image
        """
        fig, ax = plt.subplots(figsize=(10, 8))
        
        scatter = ax.scatter(x_data, y_data, alpha=0.7, s=60)
        
        # Add trend line
        z = np.polyfit(x_data, y_data, 1)
        p = np.poly1d(z)
        ax.plot(x_data, p(x_data), "r--", alpha=0.8, label=f'Trend line: y={z[0]:.2f}x+{z[1]:.2f}')
        
        ax.set_title(title, fontsize=16, fontweight='bold')
        ax.set_xlabel(xlabel, fontsize=12)
        ax.set_ylabel(ylabel, fontsize=12)
        ax.legend()
        ax.grid(True, alpha=0.3)
        
        plt.tight_layout()
        
        filepath = self.output_dir / filename
        plt.savefig(filepath, dpi=300, bbox_inches='tight')
        plt.close()
        
        return str(filepath)
    
    def create_heatmap(
        self,
        data: List[List[float]], 
        x_labels: List[str], 
        y_labels: List[str],
        title: str = "Multi-dimensional Analysis",
        filename: str = "heatmap.png"
    ) -> str:
        """
        Create a heatmap for multi-dimensional performance analysis.
        
        Args:
            data: 2D list of values
            x_labels: Labels for x-axis
            y_labels: Labels for y-axis
            title: Chart title
            filename: Output filename
            
        Returns:
            Path to saved image
        """
        fig, ax = plt.subplots(figsize=(12, 8))
        
        im = ax.imshow(data, cmap='viridis', aspect='auto', origin='upper')
        
        # Set ticks and labels
        ax.set_xticks(np.arange(len(x_labels)))
        ax.set_yticks(np.arange(len(y_labels)))
        ax.set_xticklabels(x_labels)
        ax.set_yticklabels(y_labels)
        
        # Rotate x-axis labels
        plt.setp(ax.get_xticklabels(), rotation=45, ha="right", rotation_mode="anchor")
        
        # Add colorbar
        cbar = ax.figure.colorbar(im, ax=ax)
        cbar.ax.set_ylabel("Value", rotation=-90, va="bottom")
        
        # Add text annotations
        for i in range(len(y_labels)):
            for j in range(len(x_labels)):
                text = ax.text(j, i, f'{data[i][j]:.2f}',
                             ha="center", va="center", color="white", fontsize=9)
        
        ax.set_title(title, fontsize=16, fontweight='bold')
        plt.tight_layout()
        
        filepath = self.output_dir / filename
        plt.savefig(filepath, dpi=300, bbox_inches='tight')
        plt.close()
        
        return str(filepath)
    
    def create_interactive_comparison_dashboard(
        self,
        benchmark_results: Dict,
        title: str = "Interactive Benchmark Dashboard",
        filename: str = "dashboard.html"
    ) -> str:
        """
        Create an interactive HTML dashboard using Plotly.
        
        Args:
            benchmark_results: Dictionary with benchmark results
            title: Dashboard title
            filename: Output filename
            
        Returns:
            Path to saved HTML file
        """
        # Create subplots
        fig = make_subplots(
            rows=2, cols=2,
            subplot_titles=('Performance Comparison', 'Distribution Analysis', 
                          'Time Series', 'Correlation'),
            specs=[[{"type": "bar"}, {"type": "box"}],
                   [{"type": "scatter"}, {"type": "scatter"}]]
        )
        
        # Add sample data for demonstration (in practice, extract from results)
        tools = ['CyberSec-CLI', 'Nmap', 'Masscan', 'Zmap', 'Rustscan']
        speeds = [100, 85, 150, 120, 90]  # Performance scores
        
        # Bar chart - Performance comparison
        fig.add_trace(
            go.Bar(x=tools, y=speeds, name='Performance Score'),
            row=1, col=1
        )
        
        # Box plot - Distribution
        sample_data = [np.random.normal(speed, speed*0.1, 100) for speed in speeds]
        for i, (tool, data) in enumerate(zip(tools, sample_data)):
            fig.add_trace(
                go.Box(y=data, name=tool, showlegend=False),
                row=1, col=2
            )
        
        # Time series - Performance over time
        time_points = list(range(1, 11))
        perf_values = [100 + np.random.normal(0, 5) for _ in time_points]
        fig.add_trace(
            go.Scatter(x=time_points, y=perf_values, mode='lines+markers', name='Performance Trend'),
            row=2, col=1
        )
        
        # Correlation scatter
        x_vals = np.random.rand(50) * 100
        y_vals = 2 * x_vals + np.random.normal(0, 10, 50)
        fig.add_trace(
            go.Scatter(x=x_vals, y=y_vals, mode='markers', name='Correlation'),
            row=2, col=2
        )
        
        fig.update_layout(height=800, showlegend=True, title_text=title)
        
        filepath = self.output_dir / filename
        fig.write_html(str(filepath))
        
        return str(filepath)
    
    def visualize_from_json_results(
        self, 
        results_file: Union[str, Path],
        output_prefix: str = "benchmark_visualization"
    ) -> List[str]:
        """
        Automatically generate visualizations from a JSON benchmark results file.
        
        Args:
            results_file: Path to JSON results file
            output_prefix: Prefix for output files
            
        Returns:
            List of paths to generated visualizations
        """
        with open(results_file, 'r') as f:
            data = json.load(f)
        
        generated_files = []
        
        # Extract performance metrics for visualization
        metrics_data = self._extract_numeric_metrics(data)
        
        if metrics_data:
            # Create bar chart for top-level metrics
            if len(metrics_data) <= 10:  # Only if not too many items
                bar_data = {k: v[0] if isinstance(v, list) and len(v) > 0 else v 
                           for k, v in list(metrics_data.items())[:10]}
                bar_file = self.create_performance_comparison_bar_chart(
                    bar_data,
                    f"Performance Metrics - {Path(results_file).stem}",
                    f"{output_prefix}_bar_chart.png"
                )
                generated_files.append(bar_file)
            
            # Create distribution plots for metrics that have multiple values
            multi_valued = {k: v for k, v in metrics_data.items() 
                           if isinstance(v, list) and len(v) > 1}
            if multi_valued:
                box_file = self.create_distribution_box_plot(
                    multi_valued,
                    f"Distribution Analysis - {Path(results_file).stem}",
                    f"{output_prefix}_box_plot.png"
                )
                generated_files.append(box_file)
        
        return generated_files
    
    def _extract_numeric_metrics(self, data: Dict) -> Dict[str, Union[float, List[float]]]:
        """Extract numeric metrics from nested dictionary structure."""
        metrics = {}
        
        def extract_recursive(obj, path=""):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    new_path = f"{path}.{key}" if path else key
                    if isinstance(value, (int, float)):
                        metrics[new_path] = [float(value)]
                    elif isinstance(value, list):
                        if all(isinstance(v, (int, float)) for v in value):
                            metrics[new_path] = [float(v) for v in value]
                        else:
                            extract_recursive(value, new_path)
                    else:
                        extract_recursive(value, new_path)
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    new_path = f"{path}[{i}]"
                    extract_recursive(item, new_path)
        
        extract_recursive(data)
        return metrics


def main():
    """Example usage of visualization tools."""
    print("Visualization Tools for CyberSec-CLI Benchmarks")
    print("=" * 50)
    
    visualizer = BenchmarkVisualizer()
    
    # Example 1: Create a performance comparison bar chart
    performance_data = {
        "CyberSec-CLI": 95.5,
        "Nmap": 88.2,
        "Masscan": 92.1,
        "Zmap": 89.7,
        "Rustscan": 85.3
    }
    
    bar_chart = visualizer.create_performance_comparison_bar_chart(
        performance_data,
        "Tool Performance Comparison",
        "example_performance_comparison.png"
    )
    print(f"Created bar chart: {bar_chart}")
    
    # Example 2: Create a distribution box plot
    distribution_data = {
        "CyberSec-CLI": [90, 92, 95, 94, 96, 93, 95, 94, 96, 92],
        "Nmap": [85, 87, 88, 86, 89, 84, 87, 88, 86, 85],
        "Masscan": [91, 93, 92, 94, 91, 93, 92, 94, 93, 92]
    }
    
    box_plot = visualizer.create_distribution_box_plot(
        distribution_data,
        "Performance Distribution Across Tools",
        "example_distribution_boxplot.png"
    )
    print(f"Created box plot: {box_plot}")
    
    # Example 3: Create a time series plot
    time_points = [f"Run {i+1}" for i in range(10)]
    perf_values = [90 + i*0.5 + np.random.normal(0, 1) for i in range(10)]
    
    time_series = visualizer.create_time_series_plot(
        time_points,
        perf_values,
        "Performance Over Time",
        "Score",
        "example_time_series.png"
    )
    print(f"Created time series: {time_series}")
    
    # Example 4: Create a scatter plot
    x_data = np.random.rand(50) * 100
    y_data = 2 * x_data + np.random.normal(0, 10, 50)
    
    scatter_plot = visualizer.create_scatter_plot(
        x_data.tolist(),
        y_data.tolist(),
        "Correlation Analysis",
        "X Metric",
        "Y Metric",
        "example_scatter_plot.png"
    )
    print(f"Created scatter plot: {scatter_plot}")
    
    print(f"\nAll visualizations saved to: {visualizer.output_dir}")


if __name__ == "__main__":
    main()