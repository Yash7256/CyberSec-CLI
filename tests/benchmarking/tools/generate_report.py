"""
Comprehensive benchmark report generator for CyberSec-CLI.
Creates detailed reports with statistical analysis and visualizations.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Union

from tests.benchmarking.tools.statistical_analysis import StatisticalAnalyzer
from tests.benchmarking.tools.visualization import BenchmarkVisualizer


class BenchmarkReportGenerator:
    """
    Generate comprehensive benchmark reports with statistical analysis and visualizations.
    """
    
    def __init__(self):
        """Initialize report generator."""
        self.analyzer = StatisticalAnalyzer()
        self.visualizer = BenchmarkVisualizer()
        self.reports_dir = Path("tests/benchmarking/results/reports")
        self.reports_dir.mkdir(parents=True, exist_ok=True)
    
    def load_benchmark_results(self, results_dir: Union[str, Path]) -> Dict:
        """
        Load all benchmark results from a directory.
        
        Args:
            results_dir: Directory containing benchmark result files
            
        Returns:
            Dictionary with loaded results
        """
        results_dir = Path(results_dir)
        all_results = {}
        
        for json_file in results_dir.rglob("*.json"):
            try:
                with open(json_file, 'r') as f:
                    data = json.load(f)
                    all_results[json_file.stem] = data
            except json.JSONDecodeError:
                print(f"Warning: Could not parse JSON file: {json_file}")
            except Exception as e:
                print(f"Warning: Could not read file {json_file}: {e}")
        
        return all_results
    
    def generate_executive_summary(self, results: Dict) -> str:
        """
        Generate executive summary of benchmark results.
        
        Args:
            results: Loaded benchmark results
            
        Returns:
            Executive summary as string
        """
        summary_parts = []
        summary_parts.append("# Executive Summary\n")
        summary_parts.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        summary_parts.append(f"**Total Result Files:** {len(results)}\n")
        
        # Count different types of tests
        performance_tests = 0
        reliability_tests = 0
        accuracy_tests = 0
        comparative_tests = 0
        other_tests = 0
        
        for name, data in results.items():
            if 'performance' in name.lower():
                performance_tests += 1
            elif 'reliability' in name.lower() or 'stress' in name.lower() or 'chaos' in name.lower():
                reliability_tests += 1
            elif 'accuracy' in name.lower():
                accuracy_tests += 1
            elif 'comparison' in name.lower() or any(tool in name.lower() for tool in ['nmap', 'masscan', 'zmap', 'rustscan']):
                comparative_tests += 1
            else:
                other_tests += 1
        
        summary_parts.append("## Test Categories:\n")
        summary_parts.append(f"- Performance Tests: {performance_tests}\n")
        summary_parts.append(f"- Reliability Tests: {reliability_tests}\n")
        summary_parts.append(f"- Accuracy Tests: {accuracy_tests}\n")
        summary_parts.append(f"- Comparative Tests: {comparative_tests}\n")
        summary_parts.append(f"- Other Tests: {other_tests}\n\n")
        
        return "".join(summary_parts)
    
    def generate_performance_analysis(self, results: Dict) -> str:
        """
        Generate detailed performance analysis section.
        
        Args:
            results: Loaded benchmark results
            
        Returns:
            Performance analysis as string
        """
        analysis_parts = []
        analysis_parts.append("# Performance Analysis\n")
        
        # Look for performance-related results
        perf_results = {k: v for k, v in results.items() 
                       if any(term in k.lower() for term in ['speed', 'throughput', 'performance'])}
        
        if not perf_results:
            analysis_parts.append("*No performance test results found*\n")
        else:
            for test_name, test_data in perf_results.items():
                analysis_parts.append(f"## {test_name.replace('_', ' ').title()} Performance\n")
                
                # Extract performance metrics if available
                if isinstance(test_data, dict):
                    if 'duration' in test_data:
                        analysis_parts.append(f"- Duration: {test_data['duration']:.2f}s\n")
                    if 'throughput' in test_data:
                        analysis_parts.append(f"- Throughput: {test_data['throughput']:.2f} ops/sec\n")
                    if 'memory_diff_mb' in test_data:
                        analysis_parts.append(f"- Memory Change: {test_data['memory_diff_mb']:.2f} MB\n")
        
        analysis_parts.append("\n")
        return "".join(analysis_parts)
    
    def generate_reliability_analysis(self, results: Dict) -> str:
        """
        Generate detailed reliability analysis section.
        
        Args:
            results: Loaded benchmark results
            
        Returns:
            Reliability analysis as string
        """
        analysis_parts = []
        analysis_parts.append("# Reliability Analysis\n")
        
        # Look for reliability-related results
        rel_results = {k: v for k, v in results.items() 
                      if any(term in k.lower() for term in ['stress', 'reliability', 'endurance', 'chaos'])}
        
        if not rel_results:
            analysis_parts.append("*No reliability test results found*\n")
        else:
            for test_name, test_data in rel_results.items():
                analysis_parts.append(f"## {test_name.replace('_', ' ').title()} Reliability\n")
                
                # Extract reliability metrics if available
                if isinstance(test_data, dict):
                    if 'success_rate' in test_data:
                        analysis_parts.append(f"- Success Rate: {test_data['success_rate']:.2%}\n")
                    if 'error_count' in test_data:
                        analysis_parts.append(f"- Errors: {test_data['error_count']}\n")
                    if 'failures' in test_data:
                        analysis_parts.append(f"- Failures: {test_data['failures']}\n")
        
        analysis_parts.append("\n")
        return "".join(analysis_parts)
    
    def generate_accuracy_analysis(self, results: Dict) -> str:
        """
        Generate detailed accuracy analysis section.
        
        Args:
            results: Loaded benchmark results
            
        Returns:
            Accuracy analysis as string
        """
        analysis_parts = []
        analysis_parts.append("# Accuracy Analysis\n")
        
        # Look for accuracy-related results
        acc_results = {k: v for k, v in results.items() 
                      if any(term in k.lower() for term in ['accuracy', 'detection', 'precision', 'recall', 'f1'])}
        
        if not acc_results:
            analysis_parts.append("*No accuracy test results found*\n")
        else:
            for test_name, test_data in acc_results.items():
                analysis_parts.append(f"## {test_name.replace('_', ' ').title()} Accuracy\n")
                
                # Extract accuracy metrics if available
                if isinstance(test_data, dict):
                    if 'precision' in test_data:
                        analysis_parts.append(f"- Precision: {test_data['precision']:.4f}\n")
                    if 'recall' in test_data:
                        analysis_parts.append(f"- Recall: {test_data['recall']:.4f}\n")
                    if 'f1_score' in test_data:
                        analysis_parts.append(f"- F1 Score: {test_data['f1_score']:.4f}\n")
                    if 'accuracy' in test_data:
                        analysis_parts.append(f"- Overall Accuracy: {test_data['accuracy']:.4f}\n")
        
        analysis_parts.append("\n")
        return "".join(analysis_parts)
    
    def generate_comparative_analysis(self, results: Dict) -> str:
        """
        Generate detailed comparative analysis section.
        
        Args:
            results: Loaded benchmark results
            
        Returns:
            Comparative analysis as string
        """
        analysis_parts = []
        analysis_parts.append("# Comparative Analysis\n")
        
        # Look for comparative results
        comp_results = {k: v for k, v in results.items() 
                       if any(tool in k.lower() for tool in ['nmap', 'masscan', 'zmap', 'rustscan', 'comparison'])}
        
        if not comp_results:
            analysis_parts.append("*No comparative test results found*\n")
        else:
            for test_name, test_data in comp_results.items():
                analysis_parts.append(f"## {test_name.replace('_', ' ').title()} Comparison\n")
                
                # Extract comparative metrics if available
                if isinstance(test_data, dict):
                    # Look for tool comparison data
                    for key, value in test_data.items():
                        if isinstance(value, dict) and 'duration' in value:
                            analysis_parts.append(f"- {key}: {value['duration']:.2f}s\n")
        
        analysis_parts.append("\n")
        return "".join(analysis_parts)
    
    def generate_statistical_insights(self, results: Dict) -> str:
        """
        Generate statistical insights and analysis.
        
        Args:
            results: Loaded benchmark results
            
        Returns:
            Statistical insights as string
        """
        analysis_parts = []
        analysis_parts.append("# Statistical Insights\n")
        
        # Extract numeric data for statistical analysis
        numeric_data = self._extract_numeric_data(results)
        
        if not numeric_data:
            analysis_parts.append("*No numeric data available for statistical analysis*\n")
        else:
            analysis_parts.append("## Key Statistical Findings\n")
            
            for metric_name, values in list(numeric_data.items())[:5]:  # Limit to first 5
                if len(values) >= 2:
                    try:
                        # Calculate basic statistics
                        mean_val = sum(values) / len(values)
                        min_val = min(values)
                        max_val = max(values)
                        
                        analysis_parts.append(f"- **{metric_name}**: Mean={mean_val:.2f}, Min={min_val:.2f}, Max={max_val:.2f}\n")
                        
                        # Calculate confidence interval if possible
                        if len(values) >= 2:
                            ci_result = self.analyzer.calculate_confidence_interval(values)
                            if 'error' not in ci_result:
                                analysis_parts.append(f"  - 95% Confidence Interval: [{ci_result['interval_lower']:.2f}, {ci_result['interval_upper']:.2f}]\n")
                    
                    except Exception as e:
                        analysis_parts.append(f"- **{metric_name}**: Error calculating statistics: {e}\n")
        
        analysis_parts.append("\n")
        return "".join(analysis_parts)
    
    def _extract_numeric_data(self, results: Dict) -> Dict[str, List[float]]:
        """Extract numeric data from results for statistical analysis."""
        numeric_data = {}
        
        def extract_recursive(obj, path=""):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    new_path = f"{path}.{key}" if path else key
                    if isinstance(value, (int, float)):
                        if new_path not in numeric_data:
                            numeric_data[new_path] = []
                        numeric_data[new_path].append(float(value))
                    elif isinstance(value, list):
                        if all(isinstance(v, (int, float)) for v in value):
                            numeric_data[new_path] = [float(v) for v in value]
                        else:
                            extract_recursive(value, new_path)
                    else:
                        extract_recursive(value, new_path)
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    new_path = f"{path}[{i}]"
                    extract_recursive(item, new_path)
        
        for result_name, result_data in results.items():
            extract_recursive(result_data, result_name)
        
        return numeric_data
    
    def generate_recommendations(self, results: Dict) -> str:
        """
        Generate recommendations based on benchmark results.
        
        Args:
            results: Loaded benchmark results
            
        Returns:
            Recommendations as string
        """
        rec_parts = []
        rec_parts.append("# Recommendations\n")
        
        # Analyze results to generate recommendations
        perf_issues = []
        reliability_concerns = []
        accuracy_improvements = []
        
        for test_name, test_data in results.items():
            if isinstance(test_data, dict):
                # Check for performance issues
                if 'duration' in test_data and test_data['duration'] > 10:  # Arbitrary threshold
                    perf_issues.append(f"{test_name}: Duration {test_data['duration']:.2f}s may be excessive")
                
                # Check for reliability concerns
                if 'success_rate' in test_data and test_data['success_rate'] < 0.95:  # Below 95%
                    reliability_concerns.append(f"{test_name}: Success rate {test_data['success_rate']:.2%} is low")
                
                # Check for accuracy improvements needed
                if 'f1_score' in test_data and test_data['f1_score'] < 0.90:  # Below 90%
                    accuracy_improvements.append(f"{test_name}: F1 score {test_data['f1_score']:.3f} could be improved")
        
        if perf_issues:
            rec_parts.append("## Performance Recommendations\n")
            for issue in perf_issues:
                rec_parts.append(f"- {issue}\n")
            rec_parts.append("\n")
        
        if reliability_concerns:
            rec_parts.append("## Reliability Recommendations\n")
            for concern in reliability_concerns:
                rec_parts.append(f"- {concern}\n")
            rec_parts.append("\n")
        
        if accuracy_improvements:
            rec_parts.append("## Accuracy Recommendations\n")
            for improvement in accuracy_improvements:
                rec_parts.append(f"- {improvement}\n")
            rec_parts.append("\n")
        
        if not any([perf_issues, reliability_concerns, accuracy_improvements]):
            rec_parts.append("No immediate issues detected in the analyzed metrics.\n")
        
        return "".join(rec_parts)
    
    def generate_markdown_report(self, results: Dict, filename: str = "benchmark_report.md") -> str:
        """
        Generate a comprehensive markdown report.
        
        Args:
            results: Loaded benchmark results
            filename: Output filename
            
        Returns:
            Path to generated report
        """
        report_content = []
        
        # Add title
        report_content.append("# CyberSec-CLI Benchmark Report\n")
        report_content.append(f"**Generated on:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        # Add executive summary
        report_content.append(self.generate_executive_summary(results))
        
        # Add performance analysis
        report_content.append(self.generate_performance_analysis(results))
        
        # Add reliability analysis
        report_content.append(self.generate_reliability_analysis(results))
        
        # Add accuracy analysis
        report_content.append(self.generate_accuracy_analysis(results))
        
        # Add comparative analysis
        report_content.append(self.generate_comparative_analysis(results))
        
        # Add statistical insights
        report_content.append(self.generate_statistical_insights(results))
        
        # Add recommendations
        report_content.append(self.generate_recommendations(results))
        
        # Write report to file
        report_path = self.reports_dir / filename
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write("".join(report_content))
        
        print(f"Comprehensive benchmark report generated: {report_path}")
        return str(report_path)
    
    def generate_visualizations(self, results: Dict, output_prefix: str = "benchmark_viz") -> List[str]:
        """
        Generate visualizations from benchmark results.
        
        Args:
            results: Loaded benchmark results
            output_prefix: Prefix for output files
            
        Returns:
            List of paths to generated visualizations
        """
        all_generated_files = []
        
        # Generate visualizations for each result file
        for result_name, result_data in results.items():
            try:
                # Try to create visualizations from this result
                viz_files = self.visualizer.visualize_from_json_results(
                    f"/tmp/{result_name}_temp.json",  # This would need to be written first
                    f"{output_prefix}_{result_name}"
                )
                all_generated_files.extend(viz_files)
            except Exception as e:
                print(f"Could not generate visualizations for {result_name}: {e}")
        
        return all_generated_files


def main():
    """Example usage of the benchmark report generator."""
    print("CyberSec-CLI Benchmark Report Generator")
    print("=" * 45)
    
    generator = BenchmarkReportGenerator()
    
    # Load sample results (in a real scenario, this would load from the results directory)
    sample_results = {
        "speed_throughput_results": {
            "single_port": {"mean_latency_ms": 15.2, "median_latency_ms": 14.8},
            "100_ports": {"duration": 2.45, "throughput": 40.82},
            "1000_ports": {"duration": 18.73, "throughput": 53.39}
        },
        "stress_test_results": {
            "cpu_stress": {"avg_cpu_percent": 94.2, "success_rate": 0.98},
            "memory_stress": {"memory_peak_mb": 485.6, "success_rate": 0.95}
        },
        "accuracy_analysis_results": {
            "port_detection": {
                "localhost_services": {
                    "precision": 0.96, "recall": 0.94, "f1_score": 0.95
                }
            }
        }
    }
    
    # Generate the report
    report_path = generator.generate_markdown_report(sample_results)
    print(f"Report generated at: {report_path}")
    
    print("\nReport generation complete!")


if __name__ == "__main__":
    main()