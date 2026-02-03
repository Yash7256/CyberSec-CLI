"""
Statistical analysis tools for CyberSec-CLI benchmark results.
Provides advanced statistical analysis, hypothesis testing, and regression detection.
"""

import json
import math
from pathlib import Path
from typing import Dict, List, Union
from scipy import stats
import numpy as np


class StatisticalAnalyzer:
    """
    Advanced statistical analysis for benchmark results.
    
    Provides:
    - Hypothesis testing
    - Confidence intervals
    - Regression detection
    - Effect size calculations
    - Outlier detection
    """
    
    def __init__(self):
        """Initialize statistical analyzer."""
        self.alpha = 0.05  # Default significance level
    
    def calculate_confidence_interval(self, data: List[float], confidence: float = 0.95) -> Dict:
        """
        Calculate confidence interval for a dataset.
        
        Args:
            data: List of numerical values
            confidence: Confidence level (0-1)
            
        Returns:
            Dictionary with confidence interval information
        """
        if len(data) < 2:
            return {"error": "Need at least 2 data points for confidence interval"}
        
        mean = sum(data) / len(data)
        std_error = np.std(data, ddof=1) / math.sqrt(len(data))  # Standard error
        
        # Calculate t-value for given confidence level
        df = len(data) - 1  # degrees of freedom
        t_value = stats.t.ppf((1 + confidence) / 2, df)
        
        margin_error = t_value * std_error
        ci_lower = mean - margin_error
        ci_upper = mean + margin_error
        
        return {
            "mean": mean,
            "std_error": std_error,
            "confidence_level": confidence,
            "margin_of_error": margin_error,
            "interval_lower": ci_lower,
            "interval_upper": ci_upper,
            "sample_size": len(data)
        }
    
    def perform_t_test(self, sample1: List[float], sample2: List[float]) -> Dict:
        """
        Perform two-sample t-test to compare two datasets.
        
        Args:
            sample1: First sample dataset
            sample2: Second sample dataset
            
        Returns:
            Dictionary with t-test results
        """
        if len(sample1) < 2 or len(sample2) < 2:
            return {"error": "Need at least 2 data points in each sample"}
        
        # Perform two-sample t-test
        t_stat, p_value = stats.ttest_ind(sample1, sample2)
        
        # Calculate effect size (Cohen's d)
        pooled_std = math.sqrt(((len(sample1) - 1) * np.var(sample1, ddof=1) + 
                               (len(sample2) - 1) * np.var(sample2, ddof=1)) / 
                              (len(sample1) + len(sample2) - 2))
        mean_diff = abs(np.mean(sample1) - np.mean(sample2))
        cohens_d = mean_diff / pooled_std if pooled_std != 0 else 0
        
        # Determine significance
        significant = p_value < self.alpha
        
        return {
            "t_statistic": t_stat,
            "p_value": p_value,
            "degrees_of_freedom": len(sample1) + len(sample2) - 2,
            "significant_difference": significant,
            "effect_size_cohens_d": cohens_d,
            "sample1_mean": np.mean(sample1),
            "sample2_mean": np.mean(sample2),
            "sample1_size": len(sample1),
            "sample2_size": len(sample2),
            "interpretation": self._interpret_cohens_d(cohens_d)
        }
    
    def _interpret_cohens_d(self, cohens_d: float) -> str:
        """Interpret Cohen's d effect size."""
        if cohens_d < 0.2:
            return "negligible"
        elif cohens_d < 0.5:
            return "small"
        elif cohens_d < 0.8:
            return "medium"
        else:
            return "large"
    
    def detect_outliers(self, data: List[float], method: str = "iqr") -> Dict:
        """
        Detect outliers in a dataset using various methods.
        
        Args:
            data: Dataset to analyze
            method: Method to use ('iqr', 'zscore', 'modified_zscore')
            
        Returns:
            Dictionary with outlier detection results
        """
        if len(data) < 3:
            return {"error": "Need at least 3 data points to detect outliers"}
        
        if method == "iqr":
            return self._detect_outliers_iqr(data)
        elif method == "zscore":
            return self._detect_outliers_zscore(data)
        elif method == "modified_zscore":
            return self._detect_outliers_modified_zscore(data)
        else:
            return {"error": f"Unknown method: {method}"}
    
    def _detect_outliers_iqr(self, data: List[float]) -> Dict:
        """Detect outliers using Interquartile Range method."""
        sorted_data = sorted(data)
        n = len(sorted_data)
        
        # Calculate quartiles
        q1_idx = n // 4
        q3_idx = 3 * n // 4
        q1 = sorted_data[q1_idx]
        q3 = sorted_data[q3_idx]
        
        iqr = q3 - q1
        lower_bound = q1 - 1.5 * iqr
        upper_bound = q3 + 1.5 * iqr
        
        outliers = [x for x in data if x < lower_bound or x > upper_bound]
        outlier_indices = [i for i, x in enumerate(data) if x < lower_bound or x > upper_bound]
        
        return {
            "method": "iqr",
            "q1": q1,
            "q3": q3,
            "iqr": iqr,
            "lower_bound": lower_bound,
            "upper_bound": upper_bound,
            "outliers": outliers,
            "outlier_indices": outlier_indices,
            "outlier_count": len(outliers),
            "outlier_percentage": len(outliers) / len(data) * 100
        }
    
    def _detect_outliers_zscore(self, data: List[float]) -> Dict:
        """Detect outliers using Z-score method."""
        mean = sum(data) / len(data)
        std = np.std(data)
        
        if std == 0:
            return {"error": "Standard deviation is zero, cannot calculate z-scores"}
        
        z_scores = [(x - mean) / std for x in data]
        outliers = [data[i] for i, z in enumerate(z_scores) if abs(z) > 3.0]
        outlier_indices = [i for i, z in enumerate(z_scores) if abs(z) > 3.0]
        
        return {
            "method": "zscore",
            "mean": mean,
            "std": std,
            "threshold": 3.0,
            "outliers": outliers,
            "outlier_indices": outlier_indices,
            "outlier_count": len(outliers),
            "outlier_percentage": len(outliers) / len(data) * 100
        }
    
    def _detect_outliers_modified_zscore(self, data: List[float]) -> Dict:
        """Detect outliers using Modified Z-score method (uses median)."""
        median = np.median(data)
        mad = np.median([abs(x - median) for x in data])  # Median Absolute Deviation
        
        if mad == 0:
            return {"error": "Median Absolute Deviation is zero, cannot calculate modified z-scores"}
        
        modified_z_scores = [0.6745 * (x - median) / mad for x in data]
        outliers = [data[i] for i, mz in enumerate(modified_z_scores) if abs(mz) > 3.5]
        outlier_indices = [i for i, mz in enumerate(modified_z_scores) if abs(mz) > 3.5]
        
        return {
            "method": "modified_zscore",
            "median": median,
            "mad": mad,
            "threshold": 3.5,
            "outliers": outliers,
            "outlier_indices": outlier_indices,
            "outlier_count": len(outliers),
            "outlier_percentage": len(outliers) / len(data) * 100
        }
    
    def detect_regression(self, baseline_data: List[float], current_data: List[float], 
                         threshold: float = 0.05) -> Dict:
        """
        Detect performance regression between baseline and current results.
        
        Args:
            baseline_data: Baseline performance data
            current_data: Current performance data
            threshold: Threshold for considering regression (e.g., 0.05 for 5%)
            
        Returns:
            Dictionary with regression analysis results
        """
        if len(baseline_data) < 2 or len(current_data) < 2:
            return {"error": "Need at least 2 data points for each sample"}
        
        baseline_mean = np.mean(baseline_data)
        current_mean = np.mean(current_data)
        
        # Calculate percentage change
        if baseline_mean != 0:
            percent_change = (current_mean - baseline_mean) / abs(baseline_mean)
        else:
            percent_change = float('inf') if current_mean > 0 else 0
        
        # Perform t-test to check if difference is statistically significant
        t_test_result = self.perform_t_test(baseline_data, current_data)
        
        # Determine if regression occurred
        regression_detected = (percent_change > threshold and 
                             t_test_result.get("significant_difference", False))
        
        # Calculate practical significance (minimal meaningful difference)
        mmd = threshold * baseline_mean  # Minimal meaningful difference
        
        return {
            "baseline_mean": baseline_mean,
            "current_mean": current_mean,
            "percent_change": percent_change,
            "percent_change_readable": f"{percent_change * 100:+.2f}%",
            "threshold": threshold,
            "threshold_readable": f"{threshold * 100:.2f}%",
            "regression_detected": regression_detected,
            "statistical_significance": t_test_result.get("significant_difference", False),
            "practical_significance": abs(percent_change) > threshold,
            "t_test_result": t_test_result,
            "minimal_meaningful_difference": mmd,
            "confidence_in_regression": (
                t_test_result.get("significant_difference", False) and 
                abs(percent_change) > threshold
            )
        }
    
    def calculate_correlation(self, x_data: List[float], y_data: List[float]) -> Dict:
        """
        Calculate correlation between two datasets.
        
        Args:
            x_data: First dataset
            y_data: Second dataset
            
        Returns:
            Dictionary with correlation results
        """
        if len(x_data) != len(y_data) or len(x_data) < 2:
            return {"error": "Datasets must have equal length and at least 2 points"}
        
        # Calculate Pearson correlation coefficient
        corr_coef, p_value = stats.pearsonr(x_data, y_data)
        
        # Calculate Spearman rank correlation (non-parametric)
        spearman_coef, spearman_p = stats.spearmanr(x_data, y_data)
        
        return {
            "pearson_correlation": corr_coef,
            "pearson_p_value": p_value,
            "spearman_correlation": spearman_coef,
            "spearman_p_value": spearman_p,
            "sample_size": len(x_data),
            "correlation_strength": self._interpret_correlation(corr_coef),
            "significant_correlation": p_value < self.alpha
        }
    
    def _interpret_correlation(self, r: float) -> str:
        """Interpret correlation strength."""
        abs_r = abs(r)
        if abs_r < 0.1:
            return "negligible"
        elif abs_r < 0.3:
            return "weak"
        elif abs_r < 0.5:
            return "moderate"
        elif abs_r < 0.7:
            return "strong"
        else:
            return "very strong"


class BenchmarkComparator:
    """
    Compare benchmark results and detect performance changes.
    """
    
    def __init__(self):
        self.analyzer = StatisticalAnalyzer()
    
    def compare_results(self, baseline_file: Union[str, Path], 
                       current_file: Union[str, Path]) -> Dict:
        """
        Compare two benchmark result files.
        
        Args:
            baseline_file: Path to baseline results file
            current_file: Path to current results file
            
        Returns:
            Dictionary with comparison results
        """
        try:
            with open(baseline_file, 'r') as f:
                baseline_data = json.load(f)
            
            with open(current_file, 'r') as f:
                current_data = json.load(f)
            
            # Extract performance metrics (assuming they're stored as lists of values)
            baseline_metrics = self._extract_metrics(baseline_data)
            current_metrics = self._extract_metrics(current_data)
            
            comparison_results = {}
            
            for metric_name, baseline_values in baseline_metrics.items():
                if metric_name in current_metrics:
                    current_values = current_metrics[metric_name]
                    
                    # Perform statistical comparison
                    t_test_result = self.analyzer.perform_t_test(baseline_values, current_values)
                    regression_result = self.analyzer.detect_regression(
                        baseline_values, current_values
                    )
                    
                    comparison_results[metric_name] = {
                        "baseline_stats": {
                            "mean": np.mean(baseline_values),
                            "std": np.std(baseline_values),
                            "min": min(baseline_values),
                            "max": max(baseline_values),
                            "count": len(baseline_values)
                        },
                        "current_stats": {
                            "mean": np.mean(current_values),
                            "std": np.std(current_values),
                            "min": min(current_values),
                            "max": max(current_values),
                            "count": len(current_values)
                        },
                        "t_test": t_test_result,
                        "regression_analysis": regression_result
                    }
            
            return {
                "comparison_date": "now",  # Would be actual timestamp
                "baseline_file": str(baseline_file),
                "current_file": str(current_file),
                "metrics_compared": list(comparison_results.keys()),
                "detailed_results": comparison_results
            }
            
        except FileNotFoundError as e:
            return {"error": f"File not found: {e}"}
        except json.JSONDecodeError:
            return {"error": "Invalid JSON in result files"}
        except Exception as e:
            return {"error": f"Comparison failed: {str(e)}"}
    
    def _extract_metrics(self, data: Dict) -> Dict[str, List[float]]:
        """Extract numeric metrics from benchmark result data."""
        metrics = {}
        
        def extract_recursive(obj, path=""):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    new_path = f"{path}.{key}" if path else key
                    if isinstance(value, (int, float)):
                        metrics[new_path] = [float(value)]
                    elif isinstance(value, list) and all(isinstance(v, (int, float)) for v in value):
                        metrics[new_path] = [float(v) for v in value]
                    else:
                        extract_recursive(value, new_path)
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    new_path = f"{path}[{i}]"
                    extract_recursive(item, new_path)
        
        extract_recursive(data)
        return metrics


def main():
    """Example usage of statistical analysis tools."""
    print("Statistical Analysis Tools for CyberSec-CLI Benchmarks")
    print("=" * 50)
    
    # Example: Compare two sets of performance results
    analyzer = StatisticalAnalyzer()
    
    # Simulated performance data (e.g., execution times in milliseconds)
    baseline_times = [100, 105, 98, 102, 101, 99, 103, 104, 100, 97]
    current_times = [110, 115, 108, 112, 111, 109, 113, 114, 110, 107]
    
    print("Sample datasets:")
    print(f"Baseline times: {baseline_times}")
    print(f"Current times: {current_times}")
    print()
    
    # Calculate confidence intervals
    baseline_ci = analyzer.calculate_confidence_interval(baseline_times)
    current_ci = analyzer.calculate_confidence_interval(current_times)
    
    print("Confidence Intervals:")
    print(f"Baseline: {baseline_ci['interval_lower']:.2f} - {baseline_ci['interval_upper']:.2f} ms")
    print(f"Current:  {current_ci['interval_lower']:.2f} - {current_ci['interval_upper']:.2f} ms")
    print()
    
    # Perform t-test
    t_test = analyzer.perform_t_test(baseline_times, current_times)
    print("T-Test Results:")
    print(f"Significant difference: {t_test['significant_difference']}")
    print(f"Effect size: {t_test['effect_size_cohens_d']:.2f} ({t_test['interpretation']})")
    print()
    
    # Detect regression
    regression = analyzer.detect_regression(baseline_times, current_times)
    print("Regression Analysis:")
    print(f"Regression detected: {regression['regression_detected']}")
    print(f"Performance change: {regression['percent_change_readable']}")
    print()
    
    # Detect outliers
    outliers = analyzer.detect_outliers(current_times, method="iqr")
    print(f"Outliers detected: {outliers['outlier_count']}")
    print(f"Outlier values: {outliers['outliers']}")


if __name__ == "__main__":
    main()