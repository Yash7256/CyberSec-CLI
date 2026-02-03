"""
Statistical analysis utilities for benchmark results.
Provides hypothesis testing, confidence intervals, and comparative analysis.
"""

import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
from scipy import stats


class StatisticalAnalyzer:
    """
    Provides statistical analysis for benchmark results.
    
    Includes:
    - Hypothesis testing (t-tests, ANOVA)
    - Confidence intervals
    - Effect size calculation
    - Outlier detection
    """

    @staticmethod
    def calculate_confidence_interval(
        data: List[float], confidence: float = 0.95
    ) -> Tuple[float, float, float]:
        """
        Calculate confidence interval for data.
        
        Args:
            data: List of values
            confidence: Confidence level (default 0.95 for 95%)
            
        Returns:
            Tuple of (mean, lower_bound, upper_bound)
        """
        if not data:
            return (0, 0, 0)

        data_array = np.array(data)
        mean = np.mean(data_array)
        sem = stats.sem(data_array)  # Standard error of mean
        interval = sem * stats.t.ppf((1 + confidence) / 2, len(data) - 1)

        return (mean, mean - interval, mean + interval)

    @staticmethod
    def t_test_independent(
        sample1: List[float], sample2: List[float], alpha: float = 0.05
    ) -> Dict[str, any]:
        """
        Perform independent t-test to compare two samples.
        
        Args:
            sample1: First sample
            sample2: Second sample
            alpha: Significance level (default 0.05)
            
        Returns:
            Dictionary with test results
        """
        if not sample1 or not sample2:
            return {"error": "Empty samples"}

        # Perform t-test
        t_statistic, p_value = stats.ttest_ind(sample1, sample2)

        # Calculate effect size (Cohen's d)
        mean1, mean2 = np.mean(sample1), np.mean(sample2)
        std1, std2 = np.std(sample1, ddof=1), np.std(sample2, ddof=1)
        pooled_std = np.sqrt(((len(sample1) - 1) * std1**2 + (len(sample2) - 1) * std2**2) / (len(sample1) + len(sample2) - 2))
        cohens_d = (mean1 - mean2) / pooled_std if pooled_std > 0 else 0

        return {
            "t_statistic": t_statistic,
            "p_value": p_value,
            "significant": p_value < alpha,
            "alpha": alpha,
            "cohens_d": cohens_d,
            "effect_size": (
                "small" if abs(cohens_d) < 0.5
                else "medium" if abs(cohens_d) < 0.8
                else "large"
            ),
            "sample1_mean": mean1,
            "sample2_mean": mean2,
            "sample1_std": std1,
            "sample2_std": std2,
        }

    @staticmethod
    def paired_t_test(
        before: List[float], after: List[float], alpha: float = 0.05
    ) -> Dict[str, any]:
        """
        Perform paired t-test (for before/after comparisons).
        
        Args:
            before: Measurements before treatment
            after: Measurements after treatment
            alpha: Significance level
            
        Returns:
            Dictionary with test results
        """
        if not before or not after or len(before) != len(after):
            return {"error": "Invalid samples"}

        t_statistic, p_value = stats.ttest_rel(before, after)

        differences = np.array(after) - np.array(before)
        mean_diff = np.mean(differences)
        std_diff = np.std(differences, ddof=1)

        return {
            "t_statistic": t_statistic,
            "p_value": p_value,
            "significant": p_value < alpha,
            "alpha": alpha,
            "mean_difference": mean_diff,
            "std_difference": std_diff,
        }

    @staticmethod
    def anova(groups: List[List[float]], alpha: float = 0.05) -> Dict[str, any]:
        """
        Perform one-way ANOVA to compare multiple groups.
        
        Args:
            groups: List of groups (each group is a list of values)
            alpha: Significance level
            
        Returns:
            Dictionary with ANOVA results
        """
        if len(groups) < 2:
            return {"error": "Need at least 2 groups"}

        f_statistic, p_value = stats.f_oneway(*groups)

        return {
            "f_statistic": f_statistic,
            "p_value": p_value,
            "significant": p_value < alpha,
            "alpha": alpha,
            "num_groups": len(groups),
        }

    @staticmethod
    def detect_outliers_iqr(data: List[float], multiplier: float = 1.5) -> Dict[str, any]:
        """
        Detect outliers using IQR method.
        
        Args:
            data: List of values
            multiplier: IQR multiplier (default 1.5)
            
        Returns:
            Dictionary with outlier information
        """
        if not data:
            return {"outliers": [], "outlier_indices": []}

        data_array = np.array(data)
        q1 = np.percentile(data_array, 25)
        q3 = np.percentile(data_array, 75)
        iqr = q3 - q1

        lower_bound = q1 - multiplier * iqr
        upper_bound = q3 + multiplier * iqr

        outlier_mask = (data_array < lower_bound) | (data_array > upper_bound)
        outliers = data_array[outlier_mask].tolist()
        outlier_indices = np.where(outlier_mask)[0].tolist()

        return {
            "outliers": outliers,
            "outlier_indices": outlier_indices,
            "lower_bound": lower_bound,
            "upper_bound": upper_bound,
            "q1": q1,
            "q3": q3,
            "iqr": iqr,
        }

    @staticmethod
    def detect_outliers_zscore(data: List[float], threshold: float = 3.0) -> Dict[str, any]:
        """
        Detect outliers using Z-score method.
        
        Args:
            data: List of values
            threshold: Z-score threshold (default 3.0)
            
        Returns:
            Dictionary with outlier information
        """
        if not data:
            return {"outliers": [], "outlier_indices": []}

        data_array = np.array(data)
        mean = np.mean(data_array)
        std = np.std(data_array)

        if std == 0:
            return {"outliers": [], "outlier_indices": []}

        z_scores = np.abs((data_array - mean) / std)
        outlier_mask = z_scores > threshold

        outliers = data_array[outlier_mask].tolist()
        outlier_indices = np.where(outlier_mask)[0].tolist()

        return {
            "outliers": outliers,
            "outlier_indices": outlier_indices,
            "threshold": threshold,
            "mean": mean,
            "std": std,
        }

    @staticmethod
    def calculate_percentiles(
        data: List[float], percentiles: List[int] = [50, 75, 90, 95, 99]
    ) -> Dict[int, float]:
        """
        Calculate percentiles for data.
        
        Args:
            data: List of values
            percentiles: List of percentile values to calculate
            
        Returns:
            Dictionary mapping percentile to value
        """
        if not data:
            return {}

        data_array = np.array(data)
        return {p: np.percentile(data_array, p) for p in percentiles}

    @staticmethod
    def regression_analysis(
        x: List[float], y: List[float]
    ) -> Dict[str, any]:
        """
        Perform simple linear regression.
        
        Args:
            x: Independent variable
            y: Dependent variable
            
        Returns:
            Dictionary with regression results
        """
        if not x or not y or len(x) != len(y):
            return {"error": "Invalid data"}

        slope, intercept, r_value, p_value, std_err = stats.linregress(x, y)

        return {
            "slope": slope,
            "intercept": intercept,
            "r_squared": r_value**2,
            "p_value": p_value,
            "std_err": std_err,
            "correlation": r_value,
        }


class BenchmarkComparator:
    """
    Compare benchmark results across different runs or tools.
    """

    @staticmethod
    def compare_two_benchmarks(
        baseline_file: Path,
        current_file: Path,
        metric: str = "duration",
        alpha: float = 0.05,
    ) -> Dict[str, any]:
        """
        Compare two benchmark result files.
        
        Args:
            baseline_file: Path to baseline results
            current_file: Path to current results
            metric: Metric to compare (e.g., 'duration', 'throughput')
            alpha: Significance level for statistical tests
            
        Returns:
            Dictionary with comparison results
        """
        # Load results
        with open(baseline_file, "r") as f:
            baseline_data = json.load(f)

        with open(current_file, "r") as f:
            current_data = json.load(f)

        # Extract metric values
        baseline_values = [r[metric] for r in baseline_data.get("results", [])]
        current_values = [r[metric] for r in current_data.get("results", [])]

        if not baseline_values or not current_values:
            return {"error": "No data to compare"}

        # Statistical comparison
        analyzer = StatisticalAnalyzer()
        t_test_result = analyzer.t_test_independent(baseline_values, current_values, alpha)

        # Calculate change
        baseline_mean = np.mean(baseline_values)
        current_mean = np.mean(current_values)
        percent_change = ((current_mean - baseline_mean) / baseline_mean * 100) if baseline_mean > 0 else 0

        # Confidence intervals
        baseline_ci = analyzer.calculate_confidence_interval(baseline_values)
        current_ci = analyzer.calculate_confidence_interval(current_values)

        return {
            "metric": metric,
            "baseline": {
                "mean": baseline_mean,
                "std": np.std(baseline_values),
                "confidence_interval": baseline_ci,
                "n": len(baseline_values),
            },
            "current": {
                "mean": current_mean,
                "std": np.std(current_values),
                "confidence_interval": current_ci,
                "n": len(current_values),
            },
            "comparison": {
                "percent_change": percent_change,
                "absolute_change": current_mean - baseline_mean,
                "improved": current_mean < baseline_mean if metric == "duration" else current_mean > baseline_mean,
            },
            "statistical_test": t_test_result,
        }

    @staticmethod
    def detect_regression(
        baseline_file: Path,
        current_file: Path,
        threshold: float = 0.05,
        metric: str = "duration",
    ) -> Dict[str, any]:
        """
        Detect performance regression.
        
        Args:
            baseline_file: Path to baseline results
            current_file: Path to current results
            threshold: Regression threshold (e.g., 0.05 = 5% worse)
            metric: Metric to check
            
        Returns:
            Dictionary with regression detection results
        """
        comparison = BenchmarkComparator.compare_two_benchmarks(
            baseline_file, current_file, metric
        )

        if "error" in comparison:
            return comparison

        # For duration, regression means increase
        # For throughput, regression means decrease
        if metric == "duration":
            regression = comparison["comparison"]["percent_change"] > (threshold * 100)
        else:
            regression = comparison["comparison"]["percent_change"] < -(threshold * 100)

        return {
            "regression_detected": regression,
            "threshold_percent": threshold * 100,
            "actual_change_percent": comparison["comparison"]["percent_change"],
            "statistically_significant": comparison["statistical_test"]["significant"],
            "comparison": comparison,
        }


class PerformanceBudget:
    """
    Define and check performance budgets.
    """

    def __init__(self, budgets: Dict[str, Dict[str, float]]):
        """
        Initialize performance budget.
        
        Args:
            budgets: Dictionary of metric budgets
                Example: {
                    "duration": {"max": 10.0, "target": 5.0},
                    "memory_mb": {"max": 500, "target": 250},
                }
        """
        self.budgets = budgets

    def check_budget(self, results: Dict[str, float]) -> Dict[str, any]:
        """
        Check if results meet performance budget.
        
        Args:
            results: Dictionary of metric values
            
        Returns:
            Dictionary with budget check results
        """
        violations = []
        warnings = []
        passed = []

        for metric, budget in self.budgets.items():
            if metric not in results:
                continue

            value = results[metric]
            max_value = budget.get("max")
            target_value = budget.get("target")

            if max_value is not None and value > max_value:
                violations.append({
                    "metric": metric,
                    "value": value,
                    "max": max_value,
                    "exceeded_by": value - max_value,
                })
            elif target_value is not None and value > target_value:
                warnings.append({
                    "metric": metric,
                    "value": value,
                    "target": target_value,
                    "exceeded_by": value - target_value,
                })
            else:
                passed.append({
                    "metric": metric,
                    "value": value,
                })

        return {
            "passed": len(violations) == 0,
            "violations": violations,
            "warnings": warnings,
            "passed_metrics": passed,
        }
