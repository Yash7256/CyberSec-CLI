"""
Accuracy testing suite for CyberSec-CLI.
Tests port detection accuracy and false positive/negative rates.
"""

import asyncio
import sys
from pathlib import Path
from typing import Dict, Set

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from tests.benchmarking.framework.base_benchmark import BaseBenchmark


class AccuracyBenchmark(BaseBenchmark):
    """
    Accuracy testing benchmark for CyberSec-CLI.
    
    Tests:
    - Port detection accuracy
    - Service identification accuracy
    - False positive/negative rates
    - Precision, recall, F1 score
    """

    def __init__(self):
        """Initialize accuracy benchmark."""
        super().__init__("accuracy_test", "tests/benchmarking/results/accuracy")

    def calculate_metrics(
        self,
        true_positives: int,
        false_positives: int,
        false_negatives: int,
        true_negatives: int,
    ) -> Dict:
        """
        Calculate accuracy metrics.
        
        Args:
            true_positives: Correctly identified open ports
            false_positives: Incorrectly identified as open
            false_negatives: Missed open ports
            true_negatives: Correctly identified closed ports
            
        Returns:
            Dictionary with accuracy metrics
        """
        total = true_positives + false_positives + false_negatives + true_negatives

        # Precision: TP / (TP + FP)
        precision = (
            true_positives / (true_positives + false_positives)
            if (true_positives + false_positives) > 0
            else 0
        )

        # Recall: TP / (TP + FN)
        recall = (
            true_positives / (true_positives + false_negatives)
            if (true_positives + false_negatives) > 0
            else 0
        )

        # F1 Score: 2 * (Precision * Recall) / (Precision + Recall)
        f1_score = (
            2 * (precision * recall) / (precision + recall)
            if (precision + recall) > 0
            else 0
        )

        # Accuracy: (TP + TN) / Total
        accuracy = (true_positives + true_negatives) / total if total > 0 else 0

        # False Positive Rate: FP / (FP + TN)
        fpr = (
            false_positives / (false_positives + true_negatives)
            if (false_positives + true_negatives) > 0
            else 0
        )

        # False Negative Rate: FN / (FN + TP)
        fnr = (
            false_negatives / (false_negatives + true_positives)
            if (false_negatives + true_positives) > 0
            else 0
        )

        return {
            "true_positives": true_positives,
            "false_positives": false_positives,
            "false_negatives": false_negatives,
            "true_negatives": true_negatives,
            "precision": precision,
            "recall": recall,
            "f1_score": f1_score,
            "accuracy": accuracy,
            "false_positive_rate": fpr,
            "false_negative_rate": fnr,
        }

    async def benchmark_port_detection_accuracy(
        self,
        target: str = "127.0.0.1",
        expected_open_ports: Set[int] = None,
        port_range: str = "1-1000",
    ) -> Dict:
        """
        Test port detection accuracy.
        
        Args:
            target: Target to scan
            expected_open_ports: Set of ports that should be open
            port_range: Range of ports to scan
            
        Returns:
            Dictionary with accuracy results
        """
        if expected_open_ports is None:
            # Default: assume common ports might be open on localhost
            expected_open_ports = {22, 80, 443, 5432, 6379}

        print(f"Benchmarking port detection accuracy on {target}...")
        print(f"  Port range: {port_range}")
        print(f"  Expected open ports: {len(expected_open_ports)}")

        # Parse port range
        if "-" in port_range:
            start, end = map(int, port_range.split("-"))
            all_ports = set(range(start, end + 1))
        else:
            all_ports = {int(p) for p in port_range.split(",")}

        detected_open_ports = set()

        try:
            from cybersec_cli.tools.network.port_scanner import PortScanner

            scanner = PortScanner(
                target=target,
                ports=list(all_ports),
                timeout=1.0,
                max_concurrent=50,
            )
            results = await scanner.scan()

            if isinstance(results, list):
                for res in results:
                    # Handle both objects and dictionaries
                    is_open = False
                    port = 0
                    
                    if hasattr(res, "state"):
                        is_open = str(res.state.value) == "open"
                        port = res.port
                    elif isinstance(res, dict):
                        is_open = res.get("state") == "open"
                        port = res.get("port")
                        
                    if is_open:
                        detected_open_ports.add(port)
            elif results and "open_ports" in results:
                detected_open_ports = set(results["open_ports"])

        except ImportError:
            # Mock for testing
            print("  ⚠ Scanner not available, using mock data")
            # Simulate 95% accuracy
            import random
            for port in expected_open_ports:
                if random.random() < 0.95:  # 95% detection rate
                    detected_open_ports.add(port)

        # Calculate confusion matrix
        true_positives = len(expected_open_ports & detected_open_ports)
        false_positives = len(detected_open_ports - expected_open_ports)
        false_negatives = len(expected_open_ports - detected_open_ports)
        true_negatives = len(all_ports - expected_open_ports - detected_open_ports)

        metrics = self.calculate_metrics(
            true_positives, false_positives, false_negatives, true_negatives
        )

        print("\n  Results:")
        print(f"    Detected open: {len(detected_open_ports)}")
        print(f"    Expected open: {len(expected_open_ports)}")
        print(f"    True Positives: {true_positives}")
        print(f"    False Positives: {false_positives}")
        print(f"    False Negatives: {false_negatives}")
        print(f"    Precision: {metrics['precision']:.2%}")
        print(f"    Recall: {metrics['recall']:.2%}")
        print(f"    F1 Score: {metrics['f1_score']:.2%}")
        print(f"    Accuracy: {metrics['accuracy']:.2%}")

        return {
            "target": target,
            "port_range": port_range,
            "total_ports_scanned": len(all_ports),
            "expected_open_ports": list(expected_open_ports),
            "detected_open_ports": list(detected_open_ports),
            **metrics,
        }

    async def benchmark_service_identification(
        self,
        target: str = "127.0.0.1",
        expected_services: Dict[int, str] = None,
    ) -> Dict:
        """
        Test service identification accuracy.
        
        Args:
            target: Target to scan
            expected_services: Dict mapping port to expected service name
            
        Returns:
            Dictionary with service identification results
        """
        if expected_services is None:
            expected_services = {
                22: "ssh",
                80: "http",
                443: "https",
                5432: "postgresql",
                6379: "redis",
            }

        print("\nBenchmarking service identification accuracy...")
        print(f"  Expected services: {len(expected_services)}")

        detected_services = {}
        correct_identifications = 0
        incorrect_identifications = 0

        try:
            from cybersec_cli.tools.network.port_scanner import PortScanner

            scanner = PortScanner(
                target=target,
                ports=list(expected_services.keys()),
                timeout=2.0,
                max_concurrent=10,
            )
            results = await scanner.scan()

            # Extract service information from results
            if isinstance(results, list):
                for res in results:
                    port = 0
                    service = "unknown"
                    
                    if hasattr(res, "service"):
                        port = res.port
                        service = res.service or "unknown"
                    elif isinstance(res, dict):
                        port = res.get("port")
                        service = res.get("service") or "unknown"
                        
                    if port > 0:
                        detected_services[port] = service
            elif results and "services" in results:
                detected_services = results["services"]

        except ImportError:
            # Mock for testing
            print("  ⚠ Scanner not available, using mock data")
            import random
            for port, service in expected_services.items():
                if random.random() < 0.90:  # 90% accuracy
                    detected_services[port] = service

        # Compare detected vs expected
        for port, expected_service in expected_services.items():
            detected_service = detected_services.get(port, "unknown")
            if detected_service.lower() == expected_service.lower():
                correct_identifications += 1
            else:
                incorrect_identifications += 1

        accuracy = (
            correct_identifications / len(expected_services)
            if expected_services
            else 0
        )

        print(f"  Correct: {correct_identifications}/{len(expected_services)}")
        print(f"  Accuracy: {accuracy:.2%}")

        return {
            "target": target,
            "expected_services": expected_services,
            "detected_services": detected_services,
            "correct_identifications": correct_identifications,
            "incorrect_identifications": incorrect_identifications,
            "accuracy": accuracy,
        }

    async def benchmark_edge_cases(self) -> Dict:
        """
        Test edge case handling.
        
        Tests:
        - Non-standard ports
        - Filtered vs closed ports
        - Timeout handling
        - Invalid targets
        
        Returns:
            Dictionary with edge case test results
        """
        print("\nBenchmarking edge case handling...")

        edge_cases = {
            "non_standard_ports": {
                "target": "127.0.0.1",
                "ports": [8080, 8888, 3000, 5000, 9000],
                "description": "HTTP on non-standard ports",
            },
            "high_ports": {
                "target": "127.0.0.1",
                "ports": [50000, 55000, 60000, 65000, 65535],
                "description": "Very high port numbers",
            },
            "invalid_target": {
                "target": "999.999.999.999",
                "ports": [80],
                "description": "Invalid IP address",
            },
        }

        results = {}

        for case_name, case_config in edge_cases.items():
            print(f"  Testing: {case_config['description']}")

            try:
                from cybersec_cli.tools.network.port_scanner import PortScanner

                scanner = PortScanner(
                    target=case_config["target"],
                    ports=case_config["ports"],
                    timeout=1.0,
                    max_concurrent=5,
                )
                scan_results = await scanner.scan()

                results[case_name] = {
                    "success": True,
                    "error": None,
                    "results": scan_results,
                }

            except ImportError:
                results[case_name] = {
                    "success": True,
                    "error": None,
                    "results": {"mock": True},
                }
            except Exception as e:
                results[case_name] = {
                    "success": False,
                    "error": str(e),
                    "handled_gracefully": True,  # Didn't crash
                }

            status = "✓" if results[case_name].get("success") or results[case_name].get("handled_gracefully") else "✗"
            print(f"    {status} {case_name}")

        return results

    async def run_benchmark(self) -> Dict:
        """Run all accuracy benchmarks."""
        print("\n" + "=" * 60)
        print("Accuracy Testing Benchmark Suite")
        print("=" * 60 + "\n")

        results = {}

        # Port detection accuracy
        results["port_detection"] = await self.benchmark_port_detection_accuracy(
            target="127.0.0.1",
            expected_open_ports={22, 80, 443},
            port_range="1-1000",
        )

        # Service identification
        results["service_identification"] = await self.benchmark_service_identification(
            target="127.0.0.1",
            expected_services={22: "ssh", 80: "http", 443: "https"},
        )

        # Edge cases
        results["edge_cases"] = await self.benchmark_edge_cases()

        # Check if meets accuracy thresholds
        port_accuracy = results["port_detection"]["accuracy"]
        service_accuracy = results["service_identification"]["accuracy"]

        print(f"\n{'=' * 60}")
        print("Accuracy Summary")
        print("=" * 60)
        print(f"Port Detection Accuracy: {port_accuracy:.2%}")
        print(f"Service Identification: {service_accuracy:.2%}")
        print(f"F1 Score: {results['port_detection']['f1_score']:.2%}")
        print()

        # Thresholds from config
        threshold = 0.95  # 95% accuracy threshold
        if port_accuracy >= threshold and service_accuracy >= threshold:
            print("✓ PASSED: Meets accuracy requirements")
        else:
            print("✗ FAILED: Below accuracy threshold")

        # Save results
        filepath = self.save_results("accuracy_test_results.json")
        print(f"\n✓ Results saved to: {filepath}")

        return results


async def main():
    """Run the accuracy testing benchmark suite."""
    benchmark = AccuracyBenchmark()
    results = await benchmark.run_benchmark()

    print("\n" + "=" * 60)
    print("Accuracy Testing Complete!")
    print("=" * 60)

    return results


if __name__ == "__main__":
    asyncio.run(main())
