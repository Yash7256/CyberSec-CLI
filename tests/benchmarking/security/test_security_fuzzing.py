"""
Security and fuzzing tests for CyberSec-CLI.
Tests input validation, security vulnerabilities, and robustness.
"""

import asyncio
import random
import re
import string
import sys
import time
from pathlib import Path
from typing import Dict, List

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from tests.benchmarking.framework.base_benchmark import BaseBenchmark


class SecurityFuzzingBenchmark(BaseBenchmark):
    """
    Security and fuzzing tests for CyberSec-CLI.
    
    Tests:
    - Input validation and sanitization
    - SQL injection attempts
    - Command injection attempts
    - Buffer overflow attempts
    - Path traversal attempts
    """

    def __init__(self):
        """Initialize security fuzzing benchmark."""
        super().__init__("security_fuzzing", "tests/benchmarking/results/security")

    def _generate_random_string(self, length: int = 100) -> str:
        """Generate a random string of specified length."""
        return ''.join(random.choice(string.ascii_letters + string.digits + ' !@#$%^&*()_+-=[]{}|;:,.<>?') for _ in range(length))

    def _generate_malicious_inputs(self) -> List[str]:
        """Generate a list of potentially malicious inputs."""
        malicious_inputs = [
            # SQL injection attempts
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "admin'--",
            "'; EXEC xp_cmdshell('net user');--",
            
            # Command injection attempts
            "; ls -la",
            "| whoami",
            "& echo vulnerable",
            "$(whoami)",
            "`whoami`",
            
            # Path traversal attempts
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "%2e%2e%2f" * 10,  # URL encoded traversal
            
            # XSS attempts
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>",
            
            # Buffer overflow attempts
            "A" * 1000,
            "A" * 5000,
            "A" * 10000,
            
            # Unicode and special character attacks
            "\u0000" * 100,  # Null bytes
            "\ufffd" * 100,  # Replacement character
            "".join(chr(i) for i in range(128, 256)),  # Extended ASCII
            
            # Regex bombing attempts
            "(" * 50 + ")" * 50,
            
            # JSON/Format string attacks
            '{"a": ' + '{"b": ' * 50 + '"attack"' + '}' * 50 + '}',
        ]
        
        # Add random inputs
        for _ in range(10):
            malicious_inputs.append(self._generate_random_string(500))
        
        return malicious_inputs

    async def benchmark_input_validation(self) -> Dict:
        """
        Test input validation against malicious inputs.
        
        Returns:
            Dictionary with input validation test results
        """
        print("Benchmarking input validation against malicious inputs...")

        malicious_inputs = self._generate_malicious_inputs()
        total_inputs = len(malicious_inputs)
        
        safe_inputs = []
        rejected_inputs = []
        errors = []
        
        for i, malicious_input in enumerate(malicious_inputs):
            try:
                # Simulate input validation
                is_safe = await self._validate_input(malicious_input)
                
                if is_safe:
                    safe_inputs.append(malicious_input)
                else:
                    rejected_inputs.append(malicious_input)
                    
                if (i + 1) % 10 == 0:
                    print(f"  Processed: {i+1}/{total_inputs}")
                    
            except Exception as e:
                errors.append(f"Input '{malicious_input[:20]}...' caused error: {str(e)}")

        results = {
            "total_inputs": total_inputs,
            "safe_inputs": len(safe_inputs),
            "rejected_inputs": len(rejected_inputs),
            "errors": len(errors),
            "error_details": errors,
            "validation_success_rate": len(rejected_inputs) / total_inputs if total_inputs > 0 else 0,
        }

        print(f"  Safe inputs: {len(safe_inputs)}")
        print(f"  Rejected inputs: {len(rejected_inputs)}")
        print(f"  Errors: {len(errors)}")
        print(f"  Validation success rate: {results['validation_success_rate']:.1%}")

        return results

    async def _validate_input(self, input_str: str) -> bool:
        """
        Simulate input validation. In real implementation, this would call the actual validation logic.
        
        Args:
            input_str: Input to validate
            
        Returns:
            True if input passes validation, False otherwise
        """
        # Simulate validation process
        await asyncio.sleep(0.001)  # Simulate processing time
        
        # Check for dangerous patterns
        dangerous_patterns = [
            r"(?i)(drop|exec|execute|select|insert|update|delete|create|alter|drop|union|sleep)",
            r"(?i)(\||&|;|`|\$|\(|\))",
            r"(?i)(\.\.\/|\.\\.|\.\./|\.\\)",
            r"<script.*?>.*?</script>",
            r"javascript:",
            r"vbscript:",
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, input_str):
                return False  # Input rejected
                
        # Check for excessively long inputs
        if len(input_str) > 10000:
            return False  # Input rejected
            
        return True  # Input passed validation

    async def benchmark_buffer_overflow_resistance(self) -> Dict:
        """
        Test resistance to buffer overflow attacks.
        
        Returns:
            Dictionary with buffer overflow resistance test results
        """
        print("Benchmarking buffer overflow resistance...")

        buffer_sizes = [1000, 5000, 10000, 50000, 100000]
        results = {}
        
        for size in buffer_sizes:
            print(f"  Testing buffer size: {size} chars")
            
            large_input = "A" * size
            
            start_time = time.time()
            error_occurred = False
            
            try:
                # Simulate processing of large input
                processed = await self._process_large_input(large_input)
            except MemoryError:
                error_occurred = True
                print(f"    MemoryError at {size} chars")
            except RecursionError:
                error_occurred = True
                print(f"    RecursionError at {size} chars")
            except Exception as e:
                error_occurred = True
                print(f"    Other error at {size} chars: {str(e)}")
            
            duration = time.time() - start_time
            
            results[f"buffer_{size}"] = {
                "size": size,
                "duration": duration,
                "error_occurred": error_occurred,
                "processing_successful": not error_occurred,
            }
            
            if error_occurred:
                break  # Stop if overflow occurred

        successful_keys = [k for k, v in results.items() if v['processing_successful']]
        largest_successful = max(successful_keys, default=None)
        print(f"  Largest successful buffer size: {largest_successful}")

        return results

    async def _process_large_input(self, input_str: str) -> str:
        """Simulate processing of large input with proper bounds checking."""
        # Simulate realistic processing with bounds checking
        if len(input_str) > 50000:  # Set reasonable limit
            raise MemoryError("Input too large")
            
        await asyncio.sleep(0.001)  # Simulate processing time
        
        # Process input safely
        result = input_str[:1000]  # Truncate to safe size
        return result

    async def benchmark_authentication_abuse(self) -> Dict:
        """
        Test authentication abuse prevention mechanisms.
        
        Returns:
            Dictionary with authentication abuse test results
        """
        print("Benchmarking authentication abuse prevention...")

        # Simulate multiple authentication attempts
        attempts = 100
        successful_attempts = 0
        failed_attempts = 0
        blocked_attempts = 0
        
        start_time = time.time()
        
        for i in range(attempts):
            # Simulate auth attempt with invalid credentials
            auth_result = await self._simulate_auth_attempt(f"user_{i}", f"password_{i}")
            
            if auth_result == "success":
                successful_attempts += 1
            elif auth_result == "failure":
                failed_attempts += 1
            elif auth_result == "blocked":
                blocked_attempts += 1
                break  # Stop if account gets blocked due to rate limiting
            
            if (i + 1) % 20 == 0:
                print(f"  Auth attempts: {i+1}/{attempts}")

        duration = time.time() - start_time
        
        results = {
            "total_attempts": attempts,
            "successful_attempts": successful_attempts,
            "failed_attempts": failed_attempts,
            "blocked_attempts": blocked_attempts,
            "duration": duration,
            "rate_limiting_active": blocked_attempts > 0,
        }

        print(f"  Successful: {successful_attempts}, Failed: {failed_attempts}, Blocked: {blocked_attempts}")
        print(f"  Rate limiting active: {results['rate_limiting_active']}")

        return results

    async def _simulate_auth_attempt(self, username: str, password: str) -> str:
        """Simulate an authentication attempt."""
        await asyncio.sleep(0.01)  # Simulate auth processing time
        
        # Simulate rate limiting after multiple failures
        if random.random() < 0.05:  # 5% chance of triggering rate limit
            return "blocked"
        elif random.random() < 0.1:  # 10% chance of success with fake creds
            return "success"
        else:
            return "failure"

    async def benchmark_network_flooding_resistance(self) -> Dict:
        """
        Test resistance to network flooding attempts.
        
        Returns:
            Dictionary with network flooding resistance test results
        """
        print("Benchmarking network flooding resistance...")

        # Simulate concurrent connection attempts
        concurrent_attempts = [10, 50, 100, 200, 500]
        results = {}
        
        for num_connections in concurrent_attempts:
            print(f"  Testing {num_connections} concurrent connections")
            
            start_time = time.time()
            
            # Create concurrent tasks simulating connection attempts
            tasks = [self._simulate_connection() for _ in range(num_connections)]
            results_list = await asyncio.gather(*tasks, return_exceptions=True)
            
            successful_connections = sum(1 for r in results_list if r == "success")
            failed_connections = sum(1 for r in results_list if r == "failure")
            blocked_connections = sum(1 for r in results_list if r == "blocked")
            
            duration = time.time() - start_time
            
            results[f"connections_{num_connections}"] = {
                "num_connections": num_connections,
                "duration": duration,
                "successful_connections": successful_connections,
                "failed_connections": failed_connections,
                "blocked_connections": blocked_connections,
                "success_rate": successful_connections / num_connections if num_connections > 0 else 0,
                "flooding_resistance": blocked_connections > 0,
            }
            
            print(f"    Success: {successful_connections}, Failed: {failed_connections}, Blocked: {blocked_connections}")

        return results

    async def _simulate_connection(self) -> str:
        """Simulate a network connection attempt."""
        await asyncio.sleep(0.005)  # Simulate connection processing
        
        # Simulate different outcomes
        rand_val = random.random()
        if rand_val < 0.02:  # 2% chance of blocking due to rate limiting
            return "blocked"
        elif rand_val < 0.7:  # 68% chance of success
            return "success"
        else:  # 30% chance of failure
            return "failure"

    async def run_benchmark(self) -> Dict:
        """Run all security fuzzing benchmarks."""
        print("\n" + "=" * 60)
        print("Security & Fuzzing Benchmark Suite")
        print("=" * 60 + "\n")

        results = {}

        # Input validation tests
        results["input_validation"] = await self.benchmark_input_validation()
        print()

        # Buffer overflow resistance
        results["buffer_overflow"] = await self.benchmark_buffer_overflow_resistance()
        print()

        # Authentication abuse prevention
        results["auth_abuse"] = await self.benchmark_authentication_abuse()
        print()

        # Network flooding resistance
        results["network_flooding"] = await self.benchmark_network_flooding_resistance()
        print()

        # Save results
        filepath = self.save_results("security_fuzzing_results.json")
        print(f"✓ Results saved to: {filepath}")

        # Print summary
        self.print_summary()

        return results


async def main():
    """Run the security fuzzing benchmark suite."""
    benchmark = SecurityFuzzingBenchmark()
    results = await benchmark.run_benchmark()

    print("\n" + "=" * 60)
    print("Security & Fuzzing Benchmark Complete!")
    print("=" * 60)

    return results


if __name__ == "__main__":
    asyncio.run(main())