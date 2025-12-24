"""
Load testing configuration for CyberSec-CLI API using Locust.
Tests API endpoints under various load conditions.
"""
from locust import HttpUser, TaskSet, task, between, constant_pacing
import json
import random
import string


class ScanTasks(TaskSet):
    """Task set for scanning operations."""
    
    def on_start(self):
        """Initialize tasks for the user session."""
        # Set headers for API requests
        self.headers = {
            'Content-Type': 'application/json',
            'X-API-Key': 'test-api-key'  # This should match your test API key
        }
    
    @task(3)
    def get_status(self):
        """Test the status endpoint."""
        with self.client.get("/api/status", headers=self.headers, catch_response=True) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Status endpoint failed: {response.status_code}")
    
    @task(2)
    def health_check(self):
        """Test the health check endpoint."""
        with self.client.get("/health", headers=self.headers, catch_response=True) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Health check failed: {response.status_code}")
    
    @task(1)
    def redis_health_check(self):
        """Test the Redis health check."""
        with self.client.get("/health/redis", headers=self.headers, catch_response=True) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Redis health check failed: {response.status_code}")
    
    @task(4)
    def scan_endpoint(self):
        """Test the scan endpoint with different targets."""
        # Generate random targets for testing
        targets = [
            "127.0.0.1",
            "localhost",
            "example.com",  # Note: This would normally be blocked by validation
            "scanme.nmap.org",  # Use a safe test target
        ]
        
        # Use a safe test target to avoid actual scanning
        target = random.choice(targets[:3])  # Exclude example.com to avoid validation issues
        
        # Prepare scan parameters
        params = {
            "ports": "1-100",
            "timeout": 0.5,
            "max_concurrent": 5
        }
        
        with self.client.get(f"/api/scan/{target}", params=params, headers=self.headers, catch_response=True) as response:
            if response.status_code in [200, 429]:  # 429 is rate limit, which is expected under load
                if response.status_code == 429:
                    response.success()  # Rate limiting is expected behavior
                else:
                    response.success()
            else:
                response.failure(f"Scan endpoint failed: {response.status_code}")
    
    @task(2)
    def streaming_scan(self):
        """Test the streaming scan endpoint."""
        target = "127.0.0.1"
        
        with self.client.get(f"/api/stream/scan/{target}", params={"ports": "1-50"}, headers=self.headers, catch_response=True) as response:
            if response.status_code in [200, 429]:  # 429 is rate limit, which is expected under load
                if response.status_code == 429:
                    response.success()  # Rate limiting is expected behavior
                else:
                    response.success()
            else:
                response.failure(f"Streaming scan failed: {response.status_code}")
    
    @task(1)
    def get_scan_results(self):
        """Test getting scan results."""
        with self.client.get("/api/scans", params={"limit": 10}, headers=self.headers, catch_response=True) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Get scan results failed: {response.status_code}")
    
    @task(1)
    def get_metrics(self):
        """Test the metrics endpoint."""
        with self.client.get("/metrics", headers=self.headers, catch_response=True) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Metrics endpoint failed: {response.status_code}")


class CyberSecUser(HttpUser):
    """User class for CyberSec-CLI load testing."""
    
    tasks = [ScanTasks]
    
    # Wait time between requests (simulating realistic usage patterns)
    wait_time = between(1, 3)
    
    def on_start(self):
        """Actions to perform when a user starts."""
        # This could include authentication if needed
        pass
    
    def on_stop(self):
        """Actions to perform when a user stops."""
        # Cleanup actions if needed
        pass


# Advanced scenario: Heavy concurrent load
class HeavyLoadUser(HttpUser):
    """User class for heavy load testing."""
    
    tasks = [ScanTasks]
    wait_time = constant_pacing(0.5)  # Constant pacing for high load
    
    host = "http://localhost:8000"  # Default host, can be overridden


# Scenario: Mixed usage patterns
class MixedUser(HttpUser):
    """User class for mixed usage pattern testing."""
    
    tasks = {
        ScanTasks: 10,
    }
    
    wait_time = between(0.5, 2)
    
    def on_start(self):
        """Initialize with different user profiles."""
        # Could set different headers or parameters based on user type
        self.user_type = random.choice(['light', 'medium', 'heavy'])
        
        if self.user_type == 'heavy':
            self.scan_params = {"ports": "1-1000", "timeout": 1.0}
        elif self.user_type == 'medium':
            self.scan_params = {"ports": "1-500", "timeout": 0.8}
        else:
            self.scan_params = {"ports": "1-100", "timeout": 0.5}


# Custom test scenarios
class RateLimitTestUser(HttpUser):
    """User class specifically for testing rate limiting."""
    
    tasks = [ScanTasks]
    wait_time = constant_pacing(0.1)  # Very fast requests to trigger rate limiting
    
    def on_start(self):
        """Set up for rate limit testing."""
        self.headers = {
            'Content-Type': 'application/json',
            'X-API-Key': 'test-api-key'
        }
    
    @task(10)
    def rapid_scan_requests(self):
        """Send rapid scan requests to test rate limiting."""
        target = "127.0.0.1"
        
        with self.client.get(f"/api/scan/{target}", params={"ports": "1-10"}, headers=self.headers, catch_response=True) as response:
            if response.status_code in [200, 429]:
                if response.status_code == 429:
                    response.success()  # Rate limiting is expected and good
                else:
                    response.success()
            else:
                response.failure(f"Rapid request failed: {response.status_code}")


# Performance monitoring tasks
class PerformanceMonitorUser(HttpUser):
    """User class for monitoring performance metrics."""
    
    tasks = [ScanTasks]
    wait_time = between(2, 5)
    
    @task(1)
    def monitor_response_times(self):
        """Monitor response times for performance analysis."""
        import time
        
        start_time = time.time()
        with self.client.get("/api/status", headers=self.headers, catch_response=True) as response:
            response_time = time.time() - start_time
            
            if response.status_code == 200:
                response.success()
                # Log response time for analysis
                print(f"Status endpoint response time: {response_time:.3f}s")
            else:
                response.failure(f"Status endpoint failed: {response.status_code}")
    
    @task(1)
    def monitor_health_endpoints(self):
        """Monitor health endpoints for performance."""
        import time
        
        start_time = time.time()
        with self.client.get("/health", headers=self.headers, catch_response=True) as response:
            response_time = time.time() - start_time
            
            if response.status_code == 200:
                response.success()
                print(f"Health endpoint response time: {response_time:.3f}s")
            else:
                response.failure(f"Health endpoint failed: {response.status_code}")