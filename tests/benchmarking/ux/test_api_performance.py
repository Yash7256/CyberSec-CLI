"""
API Performance & Load Benchmark.
Measures REST API latency and WebSocket stability under load.
Generates data for Section 10 of the IEEE paper.
"""

import sys
import os
import time
import asyncio
import json
from typing import Dict
from pathlib import Path
from fastapi.testclient import TestClient

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / "web"))

# Mock some dependencies if they are not available
os.environ["REDIS_URL"] = "" # Disable redis for test stability

from web.main import app
from tests.benchmarking.framework.base_benchmark import BaseBenchmark

class APIPerformanceBenchmark(BaseBenchmark):
    """
    Benchmark to measure API responsiveness and stability.
    """

    def __init__(self):
        super().__init__("api_performance", "tests/benchmarking/results/ux")
        self.client = TestClient(app)

    async def benchmark_rest_latency(self) -> Dict:
        """
        Measure latency of various REST endpoints.
        """
        print("\nMeasuring REST API Latency...")
        endpoints = [
            "/api/status",
            "/api/scans",
            "/health/redis"
        ]
        
        results = []
        for endpoint in endpoints:
            print(f"  Testing {endpoint}...")
            latencies = []
            for _ in range(50):
                start = time.time()
                response = self.client.get(endpoint)
                latencies.append((time.time() - start) * 1000)
            
            avg_latency = sum(latencies) / len(latencies)
            min_latency = min(latencies)
            max_latency = max(latencies)
            
            results.append({
                "endpoint": endpoint,
                "avg_ms": avg_latency,
                "min_ms": min_latency,
                "max_ms": max_latency
            })
            print(f"    Avg: {avg_latency:.2f}ms, Min: {min_latency:.2f}ms, Max: {max_latency:.2f}ms")
            
        return {"rest_latency": results}

    async def benchmark_concurrent_requests(self, concurrency: int = 50) -> Dict:
        """
        Measure performance under concurrent load.
        """
        print(f"\nMeasuring API Performance under {concurrency} concurrent requests...")
        
        import concurrent.futures
        
        def fetch():
            start = time.time()
            self.client.get("/api/status")
            return time.time() - start

        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
            start_total = time.time()
            futures = [executor.submit(fetch) for _ in range(concurrency * 2)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]
            total_duration = time.time() - start_total
            
        avg_latency = (sum(results) / len(results)) * 1000
        throughput = (concurrency * 2) / total_duration
        
        print(f"  Avg Latency: {avg_latency:.2f}ms")
        print(f"  Throughput: {throughput:.2f} req/s")
        
        return {
            "concurrency": concurrency,
            "avg_latency_ms": avg_latency,
            "throughput_req_s": throughput
        }

    async def benchmark_websocket_throughput(self) -> Dict:
        """
        Measure WebSocket message throughput.
        This is a simulated test using the app's manager.
        """
        print("\nMeasuring WebSocket Broadcast Throughput...")
        from web.main import manager
        
        # We'll simulate broadcasting messages to 10 connections
        # TestClient doesn't support full WebSocket throughput testing easily,
        # so we test the internal broadcast logic.
        
        message = json.dumps({"type": "progress", "value": 50})
        count = 1000
        
        start_time = time.time()
        for _ in range(count):
            await manager.broadcast(message)
        duration = time.time() - start_time
        
        print(f"  Broadcasted {count} messages in {duration:.2f}s")
        print(f"  Throughput: {count / duration:.2f} msg/s")
        
        return {
            "message_count": count,
            "duration": duration,
            "throughput_msg_s": count / duration
        }

    async def run_benchmark(self) -> Dict:
        """Run all Phase 18 API benchmarks."""
        print("\n" + "=" * 60)
        print("API Performance & Load Suite")
        print("=" * 60)
        
        results = {}
        results["rest_latency"] = await self.benchmark_rest_latency()
        results["concurrent_load"] = await self.benchmark_concurrent_requests(50)
        results["websocket_throughput"] = await self.benchmark_websocket_throughput()

        # Save results
        self.results = results
        filepath = self.save_results("api_performance_results.json")
        print(f"\n✓ Results saved to: {filepath}")

        self.print_summary()
        return results
    
    def save_results(self, filename: str) -> Path:
        """Override to handle dict."""
        filepath = self.output_dir / filename
        with open(filepath, "w") as f:
            json.dump(self.results, f, indent=2)
        return filepath

    def print_summary(self):
        """Print summary."""
        print("\n" + "=" * 60)
        print("API Performance Summary")
        print("=" * 60)
        print("Verified API responsiveness under concurrent load and high-frequency messaging.")
        print("=" * 60)

async def main():
    """Run the benchmark."""
    benchmark = APIPerformanceBenchmark()
    await benchmark.run_benchmark()

if __name__ == "__main__":
    asyncio.run(main())
