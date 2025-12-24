"""
Database performance benchmarks for CyberSec-CLI.
Tests query performance and write throughput for different database backends.
"""

import asyncio
import time
import random
import string
from datetime import datetime, timedelta
from typing import Dict, List, Tuple
import sqlite3
import asyncpg
import aiomysql
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
import os


Base = declarative_base()


class ScanResult(Base):
    """Database model for scan results."""

    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    target = Column(String(255), nullable=False)
    ports = Column(Text)  # JSON string of ports and their states
    timestamp = Column(DateTime, default=datetime.utcnow)
    duration = Column(Integer)  # Duration in seconds
    status = Column(String(50))  # completed, failed, etc.


class DatabaseBenchmark:
    """Benchmark suite for database operations."""

    def __init__(self):
        self.results = {}
        self.engines = {}

    def setup_sqlite(self) -> None:
        """Setup SQLite database for testing."""
        # Use an in-memory database for testing
        self.engines["sqlite"] = create_engine(
            "sqlite:///benchmark_test.db",
            poolclass=StaticPool,
            connect_args={"check_same_thread": False},
        )
        Base.metadata.create_all(self.engines["sqlite"])

    async def setup_postgresql(self) -> None:
        """Setup PostgreSQL database for testing."""
        # Check if PostgreSQL is available
        try:
            # For testing, we'll use a mock connection string
            # In real usage, this would connect to a PostgreSQL instance
            self.engines["postgresql"] = create_engine(
                os.getenv(
                    "POSTGRES_BENCHMARK_URL",
                    "postgresql://user:password@localhost:5432/benchmark_test",
                ),
                pool_size=10,
                max_overflow=20,
            )
            Base.metadata.create_all(self.engines["postgresql"])
        except Exception as e:
            print(f"PostgreSQL not available: {e}")
            # Create a mock engine for testing purposes
            self.engines["postgresql"] = None

    def generate_mock_scan_result(self, target: str = None) -> ScanResult:
        """Generate a mock scan result for testing."""
        if target is None:
            target = f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}"

        # Generate mock port data
        ports_data = []
        for port in range(1, random.randint(10, 100)):
            state = random.choice(["open", "closed", "filtered"])
            service = random.choice(
                [
                    "http",
                    "ssh",
                    "ftp",
                    "telnet",
                    "smtp",
                    "pop3",
                    "imap",
                    "smb",
                    "mysql",
                    "postgresql",
                ]
            )
            ports_data.append({"port": port, "state": state, "service": service})

        return ScanResult(
            target=target,
            ports=str(ports_data),  # In real implementation, this would be JSON
            duration=random.randint(1, 300),
            status="completed",
        )

    def benchmark_sqlite_write_throughput(self, num_records: int = 1000) -> Dict:
        """Benchmark SQLite write throughput."""
        print(f"Benchmarking SQLite write throughput for {num_records} records...")

        Session = sessionmaker(bind=self.engines["sqlite"])
        session = Session()

        start_time = time.time()

        # Insert records
        for i in range(num_records):
            result = self.generate_mock_scan_result()
            session.add(result)

        session.commit()
        session.close()

        end_time = time.time()
        duration = end_time - start_time
        throughput = num_records / duration if duration > 0 else 0

        return {
            "database": "SQLite",
            "operation": "write",
            "records": num_records,
            "duration": duration,
            "throughput": throughput,
            "timestamp": datetime.now().isoformat(),
        }

    def benchmark_sqlite_read_performance(self, num_records: int = 1000) -> Dict:
        """Benchmark SQLite read performance."""
        print(f"Benchmarking SQLite read performance for {num_records} records...")

        # First, ensure we have records to read
        self.benchmark_sqlite_write_throughput(min(num_records, 100))

        Session = sessionmaker(bind=self.engines["sqlite"])
        session = Session()

        start_time = time.time()

        # Read records
        results = session.query(ScanResult).limit(num_records).all()

        end_time = time.time()
        duration = end_time - start_time
        throughput = len(results) / duration if duration > 0 else 0

        session.close()

        return {
            "database": "SQLite",
            "operation": "read",
            "records": len(results),
            "duration": duration,
            "throughput": throughput,
            "timestamp": datetime.now().isoformat(),
        }

    def benchmark_sqlite_query_complexity(self) -> Dict:
        """Benchmark SQLite query complexity."""
        print("Benchmarking SQLite query complexity...")

        # Insert some records for querying
        Session = sessionmaker(bind=self.engines["sqlite"])
        session = Session()

        # Insert test records
        for i in range(500):
            result = self.generate_mock_scan_result()
            session.add(result)
        session.commit()

        start_time = time.time()

        # Complex query: Find all scans from the last 24 hours
        yesterday = datetime.utcnow() - timedelta(days=1)
        recent_results = (
            session.query(ScanResult).filter(ScanResult.timestamp > yesterday).all()
        )

        # Another complex query: Count by status
        status_counts = (
            session.query(ScanResult.status, func.count(ScanResult.id))
            .group_by(ScanResult.status)
            .all()
        )

        # Third complex query: Find longest running scans
        longest_scans = (
            session.query(ScanResult)
            .order_by(ScanResult.duration.desc())
            .limit(10)
            .all()
        )

        end_time = time.time()
        duration = end_time - start_time

        session.close()

        return {
            "database": "SQLite",
            "operation": "complex_query",
            "queries_executed": 3,
            "results_returned": len(recent_results)
            + len(status_counts)
            + len(longest_scans),
            "duration": duration,
            "queries_per_second": 3 / duration if duration > 0 else 0,
            "timestamp": datetime.now().isoformat(),
        }

    def benchmark_postgresql_write_throughput(self, num_records: int = 1000) -> Dict:
        """Benchmark PostgreSQL write throughput."""
        if "postgresql" not in self.engines or self.engines["postgresql"] is None:
            print("PostgreSQL not available, skipping benchmark")
            return {
                "database": "PostgreSQL",
                "operation": "write",
                "skipped": True,
                "reason": "PostgreSQL not available",
                "timestamp": datetime.now().isoformat(),
            }

        print(f"Benchmarking PostgreSQL write throughput for {num_records} records...")

        Session = sessionmaker(bind=self.engines["postgresql"])
        session = Session()

        start_time = time.time()

        # Insert records
        for i in range(num_records):
            result = self.generate_mock_scan_result()
            session.add(result)

        session.commit()
        session.close()

        end_time = time.time()
        duration = end_time - start_time
        throughput = num_records / duration if duration > 0 else 0

        return {
            "database": "PostgreSQL",
            "operation": "write",
            "records": num_records,
            "duration": duration,
            "throughput": throughput,
            "timestamp": datetime.now().isoformat(),
        }

    def benchmark_postgresql_read_performance(self, num_records: int = 1000) -> Dict:
        """Benchmark PostgreSQL read performance."""
        if "postgresql" not in self.engines or self.engines["postgresql"] is None:
            print("PostgreSQL not available, skipping benchmark")
            return {
                "database": "PostgreSQL",
                "operation": "read",
                "skipped": True,
                "reason": "PostgreSQL not available",
                "timestamp": datetime.now().isoformat(),
            }

        print(f"Benchmarking PostgreSQL read performance for {num_records} records...")

        # First, ensure we have records to read
        self.benchmark_postgresql_write_throughput(min(num_records, 100))

        Session = sessionmaker(bind=self.engines["postgresql"])
        session = Session()

        start_time = time.time()

        # Read records
        results = session.query(ScanResult).limit(num_records).all()

        end_time = time.time()
        duration = end_time - start_time
        throughput = len(results) / duration if duration > 0 else 0

        session.close()

        return {
            "database": "PostgreSQL",
            "operation": "read",
            "records": len(results),
            "duration": duration,
            "throughput": throughput,
            "timestamp": datetime.now().isoformat(),
        }

    def benchmark_comparison(self) -> Dict:
        """Compare performance between SQLite and PostgreSQL."""
        print("Running database comparison benchmarks...")

        comparison_results = {}

        # Test with smaller numbers for comparison to keep test time reasonable
        test_size = 100

        # SQLite benchmarks
        comparison_results["sqlite_write"] = self.benchmark_sqlite_write_throughput(
            test_size
        )
        comparison_results["sqlite_read"] = self.benchmark_sqlite_read_performance(
            test_size
        )

        # PostgreSQL benchmarks (if available)
        if "postgresql" in self.engines and self.engines["postgresql"] is not None:
            comparison_results["postgresql_write"] = (
                self.benchmark_postgresql_write_throughput(test_size)
            )
            comparison_results["postgresql_read"] = (
                self.benchmark_postgresql_read_performance(test_size)
            )

        return comparison_results

    def run_all_benchmarks(self) -> Dict:
        """Run all database benchmarks."""
        print("Starting database benchmarks...")

        # Setup databases
        self.setup_sqlite()
        asyncio.run(self.setup_postgresql())

        results = {}

        # Run comparison benchmarks
        results["comparison"] = self.benchmark_comparison()

        # Run detailed benchmarks
        results["sqlite_write_1000"] = self.benchmark_sqlite_write_throughput(1000)
        print(
            f"SQLite write throughput: {results['sqlite_write_1000']['throughput']:.2f} records/sec"
        )

        results["sqlite_read_1000"] = self.benchmark_sqlite_read_performance(1000)
        print(
            f"SQLite read throughput: {results['sqlite_read_1000']['throughput']:.2f} records/sec"
        )

        results["sqlite_complex_query"] = self.benchmark_sqlite_query_complexity()
        print(
            f"SQLite complex query duration: {results['sqlite_complex_query']['duration']:.4f}s"
        )

        # PostgreSQL benchmarks if available
        if "postgresql" in self.engines and self.engines["postgresql"] is not None:
            results["postgresql_write_1000"] = (
                self.benchmark_postgresql_write_throughput(1000)
            )
            print(
                f"PostgreSQL write throughput: {results['postgresql_write_1000'].get('throughput', 'N/A')} records/sec"
            )

            results["postgresql_read_1000"] = (
                self.benchmark_postgresql_read_performance(1000)
            )
            print(
                f"PostgreSQL read throughput: {results['postgresql_read_1000'].get('throughput', 'N/A')} records/sec"
            )

        self.results = results
        return results

    def generate_report(self) -> str:
        """Generate a text report from benchmark results."""
        if not self.results:
            return "No benchmark results available."

        report = "Database Performance Benchmark Report\n"
        report += "=" * 50 + "\n\n"

        for test_name, result in self.results.items():
            report += f"{test_name.replace('_', ' ').title()}:\n"

            if isinstance(result, dict):
                for key, value in result.items():
                    if isinstance(value, float):
                        report += f"  {key}: {value:.4f}\n"
                    else:
                        report += f"  {key}: {value}\n"
            else:
                report += f"  Result: {result}\n"
            report += "\n"

        return report

    def plot_results(self, output_dir: str = "tests/performance/plots"):
        """Generate plots from benchmark results."""
        import os

        os.makedirs(output_dir, exist_ok=True)

        if not self.results:
            print("No results to plot")
            return

        # Extract write throughput data
        databases = []
        throughput_values = []

        for key, result in self.results.items():
            if "write" in key and isinstance(result, dict) and "throughput" in result:
                db_name = result.get("database", "Unknown")
                databases.append(f"{db_name} ({key})")
                throughput_values.append(result["throughput"])

        if databases and throughput_values:
            fig, ax = plt.subplots(figsize=(12, 6))

            ax.bar(databases, throughput_values)
            ax.set_ylabel("Throughput (records/second)")
            ax.set_title("Database Write Throughput Comparison")
            plt.xticks(rotation=45)
            plt.tight_layout()
            plt.savefig(f"{output_dir}/db_write_throughput.png")
            plt.close()

        # Extract read throughput data
        databases = []
        throughput_values = []

        for key, result in self.results.items():
            if "read" in key and isinstance(result, dict) and "throughput" in result:
                db_name = result.get("database", "Unknown")
                databases.append(f"{db_name} ({key})")
                throughput_values.append(result["throughput"])

        if databases and throughput_values:
            fig, ax = plt.subplots(figsize=(12, 6))

            ax.bar(databases, throughput_values)
            ax.set_ylabel("Throughput (records/second)")
            ax.set_title("Database Read Throughput Comparison")
            plt.xticks(rotation=45)
            plt.tight_layout()
            plt.savefig(f"{output_dir}/db_read_throughput.png")
            plt.close()


def main():
    """Run the database benchmark suite."""
    from sqlalchemy import func  # Import here to avoid issues

    benchmark = DatabaseBenchmark()
    results = benchmark.run_all_benchmarks()

    # Generate report
    report = benchmark.generate_report()
    print("\n" + report)

    # Save report to file
    with open("tests/performance/database_benchmark_report.txt", "w") as f:
        f.write(report)

    # Generate plots
    benchmark.plot_results()

    print(
        "Database benchmark completed. Results saved to tests/performance/database_benchmark_report.txt"
    )
    print("Plots saved to tests/performance/plots/")


if __name__ == "__main__":
    main()
