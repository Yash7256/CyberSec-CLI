"""Utility for parsing and querying JSON logs"""

import gzip
import json
import os
import re
from functools import lru_cache
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional


AUDIT_LOG_PATH = os.environ.get(
    "AUDIT_LOG_PATH",
    "/var/log/audit/audit.log",
)

@lru_cache(maxsize=1)
def _find_log_files(log_dir: str) -> tuple:
    return tuple(Path(log_dir).rglob("*.log"))


class LogParser:
    """Utility class for parsing and querying JSON logs"""

    def __init__(self, log_dir: str = "logs"):
        self.log_dir = Path(log_dir)

    def _get_log_files(self):
        """Get log files with caching for performance."""
        return _find_log_files(str(self.log_dir))


    def parse_log_file(self, file_path: str) -> Generator[Dict[str, Any], None, None]:
        """Parse a log file and yield log entries as dictionaries"""
        path = Path(file_path)

        # Handle compressed files
        if path.suffix == ".gz":
            with gzip.open(path, "rt", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            yield json.loads(line)
                        except json.JSONDecodeError:
                            # Skip invalid JSON lines
                            continue
        else:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            yield json.loads(line)
                        except json.JSONDecodeError:
                            # Skip invalid JSON lines
                            continue

    def search_logs(
        self,
        component: Optional[str] = None,
        level: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        message_pattern: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Search logs with various filters"""
        results = []

        # Find all log files using cached method
        log_files = self._get_log_files()

        for log_file in log_files:
            for entry in self.parse_log_file(log_file):
                # Apply filters - use .get() with safe defaults
                if component and entry.get("component") != component:
                    continue
                if level and entry.get("level", "").upper() != level.upper():
                    continue
                if start_time or end_time:
                    try:
                        timestamp_value = entry.get("timestamp", "")
                        if not timestamp_value:
                            continue
                        timestamp = datetime.fromisoformat(
                            timestamp_value.replace("Z", "+00:00")
                        )
                        if start_time and timestamp < start_time:
                            continue
                        if end_time and timestamp > end_time:
                            continue
                    except ValueError:
                        # Skip entries with invalid timestamp format
                        continue
                if message_pattern and not re.search(
                    message_pattern, entry.get("message", ""), re.IGNORECASE
                ):
                    continue

                results.append(entry)

                if len(results) >= limit:
                    return results

        return results

    def get_recent_logs(
        self, component: Optional[str] = None, limit: int = 50
    ) -> List[Dict[str, Any]]:
        """Get recent log entries"""
        # Get logs from the last 24 hours
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=24)

        return self.search_logs(
            component=component, start_time=start_time, end_time=end_time, limit=limit
        )

    def get_error_logs(
        self, component: Optional[str] = None, hours: int = 24
    ) -> List[Dict[str, Any]]:
        """Get error logs within a time window"""
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=hours)

        return self.search_logs(
            component=component, level="ERROR", start_time=start_time, end_time=end_time
        )

    def get_audit_events(
        self, event_type: Optional[str] = None, hours: int = 24, audit_log_path: Optional[Path] = None
    ) -> List[Dict[str, Any]]:
        """Get audit events from the audit log"""
        if audit_log_path is None:
            audit_log_path = Path(AUDIT_LOG_PATH)

        if not audit_log_path.exists():
            return []

        results = []
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=hours)

        for entry in self.parse_log_file(audit_log_path):
            # Check if it's within time range
            try:
                timestamp_value = entry.get("timestamp", "")
                if not timestamp_value:
                    continue
                timestamp = datetime.fromisoformat(
                    timestamp_value.replace("Z", "+00:00")
                )
                if start_time and timestamp < start_time:
                    continue
                if end_time and timestamp > end_time:
                    continue
            except ValueError:
                continue

            # Check if event type matches
            if event_type and entry.get("context", {}).get("event_type") != event_type:
                continue

            results.append(entry)

        return results

    def get_scan_logs(self, scan_id: str) -> List[Dict[str, Any]]:
        """Get logs for a specific scan ID"""
        results = []

        # Find all log files
        log_files = list(self.log_dir.glob("*.log")) + list(
            self.log_dir.glob("*.log.*")
        )

        for log_file in log_files:
            for entry in self.parse_log_file(log_file):
                context = entry.get("context", {})
                if context.get("scan_id") == scan_id:
                    results.append(entry)

        return results

    def generate_report(
        self,
        start_time: datetime,
        end_time: datetime,
        components: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Generate a log report for a time period"""
        report = {
            "period_start": start_time.isoformat(),
            "period_end": end_time.isoformat(),
            "components": {},
            "total_entries": 0,
            "errors": 0,
            "warnings": 0,
            "info": 0,
            "debug": 0,
        }

        # Find all log files
        log_files = list(self.log_dir.glob("*.log")) + list(
            self.log_dir.glob("*.log.*")
        )

        for log_file in log_files:
            for entry in self.parse_log_file(log_file):
                try:
                    timestamp = datetime.fromisoformat(
                        entry["timestamp"].replace("Z", "+00:00")
                    )
                    if timestamp < start_time or timestamp > end_time:
                        continue
                except ValueError:
                    continue

                component = entry.get("component", "unknown")

                # Filter by components if specified
                if components and component not in components:
                    continue

                # Update counters
                report["total_entries"] += 1
                level = entry.get("level", "UNKNOWN").upper()

                if level == "ERROR":
                    report["errors"] += 1
                elif level == "WARNING":
                    report["warnings"] += 1
                elif level == "INFO":
                    report["info"] += 1
                elif level == "DEBUG":
                    report["debug"] += 1

                # Update component-specific counters
                if component not in report["components"]:
                    report["components"][component] = {
                        "total": 0,
                        "errors": 0,
                        "warnings": 0,
                        "info": 0,
                        "debug": 0,
                    }

                report["components"][component]["total"] += 1
                report["components"][component][level.lower()] += 1

        return report


def main():
    """Command-line interface for log parsing"""
    import argparse
    from datetime import datetime, timedelta

    parser = argparse.ArgumentParser(description="Parse and query JSON logs")
    parser.add_argument(
        "--log-dir", default="logs", help="Directory containing log files"
    )
    parser.add_argument("--component", help="Filter by component")
    parser.add_argument(
        "--level", help="Filter by log level (ERROR, WARNING, INFO, DEBUG)"
    )
    parser.add_argument(
        "--hours", type=int, default=24, help="Time window in hours (default: 24)"
    )
    parser.add_argument("--pattern", help="Filter by message pattern (regex)")
    parser.add_argument(
        "--limit", type=int, default=100, help="Maximum number of results"
    )
    parser.add_argument("--scan-id", help="Filter by scan ID")
    parser.add_argument(
        "--report", action="store_true", help="Generate a summary report"
    )

    args = parser.parse_args()

    parser_util = LogParser(args.log_dir)

    if args.report:
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=args.hours)
        report = parser_util.generate_report(start_time, end_time)
        print(json.dumps(report, indent=2))
    elif args.scan_id:
        logs = parser_util.get_scan_logs(args.scan_id)
        for log in logs:
            print(json.dumps(log))
    else:
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=args.hours)

        logs = parser_util.search_logs(
            component=args.component,
            level=args.level,
            start_time=start_time,
            end_time=end_time,
            message_pattern=args.pattern,
            limit=args.limit,
        )

        for log in logs:
            print(json.dumps(log))


if __name__ == "__main__":
    main()
