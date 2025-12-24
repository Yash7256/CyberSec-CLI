"""
Anomaly Detection Module for CyberSec CLI.
Implements various anomaly detection techniques for security monitoring.
"""

import numpy as np
from typing import List, Dict, Any, Optional, Union, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum, auto
import logging
import psutil
import time
import socket
from collections import defaultdict, deque
from sklearn.ensemble import IsolationForest
import joblib
import json
import os
from pathlib import Path

# Constants
MODEL_SAVE_PATH = Path.home() / ".cybersec" / "models"
MODEL_SAVE_PATH.mkdir(parents=True, exist_ok=True)

logger = logging.getLogger(__name__)


class AnomalyType(str, Enum):
    NETWORK_TRAFFIC = "network_traffic"
    NETWORK_PROTOCOL = "network_protocol"
    PORT_ACTIVITY = "port_activity"
    CONNECTION_PATTERN = "connection_pattern"
    SYSTEM_BEHAVIOR = "system_behavior"
    SECURITY_ALERT = "security_alert"
    USER_ACTIVITY = "user_activity"


class Protocol(Enum):
    TCP = auto()
    UDP = auto()
    ICMP = auto()
    UNKNOWN = auto()


@dataclass
class Anomaly:
    """Represents a detected anomaly."""

    anomaly_type: AnomalyType
    timestamp: datetime
    score: float
    description: str
    metadata: Dict[str, Any] = None


@dataclass
class NetworkConnection:
    """Represents a network connection."""

    fd: int
    family: int
    type: int
    laddr: tuple
    raddr: tuple
    status: str
    pid: int = None
    username: str = None
    process_name: str = None
    protocol: Protocol = Protocol.UNKNOWN
    first_seen: float = field(default_factory=time.time)
    last_activity: float = field(default_factory=time.time)
    bytes_sent: int = 0
    bytes_recv: int = 0

    @property
    def duration(self) -> float:
        """Get the duration of the connection in seconds."""
        return time.time() - self.first_seen


class MLAnomalyDetector:
    """Machine Learning based anomaly detector."""

    def __init__(self, model_path: str = None):
        self.model = None
        self.scaler = None
        self.feature_names = [
            "bytes_sent",
            "bytes_recv",
            "packets_sent",
            "packets_recv",
            "error_in",
            "error_out",
            "drop_in",
            "drop_out",
            "connections",
        ]
        self.model_path = model_path or str(
            MODEL_SAVE_PATH / "anomaly_detection_model.joblib"
        )
        self.load_model()

    def preprocess(self, metrics: Dict[str, float]) -> np.ndarray:
        """Preprocess metrics for the ML model."""
        # Convert metrics to feature vector
        features = np.array(
            [metrics.get(feature, 0) for feature in self.feature_names]
        ).reshape(1, -1)
        return features

    def detect(self, metrics: Dict[str, float]) -> Tuple[bool, float]:
        """Detect anomalies using the ML model."""
        if self.model is None:
            return False, 0.0

        features = self.preprocess(metrics)
        is_anomaly = self.model.predict(features)[0] == -1
        anomaly_score = float(self.model.score_samples(features)[0])
        return is_anomaly, anomaly_score

    def train(self, X: np.ndarray, contamination: float = 0.1):
        """Train the anomaly detection model."""
        self.model = IsolationForest(
            n_estimators=100, contamination=contamination, random_state=42, n_jobs=-1
        )
        self.model.fit(X)
        self.save_model()

    def save_model(self):
        """Save the trained model to disk."""
        if self.model is not None:
            joblib.dump(self.model, self.model_path)

    def load_model(self):
        """Load a trained model from disk."""
        if os.path.exists(self.model_path):
            try:
                self.model = joblib.load(self.model_path)
            except Exception as e:
                logger.error(f"Error loading model: {e}")
                self.model = None


class AnomalyDetector:
    """Enhanced base class for anomaly detection with ML support."""

    def __init__(self, threshold: float = 3.0, use_ml: bool = True):
        self.threshold = threshold
        self.baseline = None
        self.ml_detector = MLAnomalyDetector() if use_ml else None
        self.metrics_history = []
        self.connections: Dict[tuple, NetworkConnection] = {}
        self.port_activity = defaultdict(lambda: {"count": 0, "last_seen": 0})
        self.protocol_stats = defaultdict(lambda: {"count": 0, "bytes": 0})

    def update_baseline(self, data: List[float]) -> None:
        """Update the baseline for anomaly detection."""
        if not data:
            return

        self.baseline = {
            "mean": np.mean(data),
            "median": np.median(data),
            "std": np.std(data) or 1.0,  # Avoid division by zero
            "min": np.min(data),
            "max": np.max(data),
            "percentiles": {
                "25": np.percentile(data, 25),
                "50": np.percentile(data, 50),
                "75": np.percentile(data, 75),
                "95": np.percentile(data, 95),
                "99": np.percentile(data, 99),
            },
        }

        # Train ML model if enabled
        if self.ml_detector and len(self.metrics_history) > 100:
            try:
                X = np.array(
                    [
                        [m.get(f, 0) for f in self.ml_detector.feature_names]
                        for m in self.metrics_history[-1000:]  # Use recent data
                    ]
                )
                self.ml_detector.train(X)
            except Exception as e:
                logger.error(f"Error training ML model: {e}")

    def detect(self, metrics: Dict[str, float]) -> List[Anomaly]:
        """Detect anomalies in the given metrics."""
        anomalies = []

        # Store metrics for ML analysis
        self.metrics_history.append(metrics)

        # Rule-based detection
        for metric, value in metrics.items():
            if self.baseline and metric in self.baseline.get("percentiles", {}):
                p99 = self.baseline["percentiles"].get("99", 0)
                if value > p99 * 2:  # Value exceeds 2x 99th percentile
                    score = (value - self.baseline["mean"]) / (
                        self.baseline["std"] or 1.0
                    )
                    if score > self.threshold:
                        anomalies.append(
                            Anomaly(
                                anomaly_type=AnomalyType.SYSTEM_BEHAVIOR,
                                timestamp=time.time(),
                                score=float(score),
                                description=f"Unusually high {metric}: {value:.2f} (99th: {p99:.2f})",
                                metadata={
                                    "metric": metric,
                                    "value": value,
                                    "baseline": self.baseline,
                                },
                            )
                        )

        # ML-based detection
        if self.ml_detector and len(self.metrics_history) > 50:
            try:
                is_anomaly, score = self.ml_detector.detect(metrics)
                if is_anomaly:
                    anomalies.append(
                        Anomaly(
                            anomaly_type=AnomalyType.SYSTEM_BEHAVIOR,
                            timestamp=time.time(),
                            score=float(score),
                            description="ML-detected anomaly in system behavior",
                            metadata={"metrics": metrics, "ml_score": score},
                        )
                    )
            except Exception as e:
                logger.error(f"ML detection error: {e}")

        return anomalies


import psutil
from dataclasses import dataclass
from typing import Dict, List, Optional
import time


@dataclass
class NetworkMetrics:
    """Container for network metrics."""

    bytes_sent: int = 0
    bytes_recv: int = 0
    packets_sent: int = 0
    packets_recv: int = 0
    error_in: int = 0
    error_out: int = 0
    drop_in: int = 0
    drop_out: int = 0
    connections: int = 0


class NetworkAnomalyDetector(AnomalyDetector):
    """Advanced network anomaly detector with protocol and connection analysis."""

    def __init__(self, interface: str = None, use_ml: bool = True):
        super().__init__(threshold=3.0, use_ml=use_ml)
        self.interface = interface
        self.connections: Dict[tuple, NetworkConnection] = {}
        self.port_activity = defaultdict(
            lambda: {"count": 0, "last_seen": 0, "first_seen": 0}
        )
        self.protocol_stats = defaultdict(
            lambda: {"count": 0, "bytes": 0, "connections": set()}
        )
        self.host_activity = defaultdict(lambda: {"connections": 0, "bytes": 0})
        self.last_metrics = self._get_network_metrics()
        self.last_check = time.time()
        self.suspicious_ports = {
            22,  # SSH
            23,  # Telnet
            80,  # HTTP
            443,  # HTTPS
            445,  # SMB
            1433,  # MSSQL
            1521,  # Oracle
            3306,  # MySQL
            3389,  # RDP
            5432,  # PostgreSQL
            5900,  # VNC
            8080,  # HTTP Proxy
            8443,  # HTTPS Alternative
        }

    def _get_network_metrics(self) -> NetworkMetrics:
        """Get current network metrics with enhanced connection tracking."""
        net_io = psutil.net_io_counters(pernic=bool(self.interface))

        if self.interface and self.interface in net_io:
            io = net_io[self.interface]
        else:
            io = net_io

        # Get current connections
        current_conns = {}
        current_time = time.time()

        for conn in psutil.net_connections(kind="inet"):
            try:
                # Create connection key
                if conn.raddr:  # Outbound or established connection
                    key = (conn.fd, conn.family, conn.type, conn.laddr, conn.raddr)
                    is_new = key not in self.connections

                    # Update or create connection
                    if is_new:
                        self.connections[key] = NetworkConnection(
                            fd=conn.fd,
                            family=conn.family,
                            type=conn.type,
                            laddr=conn.laddr,
                            raddr=conn.raddr,
                            status=conn.status,
                            pid=conn.pid,
                            first_seen=current_time,
                        )

                        # Track port activity
                        if conn.raddr and len(conn.raddr) > 1:
                            port = conn.raddr[1]
                            self.port_activity[port]["count"] += 1
                            if self.port_activity[port]["first_seen"] == 0:
                                self.port_activity[port]["first_seen"] = current_time
                            self.port_activity[port]["last_seen"] = current_time

                            # Track protocol stats
                            proto = self._get_protocol(port)
                            self.protocol_stats[proto]["count"] += 1
                            self.protocol_stats[proto]["connections"].add(key)

                            # Track host activity
                            self.host_activity[conn.raddr[0]]["connections"] += 1

                    conn_obj = self.connections[key]
                    conn_obj.last_activity = current_time
                    conn_obj.status = conn.status
                    current_conns[key] = conn_obj

            except (
                psutil.NoSuchProcess,
                psutil.AccessDenied,
                psutil.ZombieProcess,
            ) as e:
                logger.debug(f"Error processing connection: {e}")
                continue

        # Remove stale connections
        stale_conns = set(self.connections.keys()) - set(current_conns.keys())
        for key in stale_conns:
            del self.connections[key]

        # Calculate connection statistics
        conn_stats = {
            "total": len(current_conns),
            "by_status": defaultdict(int),
            "by_protocol": defaultdict(int),
            "by_port": defaultdict(int),
        }

        for conn in current_conns.values():
            conn_stats["by_status"][conn.status] += 1
            if conn.raddr and len(conn.raddr) > 1:
                port = conn.raddr[1]
                conn_stats["by_port"][port] += 1
                proto = self._get_protocol(port)
                conn_stats["by_protocol"][proto] += 1

        # Update metrics
        metrics = NetworkMetrics(
            bytes_sent=io.bytes_sent,
            bytes_recv=io.bytes_recv,
            packets_sent=io.packets_sent,
            packets_recv=io.packets_recv,
            error_in=io.errin,
            error_out=io.errout,
            drop_in=io.dropin,
            drop_out=io.dropout,
            connections=len(current_conns),
        )

        # Add connection stats to metrics
        metrics.connection_stats = conn_stats

        return metrics

    def _get_protocol(self, port: int) -> Protocol:
        """Get protocol type based on port number."""
        if port in {
            20,
            21,
            22,
            23,
            25,
            53,
            80,
            110,
            143,
            443,
            587,
            993,
            995,
            3306,
            3389,
            5432,
            8080,
            8443,
        }:
            return Protocol.TCP
        elif port in {53, 67, 68, 69, 123, 161, 162, 500, 1701, 1812, 1813, 4500}:
            return Protocol.UDP
        elif port == 1:
            return Protocol.ICMP
        return Protocol.UNKNOWN

    def _detect_port_scan(self) -> List[Anomaly]:
        """Detect potential port scanning activity with advanced heuristics."""
        anomalies = []
        current_time = time.time()

        # Track scan patterns
        scan_candidates = defaultdict(list)

        # Analyze connection patterns
        for conn in self.connections.values():
            if conn.raddr and conn.raddr[0] not in ["127.0.0.1", "::1"]:
                scan_candidates[conn.raddr[0]].append(
                    {
                        "port": conn.raddr[1],
                        "time": current_time,
                        "protocol": conn.protocol.name,
                    }
                )

        # Check for horizontal and vertical scans
        for ip, connections in scan_candidates.items():
            if len(connections) > 5:  # Threshold for scan detection
                # Get unique ports and protocols
                unique_ports = len({c["port"] for c in connections})
                protocols = {c["protocol"] for c in connections}

                # Calculate connections per second
                time_window = max(c["time"] for c in connections) - min(
                    c["time"] for c in connections
                )
                cps = len(connections) / (time_window or 1)

                if unique_ports > 3:  # Likely a port scan
                    score = min(10.0, 7.0 + (unique_ports * 0.3))
                    anomalies.append(
                        Anomaly(
                            anomaly_type=AnomalyType.SECURITY_ALERT,
                            timestamp=datetime.now(),
                            score=score,
                            description=f"Port scan detected from {ip}: {unique_ports} ports in {time_window:.1f}s",
                            metadata={
                                "source_ip": ip,
                                "ports_scanned": unique_ports,
                                "protocols": list(protocols),
                                "connections_per_second": cps,
                                "total_connections": len(connections),
                            },
                        )
                    )

        # Check for specific suspicious port activity
        for port, data in self.port_activity.items():
            port_connections = data["count"]
            time_window = current_time - data["first_seen"]

            # High connection rate to a single port
            if port_connections > 50 and time_window < 30:  # 50+ connections in 30s
                score = min(9.0, 6.0 + (port_connections / 20))
                anomalies.append(
                    Anomaly(
                        anomaly_type=AnomalyType.PORT_ACTIVITY,
                        timestamp=datetime.now(),
                        score=score,
                        description=f"Suspicious activity on port {port}: {port_connections} connections in {time_window:.1f}s",
                        metadata={
                            "port": port,
                            "connections": port_connections,
                            "time_window": time_window,
                            "connections_per_second": port_connections
                            / (time_window or 1),
                        },
                    )
                )

            # Known suspicious port activity
            if port in self.suspicious_ports and port_connections > 5:
                anomalies.append(
                    Anomaly(
                        anomaly_type=AnomalyType.SECURITY_ALERT,
                        timestamp=datetime.now(),
                        score=8.5,
                        description=f"Suspicious activity on known port {port}",
                        metadata={
                            "port": port,
                            "connections": port_connections,
                            "port_type": "known_suspicious",
                        },
                    )
                )

        return anomalies

    def _detect_connection_anomalies(self) -> List[Anomaly]:
        """Detect anomalies in connection patterns with advanced analysis."""
        anomalies = []
        current_time = time.time()

        # Group connections by remote address and local port
        connections_by_host = defaultdict(
            lambda: {
                "connections": [],
                "ports": set(),
                "protocols": set(),
                "first_seen": float("inf"),
                "last_seen": 0,
            }
        )

        # Analyze connection patterns
        for conn in self.connections.values():
            if not conn.raddr:
                continue

            host = conn.raddr[0]
            port = conn.raddr[1] if len(conn.raddr) > 1 else None

            host_data = connections_by_host[host]
            host_data["connections"].append(conn)
            if port:
                host_data["ports"].add(port)
            host_data["protocols"].add(conn.protocol.name)
            host_data["first_seen"] = min(host_data["first_seen"], conn.first_seen)
            host_data["last_seen"] = max(host_data["last_seen"], conn.last_activity)

        # Check each host for suspicious patterns
        for host, data in connections_by_host.items():
            conn_count = len(data["connections"])
            port_count = len(data["ports"])
            time_window = data["last_seen"] - data["first_seen"]

            # Skip localhost and private IPs for some checks
            is_private = (
                host.startswith(("127.", "10.", "192.168.", "172.16.")) or host == "::1"
            )

            # 1. Multiple connections to the same host
            if conn_count > 10:  # High number of connections
                score = min(9.5, 6.0 + (conn_count / 20))
                anomalies.append(
                    Anomaly(
                        anomaly_type=AnomalyType.CONNECTION_PATTERN,
                        timestamp=datetime.now(),
                        score=score,
                        description=f"Multiple connections to {host}: {conn_count} active connections",
                        metadata={
                            "host": host,
                            "connections": conn_count,
                            "unique_ports": port_count,
                            "protocols": list(data["protocols"]),
                            "duration": time_window,
                            "connections_per_second": conn_count / (time_window or 1),
                        },
                    )
                )

            # 2. Fast connection attempts (potential brute force)
            if (
                not is_private and time_window > 0 and (conn_count / time_window) > 5
            ):  # >5 connections/second
                anomalies.append(
                    Anomaly(
                        anomaly_type=AnomalyType.SECURITY_ALERT,
                        timestamp=datetime.now(),
                        score=8.5,
                        description=f"Rapid connection attempts to {host}: {conn_count} in {time_window:.1f}s",
                        metadata={
                            "host": host,
                            "connections": conn_count,
                            "duration": time_window,
                            "rate": conn_count / time_window,
                            "ports": list(data["ports"])[:10],  # First 10 ports
                        },
                    )
                )

            # 3. Multiple protocols to same host (potential C2 traffic)
            if len(data["protocols"]) > 2:  # Using multiple protocols
                anomalies.append(
                    Anomaly(
                        anomaly_type=AnomalyType.SECURITY_ALERT,
                        timestamp=datetime.now(),
                        score=7.5,
                        description=f"Multiple protocols to {host}: {', '.join(data['protocols'])}",
                        metadata={
                            "host": host,
                            "protocols": list(data["protocols"]),
                            "connections": conn_count,
                        },
                    )
                )

            # 4. Suspicious port combinations (e.g., 22, 23, 80, 443 from same host)
            suspicious_ports = {22, 23, 80, 443, 445, 3389, 8080, 8443}
            matched_ports = data["ports"] & suspicious_ports
            if len(matched_ports) >= 2:  # At least 2 suspicious ports
                anomalies.append(
                    Anomaly(
                        anomaly_type=AnomalyType.SECURITY_ALERT,
                        timestamp=datetime.now(),
                        score=8.0,
                        description=f"Suspicious port access to {host}: {', '.join(map(str, matched_ports))}",
                        metadata={
                            "host": host,
                            "ports": list(matched_ports),
                            "total_connections": conn_count,
                        },
                    )
                )

        return anomalies

    def analyze_traffic(self) -> List[Anomaly]:
        """Analyze current network traffic for anomalies with enhanced detection."""
        current_time = time.time()
        time_diff = current_time - self.last_check

        if time_diff < 1.0:  # Minimum 1 second between checks
            return []

        current_metrics = self._get_network_metrics()

        # Calculate rates
        rates = {
            "timestamp": current_time,
            "bytes_sent_rate": (
                current_metrics.bytes_sent - self.last_metrics.bytes_sent
            )
            / time_diff,
            "bytes_recv_rate": (
                current_metrics.bytes_recv - self.last_metrics.bytes_recv
            )
            / time_diff,
            "packets_sent_rate": (
                current_metrics.packets_sent - self.last_metrics.packets_sent
            )
            / time_diff,
            "packets_recv_rate": (
                current_metrics.packets_recv - self.last_metrics.packets_recv
            )
            / time_diff,
            "connections": current_metrics.connections,
            "error_rate": (
                (current_metrics.error_in + current_metrics.error_out)
                - (self.last_metrics.error_in + self.last_metrics.error_out)
            )
            / time_diff,
            "drop_rate": (
                (current_metrics.drop_in + current_metrics.drop_out)
                - (self.last_metrics.drop_in + self.last_metrics.drop_out)
            )
            / time_diff,
        }

        # Add connection stats
        if hasattr(current_metrics, "connection_stats"):
            rates.update(
                {
                    "total_connections": current_metrics.connection_stats["total"],
                    "established_connections": current_metrics.connection_stats[
                        "by_status"
                    ].get("ESTABLISHED", 0),
                    "time_wait_connections": current_metrics.connection_stats[
                        "by_status"
                    ].get("TIME_WAIT", 0),
                    "tcp_connections": current_metrics.connection_stats[
                        "by_protocol"
                    ].get(Protocol.TCP, 0),
                    "udp_connections": current_metrics.connection_stats[
                        "by_protocol"
                    ].get(Protocol.UDP, 0),
                    "icmp_connections": current_metrics.connection_stats[
                        "by_protocol"
                    ].get(Protocol.ICMP, 0),
                }
            )

        # Update state
        self.last_metrics = current_metrics
        self.last_check = current_time
        self.metrics_history.append(rates)

        # Keep only last 1000 samples
        if len(self.metrics_history) > 1000:
            self.metrics_history.pop(0)

        # Detect anomalies
        anomalies = []

        # 1. Statistical anomaly detection
        anomalies.extend(super().detect(rates))

        # 2. Port scanning detection
        anomalies.extend(self._detect_port_scan())

        # 3. Connection pattern analysis
        anomalies.extend(self._detect_connection_anomalies())

        # 4. Protocol analysis
        if hasattr(current_metrics, "connection_stats"):
            for proto, count in current_metrics.connection_stats["by_protocol"].items():
                if (
                    proto == Protocol.UNKNOWN and count > 5
                ):  # Many unknown protocol connections
                    anomalies.append(
                        Anomaly(
                            anomaly_type=AnomalyType.NETWORK_PROTOCOL,
                            timestamp=current_time,
                            score=7.0,
                            description=f"Multiple connections with unknown protocol: {count}",
                            metadata={"protocol": "UNKNOWN", "connection_count": count},
                        )
                    )

        # 5. Error rate monitoring
        if rates["error_rate"] > 10:  # More than 10 errors per second
            anomalies.append(
                Anomaly(
                    anomaly_type=AnomalyType.NETWORK_TRAFFIC,
                    timestamp=current_time,
                    score=6.5,
                    description=f"High network error rate: {rates['error_rate']:.2f} errors/sec",
                    metadata={
                        "error_rate": rates["error_rate"],
                        "errors_in": current_metrics.error_in
                        - self.last_metrics.error_in,
                        "errors_out": current_metrics.error_out
                        - self.last_metrics.error_out,
                    },
                )
            )

        return anomalies

    def _detect_anomalies(self, current_rates: Dict[str, float]) -> List[Anomaly]:
        """Detect anomalies in the current network rates."""
        if len(self.metrics_history) < 10:  # Need at least 10 samples for baseline
            return []

        anomalies = []

        # Check each metric for anomalies
        for metric, value in current_rates.items():
            if metric == "connections":
                continue  # Handle connections separately

            # Get historical values for this metric
            history = [m[metric] for m in self.metrics_history[:-1]]  # Exclude current

            if not history:
                continue

            # Simple z-score based anomaly detection
            mean = sum(history) / len(history)
            std = (sum((x - mean) ** 2 for x in history) / len(history)) ** 0.5 or 1.0
            z_score = abs((value - mean) / std) if std != 0 else 0

            if z_score > self.threshold:
                anomalies.append(
                    Anomaly(
                        anomaly_type=AnomalyType.NETWORK_TRAFFIC,
                        timestamp=time.time(),
                        score=z_score,
                        description=f"Unusual {metric.replace('_', ' ')}: {value:.2f}/s (mean: {mean:.2f})",
                        metadata={
                            "metric": metric,
                            "value": value,
                            "mean": mean,
                            "std": std,
                            "z_score": z_score,
                        },
                    )
                )

        # Check for unusual number of connections
        if "connections" in current_rates:
            conn_history = [m["connections"] for m in self.metrics_history[:-1]]
            if conn_history:
                mean_conn = sum(conn_history) / len(conn_history)
                std_conn = (
                    sum((x - mean_conn) ** 2 for x in conn_history) / len(conn_history)
                ) ** 0.5 or 1.0
                z_score = abs((current_rates["connections"] - mean_conn) / std_conn)

                if z_score > self.threshold:
                    anomalies.append(
                        Anomaly(
                            anomaly_type=AnomalyType.NETWORK_TRAFFIC,
                            timestamp=time.time(),
                            score=z_score,
                            description=f"Unusual number of connections: {current_rates['connections']} (mean: {mean_conn:.1f})",
                            metadata={
                                "connections": current_rates["connections"],
                                "mean_connections": mean_conn,
                                "z_score": z_score,
                            },
                        )
                    )

        return anomalies


class LogAnomalyDetector(AnomalyDetector):
    """Detects anomalies in log entries."""

    def __init__(self):
        super().__init__(threshold=2.5)
        self.error_rates = []
        self.failed_logins = []

    def analyze_logs(self, error_count: int, failed_login_count: int) -> List[Anomaly]:
        """Analyze log entries for anomalies."""
        anomalies = []

        if len(self.error_rates) >= 5:  # Minimum samples for baseline
            # Check for error rate anomalies
            self.update_baseline(self.error_rates[-50:])  # Use last 50 samples
            error_anomaly = self.detect(error_count)
            if error_anomaly:
                error_anomaly.anomaly_type = AnomalyType.LOG_ENTRY
                error_anomaly.description = (
                    f"Unusual error rate detected: {error_count} errors"
                )
                anomalies.append(error_anomaly)

            # Check for failed login anomalies
            self.update_baseline(self.failed_logins[-50:])
            login_anomaly = self.detect(failed_login_count)
            if login_anomaly:
                login_anomaly.anomaly_type = AnomalyType.USER_ACTIVITY
                login_anomaly.description = (
                    f"Suspicious login activity: {failed_login_count} failed attempts"
                )
                anomalies.append(login_anomaly)

        # Store current values
        self.error_rates.append(error_count)
        self.failed_logins.append(failed_login_count)

        return anomalies


# Example usage
if __name__ == "__main__":
    import random

    # Test Network Anomaly Detection
    print("Testing Network Anomaly Detection...")
    net_detector = NetworkAnomalyDetector()

    # Simulate normal traffic
    for _ in range(10):
        normal_packets = random.randint(80, 120)
        normal_conns = random.randint(5, 15)
        net_detector.analyze_traffic(normal_packets, normal_conns)

    # Test with anomaly (sudden spike in traffic)
    anomalies = net_detector.analyze_traffic(500, 100)
    if anomalies:
        for anomaly in anomalies:
            print(f"[!] {anomaly.description} (Score: {anomaly.score:.2f})")

    # Test Log Anomaly Detection
    print("\nTesting Log Anomaly Detection...")
    log_detector = LogAnomalyDetector()

    # Simulate normal logs
    for _ in range(10):
        normal_errors = random.randint(0, 5)
        normal_logins = random.randint(0, 2)
        log_detector.analyze_logs(normal_errors, normal_logins)

    # Test with anomaly (sudden spike in failed logins)
    anomalies = log_detector.analyze_logs(3, 15)  # 15 failed logins is unusual
    if anomalies:
        for anomaly in anomalies:
            print(f"[!] {anomaly.description} (Score: {anomaly.score:.2f})")
