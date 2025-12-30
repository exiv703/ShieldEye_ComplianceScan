from __future__ import annotations

import time
import psutil
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional
from collections import deque

from ..utils.logging_config import get_logger

logger = get_logger("monitoring")

@dataclass
class HealthStatus:
    healthy: bool
    status: str
    checks: Dict[str, bool] = field(default_factory=dict)
    metrics: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

@dataclass
class ScanMetrics:
    scan_id: str
    url: str
    start_time: float
    end_time: Optional[float] = None
    duration: Optional[float] = None
    pages_scanned: int = 0
    requests_made: int = 0
    errors_count: int = 0
    findings_count: int = 0
    status: str = "running"

class MetricsCollector:
    def __init__(self, max_history: int = 1000):
        self.max_history = max_history
        self.scan_metrics: Dict[str, ScanMetrics] = {}
        self.request_times: deque = deque(maxlen=max_history)
        self.error_counts: Dict[str, int] = {}
        self.total_scans = 0
        self.successful_scans = 0
        self.failed_scans = 0
        self.start_time = time.time()
    
    def start_scan(self, scan_id: str, url: str) -> None:
        self.scan_metrics[scan_id] = ScanMetrics(
            scan_id=scan_id,
            url=url,
            start_time=time.time(),
        )
        self.total_scans += 1
        logger.debug(f"Started tracking metrics for scan: {scan_id}")
    
    def end_scan(self, scan_id: str, status: str = "completed") -> None:
        if scan_id not in self.scan_metrics:
            logger.warning(f"Scan {scan_id} not found in metrics")
            return
        
        metrics = self.scan_metrics[scan_id]
        metrics.end_time = time.time()
        metrics.duration = metrics.end_time - metrics.start_time
        metrics.status = status
        
        if status == "completed":
            self.successful_scans += 1
        elif status == "failed":
            self.failed_scans += 1
        
        logger.debug(f"Ended tracking for scan {scan_id}: {status} in {metrics.duration:.2f}s")
    
    def record_request(self, duration: float) -> None:
        self.request_times.append(duration)
    
    def record_error(self, error_type: str) -> None:
        self.error_counts[error_type] = self.error_counts.get(error_type, 0) + 1
    
    def update_scan_metrics(
        self,
        scan_id: str,
        pages_scanned: Optional[int] = None,
        requests_made: Optional[int] = None,
        errors_count: Optional[int] = None,
        findings_count: Optional[int] = None,
    ) -> None:
        if scan_id not in self.scan_metrics:
            return
        
        metrics = self.scan_metrics[scan_id]
        
        if pages_scanned is not None:
            metrics.pages_scanned = pages_scanned
        if requests_made is not None:
            metrics.requests_made = requests_made
        if errors_count is not None:
            metrics.errors_count = errors_count
        if findings_count is not None:
            metrics.findings_count = findings_count
    
    def get_scan_metrics(self, scan_id: str) -> Optional[ScanMetrics]:
        return self.scan_metrics.get(scan_id)
    
    def get_summary(self) -> Dict[str, Any]:
        uptime = time.time() - self.start_time
        
        avg_request_time = 0.0
        if self.request_times:
            avg_request_time = sum(self.request_times) / len(self.request_times)
        
        active_scans = sum(
            1 for m in self.scan_metrics.values()
            if m.status == "running"
        )
        
        return {
            "uptime_seconds": uptime,
            "total_scans": self.total_scans,
            "successful_scans": self.successful_scans,
            "failed_scans": self.failed_scans,
            "active_scans": active_scans,
            "success_rate": (
                self.successful_scans / self.total_scans * 100
                if self.total_scans > 0 else 0
            ),
            "average_request_time_ms": avg_request_time * 1000,
            "total_errors": sum(self.error_counts.values()),
            "error_breakdown": dict(self.error_counts),
        }

class HealthChecker:
    def __init__(self, metrics_collector: Optional[MetricsCollector] = None):
        self.metrics = metrics_collector
    
    def check_system_resources(self) -> tuple[bool, Dict[str, Any]]:
        try:
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            checks = {
                "cpu_ok": cpu_percent < 90,
                "memory_ok": memory.percent < 90,
                "disk_ok": disk.percent < 90,
            }
            
            metrics = {
                "cpu_percent": cpu_percent,
                "memory_percent": memory.percent,
                "memory_available_mb": memory.available / (1024 * 1024),
                "disk_percent": disk.percent,
                "disk_free_gb": disk.free / (1024 * 1024 * 1024),
            }
            
            healthy = all(checks.values())
            return healthy, {"checks": checks, "metrics": metrics}
        
        except Exception as e:
            logger.error(f"Failed to check system resources: {e}")
            return False, {"error": str(e)}
    
    def check_application_health(self) -> tuple[bool, Dict[str, Any]]:
        checks = {}
        metrics = {}
        
        if self.metrics:
            summary = self.metrics.get_summary()
            metrics.update(summary)
            
            checks["no_excessive_errors"] = summary["total_errors"] < 100
            checks["reasonable_success_rate"] = summary["success_rate"] >= 50
            checks["active_scans_ok"] = summary["active_scans"] < 10
        
        healthy = all(checks.values()) if checks else True
        return healthy, {"checks": checks, "metrics": metrics}
    
    def perform_health_check(self) -> HealthStatus:
        all_checks = {}
        all_metrics = {}
        
        system_healthy, system_data = self.check_system_resources()
        all_checks.update(system_data.get("checks", {}))
        all_metrics.update(system_data.get("metrics", {}))
        
        app_healthy, app_data = self.check_application_health()
        all_checks.update(app_data.get("checks", {}))
        all_metrics.update(app_data.get("metrics", {}))
        
        overall_healthy = system_healthy and app_healthy
        
        if overall_healthy:
            status = "healthy"
        elif system_healthy:
            status = "degraded"
        else:
            status = "unhealthy"
        
        return HealthStatus(
            healthy=overall_healthy,
            status=status,
            checks=all_checks,
            metrics=all_metrics,
        )

_global_metrics_collector: Optional[MetricsCollector] = None

def get_metrics_collector() -> MetricsCollector:
    global _global_metrics_collector
    if _global_metrics_collector is None:
        _global_metrics_collector = MetricsCollector()
    return _global_metrics_collector

def get_health_checker() -> HealthChecker:
    return HealthChecker(get_metrics_collector())
