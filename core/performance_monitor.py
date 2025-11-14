"""
CyberGuardian AI - Performance Monitor
PHASE 6: Performance Optimization

Real-time monitoring of:
- CPU usage
- Memory usage
- Disk I/O
- Query performance
- Scanner performance
- Bottleneck detection
"""

import psutil
import time
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from collections import deque
import logging

logger = logging.getLogger(__name__)


class PerformanceMonitor:
    """
    Monitor system and application performance
    """
    
    def __init__(self, history_size: int = 1000):
        self.history_size = history_size
        
        # Performance metrics history
        self.cpu_history = deque(maxlen=history_size)
        self.memory_history = deque(maxlen=history_size)
        self.disk_history = deque(maxlen=history_size)
        
        # Scanner performance
        self.scan_times = deque(maxlen=100)
        self.scan_speeds = deque(maxlen=100)  # files per second
        
        # Query performance
        self.query_times = deque(maxlen=500)
        self.slow_queries = deque(maxlen=50)
        
        # API performance
        self.api_response_times = {}
        
        # Alerts
        self.alerts = deque(maxlen=100)
        
        # Monitoring thread
        self.monitoring = False
        self.monitor_thread = None
        
        # Thresholds
        self.thresholds = {
            "cpu_percent": 80.0,
            "memory_percent": 85.0,
            "disk_percent": 90.0,
            "query_time_ms": 100,
            "api_response_ms": 500
        }
        
        # Statistics
        self.stats = {
            "total_scans": 0,
            "total_files_scanned": 0,
            "total_queries": 0,
            "total_api_calls": 0,
            "start_time": datetime.now()
        }
    
    # ========================================================================
    # SYSTEM MONITORING
    # ========================================================================
    
    def get_cpu_usage(self) -> Dict[str, Any]:
        """Get CPU usage statistics"""
        cpu_percent = psutil.cpu_percent(interval=0.1, percpu=False)
        cpu_count = psutil.cpu_count()
        cpu_freq = psutil.cpu_freq()
        
        return {
            "percent": round(cpu_percent, 2),
            "count": cpu_count,
            "frequency_mhz": round(cpu_freq.current, 2) if cpu_freq else None,
            "per_cpu": psutil.cpu_percent(interval=0.1, percpu=True),
            "load_average": psutil.getloadavg() if hasattr(psutil, 'getloadavg') else None
        }
    
    def get_memory_usage(self) -> Dict[str, Any]:
        """Get memory usage statistics"""
        memory = psutil.virtual_memory()
        swap = psutil.swap_memory()
        
        return {
            "total_mb": round(memory.total / (1024 * 1024), 2),
            "available_mb": round(memory.available / (1024 * 1024), 2),
            "used_mb": round(memory.used / (1024 * 1024), 2),
            "percent": round(memory.percent, 2),
            "swap_used_mb": round(swap.used / (1024 * 1024), 2),
            "swap_percent": round(swap.percent, 2)
        }
    
    def get_disk_usage(self) -> Dict[str, Any]:
        """Get disk usage statistics"""
        disk = psutil.disk_usage('/')
        io_counters = psutil.disk_io_counters()
        
        return {
            "total_gb": round(disk.total / (1024 ** 3), 2),
            "used_gb": round(disk.used / (1024 ** 3), 2),
            "free_gb": round(disk.free / (1024 ** 3), 2),
            "percent": round(disk.percent, 2),
            "read_mb": round(io_counters.read_bytes / (1024 * 1024), 2) if io_counters else None,
            "write_mb": round(io_counters.write_bytes / (1024 * 1024), 2) if io_counters else None,
            "read_count": io_counters.read_count if io_counters else None,
            "write_count": io_counters.write_count if io_counters else None
        }
    
    def get_process_info(self) -> Dict[str, Any]:
        """Get current process information"""
        process = psutil.Process()
        
        return {
            "pid": process.pid,
            "name": process.name(),
            "cpu_percent": round(process.cpu_percent(interval=0.1), 2),
            "memory_mb": round(process.memory_info().rss / (1024 * 1024), 2),
            "memory_percent": round(process.memory_percent(), 2),
            "num_threads": process.num_threads(),
            "status": process.status(),
            "create_time": datetime.fromtimestamp(process.create_time()).isoformat()
        }
    
    # ========================================================================
    # PERFORMANCE TRACKING
    # ========================================================================
    
    def record_scan(self, duration: float, files_scanned: int):
        """Record scan performance"""
        self.scan_times.append(duration)
        
        if files_scanned > 0:
            speed = files_scanned / duration if duration > 0 else 0
            self.scan_speeds.append(speed)
        
        self.stats["total_scans"] += 1
        self.stats["total_files_scanned"] += files_scanned
        
        # Check thresholds
        if duration > 60:  # Scan taking more than 1 minute
            self._create_alert(
                "SLOW_SCAN",
                f"Scan took {duration:.2f}s for {files_scanned} files",
                "warning"
            )
    
    def record_query(self, query_name: str, duration: float):
        """Record query performance"""
        duration_ms = duration * 1000
        self.query_times.append({
            "name": query_name,
            "duration_ms": duration_ms,
            "timestamp": datetime.now().isoformat()
        })
        
        self.stats["total_queries"] += 1
        
        # Track slow queries
        if duration_ms > self.thresholds["query_time_ms"]:
            self.slow_queries.append({
                "name": query_name,
                "duration_ms": round(duration_ms, 2),
                "timestamp": datetime.now().isoformat()
            })
            
            if duration_ms > 500:  # Very slow query
                self._create_alert(
                    "SLOW_QUERY",
                    f"Query '{query_name}' took {duration_ms:.2f}ms",
                    "warning"
                )
    
    def record_api_call(self, endpoint: str, duration: float, status_code: int):
        """Record API call performance"""
        duration_ms = duration * 1000
        
        if endpoint not in self.api_response_times:
            self.api_response_times[endpoint] = {
                "count": 0,
                "total_time_ms": 0,
                "avg_time_ms": 0,
                "max_time_ms": 0,
                "errors": 0
            }
        
        stats = self.api_response_times[endpoint]
        stats["count"] += 1
        stats["total_time_ms"] += duration_ms
        stats["avg_time_ms"] = stats["total_time_ms"] / stats["count"]
        stats["max_time_ms"] = max(stats["max_time_ms"], duration_ms)
        
        if status_code >= 400:
            stats["errors"] += 1
        
        self.stats["total_api_calls"] += 1
        
        # Check thresholds
        if duration_ms > self.thresholds["api_response_ms"]:
            self._create_alert(
                "SLOW_API",
                f"API {endpoint} took {duration_ms:.2f}ms",
                "info"
            )
    
    # ========================================================================
    # MONITORING LOOP
    # ========================================================================
    
    def start_monitoring(self, interval: float = 5.0):
        """Start background monitoring"""
        if self.monitoring:
            logger.warning("Monitoring already running")
            return
        
        self.monitoring = True
        self.monitor_thread = threading.Thread(
            target=self._monitoring_loop,
            args=(interval,),
            daemon=True
        )
        self.monitor_thread.start()
        logger.info(f"📊 Performance monitoring started (interval: {interval}s)")
    
    def stop_monitoring(self):
        """Stop background monitoring"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        logger.info("Performance monitoring stopped")
    
    def _monitoring_loop(self, interval: float):
        """Background monitoring loop"""
        while self.monitoring:
            try:
                # Collect metrics
                cpu = self.get_cpu_usage()
                memory = self.get_memory_usage()
                disk = self.get_disk_usage()
                
                # Store in history
                timestamp = datetime.now()
                self.cpu_history.append({"timestamp": timestamp, "value": cpu["percent"]})
                self.memory_history.append({"timestamp": timestamp, "value": memory["percent"]})
                self.disk_history.append({"timestamp": timestamp, "value": disk["percent"]})
                
                # Check thresholds
                if cpu["percent"] > self.thresholds["cpu_percent"]:
                    self._create_alert(
                        "HIGH_CPU",
                        f"CPU usage at {cpu['percent']}%",
                        "warning"
                    )
                
                if memory["percent"] > self.thresholds["memory_percent"]:
                    self._create_alert(
                        "HIGH_MEMORY",
                        f"Memory usage at {memory['percent']}%",
                        "warning"
                    )
                
                if disk["percent"] > self.thresholds["disk_percent"]:
                    self._create_alert(
                        "HIGH_DISK",
                        f"Disk usage at {disk['percent']}%",
                        "critical"
                    )
                
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
            
            time.sleep(interval)
    
    # ========================================================================
    # ALERTS
    # ========================================================================
    
    def _create_alert(self, alert_type: str, message: str, severity: str):
        """Create performance alert"""
        alert = {
            "type": alert_type,
            "message": message,
            "severity": severity,
            "timestamp": datetime.now().isoformat()
        }
        self.alerts.append(alert)
        
        if severity == "critical":
            logger.error(f"🚨 {alert_type}: {message}")
        elif severity == "warning":
            logger.warning(f"⚠️  {alert_type}: {message}")
        else:
            logger.info(f"ℹ️  {alert_type}: {message}")
    
    def get_alerts(self, severity: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent alerts"""
        alerts = list(self.alerts)
        
        if severity:
            alerts = [a for a in alerts if a["severity"] == severity]
        
        return alerts[-limit:]
    
    # ========================================================================
    # STATISTICS & REPORTS
    # ========================================================================
    
    def get_scan_statistics(self) -> Dict[str, Any]:
        """Get scan performance statistics"""
        if not self.scan_times:
            return {
                "total_scans": 0,
                "avg_scan_time": 0,
                "avg_scan_speed": 0
            }
        
        return {
            "total_scans": self.stats["total_scans"],
            "total_files_scanned": self.stats["total_files_scanned"],
            "avg_scan_time_seconds": round(sum(self.scan_times) / len(self.scan_times), 2),
            "max_scan_time_seconds": round(max(self.scan_times), 2),
            "min_scan_time_seconds": round(min(self.scan_times), 2),
            "avg_scan_speed_fps": round(sum(self.scan_speeds) / len(self.scan_speeds), 2) if self.scan_speeds else 0,
            "max_scan_speed_fps": round(max(self.scan_speeds), 2) if self.scan_speeds else 0
        }
    
    def get_query_statistics(self) -> Dict[str, Any]:
        """Get query performance statistics"""
        if not self.query_times:
            return {
                "total_queries": 0,
                "avg_query_time_ms": 0
            }
        
        durations = [q["duration_ms"] for q in self.query_times]
        
        return {
            "total_queries": self.stats["total_queries"],
            "avg_query_time_ms": round(sum(durations) / len(durations), 2),
            "max_query_time_ms": round(max(durations), 2),
            "min_query_time_ms": round(min(durations), 2),
            "slow_queries_count": len(self.slow_queries),
            "recent_slow_queries": list(self.slow_queries)[-10:]
        }
    
    def get_api_statistics(self) -> Dict[str, Any]:
        """Get API performance statistics"""
        total_calls = sum(s["count"] for s in self.api_response_times.values())
        total_errors = sum(s["errors"] for s in self.api_response_times.values())
        
        # Top 10 slowest endpoints
        slowest = sorted(
            [(endpoint, stats["avg_time_ms"]) for endpoint, stats in self.api_response_times.items()],
            key=lambda x: x[1],
            reverse=True
        )[:10]
        
        return {
            "total_api_calls": total_calls,
            "total_errors": total_errors,
            "error_rate": round((total_errors / total_calls * 100), 2) if total_calls > 0 else 0,
            "slowest_endpoints": [
                {"endpoint": e, "avg_time_ms": round(t, 2)}
                for e, t in slowest
            ],
            "endpoints_count": len(self.api_response_times)
        }
    
    def get_system_health(self) -> Dict[str, Any]:
        """Get overall system health"""
        cpu = self.get_cpu_usage()
        memory = self.get_memory_usage()
        disk = self.get_disk_usage()
        process = self.get_process_info()
        
        # Calculate health score (0-100)
        health_score = 100
        
        if cpu["percent"] > self.thresholds["cpu_percent"]:
            health_score -= 20
        elif cpu["percent"] > self.thresholds["cpu_percent"] * 0.7:
            health_score -= 10
        
        if memory["percent"] > self.thresholds["memory_percent"]:
            health_score -= 20
        elif memory["percent"] > self.thresholds["memory_percent"] * 0.7:
            health_score -= 10
        
        if disk["percent"] > self.thresholds["disk_percent"]:
            health_score -= 20
        elif disk["percent"] > self.thresholds["disk_percent"] * 0.7:
            health_score -= 10
        
        # Determine status
        if health_score >= 80:
            status = "excellent"
        elif health_score >= 60:
            status = "good"
        elif health_score >= 40:
            status = "fair"
        else:
            status = "poor"
        
        return {
            "health_score": health_score,
            "status": status,
            "cpu": cpu,
            "memory": memory,
            "disk": disk,
            "process": process,
            "uptime_seconds": (datetime.now() - self.stats["start_time"]).total_seconds()
        }
    
    def get_performance_report(self) -> Dict[str, Any]:
        """Get comprehensive performance report"""
        return {
            "system_health": self.get_system_health(),
            "scan_statistics": self.get_scan_statistics(),
            "query_statistics": self.get_query_statistics(),
            "api_statistics": self.get_api_statistics(),
            "alerts": {
                "total": len(self.alerts),
                "critical": len([a for a in self.alerts if a["severity"] == "critical"]),
                "warning": len([a for a in self.alerts if a["severity"] == "warning"]),
                "recent": list(self.alerts)[-10:]
            },
            "timestamp": datetime.now().isoformat()
        }
    
    def get_bottlenecks(self) -> List[Dict[str, Any]]:
        """Detect performance bottlenecks"""
        bottlenecks = []
        
        # CPU bottleneck
        cpu = self.get_cpu_usage()
        if cpu["percent"] > self.thresholds["cpu_percent"]:
            bottlenecks.append({
                "type": "CPU",
                "severity": "high" if cpu["percent"] > 90 else "medium",
                "message": f"CPU usage at {cpu['percent']}%",
                "recommendation": "Consider optimizing CPU-intensive operations or scaling horizontally"
            })
        
        # Memory bottleneck
        memory = self.get_memory_usage()
        if memory["percent"] > self.thresholds["memory_percent"]:
            bottlenecks.append({
                "type": "MEMORY",
                "severity": "high" if memory["percent"] > 95 else "medium",
                "message": f"Memory usage at {memory['percent']}%",
                "recommendation": "Implement memory caching strategies or increase available memory"
            })
        
        # Disk bottleneck
        disk = self.get_disk_usage()
        if disk["percent"] > self.thresholds["disk_percent"]:
            bottlenecks.append({
                "type": "DISK",
                "severity": "critical" if disk["percent"] > 95 else "high",
                "message": f"Disk usage at {disk['percent']}%",
                "recommendation": "Clean up old data or expand storage capacity"
            })
        
        # Slow queries
        if len(self.slow_queries) > 10:
            bottlenecks.append({
                "type": "DATABASE",
                "severity": "medium",
                "message": f"{len(self.slow_queries)} slow queries detected",
                "recommendation": "Add indexes or optimize query patterns"
            })
        
        # Slow scans
        if self.scan_times and max(self.scan_times) > 120:
            bottlenecks.append({
                "type": "SCANNER",
                "severity": "medium",
                "message": f"Scan performance degraded (max: {max(self.scan_times):.2f}s)",
                "recommendation": "Enable parallel scanning or optimize scan algorithms"
            })
        
        return bottlenecks
    
    # ========================================================================
    # RECOMMENDATIONS
    # ========================================================================
    
    def get_optimization_recommendations(self) -> List[Dict[str, Any]]:
        """Get optimization recommendations based on performance data"""
        recommendations = []
        
        # Scan optimization
        if self.scan_speeds and max(self.scan_speeds) < 100:
            recommendations.append({
                "category": "Scanning",
                "priority": "high",
                "recommendation": "Enable multi-threaded scanning to improve scan speed",
                "expected_improvement": "2-4x faster scans"
            })
        
        # Query optimization
        if len(self.slow_queries) > 20:
            recommendations.append({
                "category": "Database",
                "priority": "high",
                "recommendation": "Add database indexes on frequently queried columns",
                "expected_improvement": "50-80% faster queries"
            })
        
        # Caching
        if self.stats["total_queries"] > 1000:
            recommendations.append({
                "category": "Caching",
                "priority": "medium",
                "recommendation": "Implement query result caching for frequently accessed data",
                "expected_improvement": "40-60% reduction in database load"
            })
        
        # Memory optimization
        memory = self.get_memory_usage()
        if memory["percent"] > 70:
            recommendations.append({
                "category": "Memory",
                "priority": "medium",
                "recommendation": "Implement aggressive garbage collection and memory pooling",
                "expected_improvement": "20-30% memory reduction"
            })
        
        return recommendations


# Global performance monitor instance
_performance_monitor = None

def get_performance_monitor() -> PerformanceMonitor:
    """Get global performance monitor instance"""
    global _performance_monitor
    if _performance_monitor is None:
        _performance_monitor = PerformanceMonitor()
    return _performance_monitor