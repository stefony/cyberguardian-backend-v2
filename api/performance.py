"""
CyberGuardian AI - Performance API
PHASE 6: Performance Optimization

API endpoints for:
- System health monitoring
- Performance metrics
- Query statistics
- Optimization recommendations
- Bottleneck detection
"""

from fastapi import APIRouter, HTTPException, Query
from typing import Dict, List, Any, Optional
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

# Create router
router = APIRouter(prefix="/api/performance", tags=["Performance"])


# ============================================================================
# SYSTEM HEALTH
# ============================================================================

@router.get("/health")
async def get_system_health():
    """
    Get overall system health status
    
    Returns:
        - health_score: 0-100 score
        - status: excellent/good/fair/poor
        - cpu, memory, disk metrics
        - process information
    """
    try:
        from core.performance_monitor import get_performance_monitor
        
        monitor = get_performance_monitor()
        health = monitor.get_system_health()
        
        return {
            "success": True,
            "health": health,
            "timestamp": datetime.now().isoformat()
        }
    
    except Exception as e:
        logger.error(f"Error getting system health: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/metrics")
async def get_performance_metrics():
    """
    Get current performance metrics
    
    Returns:
        - CPU usage
        - Memory usage
        - Disk usage
        - Process information
    """
    try:
        from core.performance_monitor import get_performance_monitor
        
        monitor = get_performance_monitor()
        
        return {
            "success": True,
            "metrics": {
                "cpu": monitor.get_cpu_usage(),
                "memory": monitor.get_memory_usage(),
                "disk": monitor.get_disk_usage(),
                "process": monitor.get_process_info()
            },
            "timestamp": datetime.now().isoformat()
        }
    
    except Exception as e:
        logger.error(f"Error getting metrics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# PERFORMANCE STATISTICS
# ============================================================================

@router.get("/statistics")
async def get_performance_statistics():
    """
    Get comprehensive performance statistics
    
    Returns:
        - Scan statistics
        - Query statistics
        - API statistics
        - Overall stats
    """
    try:
        from core.performance_monitor import get_performance_monitor
        
        monitor = get_performance_monitor()
        
        return {
            "success": True,
            "statistics": {
                "scans": monitor.get_scan_statistics(),
                "queries": monitor.get_query_statistics(),
                "api": monitor.get_api_statistics(),
                "overall": {
                    "total_scans": monitor.stats["total_scans"],
                    "total_files_scanned": monitor.stats["total_files_scanned"],
                    "total_queries": monitor.stats["total_queries"],
                    "total_api_calls": monitor.stats["total_api_calls"],
                    "uptime_seconds": (datetime.now() - monitor.stats["start_time"]).total_seconds()
                }
            },
            "timestamp": datetime.now().isoformat()
        }
    
    except Exception as e:
        logger.error(f"Error getting statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/database/stats")
async def get_database_statistics():
    """
    Get database performance statistics
    
    Returns:
        - Database size
        - Table counts
        - Index count
        - Query performance
    """
    try:
        from database.db_optimized import get_database_stats, get_performance_report
        
        db_stats = get_database_stats()
        perf_report = get_performance_report()
        
        return {
            "success": True,
            "database": db_stats,
            "performance": perf_report,
            "timestamp": datetime.now().isoformat()
        }
    
    except Exception as e:
        logger.error(f"Error getting database stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# ALERTS & BOTTLENECKS
# ============================================================================

@router.get("/alerts")
async def get_performance_alerts(
    severity: Optional[str] = Query(None, description="Filter by severity (info/warning/critical)"),
    limit: int = Query(50, ge=1, le=200, description="Maximum number of alerts")
):
    """
    Get performance alerts
    
    Args:
        severity: Filter by severity level
        limit: Maximum number of alerts
        
    Returns:
        List of performance alerts
    """
    try:
        from core.performance_monitor import get_performance_monitor
        
        monitor = get_performance_monitor()
        alerts = monitor.get_alerts(severity=severity, limit=limit)
        
        return {
            "success": True,
            "alerts": alerts,
            "total": len(alerts),
            "timestamp": datetime.now().isoformat()
        }
    
    except Exception as e:
        logger.error(f"Error getting alerts: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/bottlenecks")
async def detect_bottlenecks():
    """
    Detect performance bottlenecks
    
    Returns:
        - List of detected bottlenecks
        - Severity levels
        - Recommendations
    """
    try:
        from core.performance_monitor import get_performance_monitor
        
        monitor = get_performance_monitor()
        bottlenecks = monitor.get_bottlenecks()
        
        return {
            "success": True,
            "bottlenecks": bottlenecks,
            "count": len(bottlenecks),
            "has_critical": any(b["severity"] == "critical" for b in bottlenecks),
            "timestamp": datetime.now().isoformat()
        }
    
    except Exception as e:
        logger.error(f"Error detecting bottlenecks: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# OPTIMIZATION
# ============================================================================

@router.get("/recommendations")
async def get_optimization_recommendations():
    """
    Get optimization recommendations
    
    Returns:
        List of recommendations with priorities and expected improvements
    """
    try:
        from core.performance_monitor import get_performance_monitor
        
        monitor = get_performance_monitor()
        recommendations = monitor.get_optimization_recommendations()
        
        return {
            "success": True,
            "recommendations": recommendations,
            "total": len(recommendations),
            "high_priority": len([r for r in recommendations if r["priority"] == "high"]),
            "timestamp": datetime.now().isoformat()
        }
    
    except Exception as e:
        logger.error(f"Error getting recommendations: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/optimize/database")
async def optimize_database():
    """
    Optimize database (VACUUM, ANALYZE)
    
    Returns:
        Success status and optimization results
    """
    try:
        from database.db_optimized import optimize_database, analyze_database
        
        # Run optimization
        optimize_database()
        analyze_database()
        
        return {
            "success": True,
            "message": "Database optimized successfully",
            "timestamp": datetime.now().isoformat()
        }
    
    except Exception as e:
        logger.error(f"Error optimizing database: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/cache/clear")
async def clear_cache():
    """
    Clear query cache
    
    Returns:
        Success status
    """
    try:
        from database.db_optimized import _query_cache
        
        _query_cache.invalidate()
        
        return {
            "success": True,
            "message": "Cache cleared successfully",
            "timestamp": datetime.now().isoformat()
        }
    
    except Exception as e:
        logger.error(f"Error clearing cache: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# REPORTS
# ============================================================================

@router.get("/report")
async def get_performance_report():
    """
    Get comprehensive performance report
    
    Returns:
        - System health
        - Statistics
        - Alerts
        - Bottlenecks
        - Recommendations
    """
    try:
        from core.performance_monitor import get_performance_monitor
        
        monitor = get_performance_monitor()
        report = monitor.get_performance_report()
        bottlenecks = monitor.get_bottlenecks()
        recommendations = monitor.get_optimization_recommendations()
        
        report["bottlenecks"] = bottlenecks
        report["recommendations"] = recommendations
        
        return {
            "success": True,
            "report": report,
            "timestamp": datetime.now().isoformat()
        }
    
    except Exception as e:
        logger.error(f"Error generating report: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/report/summary")
async def get_performance_summary():
    """
    Get quick performance summary
    
    Returns:
        High-level overview of system performance
    """
    try:
        from core.performance_monitor import get_performance_monitor
        
        monitor = get_performance_monitor()
        health = monitor.get_system_health()
        bottlenecks = monitor.get_bottlenecks()
        
        # Calculate summary metrics
        critical_bottlenecks = [b for b in bottlenecks if b["severity"] == "critical"]
        
        summary = {
            "health_score": health["health_score"],
            "status": health["status"],
            "cpu_percent": health["cpu"]["percent"],
            "memory_percent": health["memory"]["percent"],
            "disk_percent": health["disk"]["percent"],
            "uptime_hours": round(health["uptime_seconds"] / 3600, 2),
            "total_scans": monitor.stats["total_scans"],
            "total_queries": monitor.stats["total_queries"],
            "active_alerts": len(monitor.alerts),
            "critical_issues": len(critical_bottlenecks),
            "needs_attention": len(bottlenecks) > 0
        }
        
        return {
            "success": True,
            "summary": summary,
            "timestamp": datetime.now().isoformat()
        }
    
    except Exception as e:
        logger.error(f"Error getting summary: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# MONITORING CONTROL
# ============================================================================

@router.post("/monitoring/start")
async def start_monitoring(interval: float = Query(5.0, ge=1.0, le=60.0, description="Monitoring interval in seconds")):
    """
    Start background performance monitoring
    
    Args:
        interval: Monitoring interval in seconds
        
    Returns:
        Success status
    """
    try:
        from core.performance_monitor import get_performance_monitor
        
        monitor = get_performance_monitor()
        monitor.start_monitoring(interval=interval)
        
        return {
            "success": True,
            "message": f"Monitoring started with {interval}s interval",
            "timestamp": datetime.now().isoformat()
        }
    
    except Exception as e:
        logger.error(f"Error starting monitoring: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/monitoring/stop")
async def stop_monitoring():
    """
    Stop background performance monitoring
    
    Returns:
        Success status
    """
    try:
        from core.performance_monitor import get_performance_monitor
        
        monitor = get_performance_monitor()
        monitor.stop_monitoring()
        
        return {
            "success": True,
            "message": "Monitoring stopped",
            "timestamp": datetime.now().isoformat()
        }
    
    except Exception as e:
        logger.error(f"Error stopping monitoring: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# HISTORY & TRENDS
# ============================================================================

@router.get("/history/cpu")
async def get_cpu_history(minutes: int = Query(60, ge=1, le=1440, description="Minutes of history")):
    """
    Get CPU usage history
    
    Args:
        minutes: Number of minutes of history
        
    Returns:
        CPU usage data points
    """
    try:
        from core.performance_monitor import get_performance_monitor
        from datetime import timedelta
        
        monitor = get_performance_monitor()
        cutoff = datetime.now() - timedelta(minutes=minutes)
        
        history = [
            {"timestamp": h["timestamp"].isoformat(), "value": h["value"]}
            for h in monitor.cpu_history
            if h["timestamp"] >= cutoff
        ]
        
        return {
            "success": True,
            "history": history,
            "count": len(history),
            "timestamp": datetime.now().isoformat()
        }
    
    except Exception as e:
        logger.error(f"Error getting CPU history: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/history/memory")
async def get_memory_history(minutes: int = Query(60, ge=1, le=1440, description="Minutes of history")):
    """
    Get memory usage history
    
    Args:
        minutes: Number of minutes of history
        
    Returns:
        Memory usage data points
    """
    try:
        from core.performance_monitor import get_performance_monitor
        from datetime import timedelta
        
        monitor = get_performance_monitor()
        cutoff = datetime.now() - timedelta(minutes=minutes)
        
        history = [
            {"timestamp": h["timestamp"].isoformat(), "value": h["value"]}
            for h in monitor.memory_history
            if h["timestamp"] >= cutoff
        ]
        
        return {
            "success": True,
            "history": history,
            "count": len(history),
            "timestamp": datetime.now().isoformat()
        }
    
    except Exception as e:
        logger.error(f"Error getting memory history: {e}")
        raise HTTPException(status_code=500, detail=str(e))