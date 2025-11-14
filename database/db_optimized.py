"""
CyberGuardian AI - Optimized Database Module
PHASE 6: Performance Optimization

Features:
- Strategic indexes for faster queries
- Connection pooling
- Query result caching
- Performance monitoring
- Optimized batch operations
"""

import sqlite3
from datetime import datetime
from typing import List, Optional, Dict, Any, Tuple
from pathlib import Path
import json
import logging
import hashlib
import time
from functools import wraps
from collections import OrderedDict
import threading

logger = logging.getLogger(__name__)

# Database file path
DB_PATH = Path(__file__).parent / "cyberguardian.db"

# ============================================================================
# CONNECTION POOLING
# ============================================================================

class ConnectionPool:
    """SQLite connection pool for better performance"""
    
    def __init__(self, db_path: str, pool_size: int = 10):
        self.db_path = db_path
        self.pool_size = pool_size
        self.connections = []
        self.in_use = set()
        self.lock = threading.Lock()
        
        # Initialize pool
        for _ in range(pool_size):
            conn = self._create_connection()
            self.connections.append(conn)
    
    def _create_connection(self):
        """Create new database connection"""
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        # Enable WAL mode for better concurrency
        conn.execute("PRAGMA journal_mode=WAL")
        # Set optimal cache size (10MB)
        conn.execute("PRAGMA cache_size=-10000")
        # Enable foreign keys
        conn.execute("PRAGMA foreign_keys=ON")
        return conn
    
    def get_connection(self):
        """Get connection from pool"""
        with self.lock:
            if self.connections:
                conn = self.connections.pop()
                self.in_use.add(id(conn))
                return conn
            else:
                # Pool exhausted, create new connection
                logger.warning("Connection pool exhausted, creating new connection")
                conn = self._create_connection()
                self.in_use.add(id(conn))
                return conn
    
    def return_connection(self, conn):
        """Return connection to pool"""
        with self.lock:
            conn_id = id(conn)
            if conn_id in self.in_use:
                self.in_use.remove(conn_id)
                if len(self.connections) < self.pool_size:
                    self.connections.append(conn)
                else:
                    conn.close()
    
    def close_all(self):
        """Close all connections"""
        with self.lock:
            for conn in self.connections:
                conn.close()
            self.connections.clear()
            self.in_use.clear()

# Global connection pool
_connection_pool = None

def get_connection_pool() -> ConnectionPool:
    """Get global connection pool"""
    global _connection_pool
    if _connection_pool is None:
        _connection_pool = ConnectionPool(str(DB_PATH), pool_size=10)
    return _connection_pool


# ============================================================================
# QUERY CACHING
# ============================================================================

class QueryCache:
    """LRU cache for query results"""
    
    def __init__(self, max_size: int = 100, ttl: int = 300):
        self.max_size = max_size
        self.ttl = ttl  # Time to live in seconds
        self.cache = OrderedDict()
        self.timestamps = {}
        self.lock = threading.Lock()
    
    def _make_key(self, query: str, params: tuple) -> str:
        """Generate cache key"""
        return hashlib.md5(f"{query}:{params}".encode()).hexdigest()
    
    def get(self, query: str, params: tuple) -> Optional[Any]:
        """Get cached result"""
        with self.lock:
            key = self._make_key(query, params)
            
            if key in self.cache:
                # Check if expired
                if time.time() - self.timestamps[key] > self.ttl:
                    del self.cache[key]
                    del self.timestamps[key]
                    return None
                
                # Move to end (mark as recently used)
                self.cache.move_to_end(key)
                return self.cache[key]
            
            return None
    
    def set(self, query: str, params: tuple, result: Any):
        """Cache result"""
        with self.lock:
            key = self._make_key(query, params)
            
            # Remove oldest if at capacity
            if len(self.cache) >= self.max_size:
                oldest_key = next(iter(self.cache))
                del self.cache[oldest_key]
                del self.timestamps[oldest_key]
            
            self.cache[key] = result
            self.timestamps[key] = time.time()
    
    def invalidate(self, pattern: Optional[str] = None):
        """Invalidate cache entries"""
        with self.lock:
            if pattern is None:
                # Clear all
                self.cache.clear()
                self.timestamps.clear()
            else:
                # Clear matching patterns
                keys_to_remove = [k for k in self.cache.keys() if pattern in k]
                for key in keys_to_remove:
                    del self.cache[key]
                    del self.timestamps[key]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        with self.lock:
            return {
                "size": len(self.cache),
                "max_size": self.max_size,
                "ttl": self.ttl
            }

# Global query cache
_query_cache = QueryCache(max_size=100, ttl=300)


# ============================================================================
# PERFORMANCE MONITORING
# ============================================================================

class PerformanceMonitor:
    """Monitor database query performance"""
    
    def __init__(self):
        self.query_stats = {}
        self.slow_queries = []
        self.lock = threading.Lock()
    
    def record_query(self, query: str, duration: float, params: Optional[tuple] = None):
        """Record query execution"""
        with self.lock:
            # Update statistics
            if query not in self.query_stats:
                self.query_stats[query] = {
                    "count": 0,
                    "total_time": 0.0,
                    "avg_time": 0.0,
                    "max_time": 0.0,
                    "min_time": float('inf')
                }
            
            stats = self.query_stats[query]
            stats["count"] += 1
            stats["total_time"] += duration
            stats["avg_time"] = stats["total_time"] / stats["count"]
            stats["max_time"] = max(stats["max_time"], duration)
            stats["min_time"] = min(stats["min_time"], duration)
            
            # Track slow queries (>100ms)
            if duration > 0.1:
                self.slow_queries.append({
                    "query": query[:200],  # Truncate long queries
                    "duration": duration,
                    "params": str(params)[:100] if params else None,
                    "timestamp": datetime.now().isoformat()
                })
                
                # Keep only last 100 slow queries
                if len(self.slow_queries) > 100:
                    self.slow_queries.pop(0)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get performance statistics"""
        with self.lock:
            total_queries = sum(s["count"] for s in self.query_stats.values())
            avg_time = sum(s["total_time"] for s in self.query_stats.values()) / total_queries if total_queries > 0 else 0
            
            # Top 10 slowest queries
            slowest = sorted(
                [(q, s["avg_time"]) for q, s in self.query_stats.items()],
                key=lambda x: x[1],
                reverse=True
            )[:10]
            
            return {
                "total_queries": total_queries,
                "average_query_time": round(avg_time, 4),
                "slow_queries_count": len(self.slow_queries),
                "slowest_queries": [
                    {"query": q[:100], "avg_time": round(t, 4)}
                    for q, t in slowest
                ],
                "recent_slow_queries": self.slow_queries[-10:]
            }
    
    def reset_stats(self):
        """Reset statistics"""
        with self.lock:
            self.query_stats.clear()
            self.slow_queries.clear()

# Global performance monitor
_performance_monitor = PerformanceMonitor()


# ============================================================================
# DECORATORS
# ============================================================================

def with_performance_tracking(func):
    """Decorator to track query performance"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        try:
            result = func(*args, **kwargs)
            duration = time.time() - start_time
            
            # Record performance
            _performance_monitor.record_query(
                func.__name__,
                duration,
                args[1:] if len(args) > 1 else None
            )
            
            return result
        except Exception as e:
            duration = time.time() - start_time
            logger.error(f"Query failed after {duration:.4f}s: {e}")
            raise
    
    return wrapper


def with_caching(ttl: int = 300):
    """Decorator to cache query results"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Generate cache key from function name and arguments
            cache_key = f"{func.__name__}:{args}:{kwargs}"
            
            # Try to get from cache
            cached = _query_cache.get(cache_key, ())
            if cached is not None:
                return cached
            
            # Execute query
            result = func(*args, **kwargs)
            
            # Cache result
            _query_cache.set(cache_key, (), result)
            
            return result
        
        return wrapper
    
    return decorator


# ============================================================================
# OPTIMIZED DATABASE INITIALIZATION
# ============================================================================

def create_indexes():
    """Create strategic indexes for better performance"""
    pool = get_connection_pool()
    conn = pool.get_connection()
    cursor = conn.cursor()
    
    try:
        logger.info("🔧 Creating strategic indexes...")
        
        # Threats table indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_threats_status ON threats(status)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_threats_severity ON threats(severity)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_threats_timestamp ON threats(timestamp DESC)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_threats_status_severity ON threats(status, severity)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_threats_source_ip ON threats(source_ip)")
        
        # Scans table indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_type ON scans(scan_type)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_started_at ON scans(started_at DESC)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_status_type ON scans(status, scan_type)")
        
        # File system events indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_fs_events_timestamp ON fs_events(timestamp DESC)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_fs_events_threat_level ON fs_events(threat_level)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_fs_events_quarantined ON fs_events(quarantined)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_fs_events_file_hash ON fs_events(file_hash)")
        
        # Quarantine indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_quarantine_status ON quarantine(status)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_quarantine_timestamp ON quarantine(quarantined_at DESC)")
        
        # IOC indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(ioc_value)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(ioc_type)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_iocs_severity ON iocs(severity)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_iocs_active ON iocs(is_active, is_whitelisted)")
        
        # Honeypot indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_honeypots_status ON honeypots(status)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_honeypot_logs_timestamp ON honeypot_logs(timestamp DESC)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_honeypot_logs_source_ip ON honeypot_logs(source_ip)")
        
        # Integrity indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_integrity_logs_status ON integrity_logs(status)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_integrity_logs_timestamp ON integrity_logs(timestamp DESC)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_integrity_alerts_resolved ON integrity_alerts(resolved)")
        
        # Update history indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_update_history_status ON update_history(status)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_update_history_started_at ON update_history(started_at DESC)")
        
        # MITRE indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_mitre_techniques_tactic_id ON mitre_techniques(tactic_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_threat_mitre_mappings_threat_id ON threat_mitre_mappings(threat_id)")
        
        # Exclusions indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_exclusions_type ON exclusions(type)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_exclusions_type_value ON exclusions(type, value)")
        
        # Email scanning indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scanned_emails_account_id ON scanned_emails(email_account_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scanned_emails_is_phishing ON scanned_emails(is_phishing)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_email_scan_history_account_id ON email_scan_history(email_account_id)")
        
        conn.commit()
        logger.info("✅ All indexes created successfully!")
        
    except Exception as e:
        logger.error(f"❌ Error creating indexes: {e}")
        conn.rollback()
    finally:
        pool.return_connection(conn)


def analyze_database():
    """Analyze database for query optimization"""
    pool = get_connection_pool()
    conn = pool.get_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("ANALYZE")
        conn.commit()
        logger.info("✅ Database analyzed for optimization")
    except Exception as e:
        logger.error(f"❌ Error analyzing database: {e}")
    finally:
        pool.return_connection(conn)


# ============================================================================
# OPTIMIZED QUERY FUNCTIONS
# ============================================================================

@with_performance_tracking
def execute_query(
    query: str,
    params: Optional[tuple] = None,
    fetch_one: bool = False,
    fetch_all: bool = True,
    use_cache: bool = False
) -> Optional[Any]:
    """
    Execute optimized database query
    
    Args:
        query: SQL query
        params: Query parameters
        fetch_one: Return single row
        fetch_all: Return all rows
        use_cache: Use query cache
        
    Returns:
        Query results
    """
    # Check cache if enabled
    if use_cache and params:
        cached = _query_cache.get(query, params)
        if cached is not None:
            return cached
    
    pool = get_connection_pool()
    conn = pool.get_connection()
    cursor = conn.cursor()
    
    try:
        if params:
            cursor.execute(query, params)
        else:
            cursor.execute(query)
        
        result = None
        
        if fetch_one:
            row = cursor.fetchone()
            result = dict(row) if row else None
        elif fetch_all:
            rows = cursor.fetchall()
            result = [dict(row) for row in rows]
        
        # Commit if it's a write operation
        if query.strip().upper().startswith(('INSERT', 'UPDATE', 'DELETE')):
            conn.commit()
            # Invalidate cache on writes
            _query_cache.invalidate()
        
        # Cache result if enabled
        if use_cache and params and result is not None:
            _query_cache.set(query, params, result)
        
        return result
        
    except Exception as e:
        conn.rollback()
        logger.error(f"Query error: {e}")
        raise
    finally:
        pool.return_connection(conn)


@with_performance_tracking
def execute_batch(queries: List[Tuple[str, tuple]]) -> bool:
    """
    Execute multiple queries in a single transaction
    
    Args:
        queries: List of (query, params) tuples
        
    Returns:
        Success status
    """
    pool = get_connection_pool()
    conn = pool.get_connection()
    cursor = conn.cursor()
    
    try:
        for query, params in queries:
            cursor.execute(query, params)
        
        conn.commit()
        _query_cache.invalidate()
        return True
        
    except Exception as e:
        conn.rollback()
        logger.error(f"Batch execution error: {e}")
        return False
    finally:
        pool.return_connection(conn)


# ============================================================================
# OPTIMIZED DATA ACCESS FUNCTIONS
# ============================================================================

@with_performance_tracking
@with_caching(ttl=60)
def get_threats_optimized(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 100,
    offset: int = 0
) -> List[Dict[str, Any]]:
    """Get threats with optimized query"""
    query = """
        SELECT 
            id, timestamp, source_ip, threat_type, severity, 
            description, status, details, confidence_score, 
            created_at, updated_at
        FROM threats 
        WHERE 1=1
    """
    params = []
    
    if severity:
        query += " AND severity = ?"
        params.append(severity.lower())
    
    if status:
        query += " AND status = ?"
        params.append(status.lower())
    
    query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    
    return execute_query(query, tuple(params), fetch_all=True)


@with_performance_tracking
@with_caching(ttl=30)
def get_threat_stats_optimized() -> Dict[str, Any]:
    """Get threat statistics with optimized queries"""
    stats = {}
    
    # Use COUNT(*) which is faster than COUNT(column)
    total_query = "SELECT COUNT(*) as total FROM threats"
    result = execute_query(total_query, fetch_one=True)
    stats["total_threats"] = result["total"] if result else 0
    
    # Get severity breakdown with single query
    severity_query = """
        SELECT severity, COUNT(*) as count 
        FROM threats 
        GROUP BY severity
    """
    severity_results = execute_query(severity_query, fetch_all=True)
    stats["severity_breakdown"] = {r["severity"]: r["count"] for r in severity_results}
    
    # Get status breakdown
    status_query = """
        SELECT status, COUNT(*) as count 
        FROM threats 
        GROUP BY status
    """
    status_results = execute_query(status_query, fetch_all=True)
    stats["status_breakdown"] = {r["status"]: r["count"] for r in status_results}
    
    stats["last_updated"] = datetime.now().isoformat()
    
    return stats


@with_performance_tracking
def bulk_insert_threats(threats: List[Dict[str, Any]]) -> int:
    """Bulk insert threats for better performance"""
    if not threats:
        return 0
    
    query = """
        INSERT INTO threats 
        (timestamp, source_ip, threat_type, severity, description, status, 
         details, confidence_score, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """
    
    now = datetime.now().isoformat()
    batch = []
    
    for threat in threats:
        params = (
            threat.get("timestamp", now),
            threat["source_ip"],
            threat["threat_type"],
            threat["severity"],
            threat["description"],
            threat.get("status", "active"),
            json.dumps(threat.get("details")) if threat.get("details") else None,
            threat.get("confidence_score", 0.0),
            now,
            now
        )
        batch.append((query, params))
    
    success = execute_batch(batch)
    return len(threats) if success else 0


# ============================================================================
# PERFORMANCE UTILITIES
# ============================================================================

def get_database_stats() -> Dict[str, Any]:
    """Get database statistics"""
    pool = get_connection_pool()
    conn = pool.get_connection()
    cursor = conn.cursor()
    
    try:
        stats = {}
        
        # Database size
        cursor.execute("SELECT page_count * page_size as size FROM pragma_page_count(), pragma_page_size()")
        result = cursor.fetchone()
        stats["database_size_bytes"] = result[0] if result else 0
        stats["database_size_mb"] = round(stats["database_size_bytes"] / (1024 * 1024), 2)
        
        # Table counts
        cursor.execute("""
            SELECT name FROM sqlite_master 
            WHERE type='table' AND name NOT LIKE 'sqlite_%'
        """)
        tables = [row[0] for row in cursor.fetchall()]
        
        table_stats = {}
        for table in tables:
            cursor.execute(f"SELECT COUNT(*) FROM {table}")
            count = cursor.fetchone()[0]
            table_stats[table] = count
        
        stats["table_counts"] = table_stats
        stats["total_records"] = sum(table_stats.values())
        
        # Index information
        cursor.execute("""
            SELECT COUNT(*) FROM sqlite_master 
            WHERE type='index' AND name NOT LIKE 'sqlite_%'
        """)
        stats["index_count"] = cursor.fetchone()[0]
        
        return stats
        
    finally:
        pool.return_connection(conn)


def optimize_database():
    """Optimize database (VACUUM, ANALYZE)"""
    pool = get_connection_pool()
    conn = pool.get_connection()
    cursor = conn.cursor()
    
    try:
        logger.info("🔧 Optimizing database...")
        
        # Analyze for query optimization
        cursor.execute("ANALYZE")
        
        # Vacuum to reclaim space (this can take time)
        cursor.execute("VACUUM")
        
        conn.commit()
        logger.info("✅ Database optimized successfully!")
        
    except Exception as e:
        logger.error(f"❌ Error optimizing database: {e}")
    finally:
        pool.return_connection(conn)


def get_performance_report() -> Dict[str, Any]:
    """Get comprehensive performance report"""
    return {
        "query_performance": _performance_monitor.get_stats(),
        "cache_stats": _query_cache.get_stats(),
        "database_stats": get_database_stats(),
        "connection_pool": {
            "pool_size": _connection_pool.pool_size if _connection_pool else 0,
            "available": len(_connection_pool.connections) if _connection_pool else 0,
            "in_use": len(_connection_pool.in_use) if _connection_pool else 0
        },
        "timestamp": datetime.now().isoformat()
    }


# ============================================================================
# INITIALIZATION
# ============================================================================

def initialize_optimized_database():
    """Initialize database with optimizations"""
    logger.info("🚀 Initializing optimized database...")
    
    # Create indexes
    create_indexes()
    
    # Analyze database
    analyze_database()
    
    logger.info("✅ Optimized database ready!")


# Auto-initialize on import
if __name__ != "__main__":
    try:
        initialize_optimized_database()
    except Exception as e:
        logger.error(f"Failed to initialize optimized database: {e}")