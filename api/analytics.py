"""
CyberGuardian AI - Analytics API
Statistics and Data Visualization Endpoints

Provides analytics data for:
- Threats timeline
- Detection statistics
- Honeypot activity
- Overall system statistics
"""

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime, timedelta
from fastapi import Request
from middleware.rate_limiter import limiter, READ_LIMIT
import sqlite3

# ============================================
# PYDANTIC MODELS
# ============================================

class TimelinePoint(BaseModel):
    """Single point in timeline"""
    date: str
    count: int

class DetectionBreakdown(BaseModel):
    """Detection method breakdown"""
    method: str
    count: int
    percentage: float

class ThreatCategory(BaseModel):
    """Threat category statistics"""
    category: str
    count: int
    severity: str

class OverviewStats(BaseModel):
    """Overall system statistics"""
    total_threats: int
    active_threats: int
    blocked_threats: int
    total_scans: int
    successful_scans: int
    total_honeypots: int
    active_honeypots: int
    total_interactions: int
    threats_today: int
    scans_today: int

# ============================================
# HELPER FUNCTIONS
# ============================================

def get_db_connection():
    """Get database connection"""
    conn = sqlite3.connect('database/cyberguardian.db')
    conn.row_factory = sqlite3.Row
    return conn

def get_date_range(days: int = 7):
    """Get date range for queries"""
    end_date = datetime.now()
    start_date = end_date - timedelta(days=days)
    return start_date.strftime('%Y-%m-%d'), end_date.strftime('%Y-%m-%d')

# ============================================
# INITIALIZE SAMPLE DATA
# ============================================

def initialize_sample_analytics_data():
    """
    Add sample data for analytics if tables are empty
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if scans table has data
        cursor.execute("SELECT COUNT(*) FROM scans")
        scans_count = cursor.fetchone()[0]
        
        if scans_count == 0:
            # Add sample scans
            sample_scans = [
                ("2025-01-14 09:30:00", "file", "completed", 1),
        ("2025-01-14 08:15:00", "directory", "completed", 0),
        ("2025-01-13 14:20:00", "full_system", "completed", 2),
        ("2025-01-13 11:45:00", "process", "completed", 1),
        ("2025-01-12 16:30:00", "file", "completed", 1),
            ]
            
            cursor.executemany(
                """INSERT INTO scans (started_at, scan_type, status, threats_found)
           VALUES (?, ?, ?, ?)""",
        sample_scans
            )
            print("✅ Sample scans data initialized")
        
        # Check if honeypot_logs table has data
        cursor.execute("SELECT COUNT(*) FROM honeypot_logs")
        logs_count = cursor.fetchone()[0]
        
        if logs_count == 0:
            # Add sample honeypot logs
            sample_logs = [
                (1, "2025-01-14 09:23:00", "198.51.100.29", "authentication_failed", "SSH login attempt failed"),
                (2, "2025-01-14 08:45:00", "203.0.113.17", "connection_attempt", "HTTP request to fake admin panel"),
                (1, "2025-01-13 15:12:00", "198.51.100.219", "authentication_failed", "Multiple SSH attempts"),
                (3, "2025-01-13 12:30:00", "192.0.2.51", "connection_attempt", "FTP connection attempt"),
                (2, "2025-01-12 18:20:00", "203.0.113.51", "authentication_failed", "Admin login failed"),
                (1, "2025-01-12 14:15:00", "198.51.100.100", "connection_attempt", "Port scan detected"),
                (3, "2025-01-11 10:30:00", "192.0.2.156", "authentication_failed", "FTP brute force"),
                (2, "2025-01-11 09:45:00", "203.0.113.11", "connection_attempt", "HTTP scanning"),
            ]
            
            cursor.executemany(
                """INSERT INTO honeypot_logs (honeypot_id, timestamp, source_ip, action, details)
                   VALUES (?, ?, ?, ?, ?)""",
                sample_logs
            )
            print("✅ Sample honeypot logs initialized")
        
        conn.commit()
        conn.close()
        
    except Exception as e:
        print(f"❌ Error initializing analytics data: {e}")


# Initialize on module load
initialize_sample_analytics_data()

router = APIRouter()

# ============================================
# API ENDPOINTS
# ============================================

@router.get("/overview", response_model=OverviewStats)
@limiter.limit(READ_LIMIT)
async def get_overview_stats(request: Request):
    """
    Get overall system statistics
    
    Returns comprehensive statistics across all modules
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Threats stats
        cursor.execute("SELECT COUNT(*) FROM threats")
        total_threats = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM threats WHERE status = 'active'")
        active_threats = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM threats WHERE status = 'blocked'")
        blocked_threats = cursor.fetchone()[0]
        
        # Scans stats
        cursor.execute("SELECT COUNT(*) FROM scans")
        total_scans = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM scans WHERE status = 'completed'")
        successful_scans = cursor.fetchone()[0]
        
        # Honeypots stats
        cursor.execute("SELECT COUNT(*) FROM honeypots")
        total_honeypots = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM honeypots WHERE status = 'active'")
        active_honeypots = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM honeypot_logs")
        total_interactions = cursor.fetchone()[0]
        
        # Today's stats
        today = datetime.now().strftime('%Y-%m-%d')
        cursor.execute("SELECT COUNT(*) FROM threats WHERE DATE(timestamp) = ?", (today,))
        threats_today = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM scans WHERE DATE(started_at) = ?", (today,))
        scans_today = cursor.fetchone()[0]
        
        conn.close()
        
        return OverviewStats(
            total_threats=total_threats,
            active_threats=active_threats,
            blocked_threats=blocked_threats,
            total_scans=total_scans,
            successful_scans=successful_scans,
            total_honeypots=total_honeypots,
            active_honeypots=active_honeypots,
            total_interactions=total_interactions,
            threats_today=threats_today,
            scans_today=scans_today
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get overview stats: {str(e)}")


@router.get("/threats-timeline", response_model=List[TimelinePoint])
@limiter.limit(READ_LIMIT)
async def get_threats_timeline(request: Request, days: int = Query(7, ge=1, le=90)):
    """
    Get threats timeline (threats detected over time)
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        start_date, end_date = get_date_range(days)

        query = """
            SELECT DATE(timestamp) as date, COUNT(*) as count
            FROM threats
            WHERE DATE(timestamp) BETWEEN ? AND ?
            GROUP BY DATE(timestamp)
            ORDER BY date ASC
        """

        cursor.execute(query, (start_date, end_date))
        results = cursor.fetchall()

        timeline = [
            TimelinePoint(date=row['date'], count=row['count'])
            for row in results
        ]

        return timeline

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get threats timeline: {str(e)}")
    finally:
        try:
            conn.close()
        except:
            pass


@router.get("/detection-stats", response_model=List[DetectionBreakdown])
@limiter.limit(READ_LIMIT)
async def get_detection_stats(request: Request):
    """
    Get detection method statistics
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        query = """
            SELECT scan_type as method, COUNT(*) as count
            FROM scans
            GROUP BY scan_type
        """

        cursor.execute(query)
        results = cursor.fetchall()

        total = sum(row["count"] for row in results)

        breakdown = [
            DetectionBreakdown(
                method=row["method"],
                count=row["count"],
                percentage=round((row["count"] / total * 100), 2) if total > 0 else 0
            )
            for row in results
        ]

        return breakdown

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get detection stats: {str(e)}")
    finally:
        try:
            conn.close()
        except:
            pass


@router.get("/honeypot-activity", response_model=List[TimelinePoint])
@limiter.limit(READ_LIMIT)
async def get_honeypot_activity(request: Request, days: int = Query(7, ge=1, le=90)):
    """
    Get honeypot interaction timeline
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        start_date, end_date = get_date_range(days)

        query = """
            SELECT DATE(timestamp) as date, COUNT(*) as count
            FROM honeypot_logs
            WHERE DATE(timestamp) BETWEEN ? AND ?
            GROUP BY DATE(timestamp)
            ORDER BY date ASC
        """

        cursor.execute(query, (start_date, end_date))
        results = cursor.fetchall()

        activity = [
            TimelinePoint(date=row["date"], count=row["count"])
            for row in results
        ]

        return activity

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get honeypot activity: {str(e)}")
    finally:
        try:
            conn.close()
        except:
            pass


@router.get("/top-threats", response_model=List[ThreatCategory])
@limiter.limit(READ_LIMIT)
async def get_top_threats(request: Request, limit: int = Query(5, ge=1, le=20)):
    """
    Get top threats by count
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        query = """
            SELECT threat_type as category, severity, COUNT(*) as count
            FROM threats
            GROUP BY threat_type, severity
            ORDER BY count DESC
            LIMIT ?
        """

        cursor.execute(query, (limit,))
        results = cursor.fetchall()

        top_threats = [
            ThreatCategory(
                category=row["category"],
                count=row["count"],
                severity=row["severity"]
            )
            for row in results
        ]

        return top_threats

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get top threats: {str(e)}")
    finally:
        try:
            conn.close()
        except:
            pass