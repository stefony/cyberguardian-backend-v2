"""
CyberGuardian AI - Analytics API
Statistics and Data Visualization Endpoints

Provides analytics data for:
- Threats timeline
- Detection statistics
- Honeypot activity
- Overall system statistics
"""

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime, timedelta
import sqlite3

router = APIRouter()

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
    conn = sqlite3.connect('database/cyberguardian.db')  # ← БЕЗ 'backend/'
    conn.row_factory = sqlite3.Row
    return conn

def get_date_range(days: int = 7):
    """Get date range for queries"""
    end_date = datetime.now()
    start_date = end_date - timedelta(days=days)
    return start_date.strftime('%Y-%m-%d'), end_date.strftime('%Y-%m-%d')

# ============================================
# API ENDPOINTS
# ============================================

@router.get("/analytics/overview", response_model=OverviewStats)
async def get_overview_stats():
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


@router.get("/analytics/threats-timeline", response_model=List[TimelinePoint])
async def get_threats_timeline(days: int = Query(7, ge=1, le=90)):
    """
    Get threats timeline (threats detected over time)
    
    Args:
        days: Number of days to look back (1-90)
    
    Returns:
        List of timeline points with date and count
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        start_date, end_date = get_date_range(days)
        
        # Query threats grouped by date
        query = """
            SELECT DATE(timestamp) as date, COUNT(*) as count
            FROM threats
            WHERE DATE(timestamp) BETWEEN ? AND ?
            GROUP BY DATE(timestamp)
            ORDER BY date ASC
        """
        
        cursor.execute(query, (start_date, end_date))
        results = cursor.fetchall()
        conn.close()
        
        timeline = [
            TimelinePoint(date=row['date'], count=row['count'])
            for row in results
        ]
        
        return timeline
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get threats timeline: {str(e)}")


@router.get("/analytics/detection-stats", response_model=List[DetectionBreakdown])
async def get_detection_stats():
    """
    Get detection method statistics
    
    Returns breakdown of detections by method (signature, behavioral, ML, etc.)
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Query scans grouped by scan_type
        query = """
            SELECT scan_type as method, COUNT(*) as count
            FROM scans
            GROUP BY scan_type
        """
        
        cursor.execute(query)
        results = cursor.fetchall()
        
        # Calculate total and percentages
        total = sum(row['count'] for row in results)
        
        breakdown = []
        for row in results:
            count = row['count']
            percentage = (count / total * 100) if total > 0 else 0
            breakdown.append(
                DetectionBreakdown(
                    method=row['method'],
                    count=count,
                    percentage=round(percentage, 2)
                )
            )
        
        conn.close()
        return breakdown
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get detection stats: {str(e)}")


@router.get("/analytics/honeypot-activity", response_model=List[TimelinePoint])
async def get_honeypot_activity(days: int = Query(7, ge=1, le=90)):
    """
    Get honeypot interaction timeline
    
    Args:
        days: Number of days to look back (1-90)
    
    Returns:
        List of timeline points showing interactions over time
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        start_date, end_date = get_date_range(days)
        
        # Query honeypot logs grouped by date
        query = """
            SELECT DATE(timestamp) as date, COUNT(*) as count
            FROM honeypot_logs
            WHERE DATE(timestamp) BETWEEN ? AND ?
            GROUP BY DATE(timestamp)
            ORDER BY date ASC
        """
        
        cursor.execute(query, (start_date, end_date))
        results = cursor.fetchall()
        conn.close()
        
        activity = [
            TimelinePoint(date=row['date'], count=row['count'])
            for row in results
        ]
        
        return activity
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get honeypot activity: {str(e)}")


@router.get("/analytics/top-threats", response_model=List[ThreatCategory])
async def get_top_threats(limit: int = Query(5, ge=1, le=20)):
    """
    Get top threats by count
    
    Args:
        limit: Number of top threats to return (1-20)
    
    Returns:
        List of threat categories with counts
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Query top threat types
        query = """
            SELECT threat_type as category, severity, COUNT(*) as count
            FROM threats
            GROUP BY threat_type, severity
            ORDER BY count DESC
            LIMIT ?
        """
        
        cursor.execute(query, (limit,))
        results = cursor.fetchall()
        conn.close()
        
        top_threats = [
            ThreatCategory(
                category=row['category'],
                count=row['count'],
                severity=row['severity']
            )
            for row in results
        ]
        
        return top_threats
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get top threats: {str(e)}")