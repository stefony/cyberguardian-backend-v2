"""
CyberGuardian AI - Multi-Tenancy Database Wrapper
PHASE 7: Enterprise Features

Wrapper functions that automatically add organization_id filtering
to database operations without modifying original db.py functions.
"""

from typing import List, Dict, Any, Optional
from database import db
import logging
from database.postgres import execute_query

logger = logging.getLogger(__name__)


# ============================================
# THREATS - MULTI-TENANT WRAPPERS
# ============================================

def add_threat_mt(
    organization_id: str,
    source_ip: str,
    threat_type: str,
    severity: str,
    description: str,
    details: Optional[Dict[str, Any]] = None,
    timestamp: Optional[str] = None,
    confidence_score: float = 0.0
) -> int:
    """
    Add threat with organization_id (Multi-Tenant)
    
    Args:
        organization_id: Organization ID (REQUIRED)
        ... (same as db.add_threat)
        
    Returns:
        threat_id
    """
    # Call original function
    threat_id = db.add_threat(
        source_ip=source_ip,
        threat_type=threat_type,
        severity=severity,
        description=description,
        details=details,
        timestamp=timestamp,
        confidence_score=confidence_score
    )
    
    # Update with organization_id
    conn = db.get_connection()
    cursor = conn.cursor()
    
    execute_query(cursor,"""
        UPDATE threats 
        SET organization_id = ?
        WHERE id = ?
    """, (organization_id, threat_id))
    
    conn.commit()
    conn.close()
    
    logger.debug(f"Threat {threat_id} assigned to organization {organization_id}")
    
    return threat_id


def get_threats_mt(
    organization_id: str,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 100,
    offset: int = 0
) -> List[Dict[str, Any]]:
    """
    Get threats filtered by organization_id (Multi-Tenant)
    
    Args:
        organization_id: Organization ID (REQUIRED)
        ... (same as db.get_threats)
        
    Returns:
        List of threats for this organization only
    """
    # Get all threats (from original function)
    all_threats = db.get_threats(
        severity=severity,
        status=status,
        limit=limit * 10,  # Get more, then filter
        offset=offset
    )
    
    # Filter by organization_id
    org_threats = [
        t for t in all_threats 
        if t.get("organization_id") == organization_id
    ]
    
    # Apply limit
    return org_threats[:limit]


def get_threat_stats_mt(organization_id: str) -> Dict[str, Any]:
    """
    Get threat statistics for organization (Multi-Tenant)
    
    Args:
        organization_id: Organization ID
        
    Returns:
        Statistics for this organization only
    """
    conn = db.get_connection()
    cursor = conn.cursor()
    
    # Total threats for this org
    execute_query(cursor,"""
        SELECT COUNT(*) as total 
        FROM threats 
        WHERE organization_id = ?
    """, (organization_id,))
    total = cursor.fetchone()["total"]
    
    # Count by severity
    execute_query(cursor,"""
        SELECT severity, COUNT(*) as count 
        FROM threats 
        WHERE organization_id = ?
        GROUP BY severity
    """, (organization_id,))
    severity_rows = cursor.fetchall()
    severity_counts = {row["severity"]: row["count"] for row in severity_rows}
    
    # Count by status
    execute_query(cursor,"""
        SELECT status, COUNT(*) as count 
        FROM threats 
        WHERE organization_id = ?
        GROUP BY status
    """, (organization_id,))
    status_rows = cursor.fetchall()
    status_counts = {row["status"]: row["count"] for row in status_rows}
    
    conn.close()
    
    return {
        "total_threats": total,
        "severity_breakdown": severity_counts,
        "status_breakdown": status_counts,
        "organization_id": organization_id
    }


# ============================================
# SCANS - MULTI-TENANT WRAPPERS
# ============================================

def add_scan_mt(
    organization_id: str,
    scan_type: str,
    status: str,
    started_at: str,
    completed_at: Optional[str] = None,
    duration_seconds: Optional[float] = None,
    items_scanned: int = 0,
    threats_found: int = 0,
    results: Optional[Dict[str, Any]] = None
) -> int:
    """
    Add scan with organization_id (Multi-Tenant)
    """
    scan_id = db.add_scan(
        scan_type=scan_type,
        status=status,
        started_at=started_at,
        completed_at=completed_at,
        duration_seconds=duration_seconds,
        items_scanned=items_scanned,
        threats_found=threats_found,
        results=results
    )
    
    # Update with organization_id
    conn = db.get_connection()
    cursor = conn.cursor()
    
    execute_query(cursor,"""
        UPDATE scans 
        SET organization_id = ?
        WHERE id = ?
    """, (organization_id, scan_id))
    
    conn.commit()
    conn.close()
    
    return scan_id


def get_scans_mt(
    organization_id: str,
    status: Optional[str] = None,
    scan_type: Optional[str] = None,
    limit: int = 50
) -> List[Dict[str, Any]]:
    """
    Get scans filtered by organization_id (Multi-Tenant)
    """
    all_scans = db.get_scans(
        status=status,
        scan_type=scan_type,
        limit=limit * 10
    )
    
    # Filter by organization
    org_scans = [
        s for s in all_scans 
        if s.get("organization_id") == organization_id
    ]
    
    return org_scans[:limit]


# ============================================
# HONEYPOTS - MULTI-TENANT WRAPPERS
# ============================================

def add_honeypot_mt(
    organization_id: str,
    name: str,
    type: str,
    status: str,
    ip_address: str,
    port: int,
    description: str,
    interactions: int = 0
) -> int:
    """
    Add honeypot with organization_id (Multi-Tenant)
    """
    honeypot_id = db.add_honeypot(
        name=name,
        type=type,
        status=status,
        ip_address=ip_address,
        port=port,
        description=description,
        interactions=interactions
    )
    
    # Update with organization_id
    conn = db.get_connection()
    cursor = conn.cursor()
    
    execute_query(cursor,"""
        UPDATE honeypots 
        SET organization_id = ?
        WHERE id = ?
    """, (organization_id, honeypot_id))
    
    conn.commit()
    conn.close()
    
    return honeypot_id


def get_honeypots_mt(
    organization_id: str,
    status: Optional[str] = None,
    type: Optional[str] = None,
    limit: int = 50
) -> List[Dict[str, Any]]:
    """
    Get honeypots filtered by organization_id (Multi-Tenant)
    """
    all_honeypots = db.get_honeypots(
        status=status,
        type=type,
        limit=limit * 10
    )
    
    # Filter by organization
    org_honeypots = [
        h for h in all_honeypots 
        if h.get("organization_id") == organization_id
    ]
    
    return org_honeypots[:limit]


# ============================================
# FS EVENTS - MULTI-TENANT WRAPPERS
# ============================================

def add_fs_event_mt(
    organization_id: str,
    event_type: str,
    file_path: str,
    threat_score: float = 0.0,
    threat_level: str = "low",
    ml_details: Optional[Dict[str, Any]] = None,
    file_size: Optional[int] = None,
    file_hash: Optional[str] = None,
    quarantined: bool = False
) -> int:
    """
    Add file system event with organization_id (Multi-Tenant)
    """
    event_id = db.add_fs_event(
        event_type=event_type,
        file_path=file_path,
        threat_score=threat_score,
        threat_level=threat_level,
        ml_details=ml_details,
        file_size=file_size,
        file_hash=file_hash,
        quarantined=quarantined
    )
    
    # Update with organization_id
    conn = db.get_connection()
    cursor = conn.cursor()
    
    execute_query(cursor,"""
        UPDATE fs_events 
        SET organization_id = ?
        WHERE id = ?
    """, (organization_id, event_id))
    
    conn.commit()
    conn.close()
    
    return event_id


def get_fs_events_mt(
    organization_id: str,
    limit: int = 100
) -> List[Dict[str, Any]]:
    """
    Get file system events filtered by organization_id (Multi-Tenant)
    """
    all_events = db.get_fs_events(limit=limit * 10)
    
    # Filter by organization
    org_events = [
        e for e in all_events 
        if e.get("organization_id") == organization_id
    ]
    
    return org_events[:limit]


# ============================================
# IOCs - MULTI-TENANT WRAPPERS
# ============================================

def add_ioc_mt(
    organization_id: str,
    ioc_value: str,
    ioc_type: str,
    threat_type: Optional[str] = None,
    threat_name: Optional[str] = None,
    severity: str = "medium",
    confidence: float = 50.0,
    source: str = "manual",
    description: Optional[str] = None,
    mitre_tactics: Optional[List[str]] = None,
    mitre_techniques: Optional[List[str]] = None,
    tags: Optional[List[str]] = None
) -> int:
    """
    Add IOC with organization_id (Multi-Tenant)
    """
    ioc_id = db.add_ioc(
        ioc_value=ioc_value,
        ioc_type=ioc_type,
        threat_type=threat_type,
        threat_name=threat_name,
        severity=severity,
        confidence=confidence,
        source=source,
        description=description,
        mitre_tactics=mitre_tactics,
        mitre_techniques=mitre_techniques,
        tags=tags
    )
    
    # Update with organization_id
    conn = db.get_connection()
    cursor = conn.cursor()
    
    execute_query(cursor,"""
        UPDATE iocs 
        SET organization_id = ?
        WHERE id = ?
    """, (organization_id, ioc_id))
    
    conn.commit()
    conn.close()
    
    return ioc_id


def get_iocs_mt(
    organization_id: str,
    ioc_type: Optional[str] = None,
    severity: Optional[str] = None,
    source: Optional[str] = None,
    limit: int = 100
) -> List[Dict[str, Any]]:
    """
    Get IOCs filtered by organization_id (Multi-Tenant)
    """
    all_iocs = db.get_iocs(
        ioc_type=ioc_type,
        severity=severity,
        source=source,
        limit=limit * 10
    )
    
    # Filter by organization
    org_iocs = [
        i for i in all_iocs 
        if i.get("organization_id") == organization_id
    ]
    
    return org_iocs[:limit]


# ============================================
# AUDIT LOGS
# ============================================

def get_audit_logs_mt(
    organization_id: str,
    user_id: Optional[str] = None,
    action: Optional[str] = None,
    resource_type: Optional[str] = None,
    limit: int = 100
) -> List[Dict[str, Any]]:
    """
    Get audit logs for organization (Multi-Tenant)
    
    Args:
        organization_id: Organization ID
        user_id: Filter by user (optional)
        action: Filter by action (optional)
        resource_type: Filter by resource type (optional)
        limit: Maximum number of logs
        
    Returns:
        List of audit logs
    """
    conn = db.get_connection()
    cursor = conn.cursor()
    
    query = """
        SELECT * FROM audit_logs 
        WHERE organization_id = ?
    """
    params = [organization_id]
    
    if user_id:
        query += " AND user_id = ?"
        params.append(user_id)
    
    if action:
        query += " AND action = ?"
        params.append(action)
    
    if resource_type:
        query += " AND resource_type = ?"
        params.append(resource_type)
    
    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)
    
    execute_query(cursor,query, params)
    rows = cursor.fetchall()
    conn.close()
    
    logs = []
    for row in rows:
        log = dict(row)
        if log.get("details"):
            import json
            log["details"] = json.loads(log["details"])
        logs.append(log)
    
    return logs


# ============================================
# HELPER FUNCTIONS
# ============================================

def get_organization_summary(organization_id: str) -> Dict[str, Any]:
    """
    Get summary statistics for organization
    
    Args:
        organization_id: Organization ID
        
    Returns:
        Summary dictionary
    """
    conn = db.get_connection()
    cursor = conn.cursor()
    
    # Count threats
    execute_query(cursor,"""
        SELECT COUNT(*) as count 
        FROM threats 
        WHERE organization_id = ?
    """, (organization_id,))
    threats_count = cursor.fetchone()["count"]
    
    # Count scans
    execute_query(cursor,"""
        SELECT COUNT(*) as count 
        FROM scans 
        WHERE organization_id = ?
    """, (organization_id,))
    scans_count = cursor.fetchone()["count"]
    
    # Count honeypots
    execute_query(cursor,"""
        SELECT COUNT(*) as count 
        FROM honeypots 
        WHERE organization_id = ?
    """, (organization_id,))
    honeypots_count = cursor.fetchone()["count"]
    
    # Count IOCs
    execute_query(cursor,"""
        SELECT COUNT(*) as count 
        FROM iocs 
        WHERE organization_id = ?
    """, (organization_id,))
    iocs_count = cursor.fetchone()["count"]
    
    conn.close()
    
    return {
        "organization_id": organization_id,
        "threats": threats_count,
        "scans": scans_count,
        "honeypots": honeypots_count,
        "iocs": iocs_count
    }