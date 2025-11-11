"""
CyberGuardian AI - Threats API
Threat management endpoints with SQLite integration
"""

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from datetime import datetime
from fastapi import Request
from middleware.rate_limiter import limiter, READ_LIMIT, WRITE_LIMIT

from database import db
from database.db import (
    get_threats as db_get_threats,
    get_threat_by_id as db_get_threat_by_id,
    add_threat as db_add_threat,
    update_threat_status as db_update_threat_status,
    get_threat_stats as db_get_threat_stats
)
import logging

logger = logging.getLogger(__name__)

router = APIRouter()


# Pydantic Models
class Threat(BaseModel):
    id: int
    timestamp: str
    source_ip: str
    threat_type: str
    severity: str
    description: str
    status: str
    details: Optional[Dict[str, Any]] = None
    confidence_score: Optional[float] = None  # ← ТРЯБВА ДА Е ТУК
    created_at: str
    updated_at: str


class ThreatCreate(BaseModel):
    source_ip: str
    threat_type: str
    severity: str
    description: str
    details: Optional[Dict[str, Any]] = None
    timestamp: Optional[str] = None


class ThreatAction(BaseModel):
    threat_id: int
    action: str  # block, dismiss
    reason: Optional[str] = None


# Initialize with sample threats on first run
def initialize_sample_threats():
    """
    Add sample threats if database is empty (for development/testing)
    """
    existing = db_get_threats(limit=1)
    if len(existing) == 0:
        # Add some initial threats for testing
        sample_threats = [
    {
        "source_ip": "198.51.100.42",
        "threat_type": "Brute Force",
        "severity": "critical",
        "description": "Multiple failed login attempts detected",
        "confidence_score": 95.5,  # ← ДОБАВИ
        "details": {
            "attempts": 15,
            "target": "SSH Port 22",
            "duration": "5 minutes"
        },
        "timestamp": "2025-01-14T09:41:00"
    },
    {
        "source_ip": "203.0.113.11",
        "threat_type": "Phishing",
        "severity": "high",
        "description": "Suspicious email with malicious link detected",
        "confidence_score": 87.3,  # ← ДОБАВИ
        "details": {
            "email_subject": "Urgent: Verify Your Account",
            "sender": "noreply@suspicious-domain.xyz",
            "recipients": 3
        },
        "timestamp": "2025-01-14T09:12:00"
    },
    {
        "source_ip": "192.0.2.156",
        "threat_type": "Malware",
        "severity": "medium",
        "description": "Malicious file detected in download folder",
        "confidence_score": 72.8,  # ← ДОБАВИ
        "details": {
            "file_name": "malware.sig",
            "file_size": "2.3 MB",
            "hash": "a1b2c3d4e5f6..."
        },
        "timestamp": "2025-01-14T08:57:00"
    },
]
        
        for threat in sample_threats:
            db_add_threat(
                source_ip=threat["source_ip"],
                threat_type=threat["threat_type"],
                severity=threat["severity"],
                description=threat["description"],
                details=threat.get("details"),
                timestamp=threat.get("timestamp"),
                 confidence_score=threat.get("confidence_score", 0.0)
            )
        
        print("✅ Sample threats initialized in database")


# Initialize on module load (only runs once)
initialize_sample_threats()


@router.get("/threats", response_model=List[Threat])
@limiter.limit(READ_LIMIT)  # 100 requests per minute
async def get_threats(
    request: Request,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 100,
    offset: int = 0
):
    """
    Get list of all threats with optional filters
    
    Query params:
    - severity: filter by severity (critical, high, medium, low)
    - status: filter by status (active, blocked, dismissed)
    - limit: maximum number of results
    - offset: pagination offset
    """
    threats = db_get_threats(severity=severity, status=status, limit=limit, offset=offset)
    return threats


@router.get("/threats/stats")
@limiter.limit(READ_LIMIT)  # 100 requests per minute
async def get_threat_stats(request: Request):
    """
    Get threat statistics (counts by severity, status, etc.)
    """
    stats = db_get_threat_stats()
    return stats


@router.get("/threats/{threat_id}", response_model=Threat)
@limiter.limit(READ_LIMIT)  # 100 requests per minute
async def get_threat(request: Request, threat_id: int):
    """
    Get detailed information about a specific threat
    """
    threat = db_get_threat_by_id(threat_id)
    
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")
    
    return threat


@router.post("/threats", response_model=Threat)
@limiter.limit(WRITE_LIMIT)  # 30 requests per minute
async def create_threat(request: Request, threat: ThreatCreate):
    """
    Create a new threat entry
    (Used by detection engines to report threats)
    """
    threat_id = db_add_threat(
        source_ip=threat.source_ip,
        threat_type=threat.threat_type,
        severity=threat.severity,
        description=threat.description,
        details=threat.details,
        timestamp=threat.timestamp
    )
    
    # Return the created threat
    created_threat = db_get_threat_by_id(threat_id)
    return created_threat


@router.post("/threats/block")
@limiter.limit(WRITE_LIMIT)  # 30 requests per minute
async def block_threat(request: Request, action: ThreatAction):
    """
    Block a threat by blocking the source IP
    """
    threat = db_get_threat_by_id(action.threat_id)
    
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")
    
    # Update threat status in database
    success = db_update_threat_status(
        threat_id=action.threat_id,
        status="blocked",
        action="block",
        reason=action.reason
    )
    
    if not success:
        raise HTTPException(status_code=500, detail="Failed to block threat")
    
    return {
        "success": True,
        "message": f"Threat {action.threat_id} blocked successfully",
        "threat_id": action.threat_id,
        "source_ip": threat["source_ip"],
        "action": "IP blocked in firewall"
    }


@router.post("/threats/dismiss")
@limiter.limit(WRITE_LIMIT)  # 30 requests per minute
async def dismiss_threat(request: Request, action: ThreatAction):
    """
    Dismiss a threat (mark as false positive or acknowledged)
    """
    threat = db_get_threat_by_id(action.threat_id)
    
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")
    
    # Update threat status in database
    success = db_update_threat_status(
        threat_id=action.threat_id,
        status="dismissed",
        action="dismiss",
        reason=action.reason
    )
    
    if not success:
        raise HTTPException(status_code=500, detail="Failed to dismiss threat")
    
    return {
        "success": True,
        "message": f"Threat {action.threat_id} dismissed",
        "threat_id": action.threat_id,
        "reason": action.reason or "No reason provided"
    }
    # ============================================
# BATCH OPERATIONS (NEW - Feature #2)
# ============================================

class BatchThreatAction(BaseModel):
    threat_ids: List[int]
    action: str  # block, dismiss, delete
    reason: Optional[str] = None


@router.post("/threats/batch")
@limiter.limit(WRITE_LIMIT)
async def batch_threat_action(request: Request, batch: BatchThreatAction):
    """
    Perform batch action on multiple threats
    
    Actions: block, dismiss, delete
    """
    if not batch.threat_ids:
        raise HTTPException(status_code=400, detail="No threat IDs provided")
    
    results = {
        "success": [],
        "failed": []
    }
    
    for threat_id in batch.threat_ids:
        threat = db_get_threat_by_id(threat_id)
        
        if not threat:
            results["failed"].append({
                "threat_id": threat_id,
                "reason": "Threat not found"
            })
            continue
        
        try:
            if batch.action == "block":
                success = db_update_threat_status(
                    threat_id=threat_id,
                    status="blocked",
                    action="block",
                    reason=batch.reason
                )
            elif batch.action == "dismiss":
                success = db_update_threat_status(
                    threat_id=threat_id,
                    status="dismissed",
                    action="dismiss",
                    reason=batch.reason
                )
            elif batch.action == "delete":
                # Delete threat from database
                import sqlite3
                conn = sqlite3.connect('database/cyberguardian.db')
                cursor = conn.cursor()
                cursor.execute("DELETE FROM threats WHERE id = ?", (threat_id,))
                conn.commit()
                conn.close()
                success = True
            else:
                raise HTTPException(status_code=400, detail=f"Invalid action: {batch.action}")
            
            if success:
                results["success"].append(threat_id)
            else:
                results["failed"].append({
                    "threat_id": threat_id,
                    "reason": "Action failed"
                })
        
        except Exception as e:
            results["failed"].append({
                "threat_id": threat_id,
                "reason": str(e)
            })
    
    return {
        "success": True,
        "message": f"{len(results['success'])} threats processed successfully",
        "results": results
    }

@router.get("/threats/{threat_id}/correlations")
@limiter.limit(READ_LIMIT)
async def get_threat_ioc_correlations(threat_id: int, request: Request):
    """
    Get IOC correlations for a specific threat
    """
    try:
        correlations = db.get_threat_correlations(threat_id)
        
        return {
            "success": True,
            "correlations": correlations
        }
    except Exception as e:
        logger.error(f"Error getting threat correlations: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    
    
    