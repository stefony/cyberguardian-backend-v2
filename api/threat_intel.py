"""
CyberGuardian AI - Threat Intelligence API
IOC management and threat intelligence endpoints
"""

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime
import logging

from middleware.rate_limiter import limiter, READ_LIMIT, WRITE_LIMIT
from database import db

router = APIRouter()
logger = logging.getLogger(__name__)

# ============================================
# MODELS
# ============================================

class IOCCreate(BaseModel):
    ioc_value: str
    ioc_type: str  # ip, domain, hash, url, email
    threat_type: Optional[str] = None
    threat_name: Optional[str] = None
    severity: str = "medium"  # low, medium, high, critical
    confidence: float = 50.0
    source: str = "manual"
    description: Optional[str] = None
    mitre_tactics: Optional[List[str]] = None
    mitre_techniques: Optional[List[str]] = None
    tags: Optional[List[str]] = None

class IOCCheckRequest(BaseModel):
    value: str

class IOCResponse(BaseModel):
    id: int
    ioc_type: str
    ioc_value: str
    threat_type: Optional[str]
    threat_name: Optional[str]
    severity: str
    confidence: float
    source: str
    description: Optional[str]
    times_seen: int
    first_seen: str
    last_seen: str

# ============================================
# ENDPOINTS
# ============================================

@router.get("/status")
@limiter.limit(READ_LIMIT)
async def get_threat_intel_status(request: Request):
    """
    Get threat intelligence system status
    """
    try:
        stats = db.get_ioc_statistics()
        
        return {
            "status": "operational",
            "total_iocs": stats["total_iocs"],
            "total_matches": stats["total_matches"],
            "recent_high_severity": stats["recent_high_severity"],
            "last_updated": stats["last_updated"]
        }
    except Exception as e:
        logger.error(f"Error getting threat intel status: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/iocs")
@limiter.limit(WRITE_LIMIT)
async def create_ioc(request: Request, ioc: IOCCreate):
    """
    Add new IOC to threat intelligence database
    """
    try:
        ioc_id = db.add_ioc(
            ioc_value=ioc.ioc_value,
            ioc_type=ioc.ioc_type,
            threat_type=ioc.threat_type,
            threat_name=ioc.threat_name,
            severity=ioc.severity,
            confidence=ioc.confidence,
            source=ioc.source,
            description=ioc.description,
            mitre_tactics=ioc.mitre_tactics,
            mitre_techniques=ioc.mitre_techniques,
            tags=ioc.tags
        )
        
        return {
            "success": True,
            "ioc_id": ioc_id,
            "message": "IOC added successfully"
        }
    
    except Exception as e:
        logger.error(f"Error creating IOC: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/iocs")
@limiter.limit(READ_LIMIT)
async def get_iocs(
    request: Request,
    ioc_type: Optional[str] = None,
    severity: Optional[str] = None,
    source: Optional[str] = None,
    limit: int = 100
):
    """
    Get IOCs with optional filters
    """
    try:
        iocs = db.get_iocs(
            ioc_type=ioc_type,
            severity=severity,
            source=source,
            limit=limit
        )
        
        return {
            "success": True,
            "count": len(iocs),
            "iocs": iocs
        }
    
    except Exception as e:
        logger.error(f"Error getting IOCs: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/check")
@limiter.limit(READ_LIMIT)
async def check_ioc(request: Request, body: IOCCheckRequest):
    """
    Check if a value matches any known IOC
    """
    try:
        result = db.check_ioc(body.value)
        
        return {
            "success": True,
            "checked_value": body.value,
            "result": result
        }
    
    except Exception as e:
        logger.error(f"Error checking IOC: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/statistics")
@limiter.limit(READ_LIMIT)
async def get_statistics(request: Request):
    """
    Get threat intelligence statistics
    """
    try:
        stats = db.get_ioc_statistics()
        
        return {
            "success": True,
            "statistics": stats
        }
    
    except Exception as e:
        logger.error(f"Error getting statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/recent")
@limiter.limit(READ_LIMIT)
async def get_recent_iocs(request: Request, limit: int = 50):
    """
    Get most recent IOCs
    """
    try:
        iocs = db.get_iocs(limit=limit)
        
        return {
            "success": True,
            "count": len(iocs),
            "iocs": iocs
        }
    
    except Exception as e:
        logger.error(f"Error getting recent IOCs: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/high-severity")
@limiter.limit(READ_LIMIT)
async def get_high_severity_iocs(request: Request, limit: int = 50):
    """
    Get high severity IOCs
    """
    try:
        iocs = db.get_iocs(severity="high", limit=limit)
        critical_iocs = db.get_iocs(severity="critical", limit=limit)
        
        all_high = iocs + critical_iocs
        all_high.sort(key=lambda x: x["created_at"], reverse=True)
        
        return {
            "success": True,
            "count": len(all_high[:limit]),
            "iocs": all_high[:limit]
        }
    
    except Exception as e:
        logger.error(f"Error getting high severity IOCs: {e}")
        raise HTTPException(status_code=500, detail=str(e))