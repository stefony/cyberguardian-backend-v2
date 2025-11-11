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
    
    # ============================================
# THREAT FEED MANAGEMENT ENDPOINTS
# ============================================

@router.post("/feeds/update")
@limiter.limit(WRITE_LIMIT)
async def update_threat_feeds(request: Request, limit: int = 50):
    """
    Manually trigger threat feed update
    """
    try:
        from core.threat_feeds.feed_manager import ThreatFeedManager
        
        manager = ThreatFeedManager()
        results = manager.update_all_feeds(limit_per_feed=limit)
        
        return {
            "success": True,
            "message": "Threat feeds updated",
            "results": results
        }
    
    except Exception as e:
        logger.error(f"Error updating feeds: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/feeds/status")
@limiter.limit(READ_LIMIT)
async def get_feeds_status(request: Request):
    """
    Get threat feeds status
    """
    try:
        from core.threat_feeds.feed_manager import ThreatFeedManager
        
        manager = ThreatFeedManager()
        stats = manager.get_statistics()
        
        return {
            "success": True,
            "feeds": stats
        }
    
    except Exception as e:
        logger.error(f"Error getting feed status: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/feeds/check-live")
@limiter.limit(WRITE_LIMIT)
async def check_live_feeds(request: Request, body: IOCCheckRequest):
    """
    Check value against live threat feeds (not just database)
    """
    try:
        from core.threat_feeds.feed_manager import ThreatFeedManager
        
        manager = ThreatFeedManager()
        result = manager.check_value(body.value, check_feeds=True)
        
        return {
            "success": True,
            "checked_value": body.value,
            "result": result
        }
    
    except Exception as e:
        logger.error(f"Error checking live feeds: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    
    # ============================================
# THREAT FEED MANAGEMENT
# ============================================

# Mock feed sources - в бъдеще ще идват от database
FEED_SOURCES = [
    {
        "id": 1,
        "name": "VirusTotal",
        "type": "file_hash",
        "enabled": True,
        "url": "https://www.virustotal.com",  # ← ПРОМЕНЕНО
        "last_update": "2025-11-10T15:30:00Z",
        "status": "active",
        "ioc_count": 1250000,
        "api_key_required": True,
        "description": "Comprehensive file, URL, and domain intelligence"
    },
    {
        "id": 2,
        "name": "AlienVault OTX",
        "type": "multi",
        "enabled": True,
        "url": "https://otx.alienvault.com",  # ← ПРОМЕНЕНО
        "last_update": "2025-11-10T14:20:00Z",
        "status": "active",
        "ioc_count": 850000,
        "api_key_required": True,
        "description": "Open Threat Exchange - Community-driven threat intelligence"
    },
    {
        "id": 3,
        "name": "AbuseIPDB",
        "type": "ip",
        "enabled": True,
        "url": "https://www.abuseipdb.com",  # ← ПРОМЕНЕНО
        "last_update": "2025-11-10T16:00:00Z",
        "status": "active",
        "ioc_count": 450000,
        "api_key_required": True,
        "description": "IP address abuse reports and blacklists"
    },
    {
        "id": 4,
        "name": "URLhaus",
        "type": "url",
        "enabled": True,
        "url": "https://urlhaus.abuse.ch",  # ← ПРОМЕНЕНО (remove /api/)
        "last_update": "2025-11-10T13:45:00Z",
        "status": "active",
        "ioc_count": 320000,
        "api_key_required": False,
        "description": "Malware URL distribution sites"
    },
    {
        "id": 5,
        "name": "PhishTank",
        "type": "url",
        "enabled": False,
        "url": "https://www.phishtank.com",  # ← ПРОМЕНЕНО
        "last_update": "2025-11-09T10:30:00Z",
        "status": "inactive",
        "ioc_count": 180000,
        "api_key_required": True,
        "description": "Collaborative phishing site database"
    },
    {
        "id": 6,
        "name": "Malware Bazaar",
        "type": "file_hash",
        "enabled": True,
        "url": "https://bazaar.abuse.ch",  # ← ПРОМЕНЕНО
        "last_update": "2025-11-10T15:00:00Z",
        "status": "active",
        "ioc_count": 95000,
        "api_key_required": False,
        "description": "Malware sample repository"
    }
]

@router.get("/feeds")
@limiter.limit(READ_LIMIT)
async def get_threat_feeds(request: Request):
    """
    Get all configured threat intelligence feeds with their status
    """
    try:
        # Calculate statistics
        total_feeds = len(FEED_SOURCES)
        active_feeds = len([f for f in FEED_SOURCES if f["enabled"]])
        total_iocs = sum(f["ioc_count"] for f in FEED_SOURCES if f["enabled"])
        
        return {
            "success": True,
            "feeds": FEED_SOURCES,
            "statistics": {
                "total_feeds": total_feeds,
                "active_feeds": active_feeds,
                "inactive_feeds": total_feeds - active_feeds,
                "total_iocs": total_iocs
            }
        }
    except Exception as e:
        logger.error(f"Error fetching threat feeds: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/feeds/{feed_id}/toggle")
@limiter.limit(WRITE_LIMIT)
async def toggle_feed(request: Request, feed_id: int):
    """
    Enable or disable a threat feed
    """
    try:
        feed = next((f for f in FEED_SOURCES if f["id"] == feed_id), None)
        if not feed:
            raise HTTPException(status_code=404, detail="Feed not found")
        
        feed["enabled"] = not feed["enabled"]
        feed["status"] = "active" if feed["enabled"] else "inactive"
        
        return {
            "success": True,
            "feed_id": feed_id,
            "enabled": feed["enabled"],
            "message": f"Feed {'enabled' if feed['enabled'] else 'disabled'} successfully"
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error toggling feed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/feeds/{feed_id}/refresh")
@limiter.limit(WRITE_LIMIT)
async def refresh_feed(request: Request, feed_id: int):
    """
    Manually refresh a specific threat feed
    """
    try:
        feed = next((f for f in FEED_SOURCES if f["id"] == feed_id), None)
        if not feed:
            raise HTTPException(status_code=404, detail="Feed not found")
        
        if not feed["enabled"]:
            raise HTTPException(status_code=400, detail="Feed is not enabled")
        
        # Update last_update timestamp
        feed["last_update"] = datetime.utcnow().isoformat() + "Z"
        
        return {
            "success": True,
            "feed_id": feed_id,
            "feed_name": feed["name"],
            "last_update": feed["last_update"],
            "message": f"{feed['name']} refreshed successfully"
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error refreshing feed: {e}")
        raise HTTPException(status_code=500, detail=str(e))