"""
CyberGuardian AI - Threats API
PHASE 7: Multi-Tenant Threat Management

Threat management endpoints with organization isolation.
"""

from fastapi import APIRouter, HTTPException, Request, Depends
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from datetime import datetime
from middleware.rate_limiter import limiter, READ_LIMIT, WRITE_LIMIT

# ✨ PHASE 7: Multi-tenancy imports
from database.db_multitenancy import (
    add_threat_mt,
    get_threats_mt,
    get_threat_stats_mt
)
from database.db import (
    get_threat_by_id as db_get_threat_by_id,
    update_threat_status as db_update_threat_status,
    get_threat_correlations,
    get_connection
)
from database.postgres import execute_query  # ✨ ADDED
from middleware.tenant_context import (
    require_organization,
    get_current_organization,
    get_current_user_id,
    log_organization_action
)

import logging

logger = logging.getLogger(__name__)

router = APIRouter()


# ============================================
# PYDANTIC MODELS
# ============================================

class Threat(BaseModel):
    id: int
    timestamp: str
    source_ip: str
    threat_type: str
    severity: str
    description: str
    status: str
    details: Optional[Dict[str, Any]] = None
    confidence_score: Optional[float] = None
    organization_id: Optional[str] = None  # ✨ ДОБАВЕНО
    created_at: str
    updated_at: str


class ThreatCreate(BaseModel):
    source_ip: str
    threat_type: str
    severity: str
    description: str
    details: Optional[Dict[str, Any]] = None
    timestamp: Optional[str] = None
    confidence_score: Optional[float] = 0.0  # ✨ ДОБАВЕНО


class ThreatAction(BaseModel):
    threat_id: int
    action: str
    reason: Optional[str] = None


class BatchThreatAction(BaseModel):
    threat_ids: List[int]
    action: str
    reason: Optional[str] = None


# ============================================
# ENDPOINTS
# ============================================

@router.get("/threats", response_model=List[Threat])
@limiter.limit(READ_LIMIT)
async def get_threats(
    request: Request,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    organization_id: str = Depends(require_organization)  # ✨ ДОБАВЕНО
):
    """
    Get list of threats for current organization
    
    ✨ PHASE 7: Automatically filtered by organization_id
    """
    try:
        # ✨ Use multi-tenant function
        threats = get_threats_mt(
            organization_id=organization_id,
            severity=severity,
            status=status,
            limit=limit,
            offset=offset
        )
        
        return threats
        
    except Exception as e:
        logger.error(f"Error getting threats: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/threats/stats")
@limiter.limit(READ_LIMIT)
async def get_threat_stats(
    request: Request,
    organization_id: str = Depends(require_organization)  # ✨ ДОБАВЕНО
):
    """
    Get threat statistics for current organization
    
    ✨ PHASE 7: Statistics scoped to organization
    """
    try:
        # ✨ Use multi-tenant function
        stats = get_threat_stats_mt(organization_id=organization_id)
        
        return stats
        
    except Exception as e:
        logger.error(f"Error getting threat stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/threats/{threat_id}", response_model=Threat)
@limiter.limit(READ_LIMIT)
async def get_threat(
    request: Request,
    threat_id: int,
    organization_id: str = Depends(require_organization)  # ✨ ДОБАВЕНО
):
    """
    Get detailed information about a specific threat
    
    ✨ PHASE 7: Verify threat belongs to organization
    """
    try:
        threat = db_get_threat_by_id(threat_id)
        
        if not threat:
            raise HTTPException(status_code=404, detail="Threat not found")
        
        # ✨ Security check: Verify threat belongs to this organization
        if threat.get("organization_id") != organization_id:
            raise HTTPException(
                status_code=403, 
                detail="Access denied to this threat"
            )
        
        return threat
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting threat: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/threats", response_model=Threat)
@limiter.limit(WRITE_LIMIT)
async def create_threat(
    request: Request,
    threat: ThreatCreate,
    organization_id: str = Depends(require_organization)  # ✨ ДОБАВЕНО
):
    """
    Create a new threat entry
    
    ✨ PHASE 7: Automatically assigned to current organization
    """
    try:
        # ✨ Use multi-tenant function
        threat_id = add_threat_mt(
            organization_id=organization_id,
            source_ip=threat.source_ip,
            threat_type=threat.threat_type,
            severity=threat.severity,
            description=threat.description,
            details=threat.details,
            timestamp=threat.timestamp,
            confidence_score=threat.confidence_score
        )
        
        # ✨ Audit log
        user_id = get_current_user_id(request)
        if user_id:
            log_organization_action(
                organization_id=organization_id,
                user_id=user_id,
                action="create",
                resource_type="threat",
                resource_id=str(threat_id),
                details={
                    "source_ip": threat.source_ip,
                    "threat_type": threat.threat_type,
                    "severity": threat.severity
                }
            )
        
        # Get created threat
        created_threat = db_get_threat_by_id(threat_id)
        
        return created_threat
        
    except Exception as e:
        logger.error(f"Error creating threat: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/threats/block")
@limiter.limit(WRITE_LIMIT)
async def block_threat(
    request: Request,
    action: ThreatAction,
    organization_id: str = Depends(require_organization)  # ✨ ДОБАВЕНО
):
    """
    Block a threat
    
    ✨ PHASE 7: Verify threat belongs to organization before blocking
    """
    try:
        threat = db_get_threat_by_id(action.threat_id)
        
        if not threat:
            raise HTTPException(status_code=404, detail="Threat not found")
        
        # ✨ Security check
        if threat.get("organization_id") != organization_id:
            raise HTTPException(
                status_code=403,
                detail="Access denied to this threat"
            )
        
        success = db_update_threat_status(
            threat_id=action.threat_id,
            status="blocked",
            action="block",
            reason=action.reason
        )
        
        if not success:
            raise HTTPException(status_code=500, detail="Failed to block threat")
        
        # ✨ Audit log
        user_id = get_current_user_id(request)
        if user_id:
            log_organization_action(
                organization_id=organization_id,
                user_id=user_id,
                action="block",
                resource_type="threat",
                resource_id=str(action.threat_id),
                details={"reason": action.reason}
            )
        
        return {
            "success": True,
            "message": f"Threat {action.threat_id} blocked successfully",
            "threat_id": action.threat_id,
            "source_ip": threat["source_ip"],
            "action": "IP blocked in firewall"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error blocking threat: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/threats/dismiss")
@limiter.limit(WRITE_LIMIT)
async def dismiss_threat(
    request: Request,
    action: ThreatAction,
    organization_id: str = Depends(require_organization)  # ✨ ДОБАВЕНО
):
    """
    Dismiss a threat
    
    ✨ PHASE 7: Verify threat belongs to organization before dismissing
    """
    try:
        threat = db_get_threat_by_id(action.threat_id)
        
        if not threat:
            raise HTTPException(status_code=404, detail="Threat not found")
        
        # ✨ Security check
        if threat.get("organization_id") != organization_id:
            raise HTTPException(
                status_code=403,
                detail="Access denied to this threat"
            )
        
        success = db_update_threat_status(
            threat_id=action.threat_id,
            status="dismissed",
            action="dismiss",
            reason=action.reason
        )
        
        if not success:
            raise HTTPException(status_code=500, detail="Failed to dismiss threat")
        
        # ✨ Audit log
        user_id = get_current_user_id(request)
        if user_id:
            log_organization_action(
                organization_id=organization_id,
                user_id=user_id,
                action="dismiss",
                resource_type="threat",
                resource_id=str(action.threat_id),
                details={"reason": action.reason}
            )
        
        return {
            "success": True,
            "message": f"Threat {action.threat_id} dismissed",
            "threat_id": action.threat_id,
            "reason": action.reason or "No reason provided"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error dismissing threat: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================
# BATCH OPERATIONS
# ============================================

@router.post("/threats/batch")
@limiter.limit(WRITE_LIMIT)
async def batch_threat_action(
    request: Request,
    batch: BatchThreatAction,
    organization_id: str = Depends(require_organization)  # ✨ ДОБАВЕНО
):
    """
    Perform batch action on multiple threats
    
    ✨ PHASE 7: Only processes threats from current organization
    """
    try:
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
            
            # ✨ Security check
            if threat.get("organization_id") != organization_id:
                results["failed"].append({
                    "threat_id": threat_id,
                    "reason": "Access denied"
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
                    # ✨ FIXED: Use execute_query instead of direct cursor.execute
                    conn = get_connection()
                    cursor = conn.cursor()
                    execute_query(cursor, "DELETE FROM threats WHERE id = ?", (threat_id,))
                    conn.commit()
                    conn.close()
                    success = True
                else:
                    raise HTTPException(
                        status_code=400,
                        detail=f"Invalid action: {batch.action}"
                    )
                
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
        
        # ✨ Audit log for batch action
        user_id = get_current_user_id(request)
        if user_id:
            log_organization_action(
                organization_id=organization_id,
                user_id=user_id,
                action=f"batch_{batch.action}",
                resource_type="threat",
                details={
                    "threat_ids": batch.threat_ids,
                    "action": batch.action,
                    "success_count": len(results["success"]),
                    "failed_count": len(results["failed"])
                }
            )
        
        return {
            "success": True,
            "message": f"{len(results['success'])} threats processed successfully",
            "results": results
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in batch operation: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================
# THREAT CORRELATION
# ============================================

@router.get("/threats/{threat_id}/correlations")
@limiter.limit(READ_LIMIT)
async def get_threat_ioc_correlations(
    request: Request,
    threat_id: int,
    organization_id: str = Depends(require_organization)  # ✨ ДОБАВЕНО
):
    """
    Get IOC correlations for a specific threat
    
    ✨ PHASE 7: Verify threat belongs to organization
    """
    try:
        # ✨ Security check
        threat = db_get_threat_by_id(threat_id)
        
        if not threat:
            raise HTTPException(status_code=404, detail="Threat not found")
        
        if threat.get("organization_id") != organization_id:
            raise HTTPException(
                status_code=403,
                detail="Access denied to this threat"
            )
        
        correlations = get_threat_correlations(threat_id)
        
        return {
            "success": True,
            "correlations": correlations
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting threat correlations: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================
# SAMPLE DATA (FOR DEVELOPMENT)
# ============================================

def initialize_sample_threats():
    """
    Add sample threats if database is empty (for development/testing)
    
    Note: In production, this should be disabled or use proper seeding
    """
    try:
        from database.db import get_threats as db_get_threats, add_threat as db_add_threat
        
        existing = db_get_threats(limit=1)
        if len(existing) == 0:
            sample_threats = [
                {
                    "source_ip": "198.51.100.42",
                    "threat_type": "Brute Force",
                    "severity": "critical",
                    "description": "Multiple failed login attempts detected",
                    "confidence_score": 95.5,
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
                    "confidence_score": 87.3,
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
                    "confidence_score": 72.8,
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
            
            logger.info("✅ Sample threats initialized in database")
    except Exception as e:
        logger.warning(f"Could not initialize sample threats: {e}")


# Initialize on module load (only in development)
# initialize_sample_threats()  # ⚠️ Commented out for production