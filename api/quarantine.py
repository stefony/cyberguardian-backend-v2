"""
CyberGuardian AI - Quarantine API
Manage quarantined files
"""

from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel
from typing import List, Optional
from core.quarantine import (
    quarantine_file,
    list_quarantined_files,
    get_quarantined_file,
    restore_file,
    delete_quarantined_file,
    get_quarantine_stats
)
from middleware.rate_limiter import limiter, READ_LIMIT, WRITE_LIMIT

router = APIRouter(prefix="/api/quarantine", tags=["quarantine"])


# ============================================
# PYDANTIC MODELS
# ============================================

class QuarantineRequest(BaseModel):
    file_path: str
    reason: Optional[str] = "Suspicious file detected"
    threat_score: Optional[float] = 0.0
    threat_level: Optional[str] = "unknown"
    detection_method: Optional[str] = "manual"


# ============================================
# API ENDPOINTS
# ============================================

@router.get("/")
@limiter.limit(READ_LIMIT)
async def list_files(request: Request):
    """Get all quarantined files"""
    files = list_quarantined_files()
    return {
        "success": True,
        "data": files,
        "count": len(files)
    }


@router.get("/stats")
@limiter.limit(READ_LIMIT)
async def get_stats(request: Request):
    """Get quarantine statistics"""
    stats = get_quarantine_stats()
    return {
        "success": True,
        "data": stats
    }


@router.get("/{quarantine_id}")
@limiter.limit(READ_LIMIT)
async def get_file(request: Request, quarantine_id: str):
    """Get details of specific quarantined file"""
    file_data = get_quarantined_file(quarantine_id)
    
    if not file_data:
        raise HTTPException(status_code=404, detail="Quarantined file not found")
    
    return {
        "success": True,
        "data": file_data
    }


@router.post("/")
@limiter.limit(WRITE_LIMIT)
async def add_file(request: Request, req: QuarantineRequest):
    """Quarantine a file"""
    result = quarantine_file(
        source_path=req.file_path,
        reason=req.reason,
        threat_score=req.threat_score,
        threat_level=req.threat_level,
        detection_method=req.detection_method
    )
    
    if not result:
        raise HTTPException(
            status_code=400,
            detail="Failed to quarantine file. File may not exist or is inaccessible."
        )
    
    return {
        "success": True,
        "data": result,
        "message": "File quarantined successfully"
    }


@router.post("/{quarantine_id}/restore")
@limiter.limit(WRITE_LIMIT)
async def restore(request: Request, quarantine_id: str):
    """Restore file from quarantine"""
    file_data = get_quarantined_file(quarantine_id)
    
    if not file_data:
        raise HTTPException(status_code=404, detail="Quarantined file not found")
    
    success = restore_file(quarantine_id)
    
    if not success:
        raise HTTPException(status_code=400, detail="Failed to restore file")
    
    return {
        "success": True,
        "message": f"File restored to {file_data['original_path']}"
    }


@router.delete("/{quarantine_id}")
@limiter.limit(WRITE_LIMIT)
async def delete(request: Request, quarantine_id: str):
    """Permanently delete quarantined file"""
    file_data = get_quarantined_file(quarantine_id)
    
    if not file_data:
        raise HTTPException(status_code=404, detail="Quarantined file not found")
    
    success = delete_quarantined_file(quarantine_id)
    
    if not success:
        raise HTTPException(status_code=400, detail="Failed to delete file")
    
    return {
        "success": True,
        "message": "File permanently deleted from quarantine"
    }