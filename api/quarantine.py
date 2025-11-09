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
    # ============================================
# AUTO-PURGE POLICY
# ============================================

class AutoPurgeSettings(BaseModel):
    enabled: bool = False
    days_threshold: int = 30  # Delete files older than X days
    auto_purge_critical: bool = False  # Auto-purge critical threats
    auto_purge_high: bool = False
    auto_purge_medium: bool = True
    auto_purge_low: bool = True


# Global settings (in production, store in database or config file)
_auto_purge_settings = AutoPurgeSettings()


@router.get("/auto-purge/settings")
@limiter.limit(READ_LIMIT)
async def get_auto_purge_settings(request: Request):
    """Get auto-purge policy settings"""
    return {
        "success": True,
        "data": _auto_purge_settings.dict()
    }


@router.post("/auto-purge/settings")
@limiter.limit(WRITE_LIMIT)
async def update_auto_purge_settings(request: Request, settings: AutoPurgeSettings):
    """Update auto-purge policy settings"""
    global _auto_purge_settings
    _auto_purge_settings = settings
    
    return {
        "success": True,
        "data": _auto_purge_settings.dict(),
        "message": "Auto-purge settings updated successfully"
    }


@router.post("/auto-purge/preview")
@limiter.limit(READ_LIMIT)
async def preview_auto_purge(request: Request):
    """Preview which files will be deleted by auto-purge"""
    from datetime import datetime, timedelta
    
    files = list_quarantined_files()
    threshold_date = datetime.utcnow() - timedelta(days=_auto_purge_settings.days_threshold)
    
    files_to_delete = []
    
    for file in files:
        quarantined_at = datetime.fromisoformat(file['quarantined_at'].replace('Z', '+00:00'))
        threat_level = file.get('threat_level', 'unknown').lower()
        
        # Check if file is old enough
        if quarantined_at < threshold_date:
            # Check threat level policy
            should_delete = False
            
            if threat_level == 'critical' and _auto_purge_settings.auto_purge_critical:
                should_delete = True
            elif threat_level == 'high' and _auto_purge_settings.auto_purge_high:
                should_delete = True
            elif threat_level == 'medium' and _auto_purge_settings.auto_purge_medium:
                should_delete = True
            elif threat_level == 'low' and _auto_purge_settings.auto_purge_low:
                should_delete = True
            
            if should_delete:
                files_to_delete.append({
                    "id": file['id'],
                    "name": file['original_name'],
                    "threat_level": threat_level,
                    "age_days": (datetime.utcnow() - quarantined_at).days,
                    "size": file.get('file_size', 0)
                })
    
    total_size = sum(f['size'] for f in files_to_delete)
    
    return {
        "success": True,
        "data": {
            "files_to_delete": files_to_delete,
            "total_count": len(files_to_delete),
            "total_size_bytes": total_size
        }
    }


@router.post("/auto-purge/execute")
@limiter.limit(WRITE_LIMIT)
async def execute_auto_purge(request: Request):
    """Execute auto-purge (delete old files based on policy)"""
    from datetime import datetime, timedelta
    
    if not _auto_purge_settings.enabled:
        raise HTTPException(status_code=400, detail="Auto-purge is disabled")
    
    files = list_quarantined_files()
    threshold_date = datetime.utcnow() - timedelta(days=_auto_purge_settings.days_threshold)
    
    deleted_count = 0
    deleted_size = 0
    
    for file in files:
        quarantined_at = datetime.fromisoformat(file['quarantined_at'].replace('Z', '+00:00'))
        threat_level = file.get('threat_level', 'unknown').lower()
        
        # Check if file is old enough
        if quarantined_at < threshold_date:
            # Check threat level policy
            should_delete = False
            
            if threat_level == 'critical' and _auto_purge_settings.auto_purge_critical:
                should_delete = True
            elif threat_level == 'high' and _auto_purge_settings.auto_purge_high:
                should_delete = True
            elif threat_level == 'medium' and _auto_purge_settings.auto_purge_medium:
                should_delete = True
            elif threat_level == 'low' and _auto_purge_settings.auto_purge_low:
                should_delete = True
            
            if should_delete:
                success = delete_quarantined_file(file['id'])
                if success:
                    deleted_count += 1
                    deleted_size += file.get('file_size', 0)
    
    return {
        "success": True,
        "data": {
            "deleted_count": deleted_count,
            "deleted_size_bytes": deleted_size
        },
        "message": f"Auto-purge completed: {deleted_count} files deleted"
    }