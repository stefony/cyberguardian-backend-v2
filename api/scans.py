"""
CyberGuardian AI - Scheduled Scans API
Manage scan schedules and history
"""

from fastapi import APIRouter, BackgroundTasks, Request, HTTPException
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime, timedelta
from database.db import (
    add_scan_schedule,
    get_scan_schedules,
    get_scan_schedule,
    update_scan_schedule,
    delete_scan_schedule,
    add_scan_history,
    update_scan_history,
    get_scan_history
)
from middleware.rate_limiter import limiter, READ_LIMIT, WRITE_LIMIT
from database import db

router = APIRouter(prefix="/api/scans", tags=["scans"])


# ============================================
# PYDANTIC MODELS
# ============================================

class CreateScheduleRequest(BaseModel):
    name: str
    scan_type: str  # "quick", "full", "custom"
    target_path: str
    schedule_type: str  # "daily", "weekly", "monthly", "interval"
    interval_days: Optional[int] = None
    enabled: bool = True


class UpdateScheduleRequest(BaseModel):
    name: Optional[str] = None
    enabled: Optional[bool] = None


class ManualScanRequest(BaseModel):
    scan_type: str
    target_path: str


# ============================================
# API ENDPOINTS - SCHEDULES
# ============================================

@router.get("/schedules")
@limiter.limit(READ_LIMIT)
async def list_schedules(request: Request):
    """Get all scan schedules"""
    schedules = get_scan_schedules()
    return {
        "success": True,
        "data": schedules,
        "count": len(schedules)
    }


@router.get("/schedules/{schedule_id}")
@limiter.limit(READ_LIMIT)
async def get_schedule(request: Request, schedule_id: int):
    """Get single scan schedule"""
    schedule = get_scan_schedule(schedule_id)
    
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")
    
    return {
        "success": True,
        "data": schedule
    }


@router.post("/schedules")
@limiter.limit(WRITE_LIMIT)
async def create_schedule(request: Request, req: CreateScheduleRequest):
    """Create new scan schedule"""
    
    # Calculate next run time
    next_run = None
    if req.enabled:
        if req.schedule_type == "daily":
            next_run = (datetime.utcnow() + timedelta(days=1)).isoformat() + "Z"
        elif req.schedule_type == "weekly":
            next_run = (datetime.utcnow() + timedelta(days=7)).isoformat() + "Z"
        elif req.schedule_type == "monthly":
            next_run = (datetime.utcnow() + timedelta(days=30)).isoformat() + "Z"
        elif req.schedule_type == "interval" and req.interval_days:
            next_run = (datetime.utcnow() + timedelta(days=req.interval_days)).isoformat() + "Z"
    
    schedule_id = add_scan_schedule(
        name=req.name,
        scan_type=req.scan_type,
        target_path=req.target_path,
        schedule_type=req.schedule_type,
        interval_days=req.interval_days,
        enabled=req.enabled
    )
    
    # Update with next_run
    if next_run:
        update_scan_schedule(schedule_id, next_run=next_run)
    
    schedule = get_scan_schedule(schedule_id)
    
    return {
        "success": True,
        "data": schedule,
        "message": "Schedule created successfully"
    }


@router.patch("/schedules/{schedule_id}")
@limiter.limit(WRITE_LIMIT)
async def update_schedule(request: Request, schedule_id: int, req: UpdateScheduleRequest):
    """Update scan schedule"""
    
    schedule = get_scan_schedule(schedule_id)
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")
    
    success = update_scan_schedule(
        schedule_id=schedule_id,
        name=req.name,
        enabled=req.enabled
    )
    
    if not success:
        raise HTTPException(status_code=400, detail="Failed to update schedule")
    
    updated_schedule = get_scan_schedule(schedule_id)
    
    return {
        "success": True,
        "data": updated_schedule,
        "message": "Schedule updated successfully"
    }


@router.delete("/schedules/{schedule_id}")
@limiter.limit(WRITE_LIMIT)
async def remove_schedule(request: Request, schedule_id: int):
    """Delete scan schedule"""
    
    schedule = get_scan_schedule(schedule_id)
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")
    
    success = delete_scan_schedule(schedule_id)
    
    if not success:
        raise HTTPException(status_code=400, detail="Failed to delete schedule")
    
    return {
        "success": True,
        "message": "Schedule deleted successfully"
    }


# ============================================
# API ENDPOINTS - HISTORY
# ============================================

@router.get("/history")
@limiter.limit(READ_LIMIT)
async def list_history(request: Request, limit: int = 50):
    """Get scan history"""
    history = get_scan_history(limit)
    return {
        "success": True,
        "data": history,
        "count": len(history)
    }


# ============================================
# API ENDPOINTS - MANUAL SCAN
# ============================================

@router.post("/run")
@limiter.limit(WRITE_LIMIT)
async def run_manual_scan(request: Request, req: ManualScanRequest, bt: BackgroundTasks):
    """Run manual scan immediately"""
    
    started_at = datetime.utcnow().isoformat() + "Z"
    
    # Create history entry
    history_id = add_scan_history(
        schedule_id=None,
        scan_type=req.scan_type,
        target_path=req.target_path,
        started_at=started_at,
        status="running"
    )
    
    # Run scan in background
    bt.add_task(_execute_scan, history_id, req.scan_type, req.target_path)
    
    return {
        "success": True,
        "message": "Scan started",
        "history_id": history_id
    }

# ============================================
# SCAN PROFILES
# ============================================

SCAN_PROFILES = {
    "quick": {
        "name": "Quick Scan",
        "description": "Fast scan of critical system files",
        "scan_type": "quick",
        "threads": 2,
        "max_files": 100,
        "extensions": [".exe", ".dll", ".bat", ".ps1", ".cmd", ".vbs"],
        "skip_archives": True,
        "recursive": False,
        "duration_estimate": "~2 minutes",
        "icon": "zap",
        "color": "blue"
    },
    "standard": {
        "name": "Standard Scan",
        "description": "Balanced scan for regular use",
        "scan_type": "standard",
        "threads": 4,
        "max_files": 1000,
        "extensions": [".exe", ".dll", ".bat", ".ps1", ".cmd", ".vbs", ".js", ".jar", ".zip", ".rar"],
        "skip_archives": False,
        "recursive": True,
        "duration_estimate": "~10 minutes",
        "icon": "shield",
        "color": "purple"
    },
    "deep": {
        "name": "Deep Scan",
        "description": "Comprehensive scan of entire system",
        "scan_type": "deep",
        "threads": 8,
        "max_files": 10000,
        "extensions": ["*"],
        "skip_archives": False,
        "recursive": True,
        "duration_estimate": "~30+ minutes",
        "icon": "search",
        "color": "red"
    }
}


@router.get("/profiles")
@limiter.limit(READ_LIMIT)
async def get_scan_profiles(request: Request):
    """Get available scan profiles"""
    return {
        "success": True,
        "profiles": SCAN_PROFILES
    }


@router.post("/start-profile/{profile_name}")
@limiter.limit(WRITE_LIMIT)
async def start_scan_with_profile(request: Request, profile_name: str):
    """Start scan with predefined profile"""
    try:
        if profile_name not in SCAN_PROFILES:
            raise HTTPException(status_code=400, detail="Invalid profile name")
        
        profile = SCAN_PROFILES[profile_name]
        
        # Create scan with profile settings
        scan_id = db.create_scan(
            scan_type=profile["scan_type"],
            target_path="C:\\",  # Default - can be customized
            options={
                "threads": profile["threads"],
                "max_files": profile["max_files"],
                "extensions": profile["extensions"],
                "skip_archives": profile["skip_archives"],
                "recursive": profile["recursive"],
                "profile": profile_name
            }
        )
        
        return {
            "success": True,
            "scan_id": scan_id,
            "profile": profile_name,
            "message": f"Started {profile['name']}"
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ============================================
# BACKGROUND SCAN EXECUTOR
# ============================================

def _execute_scan(history_id: int, scan_type: str, target_path: str):
    """
    Execute scan in background
    This is a simplified version - you can enhance with actual scanning logic
    """
    import time
    import os
    
    print(f"🔍 Starting scan: {scan_type} on {target_path}")
    
    start_time = time.time()
    files_scanned = 0
    threats_found = 0
    
    try:
        # Simple file counting for demo
        if os.path.exists(target_path):
            for root, dirs, files in os.walk(target_path):
                files_scanned += len(files)
                # In real implementation, scan each file
                # For now, just count files
        
        # Simulate processing time
        time.sleep(2)
        
        duration = int(time.time() - start_time)
        completed_at = datetime.utcnow().isoformat() + "Z"
        
        # Update history
        update_scan_history(
            history_id=history_id,
            completed_at=completed_at,
            status="completed",
            files_scanned=files_scanned,
            threats_found=threats_found,
            duration_seconds=duration
        )
        
        print(f"✅ Scan completed: {files_scanned} files scanned")
        
    except Exception as e:
        print(f"❌ Scan failed: {e}")
        
        update_scan_history(
            history_id=history_id,
            status="failed",
            error_message=str(e)
        )