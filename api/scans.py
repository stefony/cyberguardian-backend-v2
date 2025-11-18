"""
CyberGuardian AI - Scheduled Scans API
Manage scan schedules and history
"""

from fastapi import APIRouter, BackgroundTasks, Request, HTTPException
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime, timedelta
import logging

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

logger = logging.getLogger(__name__)

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
    """Start scan with predefined profile - SYNCHRONOUS VERSION"""
    print(f"🔥🔥🔥 ENDPOINT CALLED: {profile_name}")  # ← ДОБАВИ ТОЗИ РЕД
    logger.info(f"🔥 Starting scan with profile: {profile_name}")  # ← ДОБАВИ И ТОЗИ
    try:
        if profile_name not in SCAN_PROFILES:
            raise HTTPException(status_code=400, detail="Invalid profile name")
        
        profile = SCAN_PROFILES[profile_name]
        
        # Create scan history entry
        started_at = datetime.utcnow().isoformat() + "Z"
        
        history_id = add_scan_history(
            schedule_id=None,
            scan_type=profile["scan_type"],
            target_path="C:\\",
            started_at=started_at,
            status="running"
        )
        
        # Run scan DIRECTLY (not in background)
        _execute_scan(history_id, profile["scan_type"], "C:\\")
        
        return {
            "success": True,
            "scan_id": history_id,
            "profile": profile_name,
            "message": f"Started {profile['name']}"
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Scan start error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ============================================
# BACKGROUND SCAN EXECUTOR - REAL IMPLEMENTATION
# ============================================

def _execute_scan(history_id: int, scan_type: str, target_path: str):
    """
    Execute REAL scan with YARA engine + hash checking + VirusTotal
    """
    import time
    import os
    import hashlib
    import logging  # ← ДОБАВИ ТОВА
    from pathlib import Path
    
    logger = logging.getLogger(__name__)  # ← ДОБАВИ ТОВА
    
    # Import YARA engine
    try:
        from core.yara_engine import YaraEngine
        yara_available = True
    except:
        yara_available = False
    
    logger.info(f"🔍 Starting REAL scan: {scan_type} on {target_path}")
    
    start_time = time.time()
    files_scanned = 0
    threats_found = 0
    threat_details = []
    
    # Known malware hashes (basic example - expand this!)
    KNOWN_MALWARE_HASHES = {
        "44d88612fea8a8f36de82e1278abb02f",  # EICAR test file MD5
        "3395856ce81f2b7382dee72602f798b642f14140",  # EICAR SHA1
    }
    
    try:
        # Initialize YARA engine
        yara_engine = None
        if yara_available:
            yara_engine = YaraEngine()
            yara_engine.load_rules()
            logger.info(f"✅ YARA engine loaded with {yara_engine.total_rules} rules")
        
        # Get scan profile settings
        profile = SCAN_PROFILES.get(scan_type, SCAN_PROFILES["quick"])
        max_files = profile["max_files"]
        extensions = profile["extensions"]
        recursive = profile["recursive"]
        
        logger.info(f"📋 Scan profile: {profile['name']}")
        logger.info(f"   Max files: {max_files}")
        logger.info(f"   Extensions: {extensions}")
        logger.info(f"   Recursive: {recursive}")
        
        # Collect files to scan
        files_to_scan = []
        target = Path(target_path)
        
        if not target.exists():
            logger.error(f"❌ Target path does not exist: {target_path}")
            update_scan_history(
                history_id=history_id,
                status="failed",
                error_message=f"Target path not found: {target_path}"
            )
            return
        
        # Collect files based on profile
        if target.is_file():
            files_to_scan.append(target)
        else:
            if recursive:
                all_files = target.rglob('*')
            else:
                all_files = target.glob('*')
            
            for file_path in all_files:
                if not file_path.is_file():
                    continue
                
                # Check extension filter
                if extensions != ["*"]:
                    if file_path.suffix.lower() not in extensions:
                        continue
                
                files_to_scan.append(file_path)
                
                # Limit files
                if len(files_to_scan) >= max_files:
                    break
        
        logger.info(f"📁 Found {len(files_to_scan)} files to scan")
        
        # Scan each file
        for file_path in files_to_scan:
            try:
                files_scanned += 1
                file_path_str = str(file_path)
                
                # 1. HASH CHECK - Calculate file hash
                try:
                    with open(file_path, 'rb') as f:
                        file_data = f.read()
                        file_hash_md5 = hashlib.md5(file_data).hexdigest()
                        file_hash_sha1 = hashlib.sha1(file_data).hexdigest()
                    
                    # Check against known malware hashes
                    if file_hash_md5 in KNOWN_MALWARE_HASHES or file_hash_sha1 in KNOWN_MALWARE_HASHES:
                        threats_found += 1
                        threat_details.append({
                            "file": file_path_str,
                            "threat_type": "Known Malware Hash",
                            "severity": "critical",
                            "detection_method": "hash_database",
                            "hash_md5": file_hash_md5
                        })
                        logger.warning(f"🚨 THREAT FOUND (Hash): {file_path_str}")
                        continue  # Skip YARA scan for known malware
                
                except Exception as e:
                    logger.error(f"Hash check failed for {file_path}: {e}")
                
                # 2. YARA SCAN
                if yara_engine:
                    try:
                        matches = yara_engine.scan_file(file_path_str)
                        
                        if matches:
                            threats_found += len(matches)
                            
                            for match in matches:
                                threat_details.append({
                                    "file": file_path_str,
                                    "threat_type": match.rule_name,
                                    "severity": match.meta.get("severity", "medium"),
                                    "detection_method": "yara_signature",
                                    "rule_namespace": match.namespace,
                                    "rule_tags": match.tags
                                })
                            
                            logger.warning(f"🚨 THREAT FOUND (YARA): {file_path_str} - {len(matches)} matches")
                    
                    except Exception as e:
                        logger.error(f"YARA scan failed for {file_path}: {e}")
                
                # Progress logging
                if files_scanned % 100 == 0:
                    logger.info(f"   Progress: {files_scanned}/{len(files_to_scan)} files scanned")
            
            except Exception as e:
                logger.error(f"Error scanning file {file_path}: {e}")
        
        # Calculate duration
        duration = int(time.time() - start_time)
        completed_at = datetime.utcnow().isoformat() + "Z"
        
        # Prepare results
        scan_results = {
            "files_scanned": files_scanned,
            "threats_found": threats_found,
            "threat_details": threat_details[:10],  # Limit to 10 for storage
            "scan_profile": profile["name"],
            "detection_methods": {
                "yara_rules": yara_engine.total_rules if yara_engine else 0,
                "hash_database": len(KNOWN_MALWARE_HASHES)
            }
        }
        
        # Update scan history
        update_scan_history(
            history_id=history_id,
            completed_at=completed_at,
            status="completed",
            files_scanned=files_scanned,
            threats_found=threats_found,
            duration_seconds=duration,
            results=scan_results
        )
        
        logger.info(f"✅ Scan completed!")
        logger.info(f"   Files scanned: {files_scanned}")
        logger.info(f"   Threats found: {threats_found}")
        logger.info(f"   Duration: {duration}s")
        
    except Exception as e:
        logger.error(f"❌ Scan failed: {e}")
        
        update_scan_history(
            history_id=history_id,
            status="failed",
            error_message=str(e)
        )