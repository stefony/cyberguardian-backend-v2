"""
CyberGuardian AI - Protection API
Real-time file protection endpoints
"""

from fastapi import APIRouter, BackgroundTasks, Request
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime
from core.fs_watcher import FSWatcher
from core.ml_engine import get_ml_engine
from database.db import (
    add_fs_event,
    get_fs_events,
    get_protection_settings,
    update_protection_settings
)
from database import db
from middleware.rate_limiter import limiter, READ_LIMIT, WRITE_LIMIT
from core.quarantine import quarantine_file
from fastapi import APIRouter, Request, HTTPException


router = APIRouter(prefix="/api/protection", tags=["protection"])

# Global watcher instance
WATCHER = FSWatcher()

# Global statistics tracker
STATS = {
    "files_scanned": 0,
    "threats_detected": 0,
    "started_at": None,
    "last_scan": None
}


# ============================================
# PYDANTIC MODELS
# ============================================

class ToggleRequest(BaseModel):
    enabled: bool
    paths: List[str]
    auto_quarantine: Optional[bool] = None
    threat_threshold: Optional[int] = None


class ProtectionStatus(BaseModel):
    enabled: bool
    paths: List[str]
    auto_quarantine: bool
    threat_threshold: int


# ============================================
# API ENDPOINTS
# ============================================

@router.get("/status", response_model=ProtectionStatus)
@limiter.limit(READ_LIMIT)
async def get_status(request: Request):
    """Get protection status"""
    settings = get_protection_settings()
    
    return ProtectionStatus(
        enabled=WATCHER.is_enabled(),
        paths=WATCHER.get_paths() if WATCHER.is_enabled() else settings["watch_paths"],
        auto_quarantine=bool(settings["auto_quarantine"]),
        threat_threshold=settings["threat_threshold"]
    )


@router.post("/toggle", response_model=ProtectionStatus)
@limiter.limit(WRITE_LIMIT)
async def toggle_protection(request: Request, req: ToggleRequest, bt: BackgroundTasks):
    """Toggle real-time protection"""
    
    # Update settings in database
    update_protection_settings(
        enabled=req.enabled,
        watch_paths=req.paths,
        auto_quarantine=req.auto_quarantine,
        threat_threshold=req.threat_threshold
    )
    
    if req.enabled:
        if not WATCHER.is_enabled():
            WATCHER.start(req.paths)
            STATS["started_at"] = datetime.utcnow()  # ← Track start time
            bt.add_task(_consumer_loop)
    else:
        WATCHER.stop()
        STATS["started_at"] = None  # ← Reset on stop
    
    settings = get_protection_settings()
    
    return ProtectionStatus(
        enabled=WATCHER.is_enabled(),
        paths=WATCHER.get_paths() if WATCHER.is_enabled() else settings["watch_paths"],
        auto_quarantine=bool(settings["auto_quarantine"]),
        threat_threshold=settings["threat_threshold"]
    )


@router.get("/events")
@limiter.limit(READ_LIMIT)
async def get_events(request: Request, limit: int = 100):
    """Get recent file system events"""
    events = get_fs_events(limit)
    return {
        "success": True,
        "data": events,
        "count": len(events)
    }


@router.get("/stats")
@limiter.limit(READ_LIMIT)
async def get_stats(request: Request):
    """Get protection statistics"""
    uptime_seconds = 0
    if STATS["started_at"] and WATCHER.is_enabled():
        uptime_seconds = (datetime.utcnow() - STATS["started_at"]).total_seconds()
    
    return {
        "success": True,
        "data": {
            "files_scanned": STATS["files_scanned"],
            "threats_detected": STATS["threats_detected"],
            "uptime_seconds": int(uptime_seconds),
            "last_scan": STATS["last_scan"],
            "is_active": WATCHER.is_enabled()
        }
    }


# ============================================
# BACKGROUND CONSUMER
# ============================================

def _consumer_loop():
    """
    Background task that processes file events
    Runs ML threat detection on each file
    """
    print("🔄 Protection consumer loop started")
    
    ml_engine = get_ml_engine()
    
    while WATCHER.is_enabled():
        try:
            # Get event from queue (with timeout)
            ev = WATCHER.get_queue().get(timeout=1)
        except Exception:
            continue
        
        path = ev["path"]
        
        try:
            # Create log entry for ML analysis
            log = {
                "timestamp": ev["ts"],
                "source_ip": "local",
                "source_port": 0,
                "payload": f"FILE::{path}",
                "request_type": "FS",
                "country": None,
                "city": None,
            }
            
            # Run ML threat detection
            ml_result = ml_engine.calculate_threat_score(log)
            
            threat_score = ml_result.get("threat_score", 0)
            threat_level = ml_result.get("threat_level", "low")
            
            # Update statistics
            STATS["files_scanned"] += 1
            STATS["last_scan"] = ev["ts"]
            if threat_score >= 70:  # Consider 70+ as threat
                STATS["threats_detected"] += 1
            
            # Save to database
            add_fs_event(
                event_type=ev["event"],
                file_path=path,
                threat_score=threat_score,
                threat_level=threat_level,
                ml_details=ml_result,
                file_size=ev.get("size"),
                file_hash=ev.get("hash"),
                quarantined=False
            )
            
            # Auto-quarantine if enabled and threshold exceeded
            settings = get_protection_settings()
            if settings["auto_quarantine"] and threat_score >= settings["threat_threshold"]:
                quarantine_result = quarantine_file(
                    source_path=path,
                    reason=f"Auto-quarantined: Threat score {threat_score}",
                    threat_score=threat_score,
                    threat_level=threat_level,
                    detection_method="realtime_protection"
                )
                
                if quarantine_result:
                    print(f"🔒 Auto-quarantined: {path}")
                    
                    # Update database to mark as quarantined
                    from database.db import get_connection
                    conn = get_connection()
                    cursor = conn.cursor()
                    cursor.execute("""
                        UPDATE fs_events 
                        SET quarantined = 1 
                        WHERE file_path = ? AND file_hash = ?
                        ORDER BY timestamp DESC LIMIT 1
                    """, (path, ev.get("hash")))
                    conn.commit()
                    
                    conn.close()
            
            print(f"✅ Processed: {path} | Score: {threat_score} | Level: {threat_level}")
            
        except Exception as e:
            print(f"❌ Error processing {path}: {e}")
            
            # Save error event
            try:
                add_fs_event(
                    event_type=ev["event"],
                    file_path=path,
                    threat_score=0,
                    threat_level="error",
                    ml_details={"error": str(e)},
                    file_size=ev.get("size"),
                    file_hash=ev.get("hash"),
                    quarantined=False
                )
            except Exception:
                pass
    
    print("🛑 Protection consumer loop stopped")


# ============================================
# SENSITIVITY PROFILES
# ============================================

# Sensitivity Profiles
SENSITIVITY_PROFILES = {
    "low": {
        "name": "Low Sensitivity",
        "description": "Minimal false positives, catches only obvious threats",
        "threshold": 90,
        "color": "green"
    },
    "medium": {
        "name": "Medium Sensitivity",
        "description": "Balance between security and usability",
        "threshold": 75,
        "color": "yellow"
    },
    "high": {
        "name": "High Sensitivity",
        "description": "Maximum protection, aggressive detection",
        "threshold": 50,
        "color": "red"
    }
}


@router.get("/profiles")
@limiter.limit(READ_LIMIT)
async def get_profiles(request: Request):
    """Get available sensitivity profiles"""
    return {
        "success": True,
        "profiles": SENSITIVITY_PROFILES
    }


@router.post("/profile/{profile_name}")
@limiter.limit(WRITE_LIMIT)
async def set_profile(request: Request, profile_name: str):
    """Set active sensitivity profile"""
    try:
        if profile_name not in SENSITIVITY_PROFILES:
            raise HTTPException(status_code=400, detail="Invalid profile name")
        
        profile = SENSITIVITY_PROFILES[profile_name]
        threshold = profile["threshold"]
        
        # Get current settings
        current_settings = get_protection_settings()
        
        # Update threat threshold in settings
        db.update_protection_settings(
            enabled=current_settings["enabled"],
            watch_paths=current_settings["paths"] if isinstance(current_settings["paths"], list) else [],
            threat_threshold=threshold
        )
        
        return {
            "success": True,
            "profile": profile_name,
            "threshold": threshold,
            "message": f"Profile set to {profile['name']}"
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))