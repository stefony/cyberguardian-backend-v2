"""
CyberGuardian AI - Updates API
Endpoints for software update management
"""

import sys
from pathlib import Path

# Add parent directory to Python path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi import APIRouter, HTTPException, Request, BackgroundTasks
from typing import Optional, Dict, Any
import logging

from middleware.rate_limiter import limiter, READ_LIMIT, WRITE_LIMIT
from core.update_manager import UpdateManager
from core.version_control import (
    VersionControl,
    get_current_version,
    get_version_info
)
from database.db import (
    log_update_attempt,
    update_history_status,
    get_update_history,
    get_last_successful_update,
    get_update_statistics
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/updates", tags=["Updates"])

# Global update manager
_update_manager: Optional[UpdateManager] = None


def get_update_manager() -> UpdateManager:
    """Get or create update manager instance"""
    global _update_manager
    if not _update_manager:
        _update_manager = UpdateManager()
    return _update_manager


# ============================================================================
# VERSION INFO
# ============================================================================

@router.get("/version")
@limiter.limit(READ_LIMIT)
async def get_version(request: Request):
    """
    Get current version information
    """
    try:
        version_info = get_version_info()
        
        return {
            "success": True,
            "version": version_info
        }
        
    except Exception as e:
        logger.error(f"Error getting version: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/changelog")
@limiter.limit(READ_LIMIT)
async def get_changelog(request: Request, limit: int = 10):
    """
    Get version changelog
    """
    try:
        vc = VersionControl()
        changelog = vc.get_changelog(limit=limit)
        
        return {
            "success": True,
            "changelog": changelog
        }
        
    except Exception as e:
        logger.error(f"Error getting changelog: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# UPDATE CHECKING
# ============================================================================

@router.get("/check")
@limiter.limit(READ_LIMIT)
async def check_for_updates(request: Request, force: bool = False):
    """
    Check if updates are available
    
    Query params:
        force: Force check even if recently checked
    """
    try:
        manager = get_update_manager()
        update_info = manager.check_for_updates(force=force)
        
        if not update_info:
            return {
                "success": True,
                "available": False,
                "message": "No update information available"
            }
        
        return {
            "success": True,
            **update_info
        }
        
    except Exception as e:
        logger.error(f"Error checking for updates: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/status")
@limiter.limit(READ_LIMIT)
async def get_update_status(request: Request):
    """
    Get update system status
    """
    try:
        manager = get_update_manager()
        status = manager.get_update_status()
        
        return {
            "success": True,
            "status": status
        }
        
    except Exception as e:
        logger.error(f"Error getting update status: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# UPDATE CONFIGURATION
# ============================================================================

@router.post("/configure")
@limiter.limit(WRITE_LIMIT)
async def configure_updates(request: Request, config: Dict[str, Any]):
    """
    Configure update settings
    
    Body:
        {
            "auto_check": bool,
            "auto_download": bool,
            "auto_install": bool,
            "update_channel": "stable|beta|dev"
        }
    """
    try:
        manager = get_update_manager()
        manager.configure_updates(config)
        
        return {
            "success": True,
            "message": "Update configuration saved",
            "config": manager.get_update_status()
        }
        
    except Exception as e:
        logger.error(f"Error configuring updates: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# UPDATE HISTORY
# ============================================================================

@router.get("/history")
@limiter.limit(READ_LIMIT)
async def get_history(request: Request, limit: int = 50):
    """
    Get update history
    
    Query params:
        limit: Maximum number of records (default: 50)
    """
    try:
        history = get_update_history(limit=limit)
        
        return {
            "success": True,
            "total": len(history),
            "history": history
        }
        
    except Exception as e:
        logger.error(f"Error getting update history: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/history/last-successful")
@limiter.limit(READ_LIMIT)
async def get_last_update(request: Request):
    """
    Get last successful update
    """
    try:
        last_update = get_last_successful_update()
        
        if not last_update:
            return {
                "success": True,
                "last_update": None,
                "message": "No successful updates found"
            }
        
        return {
            "success": True,
            "last_update": last_update
        }
        
    except Exception as e:
        logger.error(f"Error getting last update: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# STATISTICS
# ============================================================================

@router.get("/statistics")
@limiter.limit(READ_LIMIT)
async def get_statistics(request: Request):
    """
    Get update statistics
    """
    try:
        stats = get_update_statistics()
        
        return {
            "success": True,
            "statistics": stats
        }
        
    except Exception as e:
        logger.error(f"Error getting statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# UPDATE ACTIONS (Placeholders for now)
# ============================================================================

@router.post("/download")
@limiter.limit(WRITE_LIMIT)
async def download_update(request: Request, background_tasks: BackgroundTasks):
    """
    Download available update
    
    Note: This is a placeholder for future implementation
    """
    try:
        manager = get_update_manager()
        
        # Check if update available
        update_info = manager.check_for_updates(force=True)
        
        if not update_info or not update_info.get("available"):
            return {
                "success": False,
                "message": "No updates available"
            }
        
        # Log update attempt
        update_id = log_update_attempt(
            from_version=update_info["current_version"],
            to_version=update_info["latest_version"],
            update_type=update_info["update_type"],
            download_size=update_info.get("size_bytes"),
            release_notes=update_info.get("release_notes")
        )
        
        # Download in background (mock for now)
        logger.info(f"⚠️ Mock mode: Would download update {update_info['latest_version']}")
        
        # Update status
        update_history_status(
            update_id=update_id,
            status="downloaded",
            backup_path=None
        )
        
        return {
            "success": True,
            "message": f"Update {update_info['latest_version']} download initiated",
            "update_id": update_id,
            "update_info": update_info
        }
        
    except Exception as e:
        logger.error(f"Error downloading update: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/install")
@limiter.limit(WRITE_LIMIT)
async def install_update(request: Request):
    """
    Install downloaded update
    
    Note: This is a placeholder for future implementation
    """
    try:
        return {
            "success": False,
            "message": "Update installation not yet implemented",
            "info": "This feature will be available in a future release"
        }
        
    except Exception as e:
        logger.error(f"Error installing update: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/rollback")
@limiter.limit(WRITE_LIMIT)
async def rollback_update(request: Request, update_id: int):
    """
    Rollback to previous version
    
    Note: This is a placeholder for future implementation
    """
    try:
        return {
            "success": False,
            "message": "Update rollback not yet implemented",
            "info": "This feature will be available in a future release"
        }
        
    except Exception as e:
        logger.error(f"Error rolling back update: {e}")
        raise HTTPException(status_code=500, detail=str(e))