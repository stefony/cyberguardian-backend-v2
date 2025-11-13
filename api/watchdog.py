"""
CyberGuardian AI - Watchdog & Tamper Detection API
Endpoints for process monitoring and tamper protection
"""

from fastapi import APIRouter, HTTPException, Request, BackgroundTasks
from fastapi.responses import JSONResponse
from typing import Optional, Dict, Any
from datetime import datetime
import logging
import threading

from middleware.rate_limiter import limiter, READ_LIMIT, WRITE_LIMIT
from core.process_watchdog import ProcessWatchdog
from core.config_encryption import ConfigEncryption
from database.db import (
    create_integrity_alert,
    get_integrity_alerts
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/watchdog", tags=["Watchdog & Tamper Protection"])

# Global watchdog instance
_watchdog_instance: Optional[ProcessWatchdog] = None
_watchdog_thread: Optional[threading.Thread] = None


# ============================================================================
# WATCHDOG MANAGEMENT
# ============================================================================

@router.get("/status")
@limiter.limit(READ_LIMIT)
async def get_watchdog_status(request: Request):
    """
    Get watchdog status
    """
    try:
        global _watchdog_instance
        
        if not _watchdog_instance:
            _watchdog_instance = ProcessWatchdog()
        
        status = _watchdog_instance.get_status()
        
        return {
            "success": True,
            "watchdog": status
        }
        
    except Exception as e:
        logger.error(f"Error getting watchdog status: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/start")
@limiter.limit(WRITE_LIMIT)
async def start_watchdog(request: Request, background_tasks: BackgroundTasks):
    """
    Start the watchdog monitoring
    """
    try:
        global _watchdog_instance, _watchdog_thread
        
        if _watchdog_instance and _watchdog_instance.is_running:
            return {
                "success": False,
                "message": "Watchdog is already running"
            }
        
        # Create watchdog instance
        _watchdog_instance = ProcessWatchdog()
        
        # Start in background thread
        def run_watchdog_thread():
            try:
                _watchdog_instance.monitor()
            except Exception as e:
                logger.error(f"Watchdog thread error: {e}")
        
        _watchdog_thread = threading.Thread(target=run_watchdog_thread, daemon=True)
        _watchdog_thread.start()
        
        logger.info("✅ Watchdog started")
        
        return {
            "success": True,
            "message": "Watchdog monitoring started"
        }
        
    except Exception as e:
        logger.error(f"Error starting watchdog: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/stop")
@limiter.limit(WRITE_LIMIT)
async def stop_watchdog(request: Request):
    """
    Stop the watchdog monitoring
    """
    try:
        global _watchdog_instance
        
        if not _watchdog_instance or not _watchdog_instance.is_running:
            return {
                "success": False,
                "message": "Watchdog is not running"
            }
        
        _watchdog_instance.stop()
        
        logger.info("✅ Watchdog stopped")
        
        return {
            "success": True,
            "message": "Watchdog monitoring stopped"
        }
        
    except Exception as e:
        logger.error(f"Error stopping watchdog: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/restarts")
@limiter.limit(READ_LIMIT)
async def get_restart_history(request: Request, limit: int = 50):
    """
    Get restart history
    """
    try:
        global _watchdog_instance
        
        if not _watchdog_instance:
            _watchdog_instance = ProcessWatchdog()
        
        status = _watchdog_instance.get_status()
        restarts = status.get("recent_restarts", [])
        
        return {
            "success": True,
            "total": len(restarts),
            "restarts": restarts[:limit]
        }
        
    except Exception as e:
        logger.error(f"Error getting restart history: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# CONFIG ENCRYPTION
# ============================================================================

@router.post("/config/encrypt")
@limiter.limit(WRITE_LIMIT)
async def encrypt_config(
    request: Request,
    config_data: Dict[str, Any],
    master_password: Optional[str] = None
):
    """
    Encrypt configuration data
    """
    try:
        encryptor = ConfigEncryption()
        encryptor.initialize(master_password=master_password)
        
        # Encrypt and save
        encryptor.save_encrypted_config(config_data)
        
        logger.info("✅ Configuration encrypted")
        
        return {
            "success": True,
            "message": "Configuration encrypted successfully"
        }
        
    except Exception as e:
        logger.error(f"Error encrypting config: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/config/decrypt")
@limiter.limit(READ_LIMIT)
async def decrypt_config(
    request: Request,
    master_password: Optional[str] = None
):
    """
    Decrypt configuration data
    """
    try:
        encryptor = ConfigEncryption()
        encryptor.initialize(master_password=master_password)
        
        # Load and decrypt
        config_data = encryptor.load_encrypted_config()
        
        logger.info("✅ Configuration decrypted")
        
        return {
            "success": True,
            "config": config_data
        }
        
    except Exception as e:
        logger.error(f"Error decrypting config: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/config/verify")
@limiter.limit(READ_LIMIT)
async def verify_config_integrity(request: Request):
    """
    Verify configuration integrity
    """
    try:
        encryptor = ConfigEncryption()
        encryptor.initialize()
        
        is_valid = encryptor.verify_integrity()
        
        if not is_valid:
            # Create alert
            create_integrity_alert(
                alert_type="CONFIG_COMPROMISED",
                severity="CRITICAL",
                message="Configuration file integrity check failed",
                file_path="config/config.encrypted"
            )
        
        return {
            "success": True,
            "is_valid": is_valid,
            "status": "HEALTHY" if is_valid else "COMPROMISED"
        }
        
    except Exception as e:
        logger.error(f"Error verifying config: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/config/rotate-key")
@limiter.limit(WRITE_LIMIT)
async def rotate_encryption_key(
    request: Request,
    new_master_password: Optional[str] = None
):
    """
    Rotate encryption key
    """
    try:
        encryptor = ConfigEncryption()
        encryptor.initialize()
        
        # Rotate key
        encryptor.rotate_key(new_master_password=new_master_password)
        
        logger.info("✅ Encryption key rotated")
        
        return {
            "success": True,
            "message": "Encryption key rotated successfully"
        }
        
    except Exception as e:
        logger.error(f"Error rotating key: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# TAMPER DETECTION
# ============================================================================

@router.get("/tamper/alerts")
@limiter.limit(READ_LIMIT)
async def get_tamper_alerts(
    request: Request,
    resolved: Optional[bool] = False,
    limit: int = 50
):
    """
    Get tamper detection alerts
    """
    try:
        # Get integrity alerts (includes tamper alerts)
        alerts = get_integrity_alerts(resolved=resolved, limit=limit)
        
        # Filter tamper-related alerts
        tamper_alerts = [
            alert for alert in alerts
            if alert["alert_type"] in [
                "FILE_MODIFIED",
                "FILE_MISSING",
                "CONFIG_COMPROMISED",
                "INTEGRITY_CHECK_FAILED",
                "TAMPER_DETECTED"
            ]
        ]
        
        return {
            "success": True,
            "total": len(tamper_alerts),
            "alerts": tamper_alerts
        }
        
    except Exception as e:
        logger.error(f"Error getting tamper alerts: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/protection/status")
@limiter.limit(READ_LIMIT)
async def get_protection_status(request: Request):
    """
    Get overall tamper protection status
    """
    try:
        global _watchdog_instance
        
        # Watchdog status
        if not _watchdog_instance:
            _watchdog_instance = ProcessWatchdog()
        
        watchdog_status = _watchdog_instance.get_status()
        
        # Config encryption status
        try:
            encryptor = ConfigEncryption()
            encryptor.initialize()
            config_valid = encryptor.verify_integrity()
        except:
            config_valid = False
        
        # Get active alerts
        alerts = get_integrity_alerts(resolved=False, limit=10)
        active_alerts_count = len(alerts)
        
        # Determine overall status
        if not config_valid or active_alerts_count > 5:
            overall_status = "CRITICAL"
        elif active_alerts_count > 0:
            overall_status = "WARNING"
        elif watchdog_status["is_running"]:
            overall_status = "PROTECTED"
        else:
            overall_status = "MONITORING_DISABLED"
        
        return {
            "success": True,
            "protection": {
                "overall_status": overall_status,
                "watchdog_active": watchdog_status["is_running"],
                "config_encrypted": True,
                "config_integrity": "VALID" if config_valid else "COMPROMISED",
                "active_alerts": active_alerts_count,
                "restart_count": watchdog_status["restart_count"]
            }
        }
        
    except Exception as e:
        logger.error(f"Error getting protection status: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# STATISTICS
# ============================================================================

@router.get("/statistics")
@limiter.limit(READ_LIMIT)
async def get_watchdog_statistics(request: Request):
    """
    Get watchdog and tamper protection statistics
    """
    try:
        global _watchdog_instance
        
        if not _watchdog_instance:
            _watchdog_instance = ProcessWatchdog()
        
        status = _watchdog_instance.get_status()
        
        # Get alerts
        all_alerts = get_integrity_alerts(resolved=None, limit=1000)
        resolved_alerts = [a for a in all_alerts if a["resolved"]]
        active_alerts = [a for a in all_alerts if not a["resolved"]]
        
        return {
            "success": True,
            "statistics": {
                "watchdog_running": status["is_running"],
                "total_restarts": status["restart_count"],
                "recent_restarts": len(status["recent_restarts"]),
                "total_alerts": len(all_alerts),
                "active_alerts": len(active_alerts),
                "resolved_alerts": len(resolved_alerts),
                "monitored_process": status["monitored_process"]
            }
        }
        
    except Exception as e:
        logger.error(f"Error getting statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))