"""
CyberGuardian AI - Process Protection API
Endpoints for anti-termination and process protection
"""

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from typing import Optional, Dict, Any
import logging

from middleware.rate_limiter import limiter, READ_LIMIT, WRITE_LIMIT
from core.process_protection import (
    ProcessProtection,
    check_protection_capabilities,
    enable_maximum_protection
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/process-protection", tags=["Process Protection"])

# Global instance
_protection_instance: Optional[ProcessProtection] = None


def get_protection_instance() -> ProcessProtection:
    """Get or create protection instance"""
    global _protection_instance
    if not _protection_instance:
        _protection_instance = ProcessProtection()
    return _protection_instance


# ============================================================================
# STATUS & CAPABILITIES
# ============================================================================

@router.get("/status")
@limiter.limit(READ_LIMIT)
async def get_protection_status(request: Request):
    """
    Get process protection status
    """
    try:
        protection = get_protection_instance()
        status = protection.get_protection_status()
        
        return {
            "success": True,
            "protection": status
        }
        
    except Exception as e:
        logger.error(f"Error getting protection status: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/capabilities")
@limiter.limit(READ_LIMIT)
async def get_capabilities(request: Request):
    """
    Check what protection features are available
    """
    try:
        capabilities = check_protection_capabilities()
        
        return {
            "success": True,
            "capabilities": capabilities
        }
        
    except Exception as e:
        logger.error(f"Error checking capabilities: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/privileges")
@limiter.limit(READ_LIMIT)
async def check_privileges(request: Request):
    """
    Check current privilege level
    """
    try:
        protection = get_protection_instance()
        privileges = protection.check_privileges()
        
        return {
            "success": True,
            "privileges": privileges
        }
        
    except Exception as e:
        logger.error(f"Error checking privileges: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# PROTECTION ACTIONS
# ============================================================================

@router.post("/enable-anti-termination")
@limiter.limit(WRITE_LIMIT)
async def enable_anti_termination(request: Request):
    """
    Enable anti-termination protection
    
    Requires Administrator/root privileges
    """
    try:
        protection = get_protection_instance()
        
        # Check privileges first
        privileges = protection.check_privileges()
        
        if not privileges["can_protect"]:
            return {
                "success": False,
                "message": "Insufficient privileges. Administrator/root required.",
                "privileges": privileges
            }
        
        # Enable anti-termination based on platform
        import platform
        if platform.system() == "Windows":
            success = protection.enable_anti_termination_windows()
        elif platform.system() == "Linux":
            success = protection.enable_anti_termination_linux()
        else:
            return {
                "success": False,
                "message": f"Unsupported platform: {platform.system()}"
            }
        
        if success:
            logger.info("✅ Anti-termination enabled")
            return {
                "success": True,
                "message": "Anti-termination protection enabled"
            }
        else:
            return {
                "success": False,
                "message": "Failed to enable anti-termination"
            }
        
    except Exception as e:
        logger.error(f"Error enabling anti-termination: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/enable-self-healing")
@limiter.limit(WRITE_LIMIT)
async def enable_self_healing(request: Request):
    """
    Enable self-healing mechanisms
    """
    try:
        protection = get_protection_instance()
        success = protection.enable_self_healing()
        
        if success:
            return {
                "success": True,
                "message": "Self-healing enabled. Process will auto-restart if killed."
            }
        else:
            return {
                "success": False,
                "message": "Failed to enable self-healing"
            }
        
    except Exception as e:
        logger.error(f"Error enabling self-healing: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/enable-maximum-protection")
@limiter.limit(WRITE_LIMIT)
async def enable_max_protection(request: Request):
    """
    Enable all available protection mechanisms
    """
    try:
        success = enable_maximum_protection()
        
        # Get updated status
        protection = get_protection_instance()
        status = protection.get_protection_status()
        
        return {
            "success": success,
            "message": "Maximum protection enabled" if success else "Some features could not be enabled",
            "protection": status
        }
        
    except Exception as e:
        logger.error(f"Error enabling maximum protection: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# SERVICE INSTALLATION
# ============================================================================

@router.post("/install-service")
@limiter.limit(WRITE_LIMIT)
async def install_service(
    request: Request,
    service_name: Optional[str] = None
):
    """
    Install as system service
    
    Requires Administrator/root privileges
    """
    try:
        protection = get_protection_instance()
        
        # Check privileges
        privileges = protection.check_privileges()
        
        if not privileges["can_protect"]:
            return {
                "success": False,
                "message": "Insufficient privileges. Administrator/root required.",
                "privileges": privileges
            }
        
        # Install service based on platform
        import platform
        service_name = service_name or "cyberguardian"
        
        if platform.system() == "Windows":
            success = protection.install_as_service_windows(service_name)
        elif platform.system() == "Linux":
            success = protection.install_as_service_linux(service_name)
        else:
            return {
                "success": False,
                "message": f"Unsupported platform: {platform.system()}"
            }
        
        if success:
            return {
                "success": True,
                "message": f"Service '{service_name}' installed successfully",
                "service_name": service_name
            }
        else:
            return {
                "success": False,
                "message": "Failed to install service"
            }
        
    except Exception as e:
        logger.error(f"Error installing service: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# RECOMMENDATIONS
# ============================================================================

@router.get("/recommendations")
@limiter.limit(READ_LIMIT)
async def get_recommendations(request: Request):
    """
    Get security recommendations
    """
    try:
        protection = get_protection_instance()
        status = protection.get_protection_status()
        
        return {
            "success": True,
            "recommendations": status["recommendations"],
            "current_status": {
                "is_protected": status["is_protected"],
                "service_installed": status["service_installed"],
                "can_protect": status["can_protect"]
            }
        }
        
    except Exception as e:
        logger.error(f"Error getting recommendations: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# STATISTICS
# ============================================================================

@router.get("/statistics")
@limiter.limit(READ_LIMIT)
async def get_statistics(request: Request):
    """
    Get process protection statistics
    """
    try:
        protection = get_protection_instance()
        status = protection.get_protection_status()
        privileges = protection.check_privileges()
        
        return {
            "success": True,
            "statistics": {
                "platform": status["platform"],
                "is_protected": status["is_protected"],
                "service_installed": status["service_installed"],
                "has_admin_rights": privileges.get("is_admin", False),
                "has_root_rights": privileges.get("is_root", False),
                "can_enable_protection": privileges["can_protect"],
                "recommendations_count": len(status["recommendations"])
            }
        }
        
    except Exception as e:
        logger.error(f"Error getting statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))