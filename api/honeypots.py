"""
CyberGuardian AI - Honeypots API
Real honeypot management endpoints
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import List, Optional, Dict
import logging

# Import HoneypotManager
try:
    from core.honeypot_manager import get_honeypot_manager
    HONEYPOT_AVAILABLE = True
except ImportError as e:
    HONEYPOT_AVAILABLE = False
    logging.warning(f"HoneypotManager not available: {e}")

router = APIRouter()
logger = logging.getLogger(__name__)

# ============================================
# PYDANTIC MODELS
# ============================================

class HoneypotStatusResponse(BaseModel):
    """Honeypot status"""
    name: str
    type: str
    port: int
    running: bool
    attacks_logged: int

class AttackLogResponse(BaseModel):
    """Attack log entry"""
    timestamp: str
    honeypot_type: str
    source_ip: str
    source_port: int
    attack_type: str
    payload: str
    country: Optional[str]
    city: Optional[str]

class HoneypotStatsResponse(BaseModel):
    """Honeypot statistics"""
    total_attacks: int
    active_honeypots: int
    attack_types: Dict[str, int]
    top_countries: Dict[str, int]

class StartHoneypotRequest(BaseModel):
    """Start honeypot request"""
    honeypot_type: str  # 'ssh' or 'http'

# ============================================
# API ENDPOINTS
# ============================================

@router.get("/honeypots/status")
async def get_honeypots_status():
    """
    Get status of all honeypots
    
    Returns running state, port, and attack count for each honeypot
    """
    if not HONEYPOT_AVAILABLE:
        raise HTTPException(status_code=503, detail="Honeypot system not available")
    
    try:
        manager = get_honeypot_manager()
        status = manager.get_status()
        
        result = []
        for name, info in status.items():
            result.append(HoneypotStatusResponse(
                name=info['name'],
                type=info['type'],
                port=info['port'],
                running=info['running'],
                attacks_logged=info['attacks_logged']
            ))
        
        return result
    
    except Exception as e:
        logger.error(f"Failed to get honeypot status: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/honeypots/start/{honeypot_type}")
async def start_honeypot(honeypot_type: str, background_tasks: BackgroundTasks):
    """
    Start a specific honeypot
    
    Args:
        honeypot_type: Type of honeypot ('ssh' or 'http')
    """
    if not HONEYPOT_AVAILABLE:
        raise HTTPException(status_code=503, detail="Honeypot system not available")
    
    if honeypot_type not in ['ssh', 'http']:
        raise HTTPException(status_code=400, detail="Invalid honeypot type. Use 'ssh' or 'http'")
    
    try:
        manager = get_honeypot_manager()
        
        # Start in background
        def start_task():
            manager.start_honeypot(honeypot_type)
        
        background_tasks.add_task(start_task)
        
        return {
            "success": True,
            "message": f"{honeypot_type.upper()} honeypot starting...",
            "honeypot_type": honeypot_type
        }
    
    except Exception as e:
        logger.error(f"Failed to start honeypot: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/honeypots/stop/{honeypot_type}")
async def stop_honeypot(honeypot_type: str):
    """
    Stop a specific honeypot
    
    Args:
        honeypot_type: Type of honeypot ('ssh' or 'http')
    """
    if not HONEYPOT_AVAILABLE:
        raise HTTPException(status_code=503, detail="Honeypot system not available")
    
    if honeypot_type not in ['ssh', 'http']:
        raise HTTPException(status_code=400, detail="Invalid honeypot type")
    
    try:
        manager = get_honeypot_manager()
        success = manager.stop_honeypot(honeypot_type)
        
        if success:
            return {
                "success": True,
                "message": f"{honeypot_type.upper()} honeypot stopped",
                "honeypot_type": honeypot_type
            }
        else:
            raise HTTPException(status_code=404, detail="Honeypot not found")
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to stop honeypot: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/honeypots/start-all")
async def start_all_honeypots(background_tasks: BackgroundTasks):
    """
    Start all honeypots
    """
    if not HONEYPOT_AVAILABLE:
        raise HTTPException(status_code=503, detail="Honeypot system not available")
    
    try:
        manager = get_honeypot_manager()
        
        def start_task():
            manager.start_all()
        
        background_tasks.add_task(start_task)
        
        return {
            "success": True,
            "message": "All honeypots starting..."
        }
    
    except Exception as e:
        logger.error(f"Failed to start all honeypots: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/honeypots/stop-all")
async def stop_all_honeypots():
    """
    Stop all honeypots
    """
    if not HONEYPOT_AVAILABLE:
        raise HTTPException(status_code=503, detail="Honeypot system not available")
    
    try:
        manager = get_honeypot_manager()
        manager.stop_all()
        
        return {
            "success": True,
            "message": "All honeypots stopped"
        }
    
    except Exception as e:
        logger.error(f"Failed to stop all honeypots: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/honeypots/attacks", response_model=List[AttackLogResponse])
async def get_recent_attacks(limit: int = 50):
    """
    Get recent attack logs from all honeypots
    
    Args:
        limit: Maximum number of attacks to return (default: 50)
    """
    if not HONEYPOT_AVAILABLE:
        raise HTTPException(status_code=503, detail="Honeypot system not available")
    
    try:
        manager = get_honeypot_manager()
        attacks = manager.get_recent_attacks(limit=limit)
        
        return [AttackLogResponse(**attack) for attack in attacks]
    
    except Exception as e:
        logger.error(f"Failed to get attacks: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/honeypots/statistics", response_model=HoneypotStatsResponse)
async def get_honeypot_statistics():
    """
    Get honeypot statistics
    
    Returns total attacks, active honeypots, attack types breakdown, and top countries
    """
    if not HONEYPOT_AVAILABLE:
        raise HTTPException(status_code=503, detail="Honeypot system not available")
    
    try:
        manager = get_honeypot_manager()
        stats = manager.get_statistics()
        
        return HoneypotStatsResponse(
            total_attacks=stats['total_attacks'],
            active_honeypots=stats['active_honeypots'],
            attack_types=stats['attack_types'],
            top_countries=stats['top_countries']
        )
    
    except Exception as e:
        logger.error(f"Failed to get statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/honeypots/test")
async def test_honeypot_system():
    """
    Test honeypot system availability
    """
    return {
        "available": HONEYPOT_AVAILABLE,
        "message": "Honeypot system ready" if HONEYPOT_AVAILABLE else "Honeypot system not available"
    }