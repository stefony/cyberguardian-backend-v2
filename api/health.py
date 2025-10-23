"""
CyberGuardian AI - Health Check Endpoint
"""

from fastapi import APIRouter
from datetime import datetime
import psutil
import platform

router = APIRouter()
startup_time = datetime.now()


@router.get("/health")
async def health_check():
    current_time = datetime.now()
    uptime = current_time - startup_time
    
    return {
        "status": "healthy",
        "timestamp": current_time.isoformat(),
        "uptime_seconds": uptime.total_seconds(),
        "version": "1.0.0",
        "system": {
            "platform": platform.system(),
            "cpu_percent": psutil.cpu_percent(interval=0.1),
            "memory_percent": psutil.virtual_memory().percent,
        }
    }