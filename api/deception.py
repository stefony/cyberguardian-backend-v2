"""
CyberGuardian AI - Deception API
Honeypot and deception layer management
"""

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from datetime import datetime
import random
from middleware.rate_limiter import limiter, READ_LIMIT, WRITE_LIMIT

from database.db import (
    get_honeypots as db_get_honeypots,
    get_honeypot_by_id as db_get_honeypot_by_id,
    add_honeypot as db_add_honeypot,
    update_honeypot_status as db_update_honeypot_status,
    get_honeypot_logs as db_get_honeypot_logs,
    add_honeypot_log as db_add_honeypot_log,
    get_deception_stats as db_get_deception_stats
)

router = APIRouter()


# Pydantic Models
class Honeypot(BaseModel):
    id: int
    name: str
    type: str  # ssh, ftp, http, smb, database
    status: str  # active, inactive, compromised
    ip_address: str
    port: int
    description: str
    interactions: int
    last_interaction: Optional[str] = None
    created_at: str
    updated_at: str


class HoneypotCreate(BaseModel):
    name: str
    type: str
    ip_address: str
    port: int
    description: str


class HoneypotLog(BaseModel):
    id: int
    honeypot_id: int
    timestamp: str
    source_ip: str
    action: str
    details: Optional[Dict[str, Any]] = None


class HoneypotStatusUpdate(BaseModel):
    honeypot_id: int
    status: str  # active, inactive


class DeceptionStatus(BaseModel):
    total_honeypots: int
    active_honeypots: int
    total_interactions: int
    interactions_today: int
    compromised_honeypots: int


# Initialize sample honeypots on first run
def initialize_sample_honeypots():
    """Add sample honeypots if database is empty"""
    existing = db_get_honeypots(limit=1)
    if len(existing) == 0:
        sample_honeypots = [
            {
                "name": "SSH Trap Alpha",
                "type": "ssh",
                "status": "active",
                "ip_address": "10.0.1.10",
                "port": 22,
                "description": "Fake SSH server monitoring brute force attempts",
                "interactions": 47
            },
            {
                "name": "FTP Honeypot Beta",
                "type": "ftp",
                "status": "active",
                "ip_address": "10.0.1.11",
                "port": 21,
                "description": "Decoy FTP server with fake sensitive files",
                "interactions": 23
            },
            {
                "name": "Web Server Gamma",
                "type": "http",
                "status": "active",
                "ip_address": "10.0.1.12",
                "port": 8080,
                "description": "Fake admin panel to detect unauthorized access",
                "interactions": 15
            },
            {
                "name": "Database Delta",
                "type": "database",
                "status": "active",
                "ip_address": "10.0.1.13",
                "port": 3306,
                "description": "MySQL honeypot with fake customer data",
                "interactions": 8
            },
            {
                "name": "SMB Share Epsilon",
                "type": "smb",
                "status": "inactive",
                "ip_address": "10.0.1.14",
                "port": 445,
                "description": "Windows file share honeypot",
                "interactions": 0
            }
        ]
        
        for honeypot in sample_honeypots:
            honeypot_id = db_add_honeypot(
                name=honeypot["name"],
                type=honeypot["type"],
                status=honeypot["status"],
                ip_address=honeypot["ip_address"],
                port=honeypot["port"],
                description=honeypot["description"],
                interactions=honeypot.get("interactions", 0)
            )
            
            # Add some sample logs for active honeypots
            if honeypot["status"] == "active" and honeypot["interactions"] > 0:
                sample_logs = [
                    {
                        "honeypot_id": honeypot_id,
                        "source_ip": f"203.0.113.{random.randint(1, 254)}",
                        "action": "connection_attempt",
                        "details": {
                            "method": "SSH" if honeypot["type"] == "ssh" else "TCP",
                            "credentials_tried": random.randint(1, 10)
                        }
                    },
                    {
                        "honeypot_id": honeypot_id,
                        "source_ip": f"198.51.100.{random.randint(1, 254)}",
                        "action": "authentication_failed",
                        "details": {
                            "username": "admin",
                            "attempts": random.randint(3, 15)
                        }
                    }
                ]
                
                for log in sample_logs:
                    db_add_honeypot_log(
                        honeypot_id=log["honeypot_id"],
                        source_ip=log["source_ip"],
                        action=log["action"],
                        details=log.get("details")
                    )
        
        print("✅ Sample honeypots initialized in database")


# Initialize on module load
initialize_sample_honeypots()


@router.get("/deception/status", response_model=DeceptionStatus)
@limiter.limit(READ_LIMIT)  # 100 requests per minute
async def get_status(request: Request):
    """
    Get current deception layer status
    """
    stats = db_get_deception_stats()
    
    return DeceptionStatus(
        total_honeypots=stats["total_honeypots"],
        active_honeypots=stats["active_honeypots"],
        total_interactions=stats["total_interactions"],
        interactions_today=stats["interactions_today"],
        compromised_honeypots=stats["compromised_honeypots"]
    )


@router.get("/deception/honeypots", response_model=List[Honeypot])
@limiter.limit(READ_LIMIT)  # 100 requests per minute
async def get_honeypots(
    request: Request,
    status: Optional[str] = None,
    type: Optional[str] = None,
    limit: int = 50
):
    """
    Get honeypots with optional filters
    
    Query params:
    - status: filter by status (active, inactive, compromised)
    - type: filter by type (ssh, ftp, http, smb, database)
    - limit: maximum number of results
    """
    honeypots = db_get_honeypots(status=status, type=type, limit=limit)
    return honeypots


@router.get("/deception/honeypots/{honeypot_id}", response_model=Honeypot)
@limiter.limit(READ_LIMIT)  # 100 requests per minute
async def get_honeypot(request: Request, honeypot_id: int):
    """
    Get detailed information about a specific honeypot
    """
    honeypot = db_get_honeypot_by_id(honeypot_id)
    
    if not honeypot:
        raise HTTPException(status_code=404, detail="Honeypot not found")
    
    return honeypot


@router.post("/deception/honeypots", response_model=Honeypot)
@limiter.limit(WRITE_LIMIT)  # 30 requests per minute
async def create_honeypot(request: Request, honeypot: HoneypotCreate):
    """
    Create a new honeypot
    """
    honeypot_id = db_add_honeypot(
        name=honeypot.name,
        type=honeypot.type,
        status="inactive",  # New honeypots start inactive
        ip_address=honeypot.ip_address,
        port=honeypot.port,
        description=honeypot.description
    )
    
    created_honeypot = db_get_honeypot_by_id(honeypot_id)
    return created_honeypot


@router.post("/deception/honeypots/activate")
@limiter.limit(WRITE_LIMIT)  # 30 requests per minute
async def activate_honeypot(request: Request, update: HoneypotStatusUpdate):
    """
    Activate a honeypot
    """
    honeypot = db_get_honeypot_by_id(update.honeypot_id)
    
    if not honeypot:
        raise HTTPException(status_code=404, detail="Honeypot not found")
    
    success = db_update_honeypot_status(
        honeypot_id=update.honeypot_id,
        status="active"
    )
    
    if not success:
        raise HTTPException(status_code=500, detail="Failed to activate honeypot")
    
    return {
        "success": True,
        "message": f"Honeypot {honeypot['name']} activated",
        "honeypot_id": update.honeypot_id
    }


@router.post("/deception/honeypots/deactivate")
@limiter.limit(WRITE_LIMIT)  # 30 requests per minute
async def deactivate_honeypot(request: Request, update: HoneypotStatusUpdate):
    """
    Deactivate a honeypot
    """
    honeypot = db_get_honeypot_by_id(update.honeypot_id)
    
    if not honeypot:
        raise HTTPException(status_code=404, detail="Honeypot not found")
    
    success = db_update_honeypot_status(
        honeypot_id=update.honeypot_id,
        status="inactive"
    )
    
    if not success:
        raise HTTPException(status_code=500, detail="Failed to deactivate honeypot")
    
    return {
        "success": True,
        "message": f"Honeypot {honeypot['name']} deactivated",
        "honeypot_id": update.honeypot_id
    }


@router.get("/deception/logs", response_model=List[HoneypotLog])
@limiter.limit(READ_LIMIT)  # 100 requests per minute
async def get_logs(
    request: Request,
    honeypot_id: Optional[int] = None,
    limit: int = 100
):
    """
    Get honeypot interaction logs
    
    Query params:
    - honeypot_id: filter by specific honeypot
    - limit: maximum number of results
    """
    logs = db_get_honeypot_logs(honeypot_id=honeypot_id, limit=limit)
    return logs


@router.get("/deception/status", response_model=DeceptionStatus)
@limiter.limit(READ_LIMIT)  # 100 requests per minute
async def get_status(request: Request):
    """
    Get deception layer statistics
    """
    stats = db_get_deception_stats()
    return stats