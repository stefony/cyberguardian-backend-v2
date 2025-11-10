"""
CyberGuardian AI - MITRE ATT&CK API
Endpoints for MITRE ATT&CK framework data
"""

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime
import logging

from middleware.rate_limiter import limiter, READ_LIMIT, WRITE_LIMIT
from database import db

router = APIRouter()
logger = logging.getLogger(__name__)

# ============================================
# MODELS
# ============================================

class ThreatMitreMapping(BaseModel):
    threat_id: int
    threat_type: str
    threat_name: str
    technique_id: str
    tactic_id: str
    confidence: int = 50
    mapping_source: str = "automatic"
    description: Optional[str] = None
    evidence: Optional[dict] = None

# ============================================
# ENDPOINTS
# ============================================

@router.get("/tactics")
@limiter.limit(READ_LIMIT)
async def get_tactics(request: Request):
    """
    Get all MITRE ATT&CK tactics
    """
    try:
        tactics = db.get_mitre_tactics()
        
        return {
            "success": True,
            "count": len(tactics),
            "tactics": tactics
        }
    
    except Exception as e:
        logger.error(f"Error getting tactics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/techniques")
@limiter.limit(READ_LIMIT)
async def get_techniques(request: Request, tactic_id: Optional[str] = None):
    """
    Get MITRE ATT&CK techniques
    
    Optional filter by tactic_id (e.g., TA0001)
    """
    try:
        techniques = db.get_mitre_techniques(tactic_id=tactic_id)
        
        return {
            "success": True,
            "count": len(techniques),
            "techniques": techniques
        }
    
    except Exception as e:
        logger.error(f"Error getting techniques: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/techniques/{technique_id}")
@limiter.limit(READ_LIMIT)
async def get_technique(request: Request, technique_id: str):
    """
    Get single MITRE technique by ID
    """
    try:
        techniques = db.get_mitre_techniques()
        technique = next((t for t in techniques if t["technique_id"] == technique_id), None)
        
        if not technique:
            raise HTTPException(status_code=404, detail="Technique not found")
        
        return {
            "success": True,
            "technique": technique
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting technique: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/mappings")
@limiter.limit(WRITE_LIMIT)
async def create_threat_mapping(request: Request, mapping: ThreatMitreMapping):
    """
    Create threat to MITRE technique mapping
    """
    try:
        mapping_id = db.add_threat_mitre_mapping(
            threat_id=mapping.threat_id,
            threat_type=mapping.threat_type,
            threat_name=mapping.threat_name,
            technique_id=mapping.technique_id,
            tactic_id=mapping.tactic_id,
            confidence=mapping.confidence,
            mapping_source=mapping.mapping_source,
            description=mapping.description,
            evidence=mapping.evidence
        )
        
        return {
            "success": True,
            "mapping_id": mapping_id,
            "message": "Threat mapping created successfully"
        }
    
    except Exception as e:
        logger.error(f"Error creating mapping: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/mappings")
@limiter.limit(READ_LIMIT)
async def get_threat_mappings(request: Request, threat_id: Optional[int] = None, limit: int = 100):
    """
    Get threat to MITRE mappings
    
    Optional filter by threat_id
    """
    try:
        mappings = db.get_threat_mitre_mappings(threat_id=threat_id, limit=limit)
        
        return {
            "success": True,
            "count": len(mappings),
            "mappings": mappings
        }
    
    except Exception as e:
        logger.error(f"Error getting mappings: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/statistics")
@limiter.limit(READ_LIMIT)
async def get_statistics(request: Request):
    """
    Get MITRE ATT&CK statistics
    """
    try:
        stats = db.get_mitre_statistics()
        
        return {
            "success": True,
            "statistics": stats
        }
    
    except Exception as e:
        logger.error(f"Error getting statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/matrix")
@limiter.limit(READ_LIMIT)
async def get_attack_matrix(request: Request):
    """
    Get MITRE ATT&CK matrix (tactics with their techniques)
    """
    try:
        tactics = db.get_mitre_tactics()
        
        matrix = []
        for tactic in tactics:
            techniques = db.get_mitre_techniques(tactic_id=tactic["tactic_id"])
            
            matrix.append({
                "tactic_id": tactic["tactic_id"],
                "tactic_name": tactic["name"],
                "description": tactic["description"],
                "technique_count": len(techniques),
                "techniques": techniques
            })
        
        return {
            "success": True,
            "matrix": matrix
        }
    
    except Exception as e:
        logger.error(f"Error getting matrix: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/coverage")
@limiter.limit(READ_LIMIT)
async def get_coverage(request: Request):
    """
    Get detection coverage for MITRE techniques
    """
    try:
        # For now, return basic coverage info
        # This will be enhanced later with real detection capabilities
        
        techniques = db.get_mitre_techniques()
        
        coverage = {
            "total_techniques": len(techniques),
            "covered_techniques": 0,  # Will be calculated from detection_coverage table
            "coverage_percentage": 0.0,
            "by_tactic": {}
        }
        
        return {
            "success": True,
            "coverage": coverage
        }
    
    except Exception as e:
        logger.error(f"Error getting coverage: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/seed")
@limiter.limit(WRITE_LIMIT)
async def seed_mitre_data_endpoint(request: Request):
    """
    Seed MITRE ATT&CK data (ADMIN ONLY - remove after first use)
    
    ⚠️ WARNING: This endpoint should be removed after seeding production!
    """
    try:
        from database.seed_mitre import seed_mitre_data
        
        # Run seeding
        seed_mitre_data()
        
        # Get stats
        stats = db.get_mitre_statistics()
        
        return {
            "success": True,
            "message": "MITRE ATT&CK data seeded successfully",
            "statistics": stats
        }
    
    except Exception as e:
        logger.error(f"Error seeding MITRE data: {e}")
        raise HTTPException(status_code=500, detail=str(e))    
    
    