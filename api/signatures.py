"""
CyberGuardian AI - Signature-based Detection API
YARA signature scanning endpoints
"""

from fastapi import APIRouter, HTTPException, Request, UploadFile, File
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime
import logging
import tempfile
import os
from middleware.rate_limiter import limiter, READ_LIMIT, WRITE_LIMIT

# Import YARA engine
try:
    from core.yara_engine import YaraEngine, YaraMatch
    YARA_AVAILABLE = True
except ImportError as e:
    YARA_AVAILABLE = False
    logging.warning(f"YARA engine not available: {e}")

router = APIRouter()
logger = logging.getLogger(__name__)

# Initialize YARA engine (singleton)
yara_engine = None
if YARA_AVAILABLE:
    try:
        yara_engine = YaraEngine()
        yara_engine.load_rules()
        logger.info("✅ YARA engine initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize YARA engine: {e}")

# ============================================
# MODELS
# ============================================

class ScanFileRequest(BaseModel):
    file_path: str

class ScanFileResponse(BaseModel):
    file_path: str
    matches: List[dict]
    threat_detected: bool
    scan_time: str

class YaraStatsResponse(BaseModel):
    rules_loaded: int
    scans_performed: int
    matches_found: int
    engine_ready: bool

# ============================================
# ENDPOINTS
# ============================================

@router.get("/status")
@limiter.limit(READ_LIMIT)
async def get_signature_status(request: Request):
    """
    Get YARA signature engine status
    """
    if not YARA_AVAILABLE or not yara_engine:
        return {
            "available": False,
            "message": "YARA engine not available"
        }
    
    stats = yara_engine.get_statistics()
    return {
        "available": True,
        "engine_ready": stats["engine_ready"],
        "rules_loaded": stats["rules_loaded"],
        "message": f"YARA engine ready with {stats['rules_loaded']} rules"
    }


@router.post("/scan/file", response_model=ScanFileResponse)
@limiter.limit(WRITE_LIMIT)
async def scan_file_with_yara(request: Request, body: ScanFileRequest):
    """
    Scan a file with YARA signatures
    """
    if not YARA_AVAILABLE or not yara_engine:
        raise HTTPException(status_code=503, detail="YARA engine not available")
    
    if not os.path.exists(body.file_path):
        raise HTTPException(status_code=404, detail="File not found")
    
    try:
        # Scan file
        matches = yara_engine.scan_file(body.file_path)
        
        # Convert to dict
        match_dicts = []
        for match in matches:
            match_dicts.append({
                "rule_name": match.rule_name,
                "namespace": match.namespace,
                "tags": match.tags,
                "meta": match.meta,
                "severity": match.meta.get("severity", "unknown"),
                "category": match.meta.get("category", "unknown"),
                "description": match.meta.get("description", "")
            })
        
        return ScanFileResponse(
            file_path=body.file_path,
            matches=match_dicts,
            threat_detected=len(matches) > 0,
            scan_time=datetime.now().isoformat()
        )
    
    except Exception as e:
        logger.error(f"YARA scan failed: {e}")
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


@router.post("/scan/upload")
@limiter.limit(WRITE_LIMIT)
async def scan_uploaded_file(request: Request, file: UploadFile = File(...)):
    """
    Scan an uploaded file with YARA signatures
    """
    if not YARA_AVAILABLE or not yara_engine:
        raise HTTPException(status_code=503, detail="YARA engine not available")
    
    try:
        # Save uploaded file to temp location
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            content = await file.read()
            temp_file.write(content)
            temp_path = temp_file.name
        
        try:
            # Scan file
            matches = yara_engine.scan_file(temp_path)
            
            # Convert to dict
            match_dicts = []
            for match in matches:
                match_dicts.append({
                    "rule_name": match.rule_name,
                    "namespace": match.namespace,
                    "tags": match.tags,
                    "meta": match.meta,
                    "severity": match.meta.get("severity", "unknown"),
                    "category": match.meta.get("category", "unknown"),
                    "description": match.meta.get("description", "")
                })
            
            return {
                "filename": file.filename,
                "size": len(content),
                "matches": match_dicts,
                "threat_detected": len(matches) > 0,
                "scan_time": datetime.now().isoformat()
            }
        
        finally:
            # Clean up temp file
            os.unlink(temp_path)
    
    except Exception as e:
        logger.error(f"Upload scan failed: {e}")
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


@router.get("/stats", response_model=YaraStatsResponse)
@limiter.limit(READ_LIMIT)
async def get_yara_stats(request: Request):
    """
    Get YARA engine statistics
    """
    if not YARA_AVAILABLE or not yara_engine:
        raise HTTPException(status_code=503, detail="YARA engine not available")
    
    stats = yara_engine.get_statistics()
    
    return YaraStatsResponse(
        rules_loaded=stats["rules_loaded"],
        scans_performed=stats["scans_performed"],
        matches_found=stats["matches_found"],
        engine_ready=stats["engine_ready"]
    )


@router.post("/reload")
@limiter.limit(WRITE_LIMIT)
async def reload_yara_rules(request: Request):
    """
    Reload YARA rules from disk
    """
    if not YARA_AVAILABLE or not yara_engine:
        raise HTTPException(status_code=503, detail="YARA engine not available")
    
    try:
        success = yara_engine.reload_rules()
        
        if success:
            stats = yara_engine.get_statistics()
            return {
                "success": True,
                "message": f"Reloaded {stats['rules_loaded']} YARA rules",
                "rules_loaded": stats["rules_loaded"]
            }
        else:
            raise HTTPException(status_code=500, detail="Failed to reload rules")
    
    except Exception as e:
        logger.error(f"Rule reload failed: {e}")
        raise HTTPException(status_code=500, detail=f"Reload failed: {str(e)}")