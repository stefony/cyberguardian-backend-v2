"""
CyberGuardian AI - Signature-based Detection API
YARA signature scanning endpoints + Heuristic analysis + Multi-Engine Detection
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

# Import Heuristic engine
try:
    from core.heuristics import HeuristicEngine, HeuristicResult
    HEURISTIC_AVAILABLE = True
except ImportError as e:
    HEURISTIC_AVAILABLE = False
    logging.warning(f"Heuristic engine not available: {e}")

# Import Multi-Engine Detector
try:
    from core.detection_engine import MultiEngineDetector
    MULTI_ENGINE_AVAILABLE = True
except ImportError as e:
    MULTI_ENGINE_AVAILABLE = False
    logging.warning(f"Multi-Engine detector not available: {e}")

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

# Initialize Heuristic engine (singleton)
heuristic_engine = None
if HEURISTIC_AVAILABLE:
    try:
        heuristic_engine = HeuristicEngine()
        logger.info("✅ Heuristic engine initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize Heuristic engine: {e}")

# Initialize Multi-Engine Detector (singleton)
multi_engine = None
if MULTI_ENGINE_AVAILABLE:
    try:
        multi_engine = MultiEngineDetector()
        logger.info("✅ Multi-Engine detector initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize Multi-Engine detector: {e}")

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
# YARA ENDPOINTS
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


# ============================================
# HEURISTIC ANALYSIS ENDPOINTS
# ============================================

@router.post("/heuristic/analyze")
@limiter.limit(WRITE_LIMIT)
async def heuristic_analyze_file(request: Request, body: ScanFileRequest):
    """
    Perform heuristic analysis on a file (PE/ELF)
    """
    if not HEURISTIC_AVAILABLE or not heuristic_engine:
        raise HTTPException(status_code=503, detail="Heuristic engine not available")
    
    if not os.path.exists(body.file_path):
        raise HTTPException(status_code=404, detail="File not found")
    
    try:
        result = heuristic_engine.analyze_file(body.file_path)
        
        return {
            "file_path": result.file_path,
            "file_type": result.file_type,
            "file_size": result.file_size,
            "threat_score": result.threat_score,
            "threat_level": result.threat_level,
            "is_packed": result.is_packed,
            "entropy": result.entropy,
            "indicators": result.indicators,
            "timestamp": result.timestamp
        }
    
    except Exception as e:
        logger.error(f"Heuristic analysis failed: {e}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@router.post("/heuristic/upload")
@limiter.limit(WRITE_LIMIT)
async def heuristic_analyze_upload(request: Request, file: UploadFile = File(...)):
    """
    Perform heuristic analysis on uploaded file
    """
    if not HEURISTIC_AVAILABLE or not heuristic_engine:
        raise HTTPException(status_code=503, detail="Heuristic engine not available")
    
    try:
        # Save to temp
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            content = await file.read()
            temp_file.write(content)
            temp_path = temp_file.name
        
        try:
            result = heuristic_engine.analyze_file(temp_path)
            
            return {
                "filename": file.filename,
                "file_type": result.file_type,
                "file_size": result.file_size,
                "threat_score": result.threat_score,
                "threat_level": result.threat_level,
                "is_packed": result.is_packed,
                "entropy": result.entropy,
                "indicators": result.indicators,
                "timestamp": result.timestamp
            }
        finally:
            os.unlink(temp_path)
    
    except Exception as e:
        logger.error(f"Heuristic upload analysis failed: {e}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@router.get("/heuristic/stats")
@limiter.limit(READ_LIMIT)
async def get_heuristic_stats(request: Request):
    """
    Get heuristic engine statistics
    """
    if not HEURISTIC_AVAILABLE or not heuristic_engine:
        raise HTTPException(status_code=503, detail="Heuristic engine not available")
    
    stats = heuristic_engine.get_statistics()
    return stats


# ============================================
# MULTI-ENGINE DETECTION ENDPOINTS
# ============================================

@router.post("/detect")
@limiter.limit(WRITE_LIMIT)
async def multi_engine_detect(request: Request, body: ScanFileRequest):
    """
    Perform comprehensive multi-engine detection (YARA + Heuristics + ML)
    """
    if not MULTI_ENGINE_AVAILABLE or not multi_engine:
        raise HTTPException(status_code=503, detail="Multi-engine detector not available")
    
    if not os.path.exists(body.file_path):
        raise HTTPException(status_code=404, detail="File not found")
    
    try:
        result = multi_engine.scan_file(body.file_path)
        
        return {
            "file_path": result.file_path,
            "file_size": result.file_size,
            "is_malware": result.is_malware,
            "confidence_score": result.confidence_score,
            "threat_level": result.threat_level,
            "yara_detected": result.yara_detected,
            "yara_matches": result.yara_matches,
            "heuristic_detected": result.heuristic_detected,
            "heuristic_indicators": result.heuristic_indicators[:5],  # Limit to 5
            "ml_detected": result.ml_detected,
            "detection_methods": result.detection_methods,
            "threat_indicators": result.threat_indicators[:10],  # Limit to 10
            "recommendation": result.recommendation,
            "timestamp": result.timestamp
        }
    
    except Exception as e:
        logger.error(f"Multi-engine detection failed: {e}")
        raise HTTPException(status_code=500, detail=f"Detection failed: {str(e)}")


@router.post("/detect/upload")
@limiter.limit(WRITE_LIMIT)
async def multi_engine_detect_upload(request: Request, file: UploadFile = File(...)):
    """
    Perform comprehensive multi-engine detection on uploaded file
    """
    if not MULTI_ENGINE_AVAILABLE or not multi_engine:
        raise HTTPException(status_code=503, detail="Multi-engine detector not available")
    
    try:
        # Save to temp
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            content = await file.read()
            temp_file.write(content)
            temp_path = temp_file.name
        
        try:
            result = multi_engine.scan_file(temp_path)
            
            return {
                "filename": file.filename,
                "file_size": result.file_size,
                "is_malware": result.is_malware,
                "confidence_score": result.confidence_score,
                "threat_level": result.threat_level,
                "yara_detected": result.yara_detected,
                "yara_matches": result.yara_matches,
                "heuristic_detected": result.heuristic_detected,
                "heuristic_indicators": result.heuristic_indicators[:5],
                "ml_detected": result.ml_detected,
                "detection_methods": result.detection_methods,
                "threat_indicators": result.threat_indicators[:10],
                "recommendation": result.recommendation,
                "timestamp": result.timestamp
            }
        finally:
            os.unlink(temp_path)
    
    except Exception as e:
        logger.error(f"Multi-engine upload detection failed: {e}")
        raise HTTPException(status_code=500, detail=f"Detection failed: {str(e)}")


@router.get("/detect/stats")
@limiter.limit(READ_LIMIT)
async def get_multi_engine_stats(request: Request):
    """
    Get multi-engine detector statistics
    """
    if not MULTI_ENGINE_AVAILABLE or not multi_engine:
        raise HTTPException(status_code=503, detail="Multi-engine detector not available")
    
    stats = multi_engine.get_statistics()
    return stats