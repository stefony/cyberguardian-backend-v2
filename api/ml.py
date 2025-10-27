"""
CyberGuardian AI - ML API
Machine Learning endpoints for threat detection
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks, Request
from pydantic import BaseModel
from typing import List, Optional, Dict
import logging
from middleware.rate_limiter import limiter, READ_LIMIT, WRITE_LIMIT

# Import ML Engine
try:
    from core.ml_engine import get_ml_engine
    ML_AVAILABLE = True
except ImportError as e:
    ML_AVAILABLE = False
    logging.warning(f"ML Engine not available: {e}")

router = APIRouter()
logger = logging.getLogger(__name__)

# ============================================
# PYDANTIC MODELS
# ============================================

class LogEntry(BaseModel):
    """Log entry for analysis"""
    timestamp: str
    source_ip: str
    source_port: int
    payload: str
    request_type: Optional[str] = "HTTP"
    country: Optional[str] = None
    city: Optional[str] = None

class AnomalyPredictionResponse(BaseModel):
    """Anomaly prediction result"""
    is_anomaly: bool
    anomaly_score: float
    confidence: float
    threshold: Optional[float] = None

class BehaviorAnalysisResponse(BaseModel):
    """Behavior analysis result"""
    cluster: int
    cluster_name: str
    n_clusters: Optional[int] = None

class ThreatScoreResponse(BaseModel):
    """Threat score result"""
    threat_score: float
    threat_level: str
    is_anomaly: bool
    anomaly_score: float
    behavior_cluster: str
    confidence: float

class ModelStatusResponse(BaseModel):
    """ML model status"""
    model_trained: bool
    training_date: Optional[str]
    training_samples: int
    anomaly_detector_available: bool
    behavior_clusterer_available: bool
    feature_count: int
    features: List[str]

class TrainingRequest(BaseModel):
    """Model training request"""
    n_clusters: int = 3
    contamination: float = 0.1

class TrainingResponse(BaseModel):
    """Training result"""
    success: bool
    training_samples: Optional[int] = None
    n_clusters: Optional[int] = None
    silhouette_score: Optional[float] = None
    mean_anomaly_score: Optional[float] = None
    training_date: Optional[str] = None
    error: Optional[str] = None

# ============================================
# API ENDPOINTS
# ============================================

@router.get("/ml/status", response_model=ModelStatusResponse)
@limiter.limit(READ_LIMIT)  # 100 requests per minute
async def get_ml_status(request: Request):
    """
    Get ML model status and metadata
    
    Returns current training status, feature information, and model availability
    """
    if not ML_AVAILABLE:
        raise HTTPException(status_code=503, detail="ML engine not available")
    
    try:
        engine = get_ml_engine()
        status = engine.get_model_status()
        
        return ModelStatusResponse(**status)
    
    except Exception as e:
        logger.error(f"Failed to get ML status: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/ml/train", response_model=TrainingResponse)
@limiter.limit(WRITE_LIMIT)  # 30 requests per minute
async def train_models(http_request: Request, request: TrainingRequest, background_tasks: BackgroundTasks):
    """
    Train ML models on available data
    
    Args:
        request: Training parameters (n_clusters, contamination)
    
    Trains Anomaly Detection and Behavioral Analysis models
    """
    if not ML_AVAILABLE:
        raise HTTPException(status_code=503, detail="ML engine not available")
    
    try:
        engine = get_ml_engine()
        
        # Train in background
        def train_task():
            results = engine.train_models(
                n_clusters=request.n_clusters,
                contamination=request.contamination
            )
            logger.info(f"Training completed: {results}")
        
        background_tasks.add_task(train_task)
        
        return TrainingResponse(
            success=True,
            training_samples=0,
            n_clusters=request.n_clusters,
            error=None
        )
    
    except Exception as e:
        logger.error(f"Failed to start training: {e}")
        return TrainingResponse(
            success=False,
            error=str(e)
        )

@router.post("/ml/predict/anomaly", response_model=AnomalyPredictionResponse)
@limiter.limit(WRITE_LIMIT)  # 30 requests per minute
async def predict_anomaly(request: Request, log: LogEntry):
    """
    Predict if a log entry is anomalous
    
    Args:
        log: Log entry to analyze
    
    Returns:
        Anomaly prediction with score and confidence
    """
    if not ML_AVAILABLE:
        raise HTTPException(status_code=503, detail="ML engine not available")
    
    try:
        engine = get_ml_engine()
        
        log_dict = log.dict()
        result = engine.predict_anomaly(log_dict)
        
        if 'error' in result:
            raise HTTPException(status_code=400, detail=result['error'])
        
        return AnomalyPredictionResponse(**result)
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to predict anomaly: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/ml/analyze/behavior", response_model=BehaviorAnalysisResponse)
@limiter.limit(WRITE_LIMIT)  # 30 requests per minute
async def analyze_behavior(request: Request, log: LogEntry):
    """
    Analyze behavioral patterns in log entry
    
    Args:
        log: Log entry to analyze
    
    Returns:
        Behavior cluster classification
    """
    if not ML_AVAILABLE:
        raise HTTPException(status_code=503, detail="ML engine not available")
    
    try:
        engine = get_ml_engine()
        
        log_dict = log.dict()
        result = engine.analyze_behavior(log_dict)
        
        if 'error' in result:
            raise HTTPException(status_code=400, detail=result['error'])
        
        return BehaviorAnalysisResponse(**result)
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to analyze behavior: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/ml/threat-score", response_model=ThreatScoreResponse)
@limiter.limit(WRITE_LIMIT)  # 30 requests per minute
async def calculate_threat_score(request: Request, log: LogEntry):
    """
    Calculate comprehensive threat score
    
    Args:
        log: Log entry to analyze
    
    Returns:
        Threat score (0-100), level, and detailed analysis
    """
    if not ML_AVAILABLE:
        raise HTTPException(status_code=503, detail="ML engine not available")
    
    try:
        engine = get_ml_engine()
        
        log_dict = log.dict()
        result = engine.calculate_threat_score(log_dict)
        
        if 'error' in result:
            raise HTTPException(status_code=400, detail=result['error'])
        
        return ThreatScoreResponse(**result)
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to calculate threat score: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/ml/batch/threat-scores")
@limiter.limit(WRITE_LIMIT)  # 30 requests per minute
async def batch_threat_scores(request: Request, logs: List[LogEntry]):
    """
    Calculate threat scores for multiple logs
    
    Args:
        logs: List of log entries
    
    Returns:
        List of threat scores
    """
    if not ML_AVAILABLE:
        raise HTTPException(status_code=503, detail="ML engine not available")
    
    try:
        engine = get_ml_engine()
        
        results = []
        for log in logs:
            log_dict = log.dict()
            score = engine.calculate_threat_score(log_dict)
            results.append(score)
        
        return {
            'total': len(results),
            'scores': results
        }
    
    except Exception as e:
        logger.error(f"Failed to calculate batch scores: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/ml/test")
@limiter.limit(READ_LIMIT)  # 100 requests per minute
async def test_ml_system(request: Request):
    """
    Test ML system availability
    """
    return {
        "available": ML_AVAILABLE,
        "message": "ML system ready" if ML_AVAILABLE else "ML system not available"
    }