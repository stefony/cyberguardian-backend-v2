"""
CyberGuardian AI - ML API
Machine Learning endpoints for threat detection
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks, Request
from pydantic import BaseModel
from typing import List, Optional, Dict, Literal
import logging

from middleware.rate_limiter import limiter, READ_LIMIT, WRITE_LIMIT

# 🔎 training data probe
from core.data_probe import probe_training_file

# Import ML Engine
try:
    from core.ml_engine import get_ml_engine, save_models, load_latest_models
    ML_AVAILABLE = True
except ImportError as e:
    ML_AVAILABLE = False
    logging.warning(f"ML Engine not available: {e}")

from core.feedback_store import append_label, stats as feedback_stats

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

    # Diagnostics (optional)
    training_data_present: Optional[bool] = None
    training_data_lines: Optional[int] = None
    training_data_size: Optional[int] = None
    training_data_path: Optional[str] = None

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

class FeedbackItem(BaseModel):
    label: Literal["benign", "malicious", "suspicious"]
    log: LogEntry
    notes: Optional[str] = None

class MetricsResponse(BaseModel):
    trained: bool
    samples: int
    n_clusters: Optional[int] = None
    silhouette: Optional[float] = None
    mean_anomaly: Optional[float] = None
    labeled_count: int
    classifier_available: bool
    training_date: Optional[str] = None

# --- NEW: Thresholds models ---
class ThresholdsRequest(BaseModel):
    anomaly_threshold: Optional[float] = None  # e.g. 0.7

class ThresholdsResponse(BaseModel):
    anomaly_threshold: float

# ============================================
# INTERNAL HELPERS
# ============================================

def _build_artifacts_from_engine(eng):
    """Collect current ML artifacts from engine state for persistence."""
    if not eng.state.model_trained:
        return None
    return {
        "scaler": eng.state.scaler,
        "kmeans": eng.state.clusterer,
        "isoforest": eng.state.anomaly_detector,
        "classifier": eng.state.classifier,
        "metadata": {
            "samples": eng.state.training_samples,
            "silhouette": eng.state.silhouette,
            "mean_anomaly": eng.state.mean_anomaly,
            "n_clusters": eng.state.n_clusters,
            "training_date": eng.state.training_date,
        },
    }

# ============================================
# API ENDPOINTS
# ============================================

@router.get("/ml/status", response_model=ModelStatusResponse)
@limiter.limit(READ_LIMIT)  # 100 requests per minute
async def get_ml_status(request: Request):
    """
    Get ML model status and metadata + training data diagnostics
    """
    diag = probe_training_file()  # CG_TRAINING_PATH или data/training_logs.jsonl

    if not ML_AVAILABLE:
        return ModelStatusResponse(
            model_trained=False,
            training_date=None,
            training_samples=0,
            anomaly_detector_available=False,
            behavior_clusterer_available=False,
            feature_count=0,
            features=[],
            training_data_present=diag.get("present"),
            training_data_lines=diag.get("line_count"),
            training_data_size=diag.get("size_bytes"),
            training_data_path=diag.get("path"),
        )

    try:
        engine = get_ml_engine()
        status: Dict = engine.get_model_status()
        status.update({
            "training_data_present": diag.get("present"),
            "training_data_lines": diag.get("line_count"),
            "training_data_size": diag.get("size_bytes"),
            "training_data_path": diag.get("path"),
        })
        return ModelStatusResponse(**status)
    except Exception as e:
        logger.error(f"Failed to get ML status: {e}")
        return ModelStatusResponse(
            model_trained=False,
            training_date=None,
            training_samples=0,
            anomaly_detector_available=False,
            behavior_clusterer_available=False,
            feature_count=0,
            features=[],
            training_data_present=diag.get("present"),
            training_data_lines=diag.get("line_count"),
            training_data_size=diag.get("size_bytes"),
            training_data_path=diag.get("path"),
        )

@router.post("/ml/train", response_model=TrainingResponse)
@limiter.limit(WRITE_LIMIT)  # 30 requests per minute
async def train_models(
    request: Request,
    background_tasks: BackgroundTasks,
    request_body: TrainingRequest,
    sync: bool = False  # ?sync=1 за блокиращо обучение
):
    """
    Train ML models on available data.
    If sync=1 is passed, training runs synchronously and returns actual results.
    Otherwise it schedules a background task and returns immediately.
    """
    if not ML_AVAILABLE:
        raise HTTPException(status_code=503, detail="ML engine not available")

    try:
        engine = get_ml_engine()

        def do_train():
            try:
                results = engine.train_models(
                    n_clusters=request_body.n_clusters,
                    contamination=request_body.contamination
                )
                logger.info(f"[ML] Training completed: {results}")
            except Exception as e:
                logger.exception(f"[ML] Training failed: {e}")

        if sync:
            results = engine.train_models(
                n_clusters=request_body.n_clusters,
                contamination=request_body.contamination
            )
            return TrainingResponse(
                success=True,
                training_samples=results.get("training_samples", 0),
                n_clusters=results.get("n_clusters"),
                silhouette_score=results.get("silhouette_score"),
                mean_anomaly_score=results.get("mean_anomaly_score"),
                training_date=results.get("training_date"),
                error=None
            )

        # async (background) path
        background_tasks.add_task(do_train)
        return TrainingResponse(
            success=True,
            training_samples=0,
            n_clusters=request_body.n_clusters,
            error=None
        )

    except Exception as e:
        logger.error(f"Failed to start training: {e}")
        return TrainingResponse(success=False, error=str(e))

@router.post("/ml/predict/anomaly", response_model=AnomalyPredictionResponse)
@limiter.limit(WRITE_LIMIT)  # 30 requests per minute
async def predict_anomaly(request: Request, log: LogEntry):
    """
    Predict if a log entry is anomalous
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
        return {'total': len(results), 'scores': results}
    except Exception as e:
        logger.error(f"Failed to calculate batch scores: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/ml/feedback")
@limiter.limit(WRITE_LIMIT)  # 30 req/min
async def post_feedback(request: Request, item: FeedbackItem):
    """
    Save a labeled log for active learning.
    """
    try:
        append_label(example=item.log.dict(), label=item.label, notes=item.notes)
        return {"ok": True, "saved": 1}
    except Exception as e:
        logger.error(f"Failed to save feedback: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/ml/feedback/stats")
@limiter.limit(READ_LIMIT)  # 100 req/min
async def get_feedback_stats(request: Request):
    """
    Quick stats for labeled logs.
    """
    try:
        return feedback_stats()
    except Exception as e:
        logger.error(f"Failed to read feedback stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ===== Persist & Load endpoints =====
@router.post("/ml/save")
@limiter.limit(WRITE_LIMIT)
async def ml_save(request: Request):
    if not ML_AVAILABLE:
        raise HTTPException(status_code=503, detail="ML engine not available")
    eng = get_ml_engine()
    artifacts = _build_artifacts_from_engine(eng)
    if not artifacts:
        raise HTTPException(status_code=400, detail="Model not trained")
    try:
        p = save_models(artifacts)
        return {"ok": True, "saved_as": p.name}
    except Exception as e:
        logging.exception("Persisting model failed")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/ml/load")
@limiter.limit(WRITE_LIMIT)
async def ml_load(request: Request):
    if not ML_AVAILABLE:
        raise HTTPException(status_code=503, detail="ML engine not available")
    eng = get_ml_engine()
    artifacts = load_latest_models()
    if not artifacts:
        raise HTTPException(status_code=404, detail="No persisted model found")
    try:
        eng._hydrate_state_from_artifacts(artifacts)
        return {
            "ok": True,
            "model_trained": eng.state.model_trained,
            "training_date": eng.state.training_date,
            "samples": eng.state.training_samples,
            "n_clusters": eng.state.n_clusters,
        }
    except Exception as e:
        logging.exception("Hydrating state failed")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/ml/metrics", response_model=MetricsResponse)
@limiter.limit(READ_LIMIT)
async def get_ml_metrics(request: Request):
    if not ML_AVAILABLE:
        raise HTTPException(status_code=503, detail="ML engine not available")
    eng = get_ml_engine()
    st = eng.state
    return MetricsResponse(
        trained=st.model_trained,
        samples=st.training_samples or 0,
        n_clusters=st.n_clusters,
        silhouette=st.silhouette,
        mean_anomaly=st.mean_anomaly,
        labeled_count=st.labeled_count or 0,
        classifier_available=bool(st.classifier is not None),
        training_date=st.training_date,
    )

# --- NEW: Thresholds endpoints ---
@router.get("/ml/thresholds", response_model=ThresholdsResponse)
@limiter.limit(READ_LIMIT)
async def get_thresholds(request: Request):
    if not ML_AVAILABLE:
        raise HTTPException(status_code=503, detail="ML engine not available")
    eng = get_ml_engine()
    return ThresholdsResponse(**eng.get_thresholds())

@router.post("/ml/thresholds", response_model=ThresholdsResponse)
@limiter.limit(WRITE_LIMIT)
async def set_thresholds(request: Request, body: ThresholdsRequest):
    if not ML_AVAILABLE:
        raise HTTPException(status_code=503, detail="ML engine not available")
    eng = get_ml_engine()
    try:
        updated = eng.set_thresholds(anomaly_threshold=body.anomaly_threshold)
        return ThresholdsResponse(**updated)
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        logger.exception("Failed to set thresholds")
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
