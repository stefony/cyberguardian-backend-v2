# core/ml_engine.py
import os
import re
import math
import json
import logging
from datetime import datetime

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans
from sklearn.ensemble import IsolationForest
from sklearn.metrics import silhouette_score

log = logging.getLogger("ml_engine")


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    # ограничаваме до разумен размер, за да не взривим паметта при ботове
    s = str(s)
    s = s[:2048]
    probs = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs if p > 0)


SQL_PAT = re.compile(r"(select|union|sleep\(|or\s+1=1|drop\s+table|--|;)", re.IGNORECASE)
XSS_PAT = re.compile(r"(<script>|onerror=|javascript:|alert\()", re.IGNORECASE)
LFI_PAT = re.compile(r"(\.\./\.\.|/etc/passwd|/proc/self)", re.IGNORECASE)
ADMIN_PAT = re.compile(r"(/admin|/wp-login\.php|/login)", re.IGNORECASE)

# за прост „geo-risk“, държави с по-честа злонамерена активност (примерно)
GEO_RISK = {
    "RU": 0.9, "CN": 0.8, "IR": 0.7, "KP": 0.7,
    "US": 0.4, "DE": 0.3, "NL": 0.3, "BG": 0.2,
}

REQUEST_MAP = {"HTTP": 0, "DNS": 1, "SMB": 2, "SSH": 3, "OTHER": 4}


class _EngineState:
    def __init__(self):
        self.model_trained = False
        self.training_date = None
        self.training_samples = 0
        self.features = [
            "payload_len", "payload_entropy",
            "ratio_digits", "ratio_specials",
            "has_sql", "has_xss", "has_lfi", "has_admin",
            "port_bin", "req_type",
            "geo_risk"
        ]
        self.feature_count = len(self.features)
        self.silhouette = None
        self.mean_anomaly = None
        self.n_clusters = None
        self.anomaly_detector = None
        self.clusterer = None
        self.scaler = None


class MLEngine:
    def __init__(self, dataset_path: str | None = None):
        self.state = _EngineState()
        self.dataset_path = dataset_path or os.getenv("ML_DATASET_PATH", "data/ml_training_logs.csv")
        log.info(f"[ML] Using dataset: {self.dataset_path}")

    # ---------- Public API (called by routes) ----------
    def get_model_status(self) -> dict:
        return {
            "model_trained": self.state.model_trained,
            "training_date": self.state.training_date,
            "training_samples": self.state.training_samples,
            "anomaly_detector_available": self.state.anomaly_detector is not None,
            "behavior_clusterer_available": self.state.clusterer is not None,
            "feature_count": self.state.feature_count,
            "features": self.state.features,
        }

    def train_models(self, n_clusters: int = 3, contamination: float = 0.1) -> dict:
        df = self._load_dataset()
        if df.empty:
            log.warning("[ML] Dataset is empty")
            self.state.model_trained = False
            self.state.training_samples = 0
            return {
                "success": True,
                "training_samples": 0,
                "n_clusters": n_clusters,
                "silhouette_score": None,
                "mean_anomaly_score": None,
                "training_date": None,
            }

        X = self._featurize(df)
        if X.shape[0] < max(10, n_clusters + 1):
            log.warning(f"[ML] Not enough rows to train: {X.shape[0]}")
            self.state.model_trained = False
            self.state.training_samples = X.shape[0]
            return {
                "success": True,
                "training_samples": int(X.shape[0]),
                "n_clusters": n_clusters,
                "silhouette_score": None,
                "mean_anomaly_score": None,
                "training_date": None,
            }

        # scale
        scaler = StandardScaler()
        Xs = scaler.fit_transform(X)

        # clustering
        kmeans = KMeans(n_clusters=n_clusters, n_init="auto", random_state=42)
        labels = kmeans.fit_predict(Xs)

        # anomaly
        iso = IsolationForest(
            n_estimators=200,
            contamination=min(max(contamination, 0.01), 0.4),
            random_state=42,
        )
        anomaly_scores = -iso.fit_score(Xs)  # по-високо = по-аномално

        sil = None
        try:
            # silhouette изисква поне 2 различни етикета
            if len(set(labels)) > 1:
                sil = float(silhouette_score(Xs, labels))
        except Exception as e:
            log.warning(f"[ML] Silhouette failed: {e}")

        self.state.anomaly_detector = iso
        self.state.clusterer = kmeans
        self.state.scaler = scaler
        self.state.model_trained = True
        self.state.training_samples = int(X.shape[0])
        self.state.silhouette = sil
        self.state.mean_anomaly = float(np.mean(anomaly_scores)) if len(anomaly_scores) else None
        self.state.n_clusters = int(n_clusters)
        self.state.training_date = datetime.utcnow().isoformat()

        log.info(f"[ML] Training done: samples={self.state.training_samples}, "
                 f"clusters={self.state.n_clusters}, silhouette={self.state.silhouette}, "
                 f"mean_anomaly={self.state.mean_anomaly}")

        return {
            "success": True,
            "training_samples": self.state.training_samples,
            "n_clusters": self.state.n_clusters,
            "silhouette_score": self.state.silhouette,
            "mean_anomaly_score": self.state.mean_anomaly,
            "training_date": self.state.training_date,
        }

    def predict_anomaly(self, log_row: dict) -> dict:
        if not self.state.model_trained:
            return {"error": "Model not trained"}
        X = self._featurize(pd.DataFrame([log_row]))
        Xs = self.state.scaler.transform(X)
        score = -self.state.anomaly_detector.score_samples(Xs)[0]
        # просто доверие като нормализирана функция
        conf = float(min(max(score / 5.0, 0.0), 1.0))
        return {
            "is_anomaly": bool(score > 1.0),
            "anomaly_score": float(score),
            "confidence": conf,
            "threshold": 1.0,
        }

    def analyze_behavior(self, log_row: dict) -> dict:
        if not self.state.model_trained:
            return {"error": "Model not trained"}
        X = self._featurize(pd.DataFrame([log_row]))
        Xs = self.state.scaler.transform(X)
        label = int(self.state.clusterer.predict(Xs)[0])
        return {"cluster": label, "cluster_name": f"Cluster {label}", "n_clusters": self.state.n_clusters}

    def calculate_threat_score(self, log_row: dict) -> dict:
        an = self.predict_anomaly(log_row)
        if "error" in an:
            return an
        beh = self.analyze_behavior(log_row)
        base = 20.0 + 70.0 * min(max(an["anomaly_score"] / 3.0, 0.0), 1.0)
        lvl = "LOW"
        if base >= 80: lvl = "CRITICAL"
        elif base >= 60: lvl = "HIGH"
        elif base >= 40: lvl = "MEDIUM"
        return {
            "threat_score": float(round(base, 2)),
            "threat_level": lvl,
            "is_anomaly": an["is_anomaly"],
            "anomaly_score": float(round(an["anomaly_score"], 4)),
            "behavior_cluster": beh.get("cluster_name", "Unknown"),
            "confidence": float(round(an["confidence"], 3)),
        }

    # ---------- Helpers ----------
    def _load_dataset(self) -> pd.DataFrame:
        path = self.dataset_path
        try:
            if not os.path.exists(path):
                log.warning(f"[ML] Dataset not found at {path}")
                return pd.DataFrame()
            df = pd.read_csv(path)
            # стандартизиране на колоните
            expected = {"timestamp","source_ip","source_port","payload","request_type","country","city"}
            missing = expected - set(df.columns)
            if missing:
                log.warning(f"[ML] Missing columns in dataset: {missing}")
                return pd.DataFrame()
            return df
        except Exception as e:
            log.error(f"[ML] Failed to load dataset: {e}")
            return pd.DataFrame()

    def _featurize(self, df: pd.DataFrame) -> np.ndarray:
        # безопасни стойности
        df = df.copy()
        df["payload"] = df["payload"].fillna("")
        df["request_type"] = df["request_type"].fillna("HTTP")
        df["country"] = df["country"].fillna("BG")
        df["source_port"] = pd.to_numeric(df["source_port"], errors="coerce").fillna(0).astype(int)

        payload = df["payload"].astype(str)
        payload_len = payload.str.len().clip(0, 4096)
        payload_entropy = payload.apply(_entropy)

        def _ratio_digits(s):
            s = str(s)
            if not s: return 0.0
            cnt = sum(c.isdigit() for c in s)
            return cnt / len(s)

        def _ratio_specials(s):
            s = str(s)
            if not s: return 0.0
            cnt = sum((not c.isalnum()) for c in s)
            return cnt / len(s)

        ratio_digits = payload.apply(_ratio_digits)
        ratio_specials = payload.apply(_ratio_specials)

        has_sql = payload.str.contains(SQL_PAT).astype(int)
        has_xss = payload.str.contains(XSS_PAT).astype(int)
        has_lfi = payload.str.contains(LFI_PAT).astype(int)
        has_admin = payload.str.contains(ADMIN_PAT).astype(int)

        # порт биннинг
        port = df["source_port"].astype(int)
        port_bin = pd.cut(
            port,
            bins=[-1, 0, 1023, 49151, 65535],
            labels=[0, 1, 2, 3]
        ).astype(int)

        req_type = df["request_type"].str.upper().map(REQUEST_MAP).fillna(4).astype(int)
        geo_risk = df["country"].str.upper().map(GEO_RISK).fillna(0.2)

        feats = np.column_stack([
            payload_len.values.astype(float),
            np.array(list(payload_entropy), dtype=float),
            ratio_digits.values.astype(float),
            ratio_specials.values.astype(float),
            has_sql.values.astype(int),
            has_xss.values.astype(int),
            has_lfi.values.astype(int),
            has_admin.values.astype(int),
            port_bin.values.astype(int),
            req_type.values.astype(int),
            geo_risk.values.astype(float),
        ])
        return feats


# --- Singleton accessor used by API ---
_engine_singleton: MLEngine | None = None

def get_ml_engine() -> MLEngine:
    global _engine_singleton
    if _engine_singleton is None:
        _engine_singleton = MLEngine()
    return _engine_singleton
