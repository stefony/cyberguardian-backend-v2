# core/ml_engine.py
import os
import re
import math
import json
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import silhouette_score
from sklearn.linear_model import LogisticRegression

log = logging.getLogger("ml_engine")

# ------------------------ Utilities ------------------------ #
def _entropy(s: str) -> float:
    """Shannon entropy of a (possibly long) string."""
    if not s:
        return 0.0
    s = str(s)[:2048]  # cap for safety
    length = len(s)
    if length == 0:
        return 0.0
    probs = [float(s.count(c)) / length for c in set(s)]
    return -sum(p * math.log2(p) for p in probs if p > 0)

SQL_PAT = re.compile(r"(select|union|sleep\(|or\s+1=1|drop\s+table|--|;)", re.IGNORECASE)
XSS_PAT = re.compile(r"(<script>|onerror=|javascript:|alert\()", re.IGNORECASE)
LFI_PAT = re.compile(r"(\.\./\.\.|/etc/passwd|/proc/self)", re.IGNORECASE)
ADMIN_PAT = re.compile(r"(/admin|/wp-login\.php|/login)", re.IGNORECASE)

# Simplified geo risk map (example)
GEO_RISK: Dict[str, float] = {
    "RU": 0.9, "CN": 0.8, "IR": 0.7, "KP": 0.7,
    "US": 0.4, "DE": 0.3, "NL": 0.3, "BG": 0.2,
}

REQUEST_MAP: Dict[str, int] = {"HTTP": 0, "DNS": 1, "SMB": 2, "SSH": 3, "OTHER": 4}

# ------------------------ State ------------------------ #
class _EngineState:
    def __init__(self):
        self.model_trained: bool = False
        self.training_date: str | None = None
        self.training_samples: int = 0

        self.features: List[str] = [
            "payload_len", "payload_entropy",
            "ratio_digits", "ratio_specials",
            "has_sql", "has_xss", "has_lfi", "has_admin",
            "port_bin", "req_type",
            "geo_risk",
        ]
        self.feature_count: int = len(self.features)

        # Active-learning classifier (optional)
        self.classifier = None
        self.classifier_threshold = 0.60
        self.labeled_count = 0

        # metrics & objects
        self.silhouette: float | None = None
        self.mean_anomaly: float | None = None
        self.n_clusters: int | None = None

        self.anomaly_detector: IsolationForest | None = None
        self.clusterer: KMeans | None = None
        self.scaler: StandardScaler | None = None

# ------------------------ Engine ------------------------ #
class MLEngine:
    """Simple ML engine for anomaly & behavior detection over request logs."""

    def __init__(self, dataset_path: str | None = None):
        # Default to JSONL since project uses data/training_logs.jsonl
        self.dataset_path = dataset_path or os.getenv(
            "ML_DATASET_PATH",
            "data/training_logs.jsonl",
        )
        self.state = _EngineState()
        log.info(f"[ML] Using dataset: {self.dataset_path}")

    # ---------- Public API (called by routes) ----------
    def get_model_status(self) -> dict:
        present, lines, size = self._probe_dataset_file()
        return {
            "model_trained": self.state.model_trained,
            "training_date": self.state.training_date,
            "training_samples": self.state.training_samples,
            "anomaly_detector_available": self.state.anomaly_detector is not None,
            "behavior_clusterer_available": self.state.clusterer is not None,
            "feature_count": self.state.feature_count,
            "features": self.state.features,
            # extras for /status
            "training_data_present": present,
            "training_data_lines": lines,
            "training_data_size": size,
            "training_data_path": self.dataset_path,
        }

    def train_models(self, n_clusters: int = 3, contamination: float = 0.1) -> dict:
        """
        Train KMeans (behavior) + IsolationForest (anomaly) on featurized dataset.
        Also (optionally) trains a lightweight classifier from labeled feedback.
        """
        df = self._load_dataset()
        if df.empty:
            log.warning("[ML] Dataset is empty")
            self._mark_untrained()
            return self._train_result(
                success=True,
                samples=0,
                n_clusters=n_clusters,
                silhouette=None,
                mean_anomaly=None,
                date=None,
            )

        X = self._featurize(df)

        # Minimal safety (need at least k+1 and > 10 rows)
        min_rows = max(10, n_clusters + 1)
        if X.shape[0] < min_rows:
            log.warning(f"[ML] Not enough rows to train: {X.shape[0]} (need >= {min_rows})")
            self._mark_untrained(samples=int(X.shape[0]))
            return self._train_result(
                success=True,
                samples=int(X.shape[0]),
                n_clusters=n_clusters,
                silhouette=None,
                mean_anomaly=None,
                date=None,
            )

        # Scale
        scaler = StandardScaler()
        Xs = scaler.fit_transform(X)

        # KMeans (behavior)
        kmeans = KMeans(n_clusters=n_clusters, n_init="auto", random_state=42)
        labels = kmeans.fit_predict(Xs)

        # IsolationForest (anomaly)
        iso = IsolationForest(
            n_estimators=200,
            contamination=float(min(max(contamination, 0.01), 0.4)),
            random_state=42,
        )
        iso.fit(Xs)
        # Higher = more anomalous
        anomaly_scores = -iso.score_samples(Xs)

        # Silhouette (if more than one cluster label)
        sil = None
        try:
            if len(set(labels)) > 1:
                sil = float(silhouette_score(Xs, labels))
        except Exception as e:
            log.warning(f"[ML] Silhouette failed: {e}")

        # ----------  Active learning from feedback (optional) ----------
        clf = None
        labeled_count = 0
        fb_rows = self._load_feedback()
        if fb_rows:
            try:
                ex_list = [ex for (ex, _) in fb_rows]
                y_labels = [1 if str(lbl).lower() == "malicious" else 0 for (_, lbl) in fb_rows]

                X_fb = self._featurize(pd.DataFrame(ex_list))
                X_fb_s = scaler.transform(X_fb)

                # Compact & stable classifier
                clf = LogisticRegression(max_iter=200)
                clf.fit(X_fb_s, y_labels)

                labeled_count = len(y_labels)
                log.info(f"[ML] Trained feedback classifier on {labeled_count} labeled rows")
            except Exception as e:
                log.warning(f"[ML] Feedback classifier training skipped: {e}")

        # ---------- Save state ----------
        self.state.anomaly_detector = iso
        self.state.clusterer = kmeans
        self.state.scaler = scaler
        self.state.classifier = clf
        self.state.labeled_count = labeled_count

        self.state.model_trained = True
        self.state.training_samples = int(X.shape[0])
        self.state.silhouette = sil
        self.state.mean_anomaly = float(np.mean(anomaly_scores)) if len(anomaly_scores) else None
        self.state.n_clusters = int(n_clusters)
        self.state.training_date = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        log.info(
            f"[ML] Training done: samples={self.state.training_samples}, "
            f"clusters={self.state.n_clusters}, silhouette={self.state.silhouette}, "
            f"mean_anomaly={self.state.mean_anomaly}, labeled={self.state.labeled_count}"
        )

        return self._train_result(
            success=True,
            samples=self.state.training_samples,
            n_clusters=self.state.n_clusters,
            silhouette=self.state.silhouette,
            mean_anomaly=self.state.mean_anomaly,
            date=self.state.training_date,
        )

    def predict_anomaly(self, log_row: dict) -> dict:
        if not self.state.model_trained:
            return {"error": "Model not trained"}
        X = self._featurize(pd.DataFrame([log_row]))
        Xs = self.state.scaler.transform(X)
        score = -float(self.state.anomaly_detector.score_samples(Xs)[0])  # invert so higher=worse
        conf = float(min(max(score / 5.0, 0.0), 1.0))  # simple soft confidence

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
        """
        Hybrid score = ML anomaly (scaled) + rule-based boosts (payload patterns + geo risk).
        If a feedback classifier exists, its probability adds a small boost.
        Returns 0..100 with levels.
        """
        # 1) ML anomaly
        an = self.predict_anomaly(log_row)
        if "error" in an:
            return an

        # 2) Behavior (for display)
        beh = self.analyze_behavior(log_row)

        # 3) Rule-based signals
        payload = str(log_row.get("payload", "") or "")
        country = str(log_row.get("country", "") or "").upper()

        rule_boost = 0.0
        if SQL_PAT.search(payload):
            rule_boost += 25.0
        if XSS_PAT.search(payload):
            rule_boost += 20.0
        if LFI_PAT.search(payload):
            rule_boost += 20.0
        if ADMIN_PAT.search(payload):
            rule_boost += 10.0

        geo = GEO_RISK.get(country, 0.2)
        if geo >= 0.7:
            rule_boost += 10.0
        elif geo >= 0.5:
            rule_boost += 5.0

        # 4) Combine ML + rules (+ optional classifier)
        ml_component = min(max(float(an["anomaly_score"]) * 20.0, 0.0), 100.0)
        score = 10.0 + ml_component * 0.6 + rule_boost

        # Optional: feedback classifier probability
        if self.state.classifier is not None:
            try:
                X = self._featurize(pd.DataFrame([log_row]))
                Xs = self.state.scaler.transform(X)
                proba = float(self.state.classifier.predict_proba(Xs)[0][1])  # P(malicious)
                score += min(10.0, 10.0 * proba)  # gentle boost up to +10
            except Exception:
                pass

        score = float(max(0.0, min(100.0, score)))

        if score >= 85:
            lvl = "CRITICAL"
        elif score >= 65:
            lvl = "HIGH"
        elif score >= 45:
            lvl = "MEDIUM"
        else:
            lvl = "LOW"

        return {
            "threat_score": float(round(score, 2)),
            "threat_level": lvl,
            "is_anomaly": an["is_anomaly"],
            "anomaly_score": float(round(an["anomaly_score"], 4)),
            "behavior_cluster": beh.get("cluster_name", "Unknown"),
            "confidence": float(round(an["confidence"], 3)),
        }

    # ------------------------ Helpers (methods) ------------------------ #
    def _train_result(
        self,
        success: bool,
        samples: int,
        n_clusters: int,
        silhouette: float | None,
        mean_anomaly: float | None,
        date: str | None,
    ) -> dict:
        return {
            "success": success,
            "training_samples": samples,
            "n_clusters": n_clusters,
            "silhouette_score": silhouette,
            "mean_anomaly_score": mean_anomaly,
            "training_date": date,
            "error": None if success else "Training failed",
        }

    def _mark_untrained(self, samples: int = 0):
        self.state.model_trained = False
        self.state.training_samples = samples
        self.state.anomaly_detector = None
        self.state.clusterer = None
        self.state.scaler = None
        self.state.classifier = None
        self.state.labeled_count = 0
        self.state.silhouette = None
        self.state.mean_anomaly = None
        self.state.n_clusters = None
        self.state.training_date = None

    def _load_feedback(self) -> list[tuple[dict, str]]:
        """Loads labeled logs from jsonl for active learning."""
        path = "data/labeled_logs.jsonl"
        if not os.path.exists(path):
            return []
        rows: list[tuple[dict, str]] = []
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    rec = json.loads(line.strip())
                    ex = rec.get("example") or rec.get("log") or {}
                    label = rec.get("label")
                    if ex and label:
                        rows.append((ex, label))
                except Exception:
                    continue
        return rows

    def _probe_dataset_file(self) -> tuple[bool, int | None, int | None]:
        """Lightweight probe for /status (does file exist, how many lines/size)."""
        path = self.dataset_path
        if not os.path.exists(path):
            return False, None, None
        try:
            size = os.path.getsize(path)
            with open(path, "rb") as f:
                lines = sum(1 for _ in f)
            return True, int(lines), int(size)
        except Exception:
            return True, None, None

    def _load_dataset(self) -> pd.DataFrame:
        """
        Robust loader for jsonl/csv:
        - Чете JSONL ред по ред и прескача повредени редове.
        - Липсващи колони се добавят с дефолтни стойности (не връщаме празно DF).
        """
        path = self.dataset_path
        if not os.path.exists(path):
            log.warning(f"[ML] Dataset not found at {path}")
            return pd.DataFrame()

        expected = {"timestamp", "source_ip", "source_port", "payload", "request_type", "country", "city"}
        rows: list[dict] = []

        try:
            if path.endswith(".jsonl"):
                with open(path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            rec = json.loads(line)
                            if isinstance(rec, dict):
                                rows.append(rec)
                        except Exception:
                            continue
                df = pd.DataFrame(rows)
            else:
                df = pd.read_csv(path)

            if df is None or df.empty:
                log.warning(f"[ML] Loaded empty dataframe from {path}")
                return pd.DataFrame()

            # add missing cols with defaults
            for col in expected:
                if col not in df.columns:
                    if col == "source_port":
                        df[col] = 0
                    elif col == "request_type":
                        df[col] = "HTTP"
                    elif col == "country":
                        df[col] = "BG"
                    else:
                        df[col] = ""

            # normalize types
            df["timestamp"] = df["timestamp"].astype(str)
            df["source_ip"] = df["source_ip"].astype(str)
            df["payload"] = df["payload"].fillna("").astype(str)
            df["request_type"] = df["request_type"].fillna("HTTP").astype(str)
            df["country"] = df["country"].fillna("BG").astype(str)
            df["city"] = df["city"].fillna("").astype(str)
            df["source_port"] = pd.to_numeric(df["source_port"], errors="coerce").fillna(0).astype(int)

            # drop obviously empty rows
            df = df[~(df["source_ip"].eq("") & df["payload"].eq(""))].reset_index(drop=True)

            log.info(f"[ML] Loaded dataset rows={len(df)} from {path}")
            return df

        except Exception as e:
            log.error(f"[ML] Failed to load dataset: {e}")
            return pd.DataFrame()

    def _featurize(self, df: pd.DataFrame) -> np.ndarray:
        """Converts raw log rows into numeric feature matrix."""
        df = df.copy()

        # Safe defaults
        df["payload"] = df.get("payload", "").fillna("").astype(str)
        df["request_type"] = df.get("request_type", "HTTP").fillna("HTTP").astype(str)
        df["country"] = df.get("country", "BG").fillna("BG").astype(str)

        # source_port → numeric
        df["source_port"] = pd.to_numeric(df.get("source_port", 0), errors="coerce").fillna(0).astype(int)

        payload = df["payload"].astype(str)
        payload_len = payload.str.len().clip(0, 4096)
        payload_entropy = payload.apply(_entropy)

        def _ratio_digits(s: str) -> float:
            s = str(s)
            if not s:
                return 0.0
            cnt = sum(c.isdigit() for c in s)
            return cnt / len(s) if len(s) else 0.0

        def _ratio_specials(s: str) -> float:
            s = str(s)
            if not s:
                return 0.0
            cnt = sum((not c.isalnum()) for c in s)
            return cnt / len(s) if len(s) else 0.0

        ratio_digits = payload.apply(_ratio_digits)
        ratio_specials = payload.apply(_ratio_specials)

        has_sql = payload.str.contains(SQL_PAT).astype(int)
        has_xss = payload.str.contains(XSS_PAT).astype(int)
        has_lfi = payload.str.contains(LFI_PAT).astype(int)
        has_admin = payload.str.contains(ADMIN_PAT).astype(int)

        # Port binning; guard against NaN by using cat codes
        port = df["source_port"].astype(int)
        port_categories = pd.cut(
            port,
            bins=[-1, 0, 1023, 49151, 65535],
            labels=[0, 1, 2, 3],
            include_lowest=True,
            right=True,
        )
        port_bin = port_categories.astype("category").cat.codes.replace(-1, 0).astype(int)

        # Request type & geo risk
        req_type = df["request_type"].str.upper().map(REQUEST_MAP).fillna(4).astype(int)
        geo_risk = df["country"].str.upper().map(GEO_RISK).fillna(0.2).astype(float)

        feats = np.column_stack(
            [
                payload_len.values.astype(float),
                np.asarray(list(payload_entropy), dtype=float),
                ratio_digits.values.astype(float),
                ratio_specials.values.astype(float),
                has_sql.values.astype(int),
                has_xss.values.astype(int),
                has_lfi.values.astype(int),
                has_admin.values.astype(int),
                port_bin.values.astype(int),
                req_type.values.astype(int),
                geo_risk.values.astype(float),
            ]
        )
        return feats

# --- Singleton accessor used by API ---
_engine_singleton: "MLEngine | None" = None

def get_ml_engine() -> "MLEngine":
    global _engine_singleton
    if _engine_singleton is None:
        _engine_singleton = MLEngine()
    return _engine_singleton
