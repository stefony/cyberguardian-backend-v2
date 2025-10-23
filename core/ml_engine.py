"""
CyberGuardian AI - Machine Learning Engine
Real ML models for threat detection and behavioral analysis
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import silhouette_score
import pickle
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import sqlite3
import json

logger = logging.getLogger(__name__)

class MLEngine:
    """
    Machine Learning Engine for CyberGuardian AI
    
    Features:
    - Anomaly Detection (Isolation Forest)
    - Behavioral Analysis (K-Means Clustering)
    - Threat Scoring
    - Feature Extraction from logs
    """
    
    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or str(Path(__file__).parent.parent / 'database' / 'cyberguardian.db')
        self.models_dir = Path(__file__).parent.parent / 'models'
        self.models_dir.mkdir(exist_ok=True)
        
        # ML Models
        self.anomaly_detector = None
        self.behavior_clusterer = None
        self.scaler = StandardScaler()
        
        # Model metadata
        self.model_trained = False
        self.training_date = None
        self.training_samples = 0
        self.anomaly_threshold = -0.5
        
        # Feature names
        self.feature_names = [
            'hour_of_day',
            'day_of_week',
            'request_count',
            'unique_ips',
            'avg_payload_size',
            'suspicious_patterns',
            'port_diversity',
            'geographic_diversity'
        ]
        
        # Load existing models
        self._load_models()
    
    def _load_models(self):
        """Load trained models from disk"""
        try:
            anomaly_path = self.models_dir / 'anomaly_detector.pkl'
            cluster_path = self.models_dir / 'behavior_clusterer.pkl'
            scaler_path = self.models_dir / 'scaler.pkl'
            metadata_path = self.models_dir / 'metadata.json'
            
            if anomaly_path.exists():
                with open(anomaly_path, 'rb') as f:
                    self.anomaly_detector = pickle.load(f)
                logger.info("Loaded anomaly detector model")
            
            if cluster_path.exists():
                with open(cluster_path, 'rb') as f:
                    self.behavior_clusterer = pickle.load(f)
                logger.info("Loaded behavior clusterer model")
            
            if scaler_path.exists():
                with open(scaler_path, 'rb') as f:
                    self.scaler = pickle.load(f)
                logger.info("Loaded scaler")
            
            if metadata_path.exists():
                with open(metadata_path, 'r') as f:
                    metadata = json.load(f)
                    self.model_trained = metadata.get('trained', False)
                    self.training_date = metadata.get('training_date')
                    self.training_samples = metadata.get('training_samples', 0)
                logger.info("Loaded model metadata")
        
        except Exception as e:
            logger.error(f"Failed to load models: {e}")
    
    def _save_models(self):
        """Save trained models to disk"""
        try:
            if self.anomaly_detector:
                with open(self.models_dir / 'anomaly_detector.pkl', 'wb') as f:
                    pickle.dump(self.anomaly_detector, f)
            
            if self.behavior_clusterer:
                with open(self.models_dir / 'behavior_clusterer.pkl', 'wb') as f:
                    pickle.dump(self.behavior_clusterer, f)
            
            with open(self.models_dir / 'scaler.pkl', 'wb') as f:
                pickle.dump(self.scaler, f)
            
            metadata = {
                'trained': self.model_trained,
                'training_date': self.training_date,
                'training_samples': self.training_samples,
                'feature_names': self.feature_names
            }
            
            with open(self.models_dir / 'metadata.json', 'w') as f:
                json.dump(metadata, f, indent=2)
            
            logger.info("Models saved successfully")
        
        except Exception as e:
            logger.error(f"Failed to save models: {e}")
    
    def extract_features(self, logs: List[Dict]) -> np.ndarray:
        """
        Extract features from security logs
        
        Args:
            logs: List of log entries with timestamp, ip, payload, etc.
        
        Returns:
            Feature matrix (n_samples, n_features)
        """
        if not logs:
            return np.array([])
        
        features = []
        
        for log in logs:
            try:
                # Time-based features
                timestamp = datetime.fromisoformat(log.get('timestamp', datetime.now().isoformat()))
                hour_of_day = timestamp.hour
                day_of_week = timestamp.weekday()
                
                # Basic counts
                request_count = 1  # Each log is one request
                
                # IP diversity (simplified - would need grouping in real scenario)
                unique_ips = 1
                
                # Payload analysis
                payload = log.get('payload', '')
                payload_size = len(payload)
                
                # Suspicious patterns
                suspicious_keywords = ['admin', 'root', 'password', '../', '<script>', 'union', 'select', 'drop']
                suspicious_count = sum(1 for keyword in suspicious_keywords if keyword.lower() in payload.lower())
                
                # Port diversity
                port = log.get('source_port', 0)
                port_diversity = 1 if port > 0 else 0
                
                # Geographic diversity (simplified)
                country = log.get('country', '')
                geo_diversity = 1 if country and country != 'Local' else 0
                
                feature_vector = [
                    hour_of_day,
                    day_of_week,
                    request_count,
                    unique_ips,
                    payload_size,
                    suspicious_count,
                    port_diversity,
                    geo_diversity
                ]
                
                features.append(feature_vector)
            
            except Exception as e:
                logger.error(f"Failed to extract features from log: {e}")
                continue
        
        return np.array(features)
    
    def _fetch_training_data(self) -> List[Dict]:
        """Fetch security logs from database for training"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Fetch honeypot logs
            cursor.execute('''
                SELECT timestamp, source_ip, source_port, payload, request_type
                FROM honeypot_logs
                ORDER BY timestamp DESC
                LIMIT 1000
            ''')
            
            rows = cursor.fetchall()
            conn.close()
            
            logs = []
            for row in rows:
                logs.append({
                    'timestamp': row[0],
                    'source_ip': row[1],
                    'source_port': row[2],
                    'payload': row[3],
                    'request_type': row[4]
                })
            
            return logs
        
        except Exception as e:
            logger.error(f"Failed to fetch training data: {e}")
            return []
    
    def train_models(self, logs: Optional[List[Dict]] = None, 
                     n_clusters: int = 3, 
                     contamination: float = 0.1) -> Dict:
        """
        Train ML models on security logs
        
        Args:
            logs: Training data (if None, fetches from database)
            n_clusters: Number of behavior clusters
            contamination: Expected proportion of anomalies
        
        Returns:
            Training results
        """
        try:
            # Get training data
            if logs is None:
                logs = self._fetch_training_data()
            
            if len(logs) < 10:
                # Generate synthetic training data for demo
                logs = self._generate_synthetic_data(100)
            
            # Extract features
            X = self.extract_features(logs)
            
            if len(X) == 0:
                raise ValueError("No valid features extracted")
            
            # Scale features
            X_scaled = self.scaler.fit_transform(X)
            
            # Train Anomaly Detector (Isolation Forest)
            self.anomaly_detector = IsolationForest(
                contamination=contamination,
                random_state=42,
                n_estimators=100
            )
            self.anomaly_detector.fit(X_scaled)
            
            # Train Behavior Clusterer (K-Means)
            self.behavior_clusterer = KMeans(
                n_clusters=n_clusters,
                random_state=42,
                n_init=10
            )
            self.behavior_clusterer.fit(X_scaled)
            
            # Calculate metrics
            silhouette = silhouette_score(X_scaled, self.behavior_clusterer.labels_)
            anomaly_scores = self.anomaly_detector.score_samples(X_scaled)
            
            # Update metadata
            self.model_trained = True
            self.training_date = datetime.now().isoformat()
            self.training_samples = len(X)
            
            # Save models
            self._save_models()
            
            results = {
                'success': True,
                'training_samples': len(X),
                'n_clusters': n_clusters,
                'silhouette_score': float(silhouette),
                'mean_anomaly_score': float(np.mean(anomaly_scores)),
                'training_date': self.training_date
            }
            
            logger.info(f"Models trained successfully: {results}")
            return results
        
        except Exception as e:
            logger.error(f"Failed to train models: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _generate_synthetic_data(self, n_samples: int = 100) -> List[Dict]:
        """Generate synthetic training data for demo purposes"""
        logs = []
        base_time = datetime.now()
        
        for i in range(n_samples):
            # Create variety of normal and anomalous patterns
            is_anomaly = np.random.random() < 0.1
            
            if is_anomaly:
                # Anomalous behavior
                payload = f"admin' OR '1'='1'; DROP TABLE users; {np.random.choice(['<script>', 'union select', '../../../etc/passwd'])}"
                hour = np.random.choice([2, 3, 4])  # Unusual hours
            else:
                # Normal behavior
                payload = f"GET /api/data?id={np.random.randint(1, 1000)}"
                hour = np.random.choice([9, 10, 11, 14, 15, 16])  # Business hours
            
            log = {
                'timestamp': (base_time - timedelta(hours=i)).isoformat(),
                'source_ip': f"192.168.1.{np.random.randint(1, 255)}",
                'source_port': np.random.randint(1024, 65535),
                'payload': payload,
                'request_type': 'HTTP',
                'country': np.random.choice(['US', 'UK', 'DE', 'FR', 'Local'])
            }
            
            logs.append(log)
        
        return logs
    
    def predict_anomaly(self, log: Dict) -> Dict:
        """
        Predict if a log entry is anomalous
        
        Args:
            log: Log entry to analyze
        
        Returns:
            Prediction result with score and classification
        """
        if not self.model_trained or self.anomaly_detector is None:
            return {
                'is_anomaly': False,
                'anomaly_score': 0.0,
                'confidence': 0.0,
                'error': 'Model not trained'
            }
        
        try:
            # Extract features
            X = self.extract_features([log])
            
            if len(X) == 0:
                raise ValueError("Failed to extract features")
            
            # Scale
            X_scaled = self.scaler.transform(X)
            
            # Predict
            prediction = self.anomaly_detector.predict(X_scaled)[0]
            score = self.anomaly_detector.score_samples(X_scaled)[0]
            
            # Calculate confidence
            confidence = abs(score) / 1.0  # Normalize score
            confidence = min(max(confidence, 0.0), 1.0)
            
            return {
                'is_anomaly': prediction == -1,
                'anomaly_score': float(score),
                'confidence': float(confidence),
                'threshold': self.anomaly_threshold
            }
        
        except Exception as e:
            logger.error(f"Failed to predict anomaly: {e}")
            return {
                'is_anomaly': False,
                'anomaly_score': 0.0,
                'confidence': 0.0,
                'error': str(e)
            }
    
    def analyze_behavior(self, log: Dict) -> Dict:
        """
        Analyze behavioral patterns in log
        
        Args:
            log: Log entry to analyze
        
        Returns:
            Behavior cluster and analysis
        """
        if not self.model_trained or self.behavior_clusterer is None:
            return {
                'cluster': -1,
                'cluster_name': 'Unknown',
                'error': 'Model not trained'
            }
        
        try:
            # Extract features
            X = self.extract_features([log])
            
            if len(X) == 0:
                raise ValueError("Failed to extract features")
            
            # Scale
            X_scaled = self.scaler.transform(X)
            
            # Predict cluster
            cluster = self.behavior_clusterer.predict(X_scaled)[0]
            
            # Map cluster to name
            cluster_names = {
                0: 'Normal Activity',
                1: 'Suspicious Activity',
                2: 'High Risk Activity'
            }
            
            return {
                'cluster': int(cluster),
                'cluster_name': cluster_names.get(cluster, 'Unknown'),
                'n_clusters': self.behavior_clusterer.n_clusters
            }
        
        except Exception as e:
            logger.error(f"Failed to analyze behavior: {e}")
            return {
                'cluster': -1,
                'cluster_name': 'Error',
                'error': str(e)
            }
    
    def calculate_threat_score(self, log: Dict) -> Dict:
        """
        Calculate comprehensive threat score
        
        Combines anomaly detection and behavioral analysis
        
        Args:
            log: Log entry to analyze
        
        Returns:
            Threat score (0-100) and classification
        """
        try:
            # Get anomaly prediction
            anomaly_result = self.predict_anomaly(log)
            
            # Get behavior analysis
            behavior_result = self.analyze_behavior(log)
            
            # Calculate base threat score
            threat_score = 0.0
            
            # Anomaly contribution (0-50 points)
            if anomaly_result.get('is_anomaly'):
                threat_score += 30 + (anomaly_result.get('confidence', 0) * 20)
            
            # Behavior contribution (0-30 points)
            cluster = behavior_result.get('cluster', 0)
            if cluster == 2:  # High risk
                threat_score += 30
            elif cluster == 1:  # Suspicious
                threat_score += 15
            
            # Content analysis (0-20 points)
            payload = log.get('payload', '')
            suspicious_keywords = ['admin', 'root', 'password', '../', '<script>', 'union', 'select']
            keyword_matches = sum(1 for kw in suspicious_keywords if kw.lower() in payload.lower())
            threat_score += min(keyword_matches * 5, 20)
            
            # Normalize to 0-100
            threat_score = min(threat_score, 100)
            
            # Classify threat level
            if threat_score >= 70:
                threat_level = 'critical'
            elif threat_score >= 50:
                threat_level = 'high'
            elif threat_score >= 30:
                threat_level = 'medium'
            else:
                threat_level = 'low'
            
            return {
                'threat_score': float(threat_score),
                'threat_level': threat_level,
                'is_anomaly': anomaly_result.get('is_anomaly', False),
                'anomaly_score': anomaly_result.get('anomaly_score', 0.0),
                'behavior_cluster': behavior_result.get('cluster_name', 'Unknown'),
                'confidence': anomaly_result.get('confidence', 0.0)
            }
        
        except Exception as e:
            logger.error(f"Failed to calculate threat score: {e}")
            return {
                'threat_score': 0.0,
                'threat_level': 'unknown',
                'error': str(e)
            }
    
    def get_model_status(self) -> Dict:
        """Get ML model status and metadata"""
        return {
            'model_trained': self.model_trained,
            'training_date': self.training_date,
            'training_samples': self.training_samples,
            'anomaly_detector_available': self.anomaly_detector is not None,
            'behavior_clusterer_available': self.behavior_clusterer is not None,
            'feature_count': len(self.feature_names),
            'features': self.feature_names
        }


# Global instance
_ml_engine = None

def get_ml_engine() -> MLEngine:
    """Get global ML engine instance"""
    global _ml_engine
    if _ml_engine is None:
        _ml_engine = MLEngine()
    return _ml_engine


# Testing
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    print("🤖 Testing ML Engine...")
    
    engine = get_ml_engine()
    
    # Train models
    print("\n📚 Training models...")
    results = engine.train_models()
    print(f"Training results: {results}")
    
    # Test prediction
    print("\n🎯 Testing predictions...")
    
    test_log_normal = {
        'timestamp': datetime.now().isoformat(),
        'source_ip': '192.168.1.100',
        'source_port': 8080,
        'payload': 'GET /api/data',
        'request_type': 'HTTP'
    }
    
    test_log_attack = {
        'timestamp': datetime.now().isoformat(),
        'source_ip': '10.0.0.1',
        'source_port': 2222,
        'payload': "admin' OR '1'='1'; DROP TABLE users;",
        'request_type': 'SQL'
    }
    
    print("\nNormal log:")
    score_normal = engine.calculate_threat_score(test_log_normal)
    print(f"  Threat Score: {score_normal['threat_score']:.1f}")
    print(f"  Threat Level: {score_normal['threat_level']}")
    
    print("\nAttack log:")
    score_attack = engine.calculate_threat_score(test_log_attack)
    print(f"  Threat Score: {score_attack['threat_score']:.1f}")
    print(f"  Threat Level: {score_attack['threat_level']}")
    
    print("\n✅ ML Engine test complete!")