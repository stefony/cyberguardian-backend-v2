"""
CyberGuardian - Machine Learning Detection Engine
==================================================

Advanced ML-powered threat detection.

Features:
- Multiple ML models (ensemble approach)
- Feature engineering
- Model training and updating
- Real-time prediction
- Model versioning
- Performance monitoring
- Adversarial ML defense

ML Models:
1. Random Forest - General classification
2. XGBoost - Gradient boosting
3. Neural Network - Deep learning
4. Ensemble - Combined predictions

Use Cases:
- Malware classification
- Phishing detection
- Network intrusion detection
- Zero-day threat prediction
- Behavioral classification

Feature Categories:
- Static features (file properties)
- Dynamic features (behavior)
- Network features (traffic patterns)
- Text features (NLP for phishing)

Training Pipeline:
1. Feature extraction
2. Data preprocessing
3. Model training
4. Validation
5. Deployment

Detection Pipeline:
1. Extract features
2. Normalize
3. Predict with ensemble
4. Calculate confidence
5. Return result
"""

import numpy as np
import pickle
import os
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
import logging

# ML imports
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

try:
    import xgboost as xgb
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False
    logging.warning("XGBoost not available")


# ============================================================================
# CONFIGURATION
# ============================================================================

class ThreatClass(Enum):
    """Threat classification labels"""
    BENIGN = 0
    MALWARE = 1
    PHISHING = 2
    EXPLOIT = 3
    RANSOMWARE = 4
    TROJAN = 5


class ModelType(Enum):
    """ML model types"""
    RANDOM_FOREST = "random_forest"
    GRADIENT_BOOSTING = "gradient_boosting"
    XGBOOST = "xgboost"
    ENSEMBLE = "ensemble"


@dataclass
class MLPrediction:
    """
    ML prediction result.
    
    Attributes:
        threat_class: Predicted threat class
        confidence: Prediction confidence (0-1)
        probabilities: Class probabilities
        features_used: Number of features
        model_version: Model version used
        is_malicious: Whether classified as threat
    """
    threat_class: ThreatClass
    confidence: float
    probabilities: Dict[str, float] = field(default_factory=dict)
    features_used: int = 0
    model_version: str = "1.0"
    is_malicious: bool = False


@dataclass
class ModelMetrics:
    """
    Model performance metrics.
    
    Attributes:
        accuracy: Overall accuracy
        precision: Precision score
        recall: Recall score
        f1_score: F1 score
        samples_trained: Training samples
        last_trained: Training timestamp
    """
    accuracy: float = 0.0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    samples_trained: int = 0
    last_trained: Optional[datetime] = None


# ============================================================================
# ML ENGINE
# ============================================================================

class MLEngine:
    """
    Machine Learning detection engine.
    
    Uses ensemble of ML models for threat detection.
    """
    
    # Feature names (for reference)
    FEATURE_NAMES = [
        'file_size',
        'entropy',
        'string_count',
        'import_count',
        'section_count',
        'packed',
        'signed',
        'cpu_usage',
        'memory_usage',
        'network_connections',
        'file_operations',
        'registry_operations',
        'process_injections',
        'privilege_level',
        'persistence_indicators'
    ]
    
    def __init__(self, model_dir: Optional[str] = None):
        """
        Initialize ML engine.
        
        Args:
            model_dir: Directory for model storage
        """
        self.logger = logging.getLogger(__name__)
        
        # Model directory
        if model_dir:
            self.model_dir = Path(model_dir)
        else:
            self.model_dir = Path.home() / '.cyberguardian' / 'ml_models'
        
        self.model_dir.mkdir(parents=True, exist_ok=True)
        
        # ML Models
        self.random_forest = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            n_jobs=-1
        )
        
        self.gradient_boosting = GradientBoostingClassifier(
            n_estimators=100,
            max_depth=5,
            random_state=42
        )
        
        if XGBOOST_AVAILABLE:
            self.xgboost = xgb.XGBClassifier(
                n_estimators=100,
                max_depth=6,
                random_state=42,
                use_label_encoder=False,
                eval_metric='logloss'
            )
        else:
            self.xgboost = None
        
        # Preprocessing
        self.scaler = StandardScaler()
        
        # Model state
        self.models_trained = False
        self.model_version = "1.0.0"
        
        # Metrics
        self.metrics = ModelMetrics()
        
        # Statistics
        self.predictions_made = 0
        self.threats_detected = 0
        
        # Load existing models if available
        self._load_models()
    
    # ========================================================================
    # FEATURE EXTRACTION
    # ========================================================================
    
    def extract_features(self, context: Dict) -> np.ndarray:
        """
        Extract ML features from context.
        
        Args:
            context: Detection context
            
        Returns:
            Feature vector (numpy array)
        """
        features = []
        
        # Extract each feature with defaults
        features.append(context.get('file_size', 0))
        features.append(context.get('entropy', 0.0))
        features.append(context.get('string_count', 0))
        features.append(context.get('import_count', 0))
        features.append(context.get('section_count', 0))
        features.append(1 if context.get('packed', False) else 0)
        features.append(1 if context.get('signed', False) else 0)
        features.append(context.get('cpu_usage', 0.0))
        features.append(context.get('memory_usage', 0.0))
        features.append(context.get('network_connections', 0))
        features.append(context.get('file_operations', 0))
        features.append(context.get('registry_operations', 0))
        features.append(context.get('process_injections', 0))
        features.append(context.get('privilege_level', 0))
        features.append(context.get('persistence_indicators', 0))
        
        return np.array(features).reshape(1, -1)
    
    # ========================================================================
    # TRAINING
    # ========================================================================
    
    def train(self, X: np.ndarray, y: np.ndarray, validation_split: float = 0.2):
        """
        Train ML models.
        
        Args:
            X: Feature matrix
            y: Labels
            validation_split: Validation data fraction
        """
        self.logger.info("Training ML models...")
        
        # Split data
        X_train, X_val, y_train, y_val = train_test_split(
            X, y,
            test_size=validation_split,
            random_state=42,
            stratify=y
        )
        
        # Normalize features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_val_scaled = self.scaler.transform(X_val)
        
        # Train Random Forest
        self.logger.info("Training Random Forest...")
        self.random_forest.fit(X_train_scaled, y_train)
        
        # Train Gradient Boosting
        self.logger.info("Training Gradient Boosting...")
        self.gradient_boosting.fit(X_train_scaled, y_train)
        
        # Train XGBoost if available
        if self.xgboost:
            self.logger.info("Training XGBoost...")
            self.xgboost.fit(X_train_scaled, y_train)
        
        # Evaluate on validation set
        self._evaluate(X_val_scaled, y_val)
        
        # Update state
        self.models_trained = True
        self.metrics.samples_trained = len(X_train)
        self.metrics.last_trained = datetime.now()
        
        # Save models
        self._save_models()
        
        self.logger.info(f"✅ Models trained successfully")
        self.logger.info(f"   Accuracy: {self.metrics.accuracy:.3f}")
        self.logger.info(f"   Precision: {self.metrics.precision:.3f}")
        self.logger.info(f"   Recall: {self.metrics.recall:.3f}")
        self.logger.info(f"   F1 Score: {self.metrics.f1_score:.3f}")
    
    def _evaluate(self, X_val: np.ndarray, y_val: np.ndarray):
        """Evaluate model performance"""
        # Get predictions from ensemble
        predictions = self._predict_ensemble(X_val)
        
        # Calculate metrics
        self.metrics.accuracy = accuracy_score(y_val, predictions)
        self.metrics.precision = precision_score(y_val, predictions, average='weighted', zero_division=0)
        self.metrics.recall = recall_score(y_val, predictions, average='weighted', zero_division=0)
        self.metrics.f1_score = f1_score(y_val, predictions, average='weighted', zero_division=0)
    
    # ========================================================================
    # PREDICTION
    # ========================================================================
    
    def predict(self, context: Dict) -> MLPrediction:
        """
        Predict threat using ML models.
        
        Args:
            context: Detection context
            
        Returns:
            MLPrediction result
        """
        self.predictions_made += 1
        
        if not self.models_trained:
            self.logger.warning("Models not trained yet")
            return MLPrediction(
                threat_class=ThreatClass.BENIGN,
                confidence=0.0,
                is_malicious=False
            )
        
        # Extract features
        features = self.extract_features(context)
        
        # Normalize
        features_scaled = self.scaler.transform(features)
        
        # Get predictions from ensemble
        prediction, confidence, probabilities = self._predict_with_confidence(features_scaled)
        
        # Convert to ThreatClass
        try:
            threat_class = ThreatClass(prediction)
        except ValueError:
            threat_class = ThreatClass.BENIGN
        
        # Determine if malicious
        is_malicious = threat_class != ThreatClass.BENIGN
        
        if is_malicious:
            self.threats_detected += 1
        
        return MLPrediction(
            threat_class=threat_class,
            confidence=float(confidence),
            probabilities={
                cls.name: float(prob)
                for cls, prob in probabilities.items()
            },
            features_used=len(features[0]),
            model_version=self.model_version,
            is_malicious=is_malicious
        )
    
    def _predict_ensemble(self, X: np.ndarray) -> np.ndarray:
        """
        Ensemble prediction (voting).
        
        Args:
            X: Feature matrix
            
        Returns:
            Predictions array
        """
        predictions = []
        
        # Random Forest prediction
        rf_pred = self.random_forest.predict(X)
        predictions.append(rf_pred)
        
        # Gradient Boosting prediction
        gb_pred = self.gradient_boosting.predict(X)
        predictions.append(gb_pred)
        
        # XGBoost prediction
        if self.xgboost:
            xgb_pred = self.xgboost.predict(X)
            predictions.append(xgb_pred)
        
        # Majority voting
        predictions = np.array(predictions)
        ensemble_pred = []
        
        for i in range(X.shape[0]):
            votes = predictions[:, i]
            # Get most common prediction
            unique, counts = np.unique(votes, return_counts=True)
            ensemble_pred.append(unique[np.argmax(counts)])
        
        return np.array(ensemble_pred)
    
    def _predict_with_confidence(self, X: np.ndarray) -> Tuple[int, float, Dict]:
        """
        Predict with confidence scores.
        
        Returns:
            Tuple of (prediction, confidence, class_probabilities)
        """
        # Get probabilities from each model
        rf_proba = self.random_forest.predict_proba(X)[0]
        gb_proba = self.gradient_boosting.predict_proba(X)[0]
        
        if self.xgboost:
            xgb_proba = self.xgboost.predict_proba(X)[0]
            avg_proba = (rf_proba + gb_proba + xgb_proba) / 3
        else:
            avg_proba = (rf_proba + gb_proba) / 2
        
        # Get prediction and confidence
        prediction = np.argmax(avg_proba)
        confidence = avg_proba[prediction]
        
        # Build probability dict
        probabilities = {}
        for i, prob in enumerate(avg_proba):
            try:
                threat_class = ThreatClass(i)
                probabilities[threat_class] = prob
            except ValueError:
                pass
        
        return prediction, confidence, probabilities
    
    # ========================================================================
    # MODEL PERSISTENCE
    # ========================================================================
    
    def _save_models(self):
        """Save trained models to disk"""
        try:
            models = {
                'random_forest': self.random_forest,
                'gradient_boosting': self.gradient_boosting,
                'xgboost': self.xgboost,
                'scaler': self.scaler,
                'version': self.model_version,
                'metrics': self.metrics
            }
            
            model_file = self.model_dir / 'models.pkl'
            
            with open(model_file, 'wb') as f:
                pickle.dump(models, f)
            
            self.logger.info(f"Models saved to {model_file}")
            
        except Exception as e:
            self.logger.error(f"Error saving models: {e}")
    
    def _load_models(self):
        """Load models from disk"""
        try:
            model_file = self.model_dir / 'models.pkl'
            
            if model_file.exists():
                with open(model_file, 'rb') as f:
                    models = pickle.load(f)
                
                self.random_forest = models['random_forest']
                self.gradient_boosting = models['gradient_boosting']
                self.xgboost = models.get('xgboost')
                self.scaler = models['scaler']
                self.model_version = models.get('version', '1.0.0')
                self.metrics = models.get('metrics', ModelMetrics())
                
                self.models_trained = True
                
                self.logger.info(f"Models loaded from {model_file}")
                self.logger.info(f"Model version: {self.model_version}")
            
        except Exception as e:
            self.logger.debug(f"No models to load: {e}")
    
    # ========================================================================
    # STATISTICS
    # ========================================================================
    
    def get_statistics(self) -> Dict:
        """Get engine statistics"""
        detection_rate = (self.threats_detected / self.predictions_made * 100) if self.predictions_made > 0 else 0
        
        return {
            'models_trained': self.models_trained,
            'model_version': self.model_version,
            'predictions_made': self.predictions_made,
            'threats_detected': self.threats_detected,
            'detection_rate': f"{detection_rate:.1f}%",
            'accuracy': f"{self.metrics.accuracy:.3f}",
            'precision': f"{self.metrics.precision:.3f}",
            'recall': f"{self.metrics.recall:.3f}",
            'f1_score': f"{self.metrics.f1_score:.3f}",
            'samples_trained': self.metrics.samples_trained,
            'last_trained': self.metrics.last_trained.isoformat() if self.metrics.last_trained else None
        }


# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================

def create_engine() -> MLEngine:
    """Create ML engine"""
    return MLEngine()


# ============================================================================
# TESTING & DEMO
# ============================================================================

if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    print("🤖 CyberGuardian ML Engine - Demo\n")
    
    # Create engine
    engine = create_engine()
    
    # Generate synthetic training data
    print("Generating synthetic training data...")
    np.random.seed(42)
    
    # Benign samples
    X_benign = np.random.randn(100, 15) * 0.5 + np.array([
        1000, 5.0, 50, 10, 3, 0, 1, 5, 50, 2, 10, 2, 0, 1, 0
    ])
    y_benign = np.zeros(100, dtype=int)
    
    # Malware samples
    X_malware = np.random.randn(100, 15) * 0.5 + np.array([
        5000, 7.5, 20, 30, 5, 1, 0, 80, 200, 20, 50, 10, 2, 2, 3
    ])
    y_malware = np.ones(100, dtype=int)
    
    # Combine
    X = np.vstack([X_benign, X_malware])
    y = np.hstack([y_benign, y_malware])
    
    # Train models
    print("\nTraining models...")
    engine.train(X, y)
    
    # Test prediction
    print("\nTesting prediction on benign sample...")
    benign_context = {
        'file_size': 1000,
        'entropy': 5.0,
        'string_count': 50,
        'import_count': 10,
        'section_count': 3,
        'packed': False,
        'signed': True,
        'cpu_usage': 5.0,
        'memory_usage': 50.0,
        'network_connections': 2,
        'file_operations': 10,
        'registry_operations': 2,
        'process_injections': 0,
        'privilege_level': 1,
        'persistence_indicators': 0
    }
    
    prediction = engine.predict(benign_context)
    print(f"   Threat Class: {prediction.threat_class.name}")
    print(f"   Confidence: {prediction.confidence:.3f}")
    print(f"   Malicious: {prediction.is_malicious}")
    
    print("\nTesting prediction on malicious sample...")
    malware_context = {
        'file_size': 5000,
        'entropy': 7.5,
        'string_count': 20,
        'import_count': 30,
        'section_count': 5,
        'packed': True,
        'signed': False,
        'cpu_usage': 80.0,
        'memory_usage': 200.0,
        'network_connections': 20,
        'file_operations': 50,
        'registry_operations': 10,
        'process_injections': 2,
        'privilege_level': 2,
        'persistence_indicators': 3
    }
    
    prediction = engine.predict(malware_context)
    print(f"   Threat Class: {prediction.threat_class.name}")
    print(f"   Confidence: {prediction.confidence:.3f}")
    print(f"   Malicious: {prediction.is_malicious}")
    
    # Statistics
    print("\n" + "="*50)
    stats = engine.get_statistics()
    print("Statistics:")
    for key, value in stats.items():
        print(f"  {key}: {value}")
    
    print("\n✅ ML engine ready!")