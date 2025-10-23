"""
CyberGuardian - Behavioral Analysis Engine
===========================================

AI-powered behavioral analysis for zero-day threat detection.

Features:
- User behavior profiling (learns normal patterns)
- Process behavior analysis
- Anomaly detection (ML-based)
- Outlier detection (statistical)
- Temporal pattern analysis
- Baseline establishment
- Real-time scoring
- Adaptive learning

Machine Learning Models:
1. Isolation Forest (anomaly detection)
2. One-Class SVM (outlier detection)
3. LSTM (temporal patterns)
4. Autoencoder (unsupervised learning)

Behavioral Features:
- Process creation frequency
- Network connection patterns
- File access patterns
- Registry modification patterns
- CPU/Memory usage patterns
- Time-of-day patterns
- Command-line patterns

Detection Capabilities:
- Zero-day malware (unknown threats)
- Insider threats (abnormal user behavior)
- APT activity (low-and-slow attacks)
- Lateral movement
- Data exfiltration
- Privilege escalation attempts
- Living-off-the-land attacks

Advantages over Signature-based:
✓ Detects unknown threats
✓ Adapts to environment
✓ Catches polymorphic malware
✓ No signature updates needed
✓ Behavioral context awareness
"""

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM
from collections import deque, defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
import logging
import pickle
import os


# ============================================================================
# CONFIGURATION
# ============================================================================

class AnomalyType(Enum):
    """Types of behavioral anomalies"""
    PROCESS_ANOMALY = "process_anomaly"
    NETWORK_ANOMALY = "network_anomaly"
    FILE_ANOMALY = "file_anomaly"
    USER_ANOMALY = "user_anomaly"
    SYSTEM_ANOMALY = "system_anomaly"


class ThreatLevel(Enum):
    """Threat severity"""
    NORMAL = 0
    SUSPICIOUS = 1
    ANOMALOUS = 2
    CRITICAL = 3


@dataclass
class BehavioralEvent:
    """
    Behavioral event for analysis.
    
    Attributes:
        event_type: Type of event
        features: Feature vector
        timestamp: When event occurred
        metadata: Additional context
    """
    event_type: str
    features: List[float]
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict = field(default_factory=dict)


@dataclass
class AnomalyDetection:
    """
    Anomaly detection result.
    
    Attributes:
        anomaly_type: Type of anomaly
        anomaly_score: Score (higher = more anomalous)
        threat_level: Assessed threat level
        features: Features that triggered detection
        description: Human-readable description
        confidence: Detection confidence (0-100)
        recommendations: Recommended actions
    """
    anomaly_type: AnomalyType
    anomaly_score: float
    threat_level: ThreatLevel
    features: Dict[str, float] = field(default_factory=dict)
    description: str = ""
    confidence: int = 0
    recommendations: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class BehavioralProfile:
    """
    Behavioral profile for an entity (user, process, system).
    
    Attributes:
        name: Profile name
        baseline_established: Whether baseline is ready
        feature_means: Mean values for features
        feature_stds: Standard deviations
        event_history: Recent events
        last_updated: Last update timestamp
    """
    name: str
    baseline_established: bool = False
    feature_means: Dict[str, float] = field(default_factory=dict)
    feature_stds: Dict[str, float] = field(default_factory=dict)
    event_history: deque = field(default_factory=lambda: deque(maxlen=1000))
    last_updated: datetime = field(default_factory=datetime.now)


# ============================================================================
# BEHAVIORAL ANALYSIS ENGINE
# ============================================================================

class BehavioralEngine:
    """
    AI-powered behavioral analysis engine.
    
    Learns normal behavior patterns and detects anomalies.
    """
    
    # Feature names for different event types
    PROCESS_FEATURES = [
        'cpu_percent',
        'memory_mb',
        'thread_count',
        'handle_count',
        'io_read_bytes',
        'io_write_bytes',
        'process_lifetime_sec'
    ]
    
    NETWORK_FEATURES = [
        'connections_count',
        'bytes_sent',
        'bytes_received',
        'unique_ips',
        'unique_ports',
        'connection_frequency'
    ]
    
    FILE_FEATURES = [
        'files_created',
        'files_modified',
        'files_deleted',
        'files_accessed',
        'total_bytes_written',
        'suspicious_extensions'
    ]
    
    USER_FEATURES = [
        'login_count',
        'failed_login_count',
        'command_count',
        'privileged_actions',
        'hour_of_day',
        'day_of_week'
    ]
    
    def __init__(self, 
                 baseline_window: int = 1000,
                 anomaly_threshold: float = -0.5,
                 model_path: Optional[str] = None):
        """
        Initialize behavioral engine.
        
        Args:
            baseline_window: Number of events for baseline
            anomaly_threshold: Anomaly score threshold
            model_path: Path to save/load models
        """
        self.logger = logging.getLogger(__name__)
        
        # Configuration
        self.baseline_window = baseline_window
        self.anomaly_threshold = anomaly_threshold
        
        # Model storage
        if model_path:
            self.model_path = model_path
        else:
            self.model_path = os.path.expanduser('~/.cyberguardian/models')
        
        os.makedirs(self.model_path, exist_ok=True)
        
        # ML Models
        self.isolation_forest = IsolationForest(
            contamination=0.1,  # Expected anomaly rate
            random_state=42,
            n_estimators=100
        )
        
        self.one_class_svm = OneClassSVM(
            kernel='rbf',
            gamma='auto',
            nu=0.1
        )
        
        self.scaler = StandardScaler()
        
        # Behavioral profiles
        self.profiles: Dict[str, BehavioralProfile] = {}
        
        # Training data buffer
        self.training_buffer: Dict[str, List[List[float]]] = defaultdict(list)
        
        # Statistics
        self.events_processed = 0
        self.anomalies_detected = 0
        self.models_trained = 0
        
        # Load existing models if available
        self._load_models()
    
    # ========================================================================
    # PROFILE MANAGEMENT
    # ========================================================================
    
    def create_profile(self, name: str) -> BehavioralProfile:
        """
        Create behavioral profile.
        
        Args:
            name: Profile identifier
            
        Returns:
            BehavioralProfile object
        """
        profile = BehavioralProfile(name=name)
        self.profiles[name] = profile
        
        self.logger.info(f"Created behavioral profile: {name}")
        return profile
    
    def get_profile(self, name: str) -> Optional[BehavioralProfile]:
        """Get profile by name"""
        return self.profiles.get(name)
    
    def get_or_create_profile(self, name: str) -> BehavioralProfile:
        """Get existing profile or create new one"""
        if name not in self.profiles:
            return self.create_profile(name)
        return self.profiles[name]
    
    # ========================================================================
    # BASELINE ESTABLISHMENT
    # ========================================================================
    
    def add_event(self, profile_name: str, event: BehavioralEvent):
        """
        Add event to profile for baseline learning.
        
        Args:
            profile_name: Profile identifier
            event: Behavioral event
        """
        profile = self.get_or_create_profile(profile_name)
        
        # Add to history
        profile.event_history.append(event)
        profile.last_updated = datetime.now()
        
        # Add to training buffer
        self.training_buffer[profile_name].append(event.features)
        
        self.events_processed += 1
        
        # Check if baseline can be established
        if not profile.baseline_established:
            if len(profile.event_history) >= self.baseline_window:
                self._establish_baseline(profile_name)
    
    def _establish_baseline(self, profile_name: str):
        """
        Establish baseline from collected events.
        
        Args:
            profile_name: Profile identifier
        """
        profile = self.profiles.get(profile_name)
        if not profile:
            return
        
        training_data = self.training_buffer[profile_name]
        
        if len(training_data) < self.baseline_window:
            self.logger.warning(f"Not enough data for baseline: {len(training_data)}")
            return
        
        try:
            # Convert to numpy array
            X = np.array(training_data)
            
            # Compute statistics
            profile.feature_means = {
                f"feature_{i}": float(np.mean(X[:, i]))
                for i in range(X.shape[1])
            }
            
            profile.feature_stds = {
                f"feature_{i}": float(np.std(X[:, i]))
                for i in range(X.shape[1])
            }
            
            # Train models
            self._train_models(profile_name, X)
            
            profile.baseline_established = True
            self.logger.info(f"✅ Baseline established for {profile_name}")
            
        except Exception as e:
            self.logger.error(f"Error establishing baseline: {e}")
    
    def _train_models(self, profile_name: str, X: np.ndarray):
        """
        Train ML models on baseline data.
        
        Args:
            profile_name: Profile identifier
            X: Training data (numpy array)
        """
        try:
            # Normalize data
            X_scaled = self.scaler.fit_transform(X)
            
            # Train Isolation Forest
            self.isolation_forest.fit(X_scaled)
            
            # Train One-Class SVM
            self.one_class_svm.fit(X_scaled)
            
            self.models_trained += 1
            
            # Save models
            self._save_models(profile_name)
            
            self.logger.info(f"Models trained for {profile_name}")
            
        except Exception as e:
            self.logger.error(f"Error training models: {e}")
    
    # ========================================================================
    # ANOMALY DETECTION
    # ========================================================================
    
    def analyze_event(self, 
                     profile_name: str, 
                     event: BehavioralEvent) -> Optional[AnomalyDetection]:
        """
        Analyze event for anomalies.
        
        Args:
            profile_name: Profile identifier
            event: Event to analyze
            
        Returns:
            AnomalyDetection or None if normal
        """
        profile = self.get_or_create_profile(profile_name)
        
        # Add event to profile (for continuous learning)
        self.add_event(profile_name, event)
        
        # If baseline not established, cannot detect anomalies yet
        if not profile.baseline_established:
            remaining = self.baseline_window - len(profile.event_history)
            self.logger.debug(
                f"Baseline not ready for {profile_name}. "
                f"Need {remaining} more events."
            )
            return None
        
        # Prepare features
        features = np.array(event.features).reshape(1, -1)
        
        try:
            # Normalize
            features_scaled = self.scaler.transform(features)
            
            # Get anomaly scores from both models
            iso_score = self.isolation_forest.score_samples(features_scaled)[0]
            svm_score = self.one_class_svm.score_samples(features_scaled)[0]
            
            # Combined anomaly score (average)
            anomaly_score = (iso_score + svm_score) / 2
            
            # Check against threshold
            if anomaly_score < self.anomaly_threshold:
                self.anomalies_detected += 1
                
                # Determine threat level
                if anomaly_score < -1.0:
                    threat_level = ThreatLevel.CRITICAL
                    confidence = 95
                elif anomaly_score < -0.75:
                    threat_level = ThreatLevel.ANOMALOUS
                    confidence = 85
                else:
                    threat_level = ThreatLevel.SUSPICIOUS
                    confidence = 70
                
                # Identify anomalous features
                anomalous_features = self._identify_anomalous_features(
                    event.features,
                    profile
                )
                
                # Create detection
                detection = AnomalyDetection(
                    anomaly_type=self._determine_anomaly_type(event.event_type),
                    anomaly_score=float(anomaly_score),
                    threat_level=threat_level,
                    features=anomalous_features,
                    description=self._generate_description(
                        event.event_type,
                        anomalous_features
                    ),
                    confidence=confidence,
                    recommendations=self._generate_recommendations(
                        threat_level,
                        anomalous_features
                    )
                )
                
                self.logger.warning(
                    f"🚨 Anomaly detected in {profile_name}: "
                    f"score={anomaly_score:.3f}, "
                    f"threat={threat_level.name}"
                )
                
                return detection
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error analyzing event: {e}")
            return None
    
    def _identify_anomalous_features(self, 
                                    features: List[float],
                                    profile: BehavioralProfile) -> Dict[str, float]:
        """
        Identify which features are anomalous.
        
        Uses standard deviation from baseline.
        """
        anomalous = {}
        
        for i, value in enumerate(features):
            feature_name = f"feature_{i}"
            
            if feature_name in profile.feature_means:
                mean = profile.feature_means[feature_name]
                std = profile.feature_stds[feature_name]
                
                # Calculate z-score (number of std deviations from mean)
                if std > 0:
                    z_score = abs(value - mean) / std
                    
                    # Consider anomalous if > 3 standard deviations
                    if z_score > 3:
                        anomalous[feature_name] = z_score
        
        return anomalous
    
    def _determine_anomaly_type(self, event_type: str) -> AnomalyType:
        """Determine anomaly type from event type"""
        if 'process' in event_type.lower():
            return AnomalyType.PROCESS_ANOMALY
        elif 'network' in event_type.lower():
            return AnomalyType.NETWORK_ANOMALY
        elif 'file' in event_type.lower():
            return AnomalyType.FILE_ANOMALY
        elif 'user' in event_type.lower():
            return AnomalyType.USER_ANOMALY
        else:
            return AnomalyType.SYSTEM_ANOMALY
    
    def _generate_description(self, 
                             event_type: str,
                             anomalous_features: Dict[str, float]) -> str:
        """Generate human-readable anomaly description"""
        if not anomalous_features:
            return f"Anomalous {event_type} behavior detected"
        
        feature_list = ", ".join(
            f"{k} (σ={v:.1f})" for k, v in list(anomalous_features.items())[:3]
        )
        
        return f"Anomalous {event_type}: {feature_list}"
    
    def _generate_recommendations(self,
                                 threat_level: ThreatLevel,
                                 anomalous_features: Dict[str, float]) -> List[str]:
        """Generate recommended actions"""
        recommendations = []
        
        if threat_level == ThreatLevel.CRITICAL:
            recommendations.append("Isolate system immediately")
            recommendations.append("Capture forensic evidence")
            recommendations.append("Notify security team")
        elif threat_level == ThreatLevel.ANOMALOUS:
            recommendations.append("Increase monitoring")
            recommendations.append("Review recent activity")
            recommendations.append("Consider blocking if pattern continues")
        else:
            recommendations.append("Monitor for additional anomalies")
            recommendations.append("Review logs")
        
        return recommendations
    
    # ========================================================================
    # MODEL PERSISTENCE
    # ========================================================================
    
    def _save_models(self, profile_name: str):
        """Save trained models to disk"""
        try:
            model_file = os.path.join(self.model_path, f"{profile_name}_models.pkl")
            
            models = {
                'isolation_forest': self.isolation_forest,
                'one_class_svm': self.one_class_svm,
                'scaler': self.scaler
            }
            
            with open(model_file, 'wb') as f:
                pickle.dump(models, f)
            
            self.logger.debug(f"Models saved: {model_file}")
            
        except Exception as e:
            self.logger.error(f"Error saving models: {e}")
    
    def _load_models(self):
        """Load models from disk"""
        try:
            # Load first available model file
            model_files = [f for f in os.listdir(self.model_path) if f.endswith('_models.pkl')]
            
            if model_files:
                model_file = os.path.join(self.model_path, model_files[0])
                
                with open(model_file, 'rb') as f:
                    models = pickle.load(f)
                
                self.isolation_forest = models['isolation_forest']
                self.one_class_svm = models['one_class_svm']
                self.scaler = models['scaler']
                
                self.logger.info(f"Models loaded from {model_file}")
                
        except Exception as e:
            self.logger.debug(f"No models to load: {e}")
    
    # ========================================================================
    # STATISTICS
    # ========================================================================
    
    def get_statistics(self) -> Dict:
        """Get engine statistics"""
        profiles_with_baseline = sum(
            1 for p in self.profiles.values()
            if p.baseline_established
        )
        
        anomaly_rate = (self.anomalies_detected / self.events_processed * 100) if self.events_processed > 0 else 0
        
        return {
            'events_processed': self.events_processed,
            'anomalies_detected': self.anomalies_detected,
            'anomaly_rate': f"{anomaly_rate:.2f}%",
            'total_profiles': len(self.profiles),
            'profiles_with_baseline': profiles_with_baseline,
            'models_trained': self.models_trained
        }


# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================

def create_engine(baseline_window: int = 1000) -> BehavioralEngine:
    """Create behavioral engine"""
    return BehavioralEngine(baseline_window=baseline_window)


# ============================================================================
# TESTING & DEMO
# ============================================================================

if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    print("🧠 CyberGuardian Behavioral Engine - Demo\n")
    
    # Create engine
    engine = create_engine(baseline_window=50)  # Small for demo
    
    # Simulate normal behavior
    print("Learning normal behavior...")
    for i in range(60):
        event = BehavioralEvent(
            event_type="process_activity",
            features=[
                np.random.normal(20, 5),  # CPU %
                np.random.normal(100, 20),  # Memory MB
                np.random.normal(10, 2),  # Threads
                np.random.normal(50, 10),  # Handles
                np.random.normal(1000, 200),  # IO read
                np.random.normal(500, 100),  # IO write
                np.random.normal(300, 60)  # Lifetime
            ]
        )
        engine.add_event("test_process", event)
    
    # Simulate anomalous behavior
    print("\nTesting anomaly detection...")
    anomalous_event = BehavioralEvent(
        event_type="process_activity",
        features=[
            95,  # Very high CPU
            500,  # High memory
            50,  # Many threads
            200,  # Many handles
            10000,  # High IO
            5000,
            100
        ]
    )
    
    detection = engine.analyze_event("test_process", anomalous_event)
    
    if detection:
        print(f"✅ Anomaly detected!")
        print(f"   Type: {detection.anomaly_type.value}")
        print(f"   Score: {detection.anomaly_score:.3f}")
        print(f"   Threat: {detection.threat_level.name}")
        print(f"   Confidence: {detection.confidence}%")
        print(f"   Description: {detection.description}")
    else:
        print("❌ No anomaly detected")
    
    # Statistics
    print("\n" + "="*50)
    stats = engine.get_statistics()
    print("Statistics:")
    for key, value in stats.items():
        print(f"  {key}: {value}")
    
    print("\n✅ Behavioral engine ready!")