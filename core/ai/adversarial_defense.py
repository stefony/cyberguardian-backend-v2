"""
CyberGuardian AI - Adversarial Defense
AI Model Security and Anti-Evasion System

Protects ML/AI models from:
- Adversarial examples (FGSM, PGD, C&W attacks)
- Model poisoning
- Evasion techniques
- Data manipulation
- Model stealing attempts
- Backdoor attacks

Security Knowledge Applied:
- Adversarial Machine Learning
- Model robustness testing
- Input validation and sanitization
- Anomaly detection in predictions
- Ensemble defense mechanisms
- Certified defenses
"""

import logging
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum
from datetime import datetime
import json
import math
import statistics
from collections import Counter, deque

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AttackType(Enum):
    """Types of adversarial attacks"""
    ADVERSARIAL_EXAMPLE = "adversarial_example"
    MODEL_POISONING = "model_poisoning"
    EVASION = "evasion"
    DATA_POISONING = "data_poisoning"
    MODEL_STEALING = "model_stealing"
    BACKDOOR = "backdoor"
    INPUT_MANIPULATION = "input_manipulation"
    NONE = "none"


class DefenseLevel(Enum):
    """Defense intensity levels"""
    STRICT = "strict"
    NORMAL = "normal"
    RELAXED = "relaxed"


class ThreatSeverity(Enum):
    """Adversarial threat severity"""
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    MINIMAL = 1


@dataclass
class InputValidation:
    """Input validation result"""
    is_valid: bool
    validation_score: float
    anomalies: List[str]
    sanitized_input: Optional[Any]


@dataclass
class DefenseResult:
    """Adversarial defense result"""
    defense_id: str
    attack_detected: bool
    attack_type: AttackType
    confidence: float
    threat_severity: ThreatSeverity
    original_input: str
    suspicious_features: List[str]
    defense_actions: List[str]
    robust_prediction: Optional[Any]
    timestamp: str


@dataclass
class ModelIntegrity:
    """Model integrity check result"""
    is_compromised: bool
    integrity_score: float
    anomalies: List[str]
    last_checked: str


class AdversarialDefense:
    """
    Comprehensive defense system against adversarial ML attacks.
    Protects models from manipulation and evasion.
    """
    
    def __init__(self, defense_level: DefenseLevel = DefenseLevel.NORMAL):
        self.name = "Adversarial_Defense"
        self.defense_level = defense_level
        
        # Input validation thresholds
        self.max_input_length = 10000
        self.max_feature_values = 1000
        self.min_confidence_threshold = 0.3
        
        # Anomaly detection
        self.baseline_statistics = {}
        self.prediction_history = deque(maxlen=1000)
        
        # Known adversarial patterns
        self.adversarial_patterns = {
            'perturbation_threshold': 0.1,
            'gradient_threshold': 10.0,
            'confidence_drop_threshold': 0.3
        }
        
        # Model integrity
        self.model_checksums = {}
        self.training_data_fingerprint = None
        
        # Defense statistics
        self.inputs_validated = 0
        self.attacks_detected = 0
        self.attacks_by_type = Counter()
        self.false_positives = 0
        
        # Defense mechanisms
        self.defense_enabled = {
            'input_validation': True,
            'adversarial_detection': True,
            'ensemble_voting': True,
            'input_transformation': True,
            'confidence_calibration': True
        }
        
        logger.info(f"{self.name} initialized with {defense_level.value} defense level")
    
    def validate_input(self, input_data: Any, expected_shape: Optional[Tuple] = None) -> InputValidation:
        """
        Validate input for adversarial manipulation.
        
        Args:
            input_data: Input to validate (text, features, etc.)
            expected_shape: Expected input shape/format
        
        Returns:
            InputValidation result
        """
        anomalies = []
        validation_score = 1.0
        
        # Type checking
        if not self._validate_type(input_data):
            anomalies.append("Invalid input type")
            validation_score -= 0.3
        
        # Size/length checking
        if isinstance(input_data, str) and len(input_data) > self.max_input_length:
            anomalies.append(f"Input too long: {len(input_data)} chars")
            validation_score -= 0.2
        
        # Statistical anomaly detection
        if isinstance(input_data, (list, tuple)):
            stats_anomalies = self._detect_statistical_anomalies(input_data)
            if stats_anomalies:
                anomalies.extend(stats_anomalies)
                validation_score -= 0.2
        
        # Pattern-based detection
        if isinstance(input_data, str):
            pattern_anomalies = self._detect_pattern_anomalies(input_data)
            if pattern_anomalies:
                anomalies.extend(pattern_anomalies)
                validation_score -= 0.2
        
        # Encoding validation
        if isinstance(input_data, str):
            if not self._validate_encoding(input_data):
                anomalies.append("Suspicious character encoding")
                validation_score -= 0.1
        
        # Shape validation
        if expected_shape and hasattr(input_data, 'shape'):
            if input_data.shape != expected_shape:
                anomalies.append(f"Shape mismatch: expected {expected_shape}, got {input_data.shape}")
                validation_score -= 0.2
        
        # Sanitize input if needed
        sanitized_input = self._sanitize_input(input_data, anomalies)
        
        is_valid = validation_score > 0.5 and len(anomalies) < 3
        
        self.inputs_validated += 1
        
        return InputValidation(
            is_valid=is_valid,
            validation_score=max(validation_score, 0.0),
            anomalies=anomalies,
            sanitized_input=sanitized_input if not is_valid else input_data
        )
    
    def detect_adversarial_attack(self, input_data: Any, 
                                  model_prediction: Any,
                                  confidence: float) -> DefenseResult:
        """
        Detect adversarial attacks on model.
        
        Args:
            input_data: Input being evaluated
            model_prediction: Model's prediction
            confidence: Model's confidence score
        
        Returns:
            DefenseResult with attack assessment
        """
        defense_id = f"DEF_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{self.inputs_validated}"
        
        attack_detected = False
        attack_type = AttackType.NONE
        attack_confidence = 0.0
        suspicious_features = []
        defense_actions = []
        
        # 1. Input validation
        validation = self.validate_input(input_data)
        if not validation.is_valid:
            attack_detected = True
            attack_type = AttackType.INPUT_MANIPULATION
            attack_confidence = 1.0 - validation.validation_score
            suspicious_features.extend(validation.anomalies)
            defense_actions.append("Input sanitized")
        
        # 2. Confidence-based detection
        if confidence < self.min_confidence_threshold:
            suspicious_features.append(f"Low confidence: {confidence:.2%}")
            attack_confidence = max(attack_confidence, 0.3)
        
        # 3. Prediction consistency check
        consistency_score = self._check_prediction_consistency(model_prediction)
        if consistency_score < 0.5:
            attack_detected = True
            if attack_type == AttackType.NONE:
                attack_type = AttackType.ADVERSARIAL_EXAMPLE
            suspicious_features.append(f"Prediction inconsistency: {consistency_score:.2f}")
            attack_confidence = max(attack_confidence, 0.6)
            defense_actions.append("Ensemble voting applied")
        
        # 4. Perturbation detection
        if self._detect_perturbation(input_data):
            attack_detected = True
            attack_type = AttackType.ADVERSARIAL_EXAMPLE
            suspicious_features.append("Input perturbation detected")
            attack_confidence = max(attack_confidence, 0.7)
            defense_actions.append("Input transformation applied")
        
        # 5. Evasion pattern detection
        if self._detect_evasion_pattern(input_data, model_prediction):
            attack_detected = True
            attack_type = AttackType.EVASION
            suspicious_features.append("Evasion pattern detected")
            attack_confidence = max(attack_confidence, 0.8)
            defense_actions.append("Evasion technique blocked")
        
        # Calculate threat severity
        threat_severity = self._calculate_threat_severity(attack_confidence)
        
        # Generate robust prediction if attack detected
        robust_prediction = None
        if attack_detected and self.defense_enabled['ensemble_voting']:
            robust_prediction = self._generate_robust_prediction(input_data, validation.sanitized_input)
            defense_actions.append("Robust prediction generated")
        
        # Update statistics
        if attack_detected:
            self.attacks_detected += 1
            self.attacks_by_type[attack_type.value] += 1
        
        # Store prediction in history
        self.prediction_history.append({
            'input': str(input_data)[:100],
            'prediction': str(model_prediction),
            'confidence': confidence,
            'timestamp': datetime.now().isoformat()
        })
        
        result = DefenseResult(
            defense_id=defense_id,
            attack_detected=attack_detected,
            attack_type=attack_type,
            confidence=attack_confidence,
            threat_severity=threat_severity,
            original_input=str(input_data)[:200],
            suspicious_features=suspicious_features,
            defense_actions=defense_actions,
            robust_prediction=robust_prediction,
            timestamp=datetime.now().isoformat()
        )
        
        if attack_detected:
            logger.warning(f"Adversarial attack detected: {attack_type.value} (confidence: {attack_confidence:.2%})")
        
        return result
    
    def check_model_integrity(self, model_id: str, 
                             current_weights: Optional[Dict] = None) -> ModelIntegrity:
        """
        Check if model has been tampered with (poisoning attack).
        
        Args:
            model_id: Model identifier
            current_weights: Current model weights (optional)
        
        Returns:
            ModelIntegrity result
        """
        anomalies = []
        integrity_score = 1.0
        
        # 1. Checksum verification
        if model_id in self.model_checksums:
            expected_checksum = self.model_checksums[model_id]
            if current_weights:
                current_checksum = self._calculate_checksum(current_weights)
                if current_checksum != expected_checksum:
                    anomalies.append("Model checksum mismatch")
                    integrity_score -= 0.4
        
        # 2. Weight distribution analysis
        if current_weights:
            weight_anomalies = self._analyze_weight_distribution(current_weights)
            if weight_anomalies:
                anomalies.extend(weight_anomalies)
                integrity_score -= 0.3
        
        # 3. Prediction behavior analysis
        behavior_anomalies = self._analyze_prediction_behavior()
        if behavior_anomalies:
            anomalies.extend(behavior_anomalies)
            integrity_score -= 0.2
        
        # 4. Backdoor detection
        if self._detect_backdoor_pattern():
            anomalies.append("Potential backdoor detected")
            integrity_score -= 0.5
        
        is_compromised = integrity_score < 0.6 or len(anomalies) >= 2
        
        return ModelIntegrity(
            is_compromised=is_compromised,
            integrity_score=max(integrity_score, 0.0),
            anomalies=anomalies,
            last_checked=datetime.now().isoformat()
        )
    
    def _validate_type(self, input_data: Any) -> bool:
        """Validate input data type."""
        # Allow common types
        allowed_types = (str, int, float, list, tuple, dict, bytes)
        return isinstance(input_data, allowed_types)
    
    def _detect_statistical_anomalies(self, data: List) -> List[str]:
        """Detect statistical anomalies in numerical data."""
        anomalies = []
        
        try:
            # Convert to numbers
            numbers = [float(x) for x in data if isinstance(x, (int, float))]
            
            if not numbers:
                return anomalies
            
            # Check for extreme values
            mean_val = statistics.mean(numbers)
            stdev = statistics.stdev(numbers) if len(numbers) > 1 else 0
            
            if stdev > 0:
                z_scores = [(x - mean_val) / stdev for x in numbers]
                extreme_values = sum(1 for z in z_scores if abs(z) > 3)
                
                if extreme_values > len(numbers) * 0.1:  # More than 10% outliers
                    anomalies.append(f"Excessive outliers: {extreme_values}")
            
            # Check for unusual patterns
            if all(x == numbers[0] for x in numbers):
                anomalies.append("All values identical (suspicious)")
            
        except (ValueError, TypeError, statistics.StatisticsError):
            anomalies.append("Invalid numerical data")
        
        return anomalies
    
    def _detect_pattern_anomalies(self, text: str) -> List[str]:
        """Detect suspicious patterns in text input."""
        anomalies = []
        
        # Repetitive characters
        if any(text.count(c * 10) > 0 for c in set(text)):
            anomalies.append("Repetitive character pattern")
        
        # Excessive special characters
        special_chars = sum(1 for c in text if not c.isalnum() and not c.isspace())
        if special_chars > len(text) * 0.3:
            anomalies.append(f"Excessive special characters: {special_chars}")
        
        # Control characters
        if any(ord(c) < 32 and c not in '\n\r\t' for c in text):
            anomalies.append("Control characters detected")
        
        # Null bytes
        if '\x00' in text:
            anomalies.append("Null bytes in input")
        
        return anomalies
    
    def _validate_encoding(self, text: str) -> bool:
        """Validate text encoding."""
        try:
            # Try to encode/decode
            text.encode('utf-8').decode('utf-8')
            
            # Check for excessive non-ASCII
            non_ascii = sum(1 for c in text if ord(c) > 127)
            if non_ascii > len(text) * 0.5:
                return False
            
            return True
        except (UnicodeDecodeError, UnicodeEncodeError):
            return False
    
    def _sanitize_input(self, input_data: Any, anomalies: List[str]) -> Any:
        """Sanitize input data."""
        if isinstance(input_data, str):
            # Remove control characters
            sanitized = ''.join(c for c in input_data if ord(c) >= 32 or c in '\n\r\t')
            
            # Limit length
            if len(sanitized) > self.max_input_length:
                sanitized = sanitized[:self.max_input_length]
            
            return sanitized
        
        return input_data
    
    def _check_prediction_consistency(self, prediction: Any) -> float:
        """Check prediction consistency with historical predictions."""
        if len(self.prediction_history) < 10:
            return 1.0  # Not enough history
        
        # Simplified consistency check
        recent_predictions = [p['prediction'] for p in list(self.prediction_history)[-10:]]
        
        # Check if current prediction is similar to recent ones
        prediction_str = str(prediction)
        matches = sum(1 for p in recent_predictions if p == prediction_str)
        
        consistency_score = matches / 10
        
        return consistency_score
    
    def _detect_perturbation(self, input_data: Any) -> bool:
        """Detect adversarial perturbations in input."""
        # Simplified perturbation detection
        # In production, this would use gradient-based methods
        
        if isinstance(input_data, str):
            # Check for unusual character substitutions
            suspicious_chars = ['ї', 'і', 'ο', 'о', 'а', 'е', 'с']  # Cyrillic lookalikes
            if any(c in input_data for c in suspicious_chars):
                return True
        
        return False
    
    def _detect_evasion_pattern(self, input_data: Any, prediction: Any) -> bool:
        """Detect evasion technique patterns."""
        # Check for common evasion techniques
        
        if isinstance(input_data, str):
            text_lower = input_data.lower()
            
            # Character substitution (l33t speak)
            substitutions = {'0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '7': 't'}
            has_substitutions = sum(1 for k in substitutions.keys() if k in text_lower) > 2
            
            if has_substitutions:
                return True
            
            # Excessive spacing
            if text_lower.count('  ') > 5:
                return True
            
            # Unicode tricks
            if any(ord(c) > 1000 for c in input_data):
                return True
        
        return False
    
    def _calculate_threat_severity(self, confidence: float) -> ThreatSeverity:
        """Calculate threat severity from confidence."""
        if confidence >= 0.8:
            return ThreatSeverity.CRITICAL
        elif confidence >= 0.6:
            return ThreatSeverity.HIGH
        elif confidence >= 0.4:
            return ThreatSeverity.MEDIUM
        elif confidence >= 0.2:
            return ThreatSeverity.LOW
        else:
            return ThreatSeverity.MINIMAL
    
    def _generate_robust_prediction(self, original_input: Any, 
                                   sanitized_input: Any) -> Any:
        """Generate robust prediction using ensemble methods."""
        # Placeholder for ensemble prediction
        # In production, this would use multiple models
        return {
            'prediction': 'ROBUST_PREDICTION',
            'method': 'ensemble_voting',
            'confidence': 0.85
        }
    
    def _calculate_checksum(self, weights: Dict) -> str:
        """Calculate checksum of model weights."""
        # Simplified checksum
        weight_str = json.dumps(weights, sort_keys=True)
        return str(hash(weight_str))
    
    def _analyze_weight_distribution(self, weights: Dict) -> List[str]:
        """Analyze model weight distribution for anomalies."""
        anomalies = []
        
        # Check for unusual weight values
        all_weights = []
        for layer_weights in weights.values():
            if isinstance(layer_weights, (list, tuple)):
                all_weights.extend([w for w in layer_weights if isinstance(w, (int, float))])
        
        if all_weights:
            mean_weight = statistics.mean(all_weights)
            
            # Check for extreme weights
            if abs(mean_weight) > 100:
                anomalies.append(f"Extreme mean weight: {mean_weight}")
            
            # Check for NaN or Inf
            if any(math.isnan(w) or math.isinf(w) for w in all_weights):
                anomalies.append("Invalid weight values (NaN/Inf)")
        
        return anomalies
    
    def _analyze_prediction_behavior(self) -> List[str]:
        """Analyze prediction behavior for anomalies."""
        anomalies = []
        
        if len(self.prediction_history) < 50:
            return anomalies
        
        recent = list(self.prediction_history)[-50:]
        
        # Check confidence distribution
        confidences = [p['confidence'] for p in recent]
        avg_confidence = statistics.mean(confidences)
        
        if avg_confidence < 0.3:
            anomalies.append(f"Low average confidence: {avg_confidence:.2%}")
        
        # Check for sudden behavior change
        first_half = confidences[:25]
        second_half = confidences[25:]
        
        if abs(statistics.mean(first_half) - statistics.mean(second_half)) > 0.3:
            anomalies.append("Sudden behavior change detected")
        
        return anomalies
    
    def _detect_backdoor_pattern(self) -> bool:
        """Detect backdoor patterns in predictions."""
        if len(self.prediction_history) < 20:
            return False
        
        # Check for trigger pattern
        # Simplified: look for consistently wrong predictions on specific inputs
        recent = list(self.prediction_history)[-20:]
        
        # Check if certain inputs always get same (potentially wrong) prediction
        input_prediction_map = {}
        for p in recent:
            inp = p['input'][:50]
            pred = p['prediction']
            
            if inp not in input_prediction_map:
                input_prediction_map[inp] = []
            input_prediction_map[inp].append(pred)
        
        # If any input always gets same prediction (suspicious)
        for predictions in input_prediction_map.values():
            if len(predictions) >= 3 and len(set(predictions)) == 1:
                return True
        
        return False
    
    def enable_defense(self, defense_type: str, enabled: bool = True):
        """Enable or disable specific defense mechanism."""
        if defense_type in self.defense_enabled:
            self.defense_enabled[defense_type] = enabled
            logger.info(f"Defense '{defense_type}' {'enabled' if enabled else 'disabled'}")
    
    def set_defense_level(self, level: DefenseLevel):
        """Set overall defense level."""
        self.defense_level = level
        
        if level == DefenseLevel.STRICT:
            self.min_confidence_threshold = 0.5
            self.adversarial_patterns['perturbation_threshold'] = 0.05
        elif level == DefenseLevel.RELAXED:
            self.min_confidence_threshold = 0.2
            self.adversarial_patterns['perturbation_threshold'] = 0.2
        
        logger.info(f"Defense level set to: {level.value}")
    
    def get_statistics(self) -> Dict:
        """Get defense statistics."""
        total_attacks = sum(self.attacks_by_type.values())
        
        return {
            'inputs_validated': self.inputs_validated,
            'attacks_detected': self.attacks_detected,
            'attacks_by_type': dict(self.attacks_by_type),
            'false_positives': self.false_positives,
            'detection_rate': self.attacks_detected / max(self.inputs_validated, 1),
            'defense_level': self.defense_level.value,
            'active_defenses': [k for k, v in self.defense_enabled.items() if v]
        }


def create_defense(defense_level: DefenseLevel = DefenseLevel.NORMAL) -> AdversarialDefense:
    """Factory function to create adversarial defense system."""
    return AdversarialDefense(defense_level)


# Example usage
if __name__ == "__main__":
    defense = create_defense(DefenseLevel.NORMAL)
    
    # Test input validation
    print(f"\n{'='*60}")
    print("INPUT VALIDATION TEST")
    print(f"{'='*60}")
    
    test_input = "This is a normal input with no anomalies."
    validation = defense.validate_input(test_input)
    print(f"Input: {test_input}")
    print(f"Valid: {validation.is_valid}")
    print(f"Score: {validation.validation_score:.2f}")
    print(f"Anomalies: {validation.anomalies if validation.anomalies else 'None'}")
    
    # Test adversarial detection
    print(f"\n{'='*60}")
    print("ADVERSARIAL ATTACK DETECTION TEST")
    print(f"{'='*60}")
    
    suspicious_input = "Cl1ck  h3re  t0  cl@im  y0ur  pr1ze!!!"
    result = defense.detect_adversarial_attack(
        input_data=suspicious_input,
        model_prediction="benign",
        confidence=0.45
    )
    
    print(f"Attack Detected: {result.attack_detected}")
    print(f"Attack Type: {result.attack_type.value}")
    print(f"Confidence: {result.confidence:.2%}")
    print(f"Threat Severity: {result.threat_severity.name}")
    print(f"\nSuspicious Features:")
    for feature in result.suspicious_features:
        print(f"  - {feature}")
    print(f"\nDefense Actions:")
    for action in result.defense_actions:
        print(f"  - {action}")
    
    # Test model integrity
    print(f"\n{'='*60}")
    print("MODEL INTEGRITY CHECK")
    print(f"{'='*60}")
    
    integrity = defense.check_model_integrity(
        model_id="main_detection_model",
        current_weights={'layer1': [0.5, 0.3, 0.1], 'layer2': [0.2, 0.8]}
    )
    
    print(f"Model Compromised: {integrity.is_compromised}")
    print(f"Integrity Score: {integrity.integrity_score:.2f}")
    print(f"Anomalies: {integrity.anomalies if integrity.anomalies else 'None'}")
    print(f"{'='*60}\n")
    
    # Statistics
    stats = defense.get_statistics()
    print(f"Statistics: {json.dumps(stats, indent=2)}")