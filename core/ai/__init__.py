"""
CyberGuardian AI - Advanced AI/ML Module
Next-Generation Security Intelligence

This module provides advanced AI/ML capabilities:
- Deep Learning (CNN, RNN, Transformers)
- NLP Analysis (phishing, deepfake, social engineering)
- Predictive Analytics (attack prediction, risk forecasting)
- Adversarial Defense (model protection, anti-evasion)
- Federated Learning (privacy-preserving collaborative learning)

Usage:
    from core.ai import (
        create_nlp_analyzer,
        create_predictive_engine,
        create_defense,
        create_federated_system
    )
    
    # NLP analysis
    nlp = create_nlp_analyzer()
    result = nlp.analyze(suspicious_text)
    
    # Attack prediction
    predictor = create_predictive_engine()
    prediction = predictor.predict_attack(indicators)
    
    # Adversarial defense
    defense = create_defense()
    defense_result = defense.detect_adversarial_attack(input_data, prediction, confidence)
    
    # Federated learning
    fl = create_federated_system()
    fl.register_client("client_1", data_samples=1000)
"""

import logging
from typing import Dict, List, Optional

# Deep Learning Engine
try:
    from .deep_learning_engine import (
        DeepLearningEngine,
        ModelType,
        TrainingMode,
        create_engine as create_dl_engine
    )
    DEEP_LEARNING_AVAILABLE = True
except ImportError as e:
    logging.warning(f"Deep Learning Engine not available: {e}")
    DEEP_LEARNING_AVAILABLE = False

# NLP Analyzer
try:
    from .nlp_analyzer import (
        NLPAnalyzer,
        ThreatType,
        SentimentType,
        TextFeatures,
        AnalysisResult,
        create_analyzer
    )
    NLP_AVAILABLE = True
except ImportError as e:
    logging.warning(f"NLP Analyzer not available: {e}")
    NLP_AVAILABLE = False

# Predictive Engine
try:
    from .predictive_engine import (
        PredictiveEngine,
        AttackPhase,
        ThreatLevel,
        PredictionType,
        ThreatEvent,
        PredictionResult,
        RiskForecast,
        create_engine as create_predictive_engine
    )
    PREDICTIVE_AVAILABLE = True
except ImportError as e:
    logging.warning(f"Predictive Engine not available: {e}")
    PREDICTIVE_AVAILABLE = False

# Adversarial Defense
try:
    from .adversarial_defense import (
        AdversarialDefense,
        AttackType,
        DefenseLevel,
        ThreatSeverity,
        InputValidation,
        DefenseResult,
        ModelIntegrity,
        create_defense
    )
    ADVERSARIAL_DEFENSE_AVAILABLE = True
except ImportError as e:
    logging.warning(f"Adversarial Defense not available: {e}")
    ADVERSARIAL_DEFENSE_AVAILABLE = False

# Federated Learning
try:
    from .federated_learning import (
        FederatedLearning,
        AggregationMethod,
        ClientStatus,
        PrivacyLevel,
        ClientInfo,
        ModelUpdate,
        AggregationResult,
        FederatedMetrics,
        create_federated_system
    )
    FEDERATED_LEARNING_AVAILABLE = True
except ImportError as e:
    logging.warning(f"Federated Learning not available: {e}")
    FEDERATED_LEARNING_AVAILABLE = False


logger = logging.getLogger(__name__)


# Module-level exports
__all__ = [
    # Factory functions
    'create_nlp_analyzer',
    'create_predictive_engine',
    'create_defense',
    'create_federated_system',
    'initialize_ai_system',
    
    # Classes - NLP
    'NLPAnalyzer',
    'ThreatType',
    'SentimentType',
    'AnalysisResult',
    
    # Classes - Predictive
    'PredictiveEngine',
    'AttackPhase',
    'ThreatLevel',
    'PredictionType',
    'PredictionResult',
    'RiskForecast',
    
    # Classes - Adversarial Defense
    'AdversarialDefense',
    'AttackType',
    'DefenseLevel',
    'DefenseResult',
    'ModelIntegrity',
    
    # Classes - Federated Learning
    'FederatedLearning',
    'AggregationMethod',
    'PrivacyLevel',
    'ClientInfo',
    'ModelUpdate',
    
    # Availability flags
    'NLP_AVAILABLE',
    'PREDICTIVE_AVAILABLE',
    'ADVERSARIAL_DEFENSE_AVAILABLE',
    'FEDERATED_LEARNING_AVAILABLE',
]


def initialize_ai_system(enable_nlp: bool = True,
                        enable_prediction: bool = True,
                        enable_defense: bool = True,
                        enable_federated: bool = False,
                        defense_level: Optional['DefenseLevel'] = None,
                        privacy_level: Optional['PrivacyLevel'] = None) -> Dict:
    """
    Initialize complete AI system with all components.
    
    Args:
        enable_nlp: Enable NLP analyzer
        enable_prediction: Enable predictive engine
        enable_defense: Enable adversarial defense
        enable_federated: Enable federated learning
        defense_level: Defense intensity level
        privacy_level: Privacy protection level
    
    Returns:
        Dictionary with initialized components
    
    Example:
        system = initialize_ai_system(
            enable_nlp=True,
            enable_prediction=True,
            enable_defense=True,
            defense_level=DefenseLevel.NORMAL
        )
        
        nlp = system['nlp']
        predictor = system['predictor']
    """
    components = {}
    
    # NLP Analyzer
    if enable_nlp and NLP_AVAILABLE:
        try:
            components['nlp'] = create_analyzer()
            logger.info("✅ NLP Analyzer initialized")
        except Exception as e:
            logger.error(f"Failed to initialize NLP Analyzer: {e}")
    
    # Predictive Engine
    if enable_prediction and PREDICTIVE_AVAILABLE:
        try:
            components['predictor'] = create_predictive_engine()
            logger.info("✅ Predictive Engine initialized")
        except Exception as e:
            logger.error(f"Failed to initialize Predictive Engine: {e}")
    
    # Adversarial Defense
    if enable_defense and ADVERSARIAL_DEFENSE_AVAILABLE:
        try:
            if defense_level:
                components['defense'] = create_defense(defense_level)
            else:
                components['defense'] = create_defense()
            logger.info("✅ Adversarial Defense initialized")
        except Exception as e:
            logger.error(f"Failed to initialize Adversarial Defense: {e}")
    
    # Federated Learning
    if enable_federated and FEDERATED_LEARNING_AVAILABLE:
        try:
            if privacy_level:
                components['federated'] = create_federated_system(
                    privacy_level=privacy_level
                )
            else:
                components['federated'] = create_federated_system()
            logger.info("✅ Federated Learning initialized")
        except Exception as e:
            logger.error(f"Failed to initialize Federated Learning: {e}")
    
    logger.info(f"AI System initialized with {len(components)} components")
    return components


def analyze_threat_text(text: str, use_defense: bool = True) -> Dict:
    """
    Convenience function for complete text threat analysis.
    
    Args:
        text: Text to analyze
        use_defense: Apply adversarial defense
    
    Returns:
        Complete analysis result
    """
    results = {}
    
    # NLP Analysis
    if NLP_AVAILABLE:
        nlp = create_analyzer()
        nlp_result = nlp.analyze(text)
        results['nlp_analysis'] = {
            'threat_type': nlp_result.threat_type.value,
            'confidence': nlp_result.confidence,
            'risk_score': nlp_result.risk_score,
            'sentiment': nlp_result.sentiment.value,
            'indicators': nlp_result.indicators
        }
    
    # Adversarial Defense Check
    if use_defense and ADVERSARIAL_DEFENSE_AVAILABLE:
        defense = create_defense()
        validation = defense.validate_input(text)
        results['validation'] = {
            'is_valid': validation.is_valid,
            'score': validation.validation_score,
            'anomalies': validation.anomalies
        }
    
    return results


def predict_attack_scenario(indicators: Dict) -> Dict:
    """
    Convenience function for attack prediction.
    
    Args:
        indicators: Current threat indicators
    
    Returns:
        Prediction results
    """
    if not PREDICTIVE_AVAILABLE:
        return {'error': 'Predictive engine not available'}
    
    predictor = create_predictive_engine()
    prediction = predictor.predict_attack(indicators)
    
    return {
        'prediction_type': prediction.prediction_type.value,
        'probability': prediction.probability,
        'threat_level': prediction.threat_level.name,
        'estimated_time': prediction.estimated_time,
        'risk_score': prediction.risk_score,
        'kill_chain_phase': prediction.kill_chain_phase.value,
        'indicators': prediction.indicators,
        'recommendations': prediction.recommendations
    }


def check_model_security(model_id: str, 
                        input_data,
                        prediction,
                        confidence: float) -> Dict:
    """
    Convenience function for complete model security check.
    
    Args:
        model_id: Model identifier
        input_data: Input being evaluated
        prediction: Model prediction
        confidence: Prediction confidence
    
    Returns:
        Security check results
    """
    if not ADVERSARIAL_DEFENSE_AVAILABLE:
        return {'error': 'Adversarial defense not available'}
    
    defense = create_defense()
    
    # Check input
    validation = defense.validate_input(input_data)
    
    # Detect adversarial attacks
    attack_result = defense.detect_adversarial_attack(
        input_data,
        prediction,
        confidence
    )
    
    # Check model integrity
    integrity = defense.check_model_integrity(model_id)
    
    return {
        'input_validation': {
            'is_valid': validation.is_valid,
            'score': validation.validation_score,
            'anomalies': validation.anomalies
        },
        'attack_detection': {
            'attack_detected': attack_result.attack_detected,
            'attack_type': attack_result.attack_type.value,
            'confidence': attack_result.confidence,
            'threat_severity': attack_result.threat_severity.name,
            'suspicious_features': attack_result.suspicious_features
        },
        'model_integrity': {
            'is_compromised': integrity.is_compromised,
            'integrity_score': integrity.integrity_score,
            'anomalies': integrity.anomalies
        }
    }


def get_system_status() -> Dict:
    """Get AI system availability status."""
    return {
        'deep_learning': DEEP_LEARNING_AVAILABLE if 'DEEP_LEARNING_AVAILABLE' in globals() else False,
        'nlp': NLP_AVAILABLE,
        'predictive': PREDICTIVE_AVAILABLE,
        'adversarial_defense': ADVERSARIAL_DEFENSE_AVAILABLE,
        'federated_learning': FEDERATED_LEARNING_AVAILABLE,
        'components_available': sum([
            NLP_AVAILABLE,
            PREDICTIVE_AVAILABLE,
            ADVERSARIAL_DEFENSE_AVAILABLE,
            FEDERATED_LEARNING_AVAILABLE
        ]),
        'total_components': 4
    }


# Module initialization
logger.info("CyberGuardian AI Module loaded")
status = get_system_status()
logger.info(f"Available components: {status['components_available']}/{status['total_components']}")