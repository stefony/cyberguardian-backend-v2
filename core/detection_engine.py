"""
CyberGuardian AI - Multi-Engine Detection System
Combines ML, YARA, and Heuristic analysis for comprehensive threat detection
"""

import logging
from typing import Dict, List, Optional
from dataclasses import dataclass
from datetime import datetime
import os

# Import detection engines
try:
    from core.yara_engine import YaraEngine
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    logging.warning("YARA engine not available")

try:
    from core.heuristics import HeuristicEngine
    HEURISTIC_AVAILABLE = True
except ImportError:
    HEURISTIC_AVAILABLE = False
    logging.warning("Heuristic engine not available")

try:
    from core.ml_engine import MLEngine
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    logging.warning("ML engine not available")

logger = logging.getLogger(__name__)

@dataclass
class DetectionResult:
    """Unified detection result from all engines"""
    file_path: str
    file_size: int
    
    # Overall verdict
    is_malware: bool
    confidence_score: float  # 0.0 - 1.0
    threat_level: str  # 'safe', 'suspicious', 'dangerous', 'critical'
    
    # Engine results
    yara_detected: bool
    yara_matches: List[str]
    yara_score: float
    
    heuristic_detected: bool
    heuristic_indicators: List[str]
    heuristic_score: float
    
    ml_detected: bool
    ml_prediction: Optional[str]
    ml_confidence: float
    
    # Combined analysis
    detection_methods: List[str]
    threat_indicators: List[str]
    recommendation: str
    
    timestamp: str

class MultiEngineDetector:
    """
    Multi-Engine Detection System
    
    Combines multiple detection methods:
    1. YARA Signatures (rule-based)
    2. Heuristic Analysis (behavioral)
    3. ML Prediction (AI-based)
    
    Uses weighted voting to determine final verdict:
    - YARA: 40% weight (high confidence in known threats)
    - Heuristics: 35% weight (good for unknown threats)
    - ML: 25% weight (additional validation)
    
    Features:
    - Graceful degradation (works even if one engine fails)
    - Confidence scoring
    - Multi-level threat classification
    - Detailed reporting
    """
    
    # Engine weights (must sum to 1.0)
    YARA_WEIGHT = 0.40
    HEURISTIC_WEIGHT = 0.35
    ML_WEIGHT = 0.25
    
    # Threat level thresholds
    THRESHOLD_CRITICAL = 0.90
    THRESHOLD_DANGEROUS = 0.70
    THRESHOLD_SUSPICIOUS = 0.40
    
    def __init__(self):
        """Initialize multi-engine detector"""
        self.yara_engine = None
        self.heuristic_engine = None
        self.ml_engine = None
        
        self.engines_loaded = []
        self.total_detections = 0
        self.threats_found = 0
        
        # Initialize engines
        self._initialize_engines()
        
        logger.info(f"Multi-Engine Detector initialized with {len(self.engines_loaded)} engines")
    
    def _initialize_engines(self):
        """Initialize all available detection engines"""
        # YARA
        if YARA_AVAILABLE:
            try:
                self.yara_engine = YaraEngine()
                if self.yara_engine.load_rules():
                    self.engines_loaded.append('YARA')
                    logger.info("✅ YARA engine loaded")
            except Exception as e:
                logger.error(f"Failed to load YARA engine: {e}")
        
        # Heuristics
        if HEURISTIC_AVAILABLE:
            try:
                self.heuristic_engine = HeuristicEngine()
                self.engines_loaded.append('Heuristic')
                logger.info("✅ Heuristic engine loaded")
            except Exception as e:
                logger.error(f"Failed to load Heuristic engine: {e}")
        
        # ML (optional for now)
        if ML_AVAILABLE:
            try:
                self.ml_engine = MLEngine()
                self.engines_loaded.append('ML')
                logger.info("✅ ML engine loaded")
            except Exception as e:
                logger.warning(f"ML engine not loaded: {e}")
    
    def scan_file(self, file_path: str) -> DetectionResult:
        """
        Perform multi-engine scan on file
        
        Args:
            file_path: Path to file to scan
            
        Returns:
            DetectionResult with combined analysis
        """
        self.total_detections += 1
        
        if not os.path.exists(file_path):
            return self._create_error_result(file_path, "File not found")
        
        file_size = os.path.getsize(file_path)
        
        # Run all engines
        yara_result = self._run_yara(file_path)
        heuristic_result = self._run_heuristic(file_path)
        ml_result = self._run_ml(file_path)
        
        # Calculate weighted confidence score
        confidence_score = self._calculate_confidence(
            yara_result, heuristic_result, ml_result
        )
        
        # Determine threat level
        threat_level = self._determine_threat_level(confidence_score)
        
        # Collect all indicators
        threat_indicators = []
        detection_methods = []
        
        if yara_result['detected']:
            detection_methods.append('YARA Signatures')
            threat_indicators.extend([f"YARA: {m}" for m in yara_result['matches'][:3]])
        
        if heuristic_result['detected']:
            detection_methods.append('Heuristic Analysis')
            threat_indicators.extend([f"Heuristic: {i}" for i in heuristic_result['indicators'][:3]])
        
        if ml_result['detected']:
            detection_methods.append('ML Prediction')
            threat_indicators.append(f"ML: {ml_result['prediction']}")
        
        # Final verdict
        is_malware = confidence_score >= self.THRESHOLD_SUSPICIOUS
        
        if is_malware:
            self.threats_found += 1
        
        # Generate recommendation
        recommendation = self._generate_recommendation(
            threat_level, detection_methods
        )
        
        return DetectionResult(
            file_path=file_path,
            file_size=file_size,
            is_malware=is_malware,
            confidence_score=confidence_score,
            threat_level=threat_level,
            yara_detected=yara_result['detected'],
            yara_matches=yara_result['matches'],
            yara_score=yara_result['score'],
            heuristic_detected=heuristic_result['detected'],
            heuristic_indicators=heuristic_result['indicators'],
            heuristic_score=heuristic_result['score'],
            ml_detected=ml_result['detected'],
            ml_prediction=ml_result['prediction'],
            ml_confidence=ml_result['confidence'],
            detection_methods=detection_methods,
            threat_indicators=threat_indicators,
            recommendation=recommendation,
            timestamp=datetime.now().isoformat()
        )
    
    def _run_yara(self, file_path: str) -> Dict:
        """Run YARA scan"""
        if not self.yara_engine:
            return {'detected': False, 'matches': [], 'score': 0.0}
        
        try:
            matches = self.yara_engine.scan_file(file_path)
            
            if matches:
                # Calculate score based on severity
                max_severity = 0
                match_names = []
                
                for match in matches:
                    match_names.append(match.rule_name)
                    severity = match.meta.get('severity', 'unknown')
                    
                    if severity == 'critical':
                        max_severity = max(max_severity, 100)
                    elif severity == 'high':
                        max_severity = max(max_severity, 80)
                    elif severity == 'medium':
                        max_severity = max(max_severity, 60)
                    elif severity == 'low':
                        max_severity = max(max_severity, 40)
                
                score = max_severity / 100.0
                
                return {
                    'detected': True,
                    'matches': match_names,
                    'score': score
                }
            
            return {'detected': False, 'matches': [], 'score': 0.0}
        
        except Exception as e:
            logger.error(f"YARA scan failed: {e}")
            return {'detected': False, 'matches': [], 'score': 0.0}
    
    def _run_heuristic(self, file_path: str) -> Dict:
        """Run heuristic analysis"""
        if not self.heuristic_engine:
            return {'detected': False, 'indicators': [], 'score': 0.0}
        
        try:
            result = self.heuristic_engine.analyze_file(file_path)
            
            # Convert threat_score (0-100) to normalized score (0-1)
            score = result.threat_score / 100.0
            detected = result.threat_level in ['suspicious', 'dangerous']
            
            return {
                'detected': detected,
                'indicators': result.indicators,
                'score': score
            }
        
        except Exception as e:
            logger.error(f"Heuristic analysis failed: {e}")
            return {'detected': False, 'indicators': [], 'score': 0.0}
    
    def _run_ml(self, file_path: str) -> Dict:
        """Run ML prediction"""
        if not self.ml_engine:
            return {'detected': False, 'prediction': None, 'confidence': 0.0}
        
        try:
            # ML prediction (simplified - would need proper implementation)
            # For now, return neutral result
            return {'detected': False, 'prediction': None, 'confidence': 0.0}
        
        except Exception as e:
            logger.error(f"ML prediction failed: {e}")
            return {'detected': False, 'prediction': None, 'confidence': 0.0}
    
    def _calculate_confidence(self, yara_result: Dict, heuristic_result: Dict, ml_result: Dict) -> float:
        """
        Calculate weighted confidence score
        
        Returns:
            Confidence score (0.0 - 1.0)
        """
        # Weighted average
        confidence = (
            yara_result['score'] * self.YARA_WEIGHT +
            heuristic_result['score'] * self.HEURISTIC_WEIGHT +
            ml_result['confidence'] * self.ML_WEIGHT
        )
        
        # Boost confidence if multiple engines agree
        engines_detected = sum([
            yara_result['detected'],
            heuristic_result['detected'],
            ml_result['detected']
        ])
        
        if engines_detected >= 2:
            confidence = min(confidence * 1.2, 1.0)  # 20% boost, cap at 1.0
        
        return confidence
    
    def _determine_threat_level(self, confidence: float) -> str:
        """Determine threat level from confidence score"""
        if confidence >= self.THRESHOLD_CRITICAL:
            return 'critical'
        elif confidence >= self.THRESHOLD_DANGEROUS:
            return 'dangerous'
        elif confidence >= self.THRESHOLD_SUSPICIOUS:
            return 'suspicious'
        else:
            return 'safe'
    
    def _generate_recommendation(self, threat_level: str, detection_methods: List[str]) -> str:
        """Generate action recommendation"""
        if threat_level == 'critical':
            return "🚨 CRITICAL THREAT - Quarantine immediately and perform system scan"
        elif threat_level == 'dangerous':
            return "⛔ DANGEROUS - Quarantine file and investigate source"
        elif threat_level == 'suspicious':
            return "⚠️ SUSPICIOUS - Review file manually before execution"
        else:
            return "✅ File appears safe"
    
    def _create_error_result(self, file_path: str, error: str) -> DetectionResult:
        """Create error result"""
        return DetectionResult(
            file_path=file_path,
            file_size=0,
            is_malware=False,
            confidence_score=0.0,
            threat_level='safe',
            yara_detected=False,
            yara_matches=[],
            yara_score=0.0,
            heuristic_detected=False,
            heuristic_indicators=[f"Error: {error}"],
            heuristic_score=0.0,
            ml_detected=False,
            ml_prediction=None,
            ml_confidence=0.0,
            detection_methods=[],
            threat_indicators=[f"Error: {error}"],
            recommendation="Unable to scan file",
            timestamp=datetime.now().isoformat()
        )
    
    def get_statistics(self) -> Dict:
        """Get detector statistics"""
        return {
            "engines_loaded": self.engines_loaded,
            "engines_count": len(self.engines_loaded),
            "total_detections": self.total_detections,
            "threats_found": self.threats_found,
            "detection_rate": f"{(self.threats_found / self.total_detections * 100):.1f}%" if self.total_detections > 0 else "0%"
        }


# Example usage
if __name__ == "__main__":
    import sys
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    if len(sys.argv) < 2:
        print("Usage: python detection_engine.py <file_path>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    
    print("🔍 CyberGuardian Multi-Engine Detection")
    print("=" * 60)
    
    detector = MultiEngineDetector()
    result = detector.scan_file(file_path)
    
    print(f"\n📁 File: {result.file_path}")
    print(f"📊 Size: {result.file_size:,} bytes")
    print(f"\n🎯 Confidence: {result.confidence_score:.1%}")
    print(f"⚠️  Threat Level: {result.threat_level.upper()}")
    print(f"🚨 Malware: {'YES' if result.is_malware else 'NO'}")
    
    print(f"\n🔍 Detection Methods ({len(result.detection_methods)}):")
    for method in result.detection_methods:
        print(f"  ✓ {method}")
    
    if result.threat_indicators:
        print(f"\n⚠️ Threat Indicators ({len(result.threat_indicators)}):")
        for indicator in result.threat_indicators[:5]:
            print(f"  - {indicator}")
    
    print(f"\n💡 Recommendation:")
    print(f"  {result.recommendation}")
    
    stats = detector.get_statistics()
    print(f"\n📊 Statistics:")
    print(f"  Engines loaded: {', '.join(stats['engines_loaded'])}")
    print(f"  Total scans: {stats['total_detections']}")
    print(f"  Threats found: {stats['threats_found']}")