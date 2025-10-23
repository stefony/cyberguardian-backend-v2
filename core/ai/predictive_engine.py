"""
CyberGuardian AI - Predictive Engine
Attack Prediction and Risk Forecasting System

Predicts future threats based on:
- Historical attack patterns
- Threat actor behavior
- Vulnerability trends
- Time series analysis
- Kill chain progression
- Risk probability modeling

Security Knowledge Applied:
- Cyber Kill Chain
- Attack lifecycle prediction
- Threat intelligence correlation
- Behavioral forecasting
- Risk assessment methodologies
- Early warning systems
"""

import logging
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, asdict
from enum import Enum
from datetime import datetime, timedelta
from collections import deque, Counter
import json
import math
import statistics

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AttackPhase(Enum):
    """Cyber Kill Chain phases"""
    RECONNAISSANCE = "reconnaissance"
    WEAPONIZATION = "weaponization"
    DELIVERY = "delivery"
    EXPLOITATION = "exploitation"
    INSTALLATION = "installation"
    COMMAND_CONTROL = "command_and_control"
    ACTIONS = "actions_on_objectives"


class ThreatLevel(Enum):
    """Predicted threat levels"""
    CRITICAL = 5
    HIGH = 4
    ELEVATED = 3
    MODERATE = 2
    LOW = 1
    MINIMAL = 0


class PredictionType(Enum):
    """Types of predictions"""
    ATTACK_IMMINENT = "attack_imminent"
    VULNERABILITY_EXPLOITATION = "vulnerability_exploitation"
    DATA_EXFILTRATION = "data_exfiltration"
    RANSOMWARE = "ransomware"
    APT_CAMPAIGN = "apt_campaign"
    INSIDER_THREAT = "insider_threat"
    DDOS = "ddos_attack"


@dataclass
class ThreatEvent:
    """Historical threat event"""
    timestamp: str
    event_type: str
    severity: int
    source_ip: Optional[str]
    target: Optional[str]
    mitre_technique: Optional[str]
    success: bool


@dataclass
class PredictionResult:
    """Prediction result"""
    prediction_id: str
    prediction_type: PredictionType
    probability: float  # 0.0 - 1.0
    threat_level: ThreatLevel
    estimated_time: str  # When attack likely to occur
    confidence: float
    indicators: List[str]
    kill_chain_phase: AttackPhase
    recommendations: List[str]
    risk_score: int  # 0-100
    timestamp: str


@dataclass
class RiskForecast:
    """Risk forecast for time period"""
    forecast_id: str
    period_start: str
    period_end: str
    overall_risk: int  # 0-100
    threat_breakdown: Dict[str, float]
    peak_risk_times: List[str]
    vulnerable_assets: List[str]
    recommended_actions: List[str]


class PredictiveEngine:
    """
    Advanced predictive engine for cyber threat forecasting.
    Predicts attacks before they happen using pattern analysis.
    """
    
    def __init__(self, history_window: int = 1000):
        self.name = "Predictive_Engine"
        self.history_window = history_window
        
        # Historical data
        self.event_history = deque(maxlen=history_window)
        self.attack_patterns = {}
        self.threat_trends = Counter()
        
        # Kill chain state tracking
        self.active_kill_chains = {}  # IP -> current phase
        
        # Risk baseline
        self.baseline_risk = 20  # Normal risk level
        
        # Prediction thresholds
        self.imminent_threshold = 0.7
        self.elevated_threshold = 0.5
        self.moderate_threshold = 0.3
        
        # Statistics
        self.predictions_made = 0
        self.predictions_correct = 0
        self.false_positives = 0
        
        # Attack phase progression probabilities
        self.phase_progression = {
            AttackPhase.RECONNAISSANCE: {
                AttackPhase.WEAPONIZATION: 0.3,
                AttackPhase.DELIVERY: 0.1
            },
            AttackPhase.WEAPONIZATION: {
                AttackPhase.DELIVERY: 0.6
            },
            AttackPhase.DELIVERY: {
                AttackPhase.EXPLOITATION: 0.7
            },
            AttackPhase.EXPLOITATION: {
                AttackPhase.INSTALLATION: 0.5,
                AttackPhase.COMMAND_CONTROL: 0.3
            },
            AttackPhase.INSTALLATION: {
                AttackPhase.COMMAND_CONTROL: 0.8
            },
            AttackPhase.COMMAND_CONTROL: {
                AttackPhase.ACTIONS: 0.9
            }
        }
        
        logger.info(f"{self.name} initialized with {history_window} event history")
    
    def add_event(self, event: ThreatEvent):
        """Add historical threat event for pattern learning."""
        self.event_history.append(event)
        self.threat_trends[event.event_type] += 1
        
        # Update kill chain tracking
        if event.source_ip:
            phase = self._identify_kill_chain_phase(event)
            self.active_kill_chains[event.source_ip] = phase
        
        # Learn patterns
        self._update_patterns(event)
    
    def predict_attack(self, current_indicators: Dict) -> PredictionResult:
        """
        Predict imminent attack based on current indicators.
        
        Args:
            current_indicators: Current threat indicators
                {
                    'suspicious_ips': [...],
                    'failed_logins': int,
                    'port_scans': int,
                    'malware_detected': bool,
                    'unusual_traffic': bool,
                    'privilege_escalation': bool
                }
        
        Returns:
            PredictionResult with attack prediction
        """
        prediction_id = f"PRED_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{self.predictions_made}"
        
        # Analyze current state
        kill_chain_phase = self._analyze_kill_chain_progress(current_indicators)
        
        # Calculate attack probability
        probability = self._calculate_attack_probability(current_indicators, kill_chain_phase)
        
        # Determine prediction type
        prediction_type = self._determine_prediction_type(current_indicators)
        
        # Calculate threat level
        threat_level = self._calculate_threat_level(probability)
        
        # Estimate time to attack
        estimated_time = self._estimate_attack_time(kill_chain_phase, probability)
        
        # Calculate confidence
        confidence = self._calculate_confidence(len(self.event_history))
        
        # Generate indicators
        indicators = self._generate_prediction_indicators(current_indicators, kill_chain_phase)
        
        # Generate recommendations
        recommendations = self._generate_prediction_recommendations(
            prediction_type, threat_level, kill_chain_phase
        )
        
        # Calculate risk score
        risk_score = int(probability * 100)
        
        self.predictions_made += 1
        
        result = PredictionResult(
            prediction_id=prediction_id,
            prediction_type=prediction_type,
            probability=probability,
            threat_level=threat_level,
            estimated_time=estimated_time,
            confidence=confidence,
            indicators=indicators,
            kill_chain_phase=kill_chain_phase,
            recommendations=recommendations,
            risk_score=risk_score,
            timestamp=datetime.now().isoformat()
        )
        
        logger.info(f"Prediction: {prediction_type.value} (probability: {probability:.2%})")
        return result
    
    def forecast_risk(self, forecast_days: int = 7) -> RiskForecast:
        """
        Generate risk forecast for upcoming time period.
        
        Args:
            forecast_days: Number of days to forecast
        
        Returns:
            RiskForecast for the period
        """
        forecast_id = f"FCST_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        period_start = datetime.now().isoformat()
        period_end = (datetime.now() + timedelta(days=forecast_days)).isoformat()
        
        # Analyze historical trends
        trend_analysis = self._analyze_trends()
        
        # Calculate overall risk
        overall_risk = self._calculate_overall_risk(trend_analysis)
        
        # Break down by threat type
        threat_breakdown = self._forecast_threat_breakdown(trend_analysis)
        
        # Identify peak risk times
        peak_risk_times = self._identify_peak_risk_times(forecast_days)
        
        # Identify vulnerable assets
        vulnerable_assets = self._identify_vulnerable_assets()
        
        # Generate recommendations
        recommended_actions = self._generate_forecast_recommendations(
            overall_risk, threat_breakdown
        )
        
        return RiskForecast(
            forecast_id=forecast_id,
            period_start=period_start,
            period_end=period_end,
            overall_risk=overall_risk,
            threat_breakdown=threat_breakdown,
            peak_risk_times=peak_risk_times,
            vulnerable_assets=vulnerable_assets,
            recommended_actions=recommended_actions
        )
    
    def _identify_kill_chain_phase(self, event: ThreatEvent) -> AttackPhase:
        """Identify which kill chain phase an event belongs to."""
        event_type_lower = event.event_type.lower()
        
        # Reconnaissance indicators
        if any(x in event_type_lower for x in ['scan', 'probe', 'enumeration', 'discovery']):
            return AttackPhase.RECONNAISSANCE
        
        # Delivery indicators
        if any(x in event_type_lower for x in ['phishing', 'email', 'attachment', 'download']):
            return AttackPhase.DELIVERY
        
        # Exploitation indicators
        if any(x in event_type_lower for x in ['exploit', 'vulnerability', 'overflow', 'injection']):
            return AttackPhase.EXPLOITATION
        
        # Installation indicators
        if any(x in event_type_lower for x in ['malware', 'backdoor', 'trojan', 'dropper']):
            return AttackPhase.INSTALLATION
        
        # C2 indicators
        if any(x in event_type_lower for x in ['c2', 'beacon', 'callback', 'command']):
            return AttackPhase.COMMAND_CONTROL
        
        # Actions on objectives
        if any(x in event_type_lower for x in ['exfiltration', 'ransomware', 'encryption', 'destruction']):
            return AttackPhase.ACTIONS
        
        return AttackPhase.RECONNAISSANCE  # Default
    
    def _analyze_kill_chain_progress(self, indicators: Dict) -> AttackPhase:
        """Analyze current kill chain progress."""
        # Check indicators for each phase
        if indicators.get('port_scans', 0) > 0:
            return AttackPhase.RECONNAISSANCE
        
        if indicators.get('malware_detected', False):
            return AttackPhase.INSTALLATION
        
        if indicators.get('privilege_escalation', False):
            return AttackPhase.EXPLOITATION
        
        if indicators.get('unusual_traffic', False):
            return AttackPhase.COMMAND_CONTROL
        
        return AttackPhase.RECONNAISSANCE
    
    def _calculate_attack_probability(self, indicators: Dict, 
                                     phase: AttackPhase) -> float:
        """Calculate probability of imminent attack."""
        probability = 0.0
        
        # Base probability from kill chain phase
        phase_weights = {
            AttackPhase.RECONNAISSANCE: 0.1,
            AttackPhase.WEAPONIZATION: 0.2,
            AttackPhase.DELIVERY: 0.4,
            AttackPhase.EXPLOITATION: 0.6,
            AttackPhase.INSTALLATION: 0.8,
            AttackPhase.COMMAND_CONTROL: 0.9,
            AttackPhase.ACTIONS: 1.0
        }
        probability += phase_weights.get(phase, 0.1) * 0.4
        
        # Indicator-based probability (60% weight)
        indicator_score = 0.0
        
        if indicators.get('failed_logins', 0) > 10:
            indicator_score += 0.15
        
        if indicators.get('port_scans', 0) > 5:
            indicator_score += 0.1
        
        if indicators.get('malware_detected', False):
            indicator_score += 0.2
        
        if indicators.get('unusual_traffic', False):
            indicator_score += 0.15
        
        if indicators.get('privilege_escalation', False):
            indicator_score += 0.25
        
        suspicious_ips = len(indicators.get('suspicious_ips', []))
        if suspicious_ips > 0:
            indicator_score += min(suspicious_ips * 0.05, 0.15)
        
        probability += min(indicator_score, 0.6)
        
        # Historical pattern matching (add small boost)
        if self._matches_known_pattern(indicators):
            probability += 0.1
        
        return min(probability, 1.0)
    
    def _determine_prediction_type(self, indicators: Dict) -> PredictionType:
        """Determine the type of predicted attack."""
        # Check for ransomware indicators
        if indicators.get('rapid_encryption', False):
            return PredictionType.RANSOMWARE
        
        # Check for data exfiltration
        if indicators.get('unusual_traffic', False) and indicators.get('large_transfers', False):
            return PredictionType.DATA_EXFILTRATION
        
        # Check for APT campaign
        if len(indicators.get('suspicious_ips', [])) > 3 and indicators.get('persistence', False):
            return PredictionType.APT_CAMPAIGN
        
        # Check for DDoS
        if indicators.get('traffic_spike', False):
            return PredictionType.DDOS
        
        # Check for insider threat
        if indicators.get('unusual_access_patterns', False) and indicators.get('internal_source', False):
            return PredictionType.INSIDER_THREAT
        
        # Default to general attack
        return PredictionType.ATTACK_IMMINENT
    
    def _calculate_threat_level(self, probability: float) -> ThreatLevel:
        """Calculate threat level from probability."""
        if probability >= 0.8:
            return ThreatLevel.CRITICAL
        elif probability >= 0.6:
            return ThreatLevel.HIGH
        elif probability >= 0.4:
            return ThreatLevel.ELEVATED
        elif probability >= 0.2:
            return ThreatLevel.MODERATE
        elif probability >= 0.1:
            return ThreatLevel.LOW
        else:
            return ThreatLevel.MINIMAL
    
    def _estimate_attack_time(self, phase: AttackPhase, probability: float) -> str:
        """Estimate when attack is likely to occur."""
        # Base time estimates by phase
        phase_times = {
            AttackPhase.RECONNAISSANCE: 72,  # hours
            AttackPhase.WEAPONIZATION: 48,
            AttackPhase.DELIVERY: 24,
            AttackPhase.EXPLOITATION: 12,
            AttackPhase.INSTALLATION: 6,
            AttackPhase.COMMAND_CONTROL: 2,
            AttackPhase.ACTIONS: 1
        }
        
        base_hours = phase_times.get(phase, 48)
        
        # Adjust by probability
        adjusted_hours = base_hours * (1 - probability * 0.5)
        
        estimated_time = datetime.now() + timedelta(hours=adjusted_hours)
        
        if adjusted_hours < 1:
            return "Imminent (within minutes)"
        elif adjusted_hours < 24:
            return f"Within {int(adjusted_hours)} hours"
        else:
            days = int(adjusted_hours / 24)
            return f"Within {days} day{'s' if days > 1 else ''}"
    
    def _calculate_confidence(self, history_size: int) -> float:
        """Calculate confidence based on available data."""
        # More historical data = higher confidence
        if history_size > 500:
            return 0.9
        elif history_size > 200:
            return 0.75
        elif history_size > 50:
            return 0.6
        else:
            return 0.4
    
    def _matches_known_pattern(self, indicators: Dict) -> bool:
        """Check if indicators match known attack patterns."""
        # Simplified pattern matching
        # In production, this would use ML models
        pattern_signature = json.dumps(sorted(indicators.keys()))
        return pattern_signature in self.attack_patterns
    
    def _update_patterns(self, event: ThreatEvent):
        """Update known attack patterns."""
        pattern_key = f"{event.event_type}_{event.severity}"
        if pattern_key not in self.attack_patterns:
            self.attack_patterns[pattern_key] = {'count': 0, 'success_rate': 0}
        
        self.attack_patterns[pattern_key]['count'] += 1
        if event.success:
            self.attack_patterns[pattern_key]['success_rate'] += 0.1
    
    def _analyze_trends(self) -> Dict:
        """Analyze historical trends."""
        if not self.event_history:
            return {'trend': 'stable', 'velocity': 0}
        
        # Calculate event frequency over time
        recent_events = [e for e in self.event_history 
                        if (datetime.now() - datetime.fromisoformat(e.timestamp)).days < 7]
        
        events_per_day = len(recent_events) / 7
        
        # Determine trend
        if events_per_day > 10:
            trend = 'increasing'
        elif events_per_day < 2:
            trend = 'decreasing'
        else:
            trend = 'stable'
        
        return {
            'trend': trend,
            'velocity': events_per_day,
            'severity_avg': statistics.mean([e.severity for e in recent_events]) if recent_events else 0
        }
    
    def _calculate_overall_risk(self, trend_analysis: Dict) -> int:
        """Calculate overall risk score (0-100)."""
        base_risk = self.baseline_risk
        
        # Adjust for trend
        if trend_analysis['trend'] == 'increasing':
            base_risk += 20
        elif trend_analysis['trend'] == 'decreasing':
            base_risk -= 10
        
        # Adjust for velocity
        velocity_factor = min(trend_analysis['velocity'] * 2, 30)
        base_risk += velocity_factor
        
        # Adjust for severity
        severity_factor = trend_analysis.get('severity_avg', 0) * 5
        base_risk += severity_factor
        
        return min(max(int(base_risk), 0), 100)
    
    def _forecast_threat_breakdown(self, trend_analysis: Dict) -> Dict[str, float]:
        """Forecast threat breakdown by type."""
        breakdown = {}
        
        total = sum(self.threat_trends.values())
        if total == 0:
            return {'unknown': 1.0}
        
        for threat_type, count in self.threat_trends.most_common(5):
            breakdown[threat_type] = count / total
        
        return breakdown
    
    def _identify_peak_risk_times(self, forecast_days: int) -> List[str]:
        """Identify peak risk times in forecast period."""
        # Analyze historical patterns for time-of-day trends
        # Simplified: common attack times
        peak_times = []
        
        for day in range(forecast_days):
            date = datetime.now() + timedelta(days=day)
            # Peak times: late night (02:00-04:00) and business hours (09:00-11:00)
            peak_times.append(f"{date.strftime('%Y-%m-%d')} 02:00-04:00 (Late night)")
            peak_times.append(f"{date.strftime('%Y-%m-%d')} 09:00-11:00 (Business hours)")
        
        return peak_times[:5]  # Return top 5
    
    def _identify_vulnerable_assets(self) -> List[str]:
        """Identify potentially vulnerable assets."""
        # Based on attack patterns
        vulnerable = []
        
        if 'web_application' in self.threat_trends:
            vulnerable.append("Web applications")
        
        if 'database' in self.threat_trends:
            vulnerable.append("Database servers")
        
        if 'email' in self.threat_trends:
            vulnerable.append("Email infrastructure")
        
        if 'endpoint' in self.threat_trends:
            vulnerable.append("User endpoints")
        
        return vulnerable if vulnerable else ["General infrastructure"]
    
    def _generate_prediction_indicators(self, indicators: Dict, 
                                       phase: AttackPhase) -> List[str]:
        """Generate list of prediction indicators."""
        result = []
        
        result.append(f"Kill chain phase: {phase.value}")
        
        if indicators.get('failed_logins', 0) > 0:
            result.append(f"Failed login attempts: {indicators['failed_logins']}")
        
        if indicators.get('port_scans', 0) > 0:
            result.append(f"Port scans detected: {indicators['port_scans']}")
        
        if indicators.get('malware_detected'):
            result.append("Malware installation detected")
        
        if indicators.get('unusual_traffic'):
            result.append("Unusual network traffic pattern")
        
        if indicators.get('privilege_escalation'):
            result.append("Privilege escalation attempts")
        
        suspicious_ips = len(indicators.get('suspicious_ips', []))
        if suspicious_ips > 0:
            result.append(f"Suspicious IPs: {suspicious_ips}")
        
        return result
    
    def _generate_prediction_recommendations(self, prediction_type: PredictionType,
                                            threat_level: ThreatLevel,
                                            phase: AttackPhase) -> List[str]:
        """Generate actionable recommendations."""
        recommendations = []
        
        if threat_level in [ThreatLevel.CRITICAL, ThreatLevel.HIGH]:
            recommendations.append("⚠️ IMMEDIATE ACTION REQUIRED")
            recommendations.append("Activate incident response team")
            recommendations.append("Increase monitoring and alerting")
        
        if prediction_type == PredictionType.RANSOMWARE:
            recommendations.extend([
                "Verify backup integrity and availability",
                "Restrict network segmentation",
                "Monitor for file encryption activity",
                "Prepare recovery procedures"
            ])
        
        elif prediction_type == PredictionType.DATA_EXFILTRATION:
            recommendations.extend([
                "Monitor outbound data transfers",
                "Review DLP policies",
                "Inspect network traffic for anomalies",
                "Lock down sensitive data access"
            ])
        
        elif prediction_type == PredictionType.APT_CAMPAIGN:
            recommendations.extend([
                "Conduct threat hunting",
                "Review all access logs",
                "Check for persistence mechanisms",
                "Coordinate with threat intelligence"
            ])
        
        # Phase-specific recommendations
        if phase in [AttackPhase.RECONNAISSANCE, AttackPhase.DELIVERY]:
            recommendations.append("Block identified suspicious IPs")
            recommendations.append("Strengthen perimeter defenses")
        
        elif phase in [AttackPhase.EXPLOITATION, AttackPhase.INSTALLATION]:
            recommendations.append("Isolate affected systems")
            recommendations.append("Deploy additional EDR coverage")
        
        elif phase in [AttackPhase.COMMAND_CONTROL, AttackPhase.ACTIONS]:
            recommendations.append("Consider network isolation")
            recommendations.append("Engage forensics team")
        
        return recommendations
    
    def _generate_forecast_recommendations(self, overall_risk: int,
                                          threat_breakdown: Dict) -> List[str]:
        """Generate recommendations for risk forecast."""
        recommendations = []
        
        if overall_risk > 70:
            recommendations.append("🔴 HIGH RISK PERIOD - Maximum vigilance required")
            recommendations.append("Increase security team staffing")
            recommendations.append("Conduct security drills")
        elif overall_risk > 50:
            recommendations.append("🟡 ELEVATED RISK - Enhanced monitoring recommended")
        
        # Threat-specific recommendations
        top_threat = max(threat_breakdown, key=threat_breakdown.get) if threat_breakdown else None
        
        if top_threat:
            recommendations.append(f"Primary threat focus: {top_threat}")
            recommendations.append(f"Review defenses against {top_threat} attacks")
        
        recommendations.extend([
            "Update all security signatures",
            "Verify backup and recovery procedures",
            "Review access controls and permissions",
            "Conduct vulnerability assessments"
        ])
        
        return recommendations
    
    def get_statistics(self) -> Dict:
        """Get prediction engine statistics."""
        accuracy = self.predictions_correct / max(self.predictions_made, 1)
        
        return {
            'predictions_made': self.predictions_made,
            'predictions_correct': self.predictions_correct,
            'false_positives': self.false_positives,
            'accuracy': accuracy,
            'events_tracked': len(self.event_history),
            'active_kill_chains': len(self.active_kill_chains),
            'known_patterns': len(self.attack_patterns)
        }


def create_engine(history_window: int = 1000) -> PredictiveEngine:
    """Factory function to create predictive engine."""
    return PredictiveEngine(history_window)


# Example usage
if __name__ == "__main__":
    engine = create_engine()
    
    # Simulate some historical events
    for i in range(10):
        event = ThreatEvent(
            timestamp=datetime.now().isoformat(),
            event_type='port_scan',
            severity=2,
            source_ip=f"192.168.1.{i}",
            target="internal_network",
            mitre_technique="T1046",
            success=True
        )
        engine.add_event(event)
    
    # Predict attack
    current_indicators = {
        'suspicious_ips': ['192.168.1.100', '10.0.0.50'],
        'failed_logins': 15,
        'port_scans': 8,
        'malware_detected': True,
        'unusual_traffic': True,
        'privilege_escalation': False
    }
    
    prediction = engine.predict_attack(current_indicators)
    
    print(f"\n{'='*60}")
    print(f"ATTACK PREDICTION")
    print(f"{'='*60}")
    print(f"Type: {prediction.prediction_type.value}")
    print(f"Probability: {prediction.probability:.2%}")
    print(f"Threat Level: {prediction.threat_level.name}")
    print(f"Estimated Time: {prediction.estimated_time}")
    print(f"Risk Score: {prediction.risk_score}/100")
    print(f"Confidence: {prediction.confidence:.2%}")
    print(f"\nKill Chain Phase: {prediction.kill_chain_phase.value}")
    print(f"\nIndicators:")
    for indicator in prediction.indicators:
        print(f"  - {indicator}")
    print(f"\nRecommendations:")
    for rec in prediction.recommendations:
        print(f"  - {rec}")
    print(f"{'='*60}\n")
    
    # Generate risk forecast
    forecast = engine.forecast_risk(forecast_days=7)
    
    print(f"\n{'='*60}")
    print(f"7-DAY RISK FORECAST")
    print(f"{'='*60}")
    print(f"Overall Risk: {forecast.overall_risk}/100")
    print(f"\nThreat Breakdown:")
    for threat, prob in forecast.threat_breakdown.items():
        print(f"  - {threat}: {prob:.1%}")
    print(f"\nPeak Risk Times:")
    for time in forecast.peak_risk_times[:3]:
        print(f"  - {time}")
    print(f"{'='*60}\n")
    
    # Statistics
    stats = engine.get_statistics()
    print(f"Statistics: {json.dumps(stats, indent=2)}")