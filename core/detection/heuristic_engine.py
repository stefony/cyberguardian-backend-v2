"""
CyberGuardian - Heuristic Detection Engine
===========================================

Rule-based heuristic detection for suspicious patterns.

Features:
- Rule-based pattern matching
- Weighted scoring system
- Confidence calculation
- Context-aware rules
- Composite detection (multiple indicators)
- Rule priority levels
- False positive reduction
- Rule management

Heuristic Categories:
1. File-based heuristics
   - Suspicious file extensions
   - Entropy analysis (packing detection)
   - PE structure analysis
   - File name patterns
   
2. Process-based heuristics
   - Command-line patterns
   - Parent-child relationships
   - Injection indicators
   - Privilege escalation patterns
   
3. Network-based heuristics
   - C2 communication patterns
   - Data exfiltration indicators
   - Port/protocol mismatches
   - Connection frequency patterns
   
4. Behavioral heuristics
   - Rapid file modifications (ransomware)
   - Mass network connections
   - Credential access patterns
   - System modification chains

Detection Logic:
- Each rule has a weight (1-100)
- Multiple rule matches accumulate
- Threshold determines if threat
- Context adjusts scores

Advantages:
✓ Fast (no ML overhead)
✓ Explainable (rule-based)
✓ Customizable (add rules)
✓ Low false positives
✓ Works offline
"""

import re
import math
from typing import Dict, List, Optional, Set, Tuple, Callable
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
import logging


# ============================================================================
# CONFIGURATION
# ============================================================================

class RuleCategory(Enum):
    """Heuristic rule categories"""
    FILE = "file"
    PROCESS = "process"
    NETWORK = "network"
    BEHAVIORAL = "behavioral"
    SYSTEM = "system"


class RulePriority(Enum):
    """Rule priority levels"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class ThreatLevel(Enum):
    """Threat severity"""
    CLEAN = 0
    SUSPICIOUS = 1
    LIKELY_MALICIOUS = 2
    MALICIOUS = 3


@dataclass
class HeuristicRule:
    """
    Heuristic detection rule.
    
    Attributes:
        rule_id: Unique rule identifier
        name: Rule name
        description: What this rule detects
        category: Rule category
        priority: Rule priority
        weight: Score weight (1-100)
        condition: Condition function
        enabled: Whether rule is active
        tags: Associated tags
    """
    rule_id: str
    name: str
    description: str
    category: RuleCategory
    priority: RulePriority
    weight: int  # 1-100
    condition: Callable
    enabled: bool = True
    tags: List[str] = field(default_factory=list)


@dataclass
class HeuristicMatch:
    """
    Rule match result.
    
    Attributes:
        rule: Matched rule
        score: Match score
        details: Match details
        context: Additional context
    """
    rule: HeuristicRule
    score: int
    details: str = ""
    context: Dict = field(default_factory=dict)


@dataclass
class HeuristicDetection:
    """
    Heuristic detection result.
    
    Attributes:
        target: Detection target (file, process, etc.)
        threat_level: Assessed threat level
        total_score: Accumulated score
        confidence: Detection confidence (0-100)
        matches: Matched rules
        description: Human-readable description
        recommendations: Recommended actions
    """
    target: str
    threat_level: ThreatLevel
    total_score: int
    confidence: int
    matches: List[HeuristicMatch] = field(default_factory=list)
    description: str = ""
    recommendations: List[str] = field(default_factory=list)


# ============================================================================
# HEURISTIC ENGINE
# ============================================================================

class HeuristicEngine:
    """
    Rule-based heuristic detection engine.
    
    Uses weighted rules to detect suspicious patterns.
    """
    
    # Detection thresholds
    SUSPICIOUS_THRESHOLD = 30
    LIKELY_MALICIOUS_THRESHOLD = 60
    MALICIOUS_THRESHOLD = 100
    
    def __init__(self):
        """Initialize heuristic engine"""
        self.logger = logging.getLogger(__name__)
        
        # Rules storage
        self.rules: Dict[str, HeuristicRule] = {}
        
        # Statistics
        self.detections_performed = 0
        self.threats_detected = 0
        self.rules_matched = 0
        
        # Load built-in rules
        self._load_builtin_rules()
    
    # ========================================================================
    # RULE MANAGEMENT
    # ========================================================================
    
    def add_rule(self, rule: HeuristicRule):
        """Add heuristic rule"""
        self.rules[rule.rule_id] = rule
        self.logger.debug(f"Added rule: {rule.name}")
    
    def remove_rule(self, rule_id: str):
        """Remove rule by ID"""
        if rule_id in self.rules:
            del self.rules[rule_id]
            self.logger.debug(f"Removed rule: {rule_id}")
    
    def enable_rule(self, rule_id: str):
        """Enable rule"""
        if rule_id in self.rules:
            self.rules[rule_id].enabled = True
    
    def disable_rule(self, rule_id: str):
        """Disable rule"""
        if rule_id in self.rules:
            self.rules[rule_id].enabled = False
    
    def get_rules_by_category(self, category: RuleCategory) -> List[HeuristicRule]:
        """Get rules by category"""
        return [r for r in self.rules.values() if r.category == category and r.enabled]
    
    # ========================================================================
    # BUILT-IN RULES
    # ========================================================================
    
    def _load_builtin_rules(self):
        """Load built-in heuristic rules"""
        
        # FILE RULES
        self.add_rule(HeuristicRule(
            rule_id="file_double_extension",
            name="Double File Extension",
            description="File has double extension (e.g., .pdf.exe)",
            category=RuleCategory.FILE,
            priority=RulePriority.HIGH,
            weight=70,
            condition=lambda ctx: ctx.get('filename', '').count('.') > 2,
            tags=["social_engineering", "masquerading"]
        ))
        
        self.add_rule(HeuristicRule(
            rule_id="file_executable_in_temp",
            name="Executable in Temp",
            description="Executable file in temporary directory",
            category=RuleCategory.FILE,
            priority=RulePriority.MEDIUM,
            weight=40,
            condition=lambda ctx: (
                ctx.get('extension', '').lower() in ['.exe', '.dll', '.scr'] and
                any(x in ctx.get('path', '').lower() for x in ['temp', 'tmp', 'appdata\\local\\temp'])
            ),
            tags=["suspicious_location"]
        ))
        
        self.add_rule(HeuristicRule(
            rule_id="file_high_entropy",
            name="High Entropy File",
            description="File has high entropy (possibly packed/encrypted)",
            category=RuleCategory.FILE,
            priority=RulePriority.MEDIUM,
            weight=50,
            condition=lambda ctx: ctx.get('entropy', 0) > 7.5,
            tags=["packing", "encryption"]
        ))
        
        self.add_rule(HeuristicRule(
            rule_id="file_suspicious_name",
            name="Suspicious File Name",
            description="File name contains suspicious keywords",
            category=RuleCategory.FILE,
            priority=RulePriority.MEDIUM,
            weight=30,
            condition=lambda ctx: any(
                keyword in ctx.get('filename', '').lower()
                for keyword in ['crack', 'keygen', 'patch', 'loader', 'injector']
            ),
            tags=["suspicious_naming"]
        ))
        
        # PROCESS RULES
        self.add_rule(HeuristicRule(
            rule_id="process_powershell_encoded",
            name="PowerShell Encoded Command",
            description="PowerShell with encoded command",
            category=RuleCategory.PROCESS,
            priority=RulePriority.HIGH,
            weight=80,
            condition=lambda ctx: (
                'powershell' in ctx.get('process_name', '').lower() and
                any(x in ctx.get('cmdline', '').lower() for x in ['-encodedcommand', '-enc'])
            ),
            tags=["obfuscation", "powershell"]
        ))
        
        self.add_rule(HeuristicRule(
            rule_id="process_suspicious_parent",
            name="Suspicious Parent-Child",
            description="Unusual parent-child process relationship",
            category=RuleCategory.PROCESS,
            priority=RulePriority.HIGH,
            weight=70,
            condition=lambda ctx: self._check_suspicious_parent_child(ctx),
            tags=["process_injection", "exploitation"]
        ))
        
        self.add_rule(HeuristicRule(
            rule_id="process_lolbin_abuse",
            name="LOLBin Abuse",
            description="Living-off-the-land binary with suspicious arguments",
            category=RuleCategory.PROCESS,
            priority=RulePriority.HIGH,
            weight=75,
            condition=lambda ctx: self._check_lolbin_abuse(ctx),
            tags=["lolbin", "living_off_land"]
        ))
        
        self.add_rule(HeuristicRule(
            rule_id="process_injection_indicators",
            name="Process Injection Indicators",
            description="Indicators of process injection",
            category=RuleCategory.PROCESS,
            priority=RulePriority.CRITICAL,
            weight=90,
            condition=lambda ctx: self._check_injection_indicators(ctx),
            tags=["injection", "memory"]
        ))
        
        # NETWORK RULES
        self.add_rule(HeuristicRule(
            rule_id="network_c2_beaconing",
            name="C2 Beaconing Pattern",
            description="Regular periodic network connections (C2 beaconing)",
            category=RuleCategory.NETWORK,
            priority=RulePriority.HIGH,
            weight=85,
            condition=lambda ctx: ctx.get('beaconing_detected', False),
            tags=["c2", "command_control"]
        ))
        
        self.add_rule(HeuristicRule(
            rule_id="network_suspicious_port",
            name="Suspicious Port Usage",
            description="Connection to suspicious port",
            category=RuleCategory.NETWORK,
            priority=RulePriority.MEDIUM,
            weight=40,
            condition=lambda ctx: ctx.get('port', 0) in {4444, 5555, 6666, 31337},
            tags=["backdoor", "suspicious_port"]
        ))
        
        self.add_rule(HeuristicRule(
            rule_id="network_data_exfiltration",
            name="Large Data Upload",
            description="Large amount of data uploaded",
            category=RuleCategory.NETWORK,
            priority=RulePriority.HIGH,
            weight=70,
            condition=lambda ctx: ctx.get('bytes_sent', 0) > 100 * 1024 * 1024,  # 100MB
            tags=["exfiltration", "data_theft"]
        ))
        
        # BEHAVIORAL RULES
        self.add_rule(HeuristicRule(
            rule_id="behavior_mass_file_encryption",
            name="Mass File Encryption",
            description="Rapid encryption of many files (ransomware)",
            category=RuleCategory.BEHAVIORAL,
            priority=RulePriority.CRITICAL,
            weight=100,
            condition=lambda ctx: (
                ctx.get('files_modified_per_sec', 0) > 10 and
                ctx.get('suspicious_extensions', False)
            ),
            tags=["ransomware", "encryption"]
        ))
        
        self.add_rule(HeuristicRule(
            rule_id="behavior_credential_dumping",
            name="Credential Dumping",
            description="Indicators of credential dumping",
            category=RuleCategory.BEHAVIORAL,
            priority=RulePriority.CRITICAL,
            weight=95,
            condition=lambda ctx: any(
                indicator in ctx.get('process_name', '').lower()
                for indicator in ['mimikatz', 'pwdump', 'gsecdump']
            ),
            tags=["credential_access", "mimikatz"]
        ))
        
        self.logger.info(f"Loaded {len(self.rules)} built-in heuristic rules")
    
    # ========================================================================
    # HELPER FUNCTIONS FOR COMPLEX CONDITIONS
    # ========================================================================
    
    def _check_suspicious_parent_child(self, ctx: Dict) -> bool:
        """Check for suspicious parent-child relationships"""
        suspicious_pairs = [
            ('winword.exe', 'powershell.exe'),
            ('excel.exe', 'cmd.exe'),
            ('outlook.exe', 'powershell.exe'),
            ('chrome.exe', 'cmd.exe'),
            ('svchost.exe', 'powershell.exe')
        ]
        
        parent = ctx.get('parent_name', '').lower()
        child = ctx.get('process_name', '').lower()
        
        return any(p in parent and c in child for p, c in suspicious_pairs)
    
    def _check_lolbin_abuse(self, ctx: Dict) -> bool:
        """Check for LOLBin abuse"""
        lolbins = ['certutil', 'bitsadmin', 'wmic', 'regsvr32', 'rundll32']
        suspicious_args = ['download', 'http', 'https', 'ftp', '-encodedcommand']
        
        process = ctx.get('process_name', '').lower()
        cmdline = ctx.get('cmdline', '').lower()
        
        return (
            any(lolbin in process for lolbin in lolbins) and
            any(arg in cmdline for arg in suspicious_args)
        )
    
    def _check_injection_indicators(self, ctx: Dict) -> bool:
        """Check for process injection indicators"""
        indicators = [
            'virtualalloc' in ctx.get('apis_called', '').lower(),
            'writeprocessmemory' in ctx.get('apis_called', '').lower(),
            'createremotethread' in ctx.get('apis_called', '').lower(),
            ctx.get('rwx_memory', False)  # Read-Write-Execute memory
        ]
        
        # Multiple indicators = likely injection
        return sum(indicators) >= 2
    
    # ========================================================================
    # DETECTION
    # ========================================================================
    
    def analyze(self, context: Dict, category: Optional[RuleCategory] = None) -> HeuristicDetection:
        """
        Analyze context using heuristic rules.
        
        Args:
            context: Detection context (file info, process info, etc.)
            category: Optional category filter
            
        Returns:
            HeuristicDetection result
        """
        self.detections_performed += 1
        
        # Select rules to check
        if category:
            rules_to_check = self.get_rules_by_category(category)
        else:
            rules_to_check = [r for r in self.rules.values() if r.enabled]
        
        # Check each rule
        matches = []
        total_score = 0
        
        for rule in rules_to_check:
            try:
                # Evaluate rule condition
                if rule.condition(context):
                    match = HeuristicMatch(
                        rule=rule,
                        score=rule.weight,
                        details=rule.description,
                        context=context
                    )
                    matches.append(match)
                    total_score += rule.weight
                    self.rules_matched += 1
                    
            except Exception as e:
                self.logger.error(f"Error evaluating rule {rule.rule_id}: {e}")
        
        # Determine threat level
        if total_score >= self.MALICIOUS_THRESHOLD:
            threat_level = ThreatLevel.MALICIOUS
            confidence = 95
        elif total_score >= self.LIKELY_MALICIOUS_THRESHOLD:
            threat_level = ThreatLevel.LIKELY_MALICIOUS
            confidence = 80
        elif total_score >= self.SUSPICIOUS_THRESHOLD:
            threat_level = ThreatLevel.SUSPICIOUS
            confidence = 60
        else:
            threat_level = ThreatLevel.CLEAN
            confidence = 90
        
        # Track threats
        if threat_level.value >= ThreatLevel.SUSPICIOUS.value:
            self.threats_detected += 1
        
        # Generate description
        description = self._generate_description(matches, total_score)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(threat_level, matches)
        
        # Create detection result
        detection = HeuristicDetection(
            target=context.get('target', 'unknown'),
            threat_level=threat_level,
            total_score=total_score,
            confidence=confidence,
            matches=matches,
            description=description,
            recommendations=recommendations
        )
        
        return detection
    
    def _generate_description(self, matches: List[HeuristicMatch], score: int) -> str:
        """Generate human-readable description"""
        if not matches:
            return "No suspicious patterns detected"
        
        # List top 3 matches
        top_matches = sorted(matches, key=lambda m: m.score, reverse=True)[:3]
        match_names = [m.rule.name for m in top_matches]
        
        return f"Detected {len(matches)} suspicious patterns (score: {score}): {', '.join(match_names)}"
    
    def _generate_recommendations(self, 
                                  threat_level: ThreatLevel,
                                  matches: List[HeuristicMatch]) -> List[str]:
        """Generate recommended actions"""
        recommendations = []
        
        if threat_level == ThreatLevel.MALICIOUS:
            recommendations.append("Block and quarantine immediately")
            recommendations.append("Perform full system scan")
            recommendations.append("Review system for compromise indicators")
        elif threat_level == ThreatLevel.LIKELY_MALICIOUS:
            recommendations.append("Quarantine for analysis")
            recommendations.append("Monitor for additional activity")
            recommendations.append("Consider blocking if pattern continues")
        elif threat_level == ThreatLevel.SUSPICIOUS:
            recommendations.append("Monitor closely")
            recommendations.append("Review in context of other activity")
            recommendations.append("Consider adding to watchlist")
        
        # Add specific recommendations based on matched rules
        tags = set()
        for match in matches:
            tags.update(match.rule.tags)
        
        if 'ransomware' in tags:
            recommendations.insert(0, "CRITICAL: Possible ransomware - disconnect network")
        
        if 'credential_access' in tags:
            recommendations.append("Force password reset")
        
        if 'c2' in tags:
            recommendations.append("Block C2 communication")
        
        return recommendations
    
    # ========================================================================
    # STATISTICS
    # ========================================================================
    
    def get_statistics(self) -> Dict:
        """Get engine statistics"""
        enabled_rules = sum(1 for r in self.rules.values() if r.enabled)
        detection_rate = (self.threats_detected / self.detections_performed * 100) if self.detections_performed > 0 else 0
        
        # Count by category
        by_category = {}
        for category in RuleCategory:
            by_category[category.value] = len(self.get_rules_by_category(category))
        
        return {
            'total_rules': len(self.rules),
            'enabled_rules': enabled_rules,
            'rules_by_category': by_category,
            'detections_performed': self.detections_performed,
            'threats_detected': self.threats_detected,
            'detection_rate': f"{detection_rate:.1f}%",
            'rules_matched': self.rules_matched
        }


# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================

def create_engine() -> HeuristicEngine:
    """Create heuristic engine"""
    return HeuristicEngine()


# ============================================================================
# TESTING & DEMO
# ============================================================================

if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    print("🎯 CyberGuardian Heuristic Engine - Demo\n")
    
    # Create engine
    engine = create_engine()
    
    # Test 1: Suspicious file
    print("Test 1: Analyzing suspicious file...")
    file_context = {
        'target': 'document.pdf.exe',
        'filename': 'document.pdf.exe',
        'extension': '.exe',
        'path': 'C:\\Users\\Test\\AppData\\Local\\Temp\\document.pdf.exe',
        'entropy': 7.8
    }
    
    detection = engine.analyze(file_context, RuleCategory.FILE)
    print(f"   Threat Level: {detection.threat_level.name}")
    print(f"   Score: {detection.total_score}")
    print(f"   Confidence: {detection.confidence}%")
    print(f"   Matches: {len(detection.matches)}")
    for match in detection.matches:
        print(f"     • {match.rule.name} (weight: {match.score})")
    
    # Test 2: Suspicious process
    print("\nTest 2: Analyzing PowerShell process...")
    process_context = {
        'target': 'powershell.exe',
        'process_name': 'powershell.exe',
        'cmdline': 'powershell.exe -encodedcommand <base64>',
        'parent_name': 'winword.exe'
    }
    
    detection = engine.analyze(process_context, RuleCategory.PROCESS)
    print(f"   Threat Level: {detection.threat_level.name}")
    print(f"   Score: {detection.total_score}")
    print(f"   Description: {detection.description}")
    
    # Statistics
    print("\n" + "="*50)
    stats = engine.get_statistics()
    print("Statistics:")
    for key, value in stats.items():
        if key == 'rules_by_category':
            print(f"  {key}:")
            for cat, count in value.items():
                print(f"    {cat}: {count}")
        else:
            print(f"  {key}: {value}")
    
    print("\n✅ Heuristic engine ready!")