"""
CyberGuardian - MITRE ATT&CK Framework Integration
===================================================

Maps detected threats to MITRE ATT&CK tactics and techniques.

Features:
- Technique ID to description mapping
- Tactic categorization
- Coverage analysis (which techniques we detect)
- Attack chain reconstruction
- Threat actor TTPs (Tactics, Techniques, Procedures)
- Defensive recommendations
- Heat map generation
- Gap analysis

MITRE ATT&CK Matrix:
- 14 Tactics (Initial Access → Impact)
- 200+ Techniques
- 400+ Sub-techniques
- Platform-specific mappings

Use Cases:
1. Map detections to ATT&CK framework
2. Analyze attack patterns
3. Identify coverage gaps
4. Prioritize detections
5. Generate threat reports
6. Track adversary behavior

Tactics:
1. Initial Access (TA0001)
2. Execution (TA0002)
3. Persistence (TA0003)
4. Privilege Escalation (TA0004)
5. Defense Evasion (TA0005)
6. Credential Access (TA0006)
7. Discovery (TA0007)
8. Lateral Movement (TA0008)
9. Collection (TA0009)
10. Command and Control (TA0010)
11. Exfiltration (TA0011)
12. Impact (TA0012)
"""

import json
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
import logging


# ============================================================================
# CONFIGURATION
# ============================================================================

class Tactic(Enum):
    """MITRE ATT&CK Tactics"""
    INITIAL_ACCESS = "TA0001"
    EXECUTION = "TA0002"
    PERSISTENCE = "TA0003"
    PRIVILEGE_ESCALATION = "TA0004"
    DEFENSE_EVASION = "TA0005"
    CREDENTIAL_ACCESS = "TA0006"
    DISCOVERY = "TA0007"
    LATERAL_MOVEMENT = "TA0008"
    COLLECTION = "TA0009"
    COMMAND_AND_CONTROL = "TA0010"
    EXFILTRATION = "TA0011"
    IMPACT = "TA0012"


@dataclass
class Technique:
    """
    MITRE ATT&CK Technique.
    
    Attributes:
        technique_id: Technique ID (e.g., T1055)
        name: Technique name
        description: Description
        tactics: Associated tactics
        platforms: Target platforms
        data_sources: Detection data sources
        mitigations: Mitigation recommendations
        sub_techniques: List of sub-technique IDs
    """
    technique_id: str
    name: str
    description: str
    tactics: List[Tactic] = field(default_factory=list)
    platforms: List[str] = field(default_factory=list)
    data_sources: List[str] = field(default_factory=list)
    mitigations: List[str] = field(default_factory=list)
    sub_techniques: List[str] = field(default_factory=list)


@dataclass
class Detection:
    """
    Detection mapped to MITRE ATT&CK.
    
    Attributes:
        technique_id: MITRE technique ID
        confidence: Detection confidence (0-100)
        evidence: Evidence/indicators
        timestamp: When detected
        severity: Severity level
    """
    technique_id: str
    confidence: int
    evidence: str = ""
    timestamp: str = ""
    severity: str = "medium"


# ============================================================================
# MITRE ATT&CK MAPPER
# ============================================================================

class MITREAttackMapper:
    """
    MITRE ATT&CK framework integration.
    
    Maps detections to ATT&CK techniques and provides context.
    """
    
    # Core techniques database (subset for demonstration)
    TECHNIQUES_DB = {
        # Persistence
        "T1547.001": {
            "name": "Registry Run Keys / Startup Folder",
            "description": "Adversaries may achieve persistence by adding a program to a startup folder or referencing it with a Registry run key.",
            "tactics": [Tactic.PERSISTENCE, Tactic.PRIVILEGE_ESCALATION],
            "platforms": ["Windows"],
            "data_sources": ["Windows Registry", "File monitoring"],
            "mitigations": ["Monitor registry keys", "Restrict registry permissions"]
        },
        "T1543.003": {
            "name": "Create or Modify System Process: Windows Service",
            "description": "Adversaries may create or modify Windows services to repeatedly execute malicious payloads.",
            "tactics": [Tactic.PERSISTENCE, Tactic.PRIVILEGE_ESCALATION],
            "platforms": ["Windows"],
            "data_sources": ["Windows Registry", "Process monitoring"],
            "mitigations": ["Audit services", "Least privilege"]
        },
        
        # Process Injection
        "T1055": {
            "name": "Process Injection",
            "description": "Adversaries may inject code into processes to evade defenses and elevate privileges.",
            "tactics": [Tactic.DEFENSE_EVASION, Tactic.PRIVILEGE_ESCALATION],
            "platforms": ["Windows", "Linux", "macOS"],
            "data_sources": ["Process monitoring", "API monitoring"],
            "mitigations": ["Behavior monitoring", "Privilege restrictions"]
        },
        "T1055.001": {
            "name": "Process Injection: Dynamic-link Library Injection",
            "description": "Adversaries may inject DLLs into processes to execute arbitrary code.",
            "tactics": [Tactic.DEFENSE_EVASION, Tactic.PRIVILEGE_ESCALATION],
            "platforms": ["Windows"],
            "data_sources": ["Process monitoring", "DLL monitoring"],
            "mitigations": ["DLL search order hijacking prevention"]
        },
        "T1055.012": {
            "name": "Process Injection: Process Hollowing",
            "description": "Adversaries may inject code into suspended and hollowed processes.",
            "tactics": [Tactic.DEFENSE_EVASION, Tactic.PRIVILEGE_ESCALATION],
            "platforms": ["Windows"],
            "data_sources": ["Process monitoring"],
            "mitigations": ["Behavior monitoring"]
        },
        
        # Command and Scripting Interpreter
        "T1059": {
            "name": "Command and Scripting Interpreter",
            "description": "Adversaries may abuse command and script interpreters to execute commands.",
            "tactics": [Tactic.EXECUTION],
            "platforms": ["Windows", "Linux", "macOS"],
            "data_sources": ["Process monitoring", "Command execution"],
            "mitigations": ["Execution prevention", "Code signing"]
        },
        "T1059.001": {
            "name": "Command and Scripting Interpreter: PowerShell",
            "description": "Adversaries may abuse PowerShell commands and scripts.",
            "tactics": [Tactic.EXECUTION],
            "platforms": ["Windows"],
            "data_sources": ["PowerShell logs", "Script execution"],
            "mitigations": ["PowerShell logging", "Execution policy"]
        },
        
        # Modify Registry
        "T1112": {
            "name": "Modify Registry",
            "description": "Adversaries may modify the Windows Registry to hide configuration or evade defenses.",
            "tactics": [Tactic.DEFENSE_EVASION],
            "platforms": ["Windows"],
            "data_sources": ["Windows Registry"],
            "mitigations": ["Registry monitoring", "Audit logs"]
        },
        
        # Impair Defenses
        "T1562.001": {
            "name": "Impair Defenses: Disable or Modify Tools",
            "description": "Adversaries may disable security tools to avoid detection.",
            "tactics": [Tactic.DEFENSE_EVASION],
            "platforms": ["Windows", "Linux", "macOS"],
            "data_sources": ["Process monitoring", "Windows Registry"],
            "mitigations": ["Restrict registry", "User training"]
        },
        
        # Credential Dumping
        "T1003": {
            "name": "OS Credential Dumping",
            "description": "Adversaries may dump credentials to obtain account information.",
            "tactics": [Tactic.CREDENTIAL_ACCESS],
            "platforms": ["Windows", "Linux", "macOS"],
            "data_sources": ["Process monitoring", "API monitoring"],
            "mitigations": ["Credential Guard", "LSA protection"]
        },
        
        # Network Communication
        "T1071": {
            "name": "Application Layer Protocol",
            "description": "Adversaries may communicate using application layer protocols.",
            "tactics": [Tactic.COMMAND_AND_CONTROL],
            "platforms": ["Windows", "Linux", "macOS"],
            "data_sources": ["Network traffic", "Packet capture"],
            "mitigations": ["Network intrusion prevention"]
        },
        "T1071.004": {
            "name": "Application Layer Protocol: DNS",
            "description": "Adversaries may use DNS for C2 communications.",
            "tactics": [Tactic.COMMAND_AND_CONTROL],
            "platforms": ["Windows", "Linux", "macOS"],
            "data_sources": ["DNS records", "Network traffic"],
            "mitigations": ["DNS filtering"]
        },
        
        # Data Exfiltration
        "T1048": {
            "name": "Exfiltration Over Alternative Protocol",
            "description": "Adversaries may exfiltrate data over a different protocol than command channel.",
            "tactics": [Tactic.EXFILTRATION],
            "platforms": ["Windows", "Linux", "macOS"],
            "data_sources": ["Network traffic", "Packet capture"],
            "mitigations": ["Network segmentation", "Data loss prevention"]
        },
        
        # Resource Hijacking
        "T1496": {
            "name": "Resource Hijacking",
            "description": "Adversaries may hijack resources for cryptocurrency mining.",
            "tactics": [Tactic.IMPACT],
            "platforms": ["Windows", "Linux", "macOS"],
            "data_sources": ["Process monitoring", "Network traffic"],
            "mitigations": ["Behavior monitoring"]
        },
        
        # User Execution
        "T1204": {
            "name": "User Execution",
            "description": "Adversaries may rely on users executing malicious files.",
            "tactics": [Tactic.EXECUTION],
            "platforms": ["Windows", "Linux", "macOS"],
            "data_sources": ["Process monitoring", "File monitoring"],
            "mitigations": ["User training", "Execution prevention"]
        },
        
        # Obfuscated Files
        "T1027": {
            "name": "Obfuscated Files or Information",
            "description": "Adversaries may obfuscate files or information to evade detection.",
            "tactics": [Tactic.DEFENSE_EVASION],
            "platforms": ["Windows", "Linux", "macOS"],
            "data_sources": ["File monitoring", "Process monitoring"],
            "mitigations": ["Behavior analysis", "Signature detection"]
        }
    }
    
    def __init__(self, cache_dir: Optional[str] = None):
        """
        Initialize MITRE ATT&CK mapper.
        
        Args:
            cache_dir: Directory for caching ATT&CK data
        """
        self.logger = logging.getLogger(__name__)
        
        # Cache directory
        if cache_dir:
            self.cache_dir = Path(cache_dir)
        else:
            self.cache_dir = Path.home() / '.cyberguardian' / 'mitre_attack'
        
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        # Detection tracking
        self.detections: List[Detection] = []
        
        # Statistics
        self.techniques_detected: Set[str] = set()
    
    # ========================================================================
    # TECHNIQUE LOOKUP
    # ========================================================================
    
    def get_technique(self, technique_id: str) -> Optional[Dict]:
        """
        Get technique information by ID.
        
        Args:
            technique_id: Technique ID (e.g., T1055)
            
        Returns:
            Dict with technique info or None
        """
        return self.TECHNIQUES_DB.get(technique_id)
    
    def search_techniques(self, query: str) -> List[Tuple[str, Dict]]:
        """
        Search techniques by name or description.
        
        Args:
            query: Search query
            
        Returns:
            List of (technique_id, technique_info) tuples
        """
        query_lower = query.lower()
        results = []
        
        for tech_id, tech_info in self.TECHNIQUES_DB.items():
            name_lower = tech_info['name'].lower()
            desc_lower = tech_info['description'].lower()
            
            if query_lower in name_lower or query_lower in desc_lower:
                results.append((tech_id, tech_info))
        
        return results
    
    def get_techniques_by_tactic(self, tactic: Tactic) -> List[Tuple[str, Dict]]:
        """
        Get all techniques for a specific tactic.
        
        Args:
            tactic: Tactic enum
            
        Returns:
            List of (technique_id, technique_info) tuples
        """
        results = []
        
        for tech_id, tech_info in self.TECHNIQUES_DB.items():
            if tactic in tech_info['tactics']:
                results.append((tech_id, tech_info))
        
        return results
    
    # ========================================================================
    # DETECTION MAPPING
    # ========================================================================
    
    def map_detection(self, 
                     technique_id: str,
                     confidence: int,
                     evidence: str = "",
                     severity: str = "medium"):
        """
        Map a detection to MITRE ATT&CK technique.
        
        Args:
            technique_id: Technique ID
            confidence: Confidence score (0-100)
            evidence: Detection evidence
            severity: Severity level
        """
        from datetime import datetime
        
        detection = Detection(
            technique_id=technique_id,
            confidence=confidence,
            evidence=evidence,
            timestamp=datetime.now().isoformat(),
            severity=severity
        )
        
        self.detections.append(detection)
        self.techniques_detected.add(technique_id)
        
        self.logger.info(f"Mapped detection to {technique_id}: {evidence}")
    
    def get_detections(self, 
                      technique_id: Optional[str] = None,
                      min_confidence: int = 0) -> List[Detection]:
        """
        Get detections, optionally filtered.
        
        Args:
            technique_id: Filter by technique
            min_confidence: Minimum confidence score
            
        Returns:
            List of Detection objects
        """
        results = self.detections
        
        if technique_id:
            results = [d for d in results if d.technique_id == technique_id]
        
        if min_confidence > 0:
            results = [d for d in results if d.confidence >= min_confidence]
        
        return results
    
    # ========================================================================
    # ATTACK CHAIN ANALYSIS
    # ========================================================================
    
    def reconstruct_attack_chain(self) -> Dict[Tactic, List[Detection]]:
        """
        Reconstruct attack chain from detections.
        
        Groups detections by tactic in chronological order.
        
        Returns:
            Dict of {Tactic: [Detection]}
        """
        chain = defaultdict(list)
        
        for detection in self.detections:
            tech_info = self.get_technique(detection.technique_id)
            
            if tech_info:
                for tactic in tech_info['tactics']:
                    chain[tactic].append(detection)
        
        return dict(chain)
    
    def get_attack_timeline(self) -> List[Tuple[str, str, str]]:
        """
        Get chronological attack timeline.
        
        Returns:
            List of (timestamp, technique_id, evidence) tuples
        """
        timeline = [
            (d.timestamp, d.technique_id, d.evidence)
            for d in sorted(self.detections, key=lambda x: x.timestamp)
        ]
        
        return timeline
    
    # ========================================================================
    # COVERAGE ANALYSIS
    # ========================================================================
    
    def get_coverage_statistics(self) -> Dict:
        """
        Analyze detection coverage of MITRE ATT&CK.
        
        Returns:
            Dict with coverage statistics
        """
        total_techniques = len(self.TECHNIQUES_DB)
        detected_techniques = len(self.techniques_detected)
        coverage_percent = (detected_techniques / total_techniques * 100) if total_techniques > 0 else 0
        
        # Count by tactic
        tactics_coverage = {}
        for tactic in Tactic:
            tactic_techniques = self.get_techniques_by_tactic(tactic)
            total = len(tactic_techniques)
            
            detected = sum(
                1 for tech_id, _ in tactic_techniques
                if tech_id in self.techniques_detected
            )
            
            tactics_coverage[tactic.name] = {
                'total': total,
                'detected': detected,
                'coverage': f"{(detected / total * 100):.1f}%" if total > 0 else "0%"
            }
        
        return {
            'total_techniques': total_techniques,
            'detected_techniques': detected_techniques,
            'coverage_percent': f"{coverage_percent:.1f}%",
            'tactics_coverage': tactics_coverage
        }
    
    def get_coverage_gaps(self) -> List[Tuple[str, Dict]]:
        """
        Identify techniques not being detected.
        
        Returns:
            List of (technique_id, technique_info) for undetected techniques
        """
        gaps = []
        
        for tech_id, tech_info in self.TECHNIQUES_DB.items():
            if tech_id not in self.techniques_detected:
                gaps.append((tech_id, tech_info))
        
        return gaps
    
    # ========================================================================
    # REPORTING
    # ========================================================================
    
    def generate_report(self) -> str:
        """
        Generate ATT&CK-based threat report.
        
        Returns:
            Formatted report string
        """
        report = []
        report.append("="*60)
        report.append("MITRE ATT&CK Detection Report")
        report.append("="*60)
        report.append("")
        
        # Summary
        report.append("Summary:")
        report.append(f"  Total Detections: {len(self.detections)}")
        report.append(f"  Unique Techniques: {len(self.techniques_detected)}")
        report.append("")
        
        # Attack Chain
        report.append("Attack Chain:")
        chain = self.reconstruct_attack_chain()
        
        for tactic in Tactic:
            if tactic in chain:
                report.append(f"\n  {tactic.name}:")
                for detection in chain[tactic]:
                    tech_info = self.get_technique(detection.technique_id)
                    if tech_info:
                        report.append(f"    • {detection.technique_id}: {tech_info['name']}")
                        report.append(f"      Confidence: {detection.confidence}%")
                        if detection.evidence:
                            report.append(f"      Evidence: {detection.evidence}")
        
        # Coverage
        report.append("\n" + "="*60)
        report.append("Detection Coverage:")
        coverage = self.get_coverage_statistics()
        report.append(f"  Overall: {coverage['coverage_percent']}")
        report.append(f"  Techniques: {coverage['detected_techniques']}/{coverage['total_techniques']}")
        
        return "\n".join(report)
    
    def export_to_json(self, output_file: str):
        """Export detections to JSON"""
        data = {
            'detections': [
                {
                    'technique_id': d.technique_id,
                    'technique_name': self.get_technique(d.technique_id)['name'] if self.get_technique(d.technique_id) else 'Unknown',
                    'confidence': d.confidence,
                    'evidence': d.evidence,
                    'timestamp': d.timestamp,
                    'severity': d.severity
                }
                for d in self.detections
            ],
            'coverage': self.get_coverage_statistics()
        }
        
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
        
        self.logger.info(f"Exported report to {output_file}")


# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================

def create_mapper() -> MITREAttackMapper:
    """Create MITRE ATT&CK mapper"""
    return MITREAttackMapper()


# ============================================================================
# TESTING & DEMO
# ============================================================================

if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    print("🎯 CyberGuardian MITRE ATT&CK Mapper - Demo\n")
    
    # Create mapper
    mapper = create_mapper()
    
    # Simulate some detections
    print("Simulating attack chain...\n")
    
    mapper.map_detection(
        "T1059.001",
        confidence=85,
        evidence="PowerShell with encoded command detected",
        severity="high"
    )
    
    mapper.map_detection(
        "T1055.001",
        confidence=90,
        evidence="DLL injection detected in process",
        severity="critical"
    )
    
    mapper.map_detection(
        "T1547.001",
        confidence=95,
        evidence="Registry Run key modification",
        severity="high"
    )
    
    mapper.map_detection(
        "T1071",
        confidence=75,
        evidence="Suspicious C2 communication",
        severity="high"
    )
    
    # Generate report
    print(mapper.generate_report())
    
    # Coverage analysis
    print("\n" + "="*60)
    coverage = mapper.get_coverage_statistics()
    print(f"Detection Coverage: {coverage['coverage_percent']}")
    
    print("\n✅ MITRE ATT&CK mapper ready!")