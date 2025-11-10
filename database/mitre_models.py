"""
CyberGuardian AI - MITRE ATT&CK Database Models
Store and manage MITRE ATT&CK framework data
"""

from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text, ForeignKey
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from database.connection import Base

class MitreTactic(Base):
    """
    MITRE ATT&CK Tactic
    
    Represents high-level adversary goals (e.g., Initial Access, Execution)
    """
    __tablename__ = "mitre_tactics"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # MITRE Information
    tactic_id = Column(String(50), nullable=False, unique=True, index=True)  # TA0001
    name = Column(String(200), nullable=False)  # Initial Access
    description = Column(Text)
    url = Column(String(500))
    
    # Metadata
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    
    # Relationships
    techniques = relationship("MitreTechnique", back_populates="tactic")
    
    def __repr__(self):
        return f"<MitreTactic {self.tactic_id}:{self.name}>"


class MitreTechnique(Base):
    """
    MITRE ATT&CK Technique
    
    Represents specific methods adversaries use (e.g., Phishing, PowerShell)
    """
    __tablename__ = "mitre_techniques"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # MITRE Information
    technique_id = Column(String(50), nullable=False, unique=True, index=True)  # T1566
    name = Column(String(200), nullable=False)  # Phishing
    description = Column(Text)
    url = Column(String(500))
    
    # Relationships
    tactic_id = Column(Integer, ForeignKey("mitre_tactics.id"), nullable=False, index=True)
    parent_technique_id = Column(Integer, ForeignKey("mitre_techniques.id"), nullable=True)  # For sub-techniques
    
    # Classification
    is_sub_technique = Column(Boolean, default=False)
    platforms = Column(Text)  # JSON array: ["Windows", "Linux", "macOS"]
    data_sources = Column(Text)  # JSON array
    
    # Metadata
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    
    # Relationships
    tactic = relationship("MitreTactic", back_populates="techniques")
    parent_technique = relationship("MitreTechnique", remote_side=[id], backref="sub_techniques")
    
    def __repr__(self):
        return f"<MitreTechnique {self.technique_id}:{self.name}>"


class ThreatMitreMapping(Base):
    """
    Threat to MITRE ATT&CK Mapping
    
    Maps detected threats to MITRE ATT&CK techniques
    """
    __tablename__ = "threat_mitre_mappings"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Threat Information
    threat_id = Column(Integer, nullable=False, index=True)  # Reference to threats table
    threat_type = Column(String(100))  # malware, ransomware, phishing, etc.
    threat_name = Column(String(200))
    
    # MITRE Mapping
    technique_id = Column(Integer, ForeignKey("mitre_techniques.id"), nullable=False, index=True)
    tactic_id = Column(Integer, ForeignKey("mitre_tactics.id"), nullable=False, index=True)
    
    # Confidence
    confidence = Column(Integer, default=50)  # 0-100
    mapping_source = Column(String(100))  # manual, automatic, ML
    
    # Context
    description = Column(Text)
    evidence = Column(Text)  # JSON: what indicated this technique
    
    # Timestamps
    detected_at = Column(DateTime(timezone=True), server_default=func.now())
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    technique = relationship("MitreTechnique")
    tactic = relationship("MitreTactic")
    
    def __repr__(self):
        return f"<ThreatMitreMapping Threat:{self.threat_id} -> {self.technique_id}>"


class MitreDetectionCoverage(Base):
    """
    MITRE ATT&CK Detection Coverage
    
    Tracks which techniques CyberGuardian can detect
    """
    __tablename__ = "mitre_detection_coverage"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Technique
    technique_id = Column(Integer, ForeignKey("mitre_techniques.id"), nullable=False, unique=True, index=True)
    
    # Coverage
    can_detect = Column(Boolean, default=False)
    detection_methods = Column(Text)  # JSON: ["YARA", "Heuristic", "ML"]
    coverage_level = Column(String(50))  # none, low, medium, high, complete
    
    # Statistics
    times_detected = Column(Integer, default=0)
    last_detected = Column(DateTime(timezone=True))
    
    # Metadata
    notes = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    
    # Relationships
    technique = relationship("MitreTechnique")
    
    def __repr__(self):
        return f"<MitreDetectionCoverage {self.technique_id} - {self.coverage_level}>"