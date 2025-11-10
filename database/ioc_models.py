"""
CyberGuardian AI - IOC (Indicators of Compromise) Database Models
Store and manage threat intelligence indicators
"""

from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text, Float
from sqlalchemy.sql import func
from database.connection import Base

class IOC(Base):
    """
    Indicator of Compromise
    
    Stores various types of threat indicators:
    - IP addresses
    - Domain names
    - File hashes (MD5, SHA1, SHA256)
    - URLs
    - Email addresses
    """
    __tablename__ = "iocs"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # IOC Details
    ioc_type = Column(String(50), nullable=False, index=True)  # ip, domain, hash, url, email
    ioc_value = Column(String(500), nullable=False, unique=True, index=True)
    
    # Threat Information
    threat_type = Column(String(100))  # malware, phishing, c2, botnet, etc.
    threat_name = Column(String(200))  # WannaCry, Emotet, etc.
    severity = Column(String(20), default="medium")  # low, medium, high, critical
    confidence = Column(Float, default=50.0)  # 0-100
    
    # Source Information
    source = Column(String(100))  # AbuseIPDB, OTX, VirusTotal, internal
    source_url = Column(String(500))
    
    # MITRE ATT&CK
    mitre_tactics = Column(Text)  # JSON array of tactics
    mitre_techniques = Column(Text)  # JSON array of techniques
    
    # Metadata
    description = Column(Text)
    tags = Column(Text)  # JSON array
    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    last_seen = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    times_seen = Column(Integer, default=1)
    
    # Status
    is_active = Column(Boolean, default=True)
    is_whitelisted = Column(Boolean, default=False)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    
    def __repr__(self):
        return f"<IOC {self.ioc_type}:{self.ioc_value} - {self.threat_type}>"


class ThreatFeed(Base):
    """
    External Threat Feed Configuration
    
    Manages connections to external threat intelligence sources
    """
    __tablename__ = "threat_feeds"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Feed Details
    name = Column(String(100), nullable=False, unique=True)
    feed_type = Column(String(50), nullable=False)  # api, rss, csv, json
    url = Column(String(500))
    api_key = Column(String(200))
    
    # Configuration
    enabled = Column(Boolean, default=True)
    refresh_interval = Column(Integer, default=3600)  # seconds
    last_refresh = Column(DateTime(timezone=True))
    
    # Statistics
    total_iocs = Column(Integer, default=0)
    successful_updates = Column(Integer, default=0)
    failed_updates = Column(Integer, default=0)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    
    def __repr__(self):
        return f"<ThreatFeed {self.name}>"


class ThreatMatch(Base):
    """
    Threat Intelligence Match
    
    Records when a detection matches an IOC
    """
    __tablename__ = "threat_matches"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Match Details
    ioc_id = Column(Integer, nullable=False, index=True)
    matched_value = Column(String(500), nullable=False)
    match_type = Column(String(50))  # exact, partial, regex
    
    # Detection Context
    detection_source = Column(String(100))  # yara, heuristic, network, etc.
    file_path = Column(String(500))
    process_name = Column(String(200))
    
    # Threat Information
    threat_level = Column(String(20))  # low, medium, high, critical
    confidence_score = Column(Float)
    
    # Action Taken
    action_taken = Column(String(100))  # blocked, quarantined, alerted, logged
    
    # Timestamps
    matched_at = Column(DateTime(timezone=True), server_default=func.now())
    
    def __repr__(self):
        return f"<ThreatMatch IOC:{self.ioc_id} - {self.matched_value}>"