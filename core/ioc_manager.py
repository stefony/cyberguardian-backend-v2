"""
CyberGuardian AI - IOC (Indicators of Compromise) Manager
Manage threat intelligence indicators
"""

import logging
from typing import List, Dict, Optional
from datetime import datetime
from sqlalchemy.orm import Session
from database.connection import get_db
from database.ioc_models import IOC, ThreatFeed, ThreatMatch
import re
import hashlib

logger = logging.getLogger(__name__)

class IOCManager:
    """
    IOC Management System
    
    Handles:
    - Adding/updating IOCs
    - Searching and matching IOCs
    - IOC enrichment
    - Statistics and reporting
    """
    
    # IOC Type validation patterns
    PATTERNS = {
        'ip': r'^(\d{1,3}\.){3}\d{1,3}$',
        'domain': r'^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$',
        'md5': r'^[a-fA-F0-9]{32}$',
        'sha1': r'^[a-fA-F0-9]{40}$',
        'sha256': r'^[a-fA-F0-9]{64}$',
        'url': r'^https?://.+',
        'email': r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    }
    
    def __init__(self, db: Session = None):
        """Initialize IOC Manager"""
        self.db = db or next(get_db())
    
    def detect_ioc_type(self, value: str) -> Optional[str]:
        """
        Auto-detect IOC type from value
        
        Args:
            value: IOC value to detect
            
        Returns:
            IOC type or None
        """
        value = value.strip()
        
        # Check patterns
        for ioc_type, pattern in self.PATTERNS.items():
            if re.match(pattern, value):
                # Distinguish between hash types
                if ioc_type in ['md5', 'sha1', 'sha256']:
                    return 'hash'
                return ioc_type
        
        return None
    
    def add_ioc(
        self,
        ioc_value: str,
        ioc_type: Optional[str] = None,
        threat_type: Optional[str] = None,
        threat_name: Optional[str] = None,
        severity: str = "medium",
        confidence: float = 50.0,
        source: str = "manual",
        description: Optional[str] = None,
        mitre_tactics: Optional[List[str]] = None,
        mitre_techniques: Optional[List[str]] = None,
        tags: Optional[List[str]] = None
    ) -> Optional[IOC]:
        """
        Add new IOC to database
        
        Args:
            ioc_value: The indicator value
            ioc_type: Type of IOC (auto-detected if None)
            threat_type: Type of threat
            threat_name: Name of threat
            severity: Severity level
            confidence: Confidence score (0-100)
            source: Source of IOC
            description: Description
            mitre_tactics: MITRE ATT&CK tactics
            mitre_techniques: MITRE ATT&CK techniques
            tags: Tags
            
        Returns:
            Created IOC or None
        """
        try:
            # Auto-detect type if not provided
            if not ioc_type:
                ioc_type = self.detect_ioc_type(ioc_value)
                if not ioc_type:
                    logger.error(f"Could not detect IOC type for: {ioc_value}")
                    return None
            
            # Check if IOC already exists
            existing = self.db.query(IOC).filter(IOC.ioc_value == ioc_value).first()
            if existing:
                # Update existing IOC
                existing.times_seen += 1
                existing.last_seen = datetime.utcnow()
                existing.confidence = max(existing.confidence, confidence)
                self.db.commit()
                logger.info(f"Updated existing IOC: {ioc_value}")
                return existing
            
            # Create new IOC
            ioc = IOC(
                ioc_type=ioc_type,
                ioc_value=ioc_value,
                threat_type=threat_type,
                threat_name=threat_name,
                severity=severity,
                confidence=confidence,
                source=source,
                description=description,
                mitre_tactics=str(mitre_tactics) if mitre_tactics else None,
                mitre_techniques=str(mitre_techniques) if mitre_techniques else None,
                tags=str(tags) if tags else None
            )
            
            self.db.add(ioc)
            self.db.commit()
            self.db.refresh(ioc)
            
            logger.info(f"Added new IOC: {ioc_type}:{ioc_value}")
            return ioc
        
        except Exception as e:
            logger.error(f"Error adding IOC: {e}")
            self.db.rollback()
            return None
    
    def search_ioc(self, value: str) -> Optional[IOC]:
        """
        Search for IOC by value
        
        Args:
            value: IOC value to search
            
        Returns:
            IOC if found, None otherwise
        """
        try:
            return self.db.query(IOC).filter(
                IOC.ioc_value == value,
                IOC.is_active == True,
                IOC.is_whitelisted == False
            ).first()
        except Exception as e:
            logger.error(f"Error searching IOC: {e}")
            return None
    
    def check_threat(self, value: str) -> Dict:
        """
        Check if value matches any IOC
        
        Args:
            value: Value to check
            
        Returns:
            Dict with threat information
        """
        ioc = self.search_ioc(value)
        
        if ioc:
            return {
                'is_threat': True,
                'ioc_id': ioc.id,
                'ioc_type': ioc.ioc_type,
                'threat_type': ioc.threat_type,
                'threat_name': ioc.threat_name,
                'severity': ioc.severity,
                'confidence': ioc.confidence,
                'source': ioc.source,
                'description': ioc.description,
                'first_seen': ioc.first_seen.isoformat() if ioc.first_seen else None,
                'times_seen': ioc.times_seen
            }
        
        return {
            'is_threat': False,
            'message': 'No threat intelligence match'
        }
    
    def get_iocs_by_type(self, ioc_type: str, limit: int = 100) -> List[IOC]:
        """Get IOCs by type"""
        try:
            return self.db.query(IOC).filter(
                IOC.ioc_type == ioc_type,
                IOC.is_active == True
            ).limit(limit).all()
        except Exception as e:
            logger.error(f"Error getting IOCs by type: {e}")
            return []
    
    def get_recent_iocs(self, limit: int = 50) -> List[IOC]:
        """Get most recent IOCs"""
        try:
            return self.db.query(IOC).filter(
                IOC.is_active == True
            ).order_by(IOC.created_at.desc()).limit(limit).all()
        except Exception as e:
            logger.error(f"Error getting recent IOCs: {e}")
            return []
    
    def record_match(
        self,
        ioc_id: int,
        matched_value: str,
        detection_source: str,
        file_path: Optional[str] = None,
        threat_level: str = "medium",
        confidence_score: float = 50.0,
        action_taken: str = "alerted"
    ) -> Optional[ThreatMatch]:
        """
        Record IOC match
        
        Args:
            ioc_id: IOC ID
            matched_value: Matched value
            detection_source: Source of detection
            file_path: File path if applicable
            threat_level: Threat level
            confidence_score: Confidence score
            action_taken: Action taken
            
        Returns:
            Created ThreatMatch
        """
        try:
            match = ThreatMatch(
                ioc_id=ioc_id,
                matched_value=matched_value,
                match_type="exact",
                detection_source=detection_source,
                file_path=file_path,
                threat_level=threat_level,
                confidence_score=confidence_score,
                action_taken=action_taken
            )
            
            self.db.add(match)
            self.db.commit()
            self.db.refresh(match)
            
            logger.info(f"Recorded threat match: IOC {ioc_id} - {matched_value}")
            return match
        
        except Exception as e:
            logger.error(f"Error recording match: {e}")
            self.db.rollback()
            return None
    
    def get_statistics(self) -> Dict:
        """Get IOC statistics"""
        try:
            total_iocs = self.db.query(IOC).filter(IOC.is_active == True).count()
            
            iocs_by_type = {}
            for ioc_type in ['ip', 'domain', 'hash', 'url', 'email']:
                count = self.db.query(IOC).filter(
                    IOC.ioc_type == ioc_type,
                    IOC.is_active == True
                ).count()
                iocs_by_type[ioc_type] = count
            
            total_matches = self.db.query(ThreatMatch).count()
            
            recent_threats = self.db.query(IOC).filter(
                IOC.is_active == True,
                IOC.severity.in_(['high', 'critical'])
            ).order_by(IOC.created_at.desc()).limit(5).all()
            
            return {
                'total_iocs': total_iocs,
                'iocs_by_type': iocs_by_type,
                'total_matches': total_matches,
                'recent_high_threats': len(recent_threats),
                'last_updated': datetime.utcnow().isoformat()
            }
        
        except Exception as e:
            logger.error(f"Error getting statistics: {e}")
            return {
                'total_iocs': 0,
                'iocs_by_type': {},
                'total_matches': 0,
                'error': str(e)
            }


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    print("🔍 Testing IOC Manager\n")
    
    manager = IOCManager()
    
    # Add test IOCs
    test_iocs = [
        {
            'ioc_value': '192.168.1.100',
            'threat_type': 'c2',
            'threat_name': 'Cobalt Strike',
            'severity': 'high',
            'confidence': 90.0,
            'description': 'Known C2 server'
        },
        {
            'ioc_value': 'malicious-domain.com',
            'threat_type': 'phishing',
            'threat_name': 'Phishing Campaign 2024',
            'severity': 'medium',
            'confidence': 75.0
        },
        {
            'ioc_value': '44d88612fea8a8f36de82e1278abb02f',
            'threat_type': 'malware',
            'threat_name': 'EICAR Test File',
            'severity': 'low',
            'confidence': 100.0
        }
    ]
    
    for ioc_data in test_iocs:
        ioc = manager.add_ioc(**ioc_data)
        if ioc:
            print(f"✅ Added: {ioc.ioc_type}:{ioc.ioc_value}")
    
    # Test search
    print(f"\n🔍 Searching for: 192.168.1.100")
    result = manager.check_threat('192.168.1.100')
    print(f"Result: {result}")
    
    # Statistics
    print(f"\n📊 Statistics:")
    stats = manager.get_statistics()
    for key, value in stats.items():
        print(f"  {key}: {value}")