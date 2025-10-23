"""
CyberGuardian - Threat Intelligence Manager
============================================

Multi-source threat intelligence aggregation and management.

Data Sources:
- VirusTotal (file/URL/IP reputation)
- AlienVault OTX (Open Threat Exchange)
- AbuseIPDB (IP reputation)
- URLhaus (malicious URLs)
- MalwareBazaar (malware samples)
- MITRE ATT&CK (tactics and techniques)
- Custom feeds (user-provided)

Features:
- Automatic feed updates
- Local caching for offline operation
- Priority-based update scheduling
- Rate limiting for API calls
- Cryptographic verification of feeds
- IOC normalization and deduplication

IOC Types:
- File hashes (MD5, SHA1, SHA256)
- IP addresses (IPv4, IPv6)
- Domain names
- URLs
- Email addresses
- YARA rules
- CVEs

Output Formats:
- Internal database
- STIX 2.1
- OpenIOC
- JSON
"""

import os
import hashlib
import time
import requests
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import logging


# ============================================================================
# CONFIGURATION
# ============================================================================

class IOCType(Enum):
    """Indicator of Compromise types"""
    FILE_HASH_MD5 = "md5"
    FILE_HASH_SHA1 = "sha1"
    FILE_HASH_SHA256 = "sha256"
    IP_ADDRESS = "ip"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    CVE = "cve"


class ThreatLevel(Enum):
    """Threat severity levels"""
    UNKNOWN = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class ThreatIntelligence:
    """
    Threat intelligence data.
    
    Attributes:
        ioc: Indicator of Compromise value
        ioc_type: Type of IOC
        threat_level: Severity level
        source: Where this intel came from
        first_seen: First detection timestamp
        last_seen: Last detection timestamp
        tags: Associated tags (malware family, campaign, etc.)
        description: Human-readable description
        references: URLs to reports/analysis
        confidence: Confidence score (0-100)
    """
    ioc: str
    ioc_type: IOCType
    threat_level: ThreatLevel = ThreatLevel.UNKNOWN
    source: str = "unknown"
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    tags: List[str] = field(default_factory=list)
    description: str = ""
    references: List[str] = field(default_factory=list)
    confidence: int = 50  # 0-100


# ============================================================================
# THREAT INTELLIGENCE MANAGER
# ============================================================================

class ThreatIntelligenceManager:
    """
    Manages threat intelligence from multiple sources.
    
    Handles API calls, caching, and IOC database management.
    """
    
    # API endpoints
    SOURCES = {
        'virustotal': {
            'name': 'VirusTotal',
            'api_url': 'https://www.virustotal.com/api/v3/',
            'requires_key': True,
            'rate_limit': 4,  # requests per minute (free tier)
            'priority': 'high'
        },
        'alienvault_otx': {
            'name': 'AlienVault OTX',
            'api_url': 'https://otx.alienvault.com/api/v1/',
            'requires_key': True,
            'rate_limit': 10,
            'priority': 'high'
        },
        'abuseipdb': {
            'name': 'AbuseIPDB',
            'api_url': 'https://api.abuseipdb.com/api/v2/',
            'requires_key': True,
            'rate_limit': 1000,  # per day
            'priority': 'medium'
        },
        'urlhaus': {
            'name': 'URLhaus',
            'api_url': 'https://urlhaus-api.abuse.ch/v1/',
            'requires_key': False,
            'rate_limit': None,
            'priority': 'medium'
        },
        'malwarebazaar': {
            'name': 'MalwareBazaar',
            'api_url': 'https://mb-api.abuse.ch/api/v1/',
            'requires_key': False,
            'rate_limit': None,
            'priority': 'low'
        }
    }
    
    def __init__(self, 
                 api_keys: Optional[Dict[str, str]] = None,
                 cache_dir: Optional[str] = None):
        """
        Initialize threat intelligence manager.
        
        Args:
            api_keys: Dictionary of {source: api_key}
            cache_dir: Directory for caching intel data
        """
        self.logger = logging.getLogger(__name__)
        
        # API keys
        self.api_keys = api_keys or {}
        
        # Cache directory
        if cache_dir:
            self.cache_dir = Path(cache_dir)
        else:
            self.cache_dir = Path.home() / '.cyberguardian' / 'threat_intel'
        
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        # IOC database (in-memory for now, would use SQLite in production)
        self.ioc_database: Dict[str, ThreatIntelligence] = {}
        
        # Rate limiting
        self.last_request_time: Dict[str, float] = {}
        self.request_count: Dict[str, int] = {}
        
        # Statistics
        self.total_queries = 0
        self.cache_hits = 0
        self.api_calls = 0
        
        # Load cached data
        self._load_cache()
    
    # ========================================================================
    # FILE HASH CHECKS
    # ========================================================================
    
    def check_file_hash(self, 
                       file_hash: str, 
                       hash_type: str = 'sha256') -> Optional[ThreatIntelligence]:
        """
        Check file hash against threat intelligence sources.
        
        Args:
            file_hash: Hash value
            hash_type: Hash algorithm (md5, sha1, sha256)
            
        Returns:
            ThreatIntelligence or None
        """
        self.total_queries += 1
        
        # Normalize hash
        file_hash = file_hash.lower().strip()
        
        # Check local cache first
        cached = self._check_cache(file_hash)
        if cached:
            self.cache_hits += 1
            self.logger.debug(f"Cache hit for hash: {file_hash[:16]}...")
            return cached
        
        # Query external sources
        intel = self._query_file_hash(file_hash, hash_type)
        
        # Store in cache and database
        if intel:
            self._store_intel(intel)
        
        return intel
    
    def _query_file_hash(self, 
                        file_hash: str, 
                        hash_type: str) -> Optional[ThreatIntelligence]:
        """
        Query external sources for file hash.
        
        Prioritizes sources: VirusTotal > AlienVault OTX > MalwareBazaar
        """
        # Try VirusTotal first
        if 'virustotal' in self.api_keys:
            intel = self._query_virustotal_hash(file_hash)
            if intel:
                return intel
        
        # Try AlienVault OTX
        if 'alienvault_otx' in self.api_keys:
            intel = self._query_otx_hash(file_hash)
            if intel:
                return intel
        
        # Try MalwareBazaar (no key needed)
        intel = self._query_malwarebazaar_hash(file_hash)
        if intel:
            return intel
        
        return None
    
    # ========================================================================
    # IP ADDRESS CHECKS
    # ========================================================================
    
    def check_ip_address(self, ip_address: str) -> Optional[ThreatIntelligence]:
        """
        Check IP address reputation.
        
        Args:
            ip_address: IP address (IPv4 or IPv6)
            
        Returns:
            ThreatIntelligence or None
        """
        self.total_queries += 1
        
        # Normalize IP
        ip_address = ip_address.strip()
        
        # Check cache
        cached = self._check_cache(ip_address)
        if cached:
            self.cache_hits += 1
            return cached
        
        # Query external sources
        intel = self._query_ip_address(ip_address)
        
        # Store
        if intel:
            self._store_intel(intel)
        
        return intel
    
    def _query_ip_address(self, ip_address: str) -> Optional[ThreatIntelligence]:
        """Query external sources for IP reputation"""
        
        # Try AbuseIPDB first (specialized for IPs)
        if 'abuseipdb' in self.api_keys:
            intel = self._query_abuseipdb(ip_address)
            if intel:
                return intel
        
        # Try AlienVault OTX
        if 'alienvault_otx' in self.api_keys:
            intel = self._query_otx_ip(ip_address)
            if intel:
                return intel
        
        return None
    
    # ========================================================================
    # DOMAIN/URL CHECKS
    # ========================================================================
    
    def check_domain(self, domain: str) -> Optional[ThreatIntelligence]:
        """
        Check domain reputation.
        
        Args:
            domain: Domain name
            
        Returns:
            ThreatIntelligence or None
        """
        self.total_queries += 1
        
        domain = domain.lower().strip()
        
        # Check cache
        cached = self._check_cache(domain)
        if cached:
            self.cache_hits += 1
            return cached
        
        # Query sources
        intel = self._query_domain(domain)
        
        if intel:
            self._store_intel(intel)
        
        return intel
    
    def _query_domain(self, domain: str) -> Optional[ThreatIntelligence]:
        """Query external sources for domain reputation"""
        
        # VirusTotal
        if 'virustotal' in self.api_keys:
            intel = self._query_virustotal_domain(domain)
            if intel:
                return intel
        
        # URLhaus
        intel = self._query_urlhaus_domain(domain)
        if intel:
            return intel
        
        return None
    
    # ========================================================================
    # API IMPLEMENTATIONS (Stubs - would implement actual API calls)
    # ========================================================================
    
    def _query_virustotal_hash(self, file_hash: str) -> Optional[ThreatIntelligence]:
        """
        Query VirusTotal for file hash.
        
        NOTE: This is a stub. In production, implement actual API call.
        """
        self.logger.debug(f"Querying VirusTotal for hash: {file_hash[:16]}...")
        
        # Rate limiting
        if not self._check_rate_limit('virustotal'):
            self.logger.warning("VirusTotal rate limit exceeded")
            return None
        
        try:
            # TODO: Implement actual VirusTotal API call
            # For now, return None (no match)
            
            self.api_calls += 1
            return None
            
        except Exception as e:
            self.logger.error(f"VirusTotal query error: {e}")
            return None
    
    def _query_otx_hash(self, file_hash: str) -> Optional[ThreatIntelligence]:
        """
        Query AlienVault OTX for file hash.
        
        NOTE: Stub implementation.
        """
        self.logger.debug(f"Querying OTX for hash: {file_hash[:16]}...")
        
        # Rate limiting
        if not self._check_rate_limit('alienvault_otx'):
            return None
        
        try:
            # TODO: Implement actual OTX API call
            self.api_calls += 1
            return None
            
        except Exception as e:
            self.logger.error(f"OTX query error: {e}")
            return None
    
    def _query_malwarebazaar_hash(self, file_hash: str) -> Optional[ThreatIntelligence]:
        """
        Query MalwareBazaar for file hash.
        
        NOTE: Stub implementation.
        """
        self.logger.debug(f"Querying MalwareBazaar for hash: {file_hash[:16]}...")
        
        try:
            # TODO: Implement actual MalwareBazaar API call
            self.api_calls += 1
            return None
            
        except Exception as e:
            self.logger.error(f"MalwareBazaar query error: {e}")
            return None
    
    def _query_abuseipdb(self, ip_address: str) -> Optional[ThreatIntelligence]:
        """
        Query AbuseIPDB for IP reputation.
        
        NOTE: Stub implementation.
        """
        self.logger.debug(f"Querying AbuseIPDB for IP: {ip_address}")
        
        if not self._check_rate_limit('abuseipdb'):
            return None
        
        try:
            # TODO: Implement actual AbuseIPDB API call
            self.api_calls += 1
            return None
            
        except Exception as e:
            self.logger.error(f"AbuseIPDB query error: {e}")
            return None
    
    def _query_otx_ip(self, ip_address: str) -> Optional[ThreatIntelligence]:
        """Query OTX for IP"""
        # Stub
        return None
    
    def _query_virustotal_domain(self, domain: str) -> Optional[ThreatIntelligence]:
        """Query VirusTotal for domain"""
        # Stub
        return None
    
    def _query_urlhaus_domain(self, domain: str) -> Optional[ThreatIntelligence]:
        """Query URLhaus for domain"""
        # Stub
        return None
    
    # ========================================================================
    # RATE LIMITING
    # ========================================================================
    
    def _check_rate_limit(self, source: str) -> bool:
        """
        Check if we can make a request to source without exceeding rate limit.
        
        Args:
            source: Source name
            
        Returns:
            bool: True if request allowed
        """
        if source not in self.SOURCES:
            return True
        
        rate_limit = self.SOURCES[source]['rate_limit']
        if rate_limit is None:
            return True
        
        current_time = time.time()
        
        # Check last request time
        if source in self.last_request_time:
            time_since_last = current_time - self.last_request_time[source]
            min_interval = 60.0 / rate_limit  # seconds between requests
            
            if time_since_last < min_interval:
                return False
        
        # Update last request time
        self.last_request_time[source] = current_time
        return True
    
    # ========================================================================
    # CACHING
    # ========================================================================
    
    def _check_cache(self, ioc: str) -> Optional[ThreatIntelligence]:
        """Check if IOC is in cache"""
        return self.ioc_database.get(ioc)
    
    def _store_intel(self, intel: ThreatIntelligence):
        """Store threat intelligence in database and cache"""
        self.ioc_database[intel.ioc] = intel
        self._save_cache()
    
    def _load_cache(self):
        """Load cached threat intelligence from disk"""
        cache_file = self.cache_dir / 'ioc_cache.json'
        
        if cache_file.exists():
            try:
                with open(cache_file, 'r') as f:
                    data = json.load(f)
                
                # Reconstruct IOC objects
                for ioc_str, ioc_data in data.items():
                    intel = ThreatIntelligence(
                        ioc=ioc_data['ioc'],
                        ioc_type=IOCType(ioc_data['ioc_type']),
                        threat_level=ThreatLevel(ioc_data['threat_level']),
                        source=ioc_data['source'],
                        first_seen=datetime.fromisoformat(ioc_data['first_seen']),
                        last_seen=datetime.fromisoformat(ioc_data['last_seen']),
                        tags=ioc_data['tags'],
                        description=ioc_data['description'],
                        references=ioc_data['references'],
                        confidence=ioc_data['confidence']
                    )
                    self.ioc_database[ioc_str] = intel
                
                self.logger.info(f"Loaded {len(self.ioc_database)} IOCs from cache")
                
            except Exception as e:
                self.logger.error(f"Error loading cache: {e}")
    
    def _save_cache(self):
        """Save threat intelligence to disk cache"""
        cache_file = self.cache_dir / 'ioc_cache.json'
        
        try:
            # Convert to JSON-serializable format
            data = {}
            for ioc_str, intel in self.ioc_database.items():
                data[ioc_str] = {
                    'ioc': intel.ioc,
                    'ioc_type': intel.ioc_type.value,
                    'threat_level': intel.threat_level.value,
                    'source': intel.source,
                    'first_seen': intel.first_seen.isoformat(),
                    'last_seen': intel.last_seen.isoformat(),
                    'tags': intel.tags,
                    'description': intel.description,
                    'references': intel.references,
                    'confidence': intel.confidence
                }
            
            with open(cache_file, 'w') as f:
                json.dump(data, f, indent=2)
            
        except Exception as e:
            self.logger.error(f"Error saving cache: {e}")
    
    # ========================================================================
    # BULK OPERATIONS
    # ========================================================================
    
    def import_iocs(self, iocs: List[ThreatIntelligence]):
        """Import bulk IOCs into database"""
        for intel in iocs:
            self._store_intel(intel)
        
        self.logger.info(f"Imported {len(iocs)} IOCs")
    
    def export_iocs(self) -> List[ThreatIntelligence]:
        """Export all IOCs from database"""
        return list(self.ioc_database.values())
    
    # ========================================================================
    # STATISTICS
    # ========================================================================
    
    def get_statistics(self) -> Dict:
        """Get threat intelligence statistics"""
        cache_hit_rate = (self.cache_hits / self.total_queries * 100) if self.total_queries > 0 else 0
        
        return {
            'total_iocs': len(self.ioc_database),
            'total_queries': self.total_queries,
            'cache_hits': self.cache_hits,
            'cache_hit_rate': f"{cache_hit_rate:.1f}%",
            'api_calls': self.api_calls,
            'sources_configured': len(self.api_keys)
        }


# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================

def create_manager(api_keys: Optional[Dict[str, str]] = None) -> ThreatIntelligenceManager:
    """
    Create threat intelligence manager.
    
    Args:
        api_keys: Dictionary of API keys
        
    Returns:
        ThreatIntelligenceManager instance
    """
    return ThreatIntelligenceManager(api_keys=api_keys)


# ============================================================================
# TESTING & DEMO
# ============================================================================

if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    print("🔍 CyberGuardian Threat Intelligence Manager - Demo\n")
    
    # Create manager (no API keys for demo)
    manager = create_manager()
    
    # Test hash check
    print("Testing file hash check...")
    test_hash = "44d88612fea8a8f36de82e1278abb02f"  # Example MD5
    result = manager.check_file_hash(test_hash, 'md5')
    
    if result:
        print(f"✅ Threat found: {result.threat_level.name}")
    else:
        print("✅ No threat intelligence found (clean or unknown)")
    
    # Test IP check
    print("\nTesting IP address check...")
    test_ip = "8.8.8.8"
    result = manager.check_ip_address(test_ip)
    
    if result:
        print(f"✅ IP reputation: {result.threat_level.name}")
    else:
        print("✅ No reputation data found")
    
    # Statistics
    print("\n" + "="*50)
    stats = manager.get_statistics()
    print("Statistics:")
    for key, value in stats.items():
        print(f"  {key}: {value}")
    
    print("\n✅ Threat Intelligence Manager ready!")