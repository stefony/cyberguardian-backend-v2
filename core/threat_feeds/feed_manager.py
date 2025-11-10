"""
CyberGuardian AI - Threat Feed Manager
Manages automatic threat feed updates
"""

import logging
from typing import List, Dict, Optional
from datetime import datetime
import sys
from pathlib import Path

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent.parent))

from database import db
from core.threat_feeds.abuseipdb import AbuseIPDBFeed
from core.threat_feeds.otx import OTXFeed

logger = logging.getLogger(__name__)

class ThreatFeedManager:
    """
    Threat Feed Manager
    
    Orchestrates multiple threat feeds:
    - AbuseIPDB
    - AlienVault OTX
    - URLhaus (future)
    - PhishTank (future)
    """
    
    def __init__(
        self,
        abuseipdb_key: Optional[str] = None,
        otx_key: Optional[str] = None
    ):
        """Initialize feed manager"""
        self.feeds = {}
        
        # Initialize AbuseIPDB
        try:
            self.feeds['abuseipdb'] = AbuseIPDBFeed(api_key=abuseipdb_key)
            logger.info("✅ AbuseIPDB feed initialized")
        except Exception as e:
            logger.error(f"Failed to initialize AbuseIPDB: {e}")
        
        # Initialize OTX
        try:
            self.feeds['otx'] = OTXFeed(api_key=otx_key)
            logger.info("✅ OTX feed initialized")
        except Exception as e:
            logger.error(f"Failed to initialize OTX: {e}")
        
        self.update_stats = {
            'total_fetched': 0,
            'total_added': 0,
            'total_updated': 0,
            'errors': 0,
            'last_update': None
        }
    
    def update_all_feeds(self, limit_per_feed: int = 100) -> Dict:
        """
        Update IOCs from all feeds
        
        Args:
            limit_per_feed: Max IOCs per feed
            
        Returns:
            Update statistics
        """
        logger.info("🔄 Starting threat feed update...")
        
        results = {
            'feeds_updated': [],
            'total_iocs_fetched': 0,
            'total_iocs_added': 0,
            'errors': []
        }
        
        # Update AbuseIPDB
        if 'abuseipdb' in self.feeds:
            try:
                logger.info("Updating AbuseIPDB feed...")
                iocs = self.feeds['abuseipdb'].get_blacklist(
                    confidence_minimum=80,
                    limit=limit_per_feed
                )
                
                added = self._import_iocs(iocs)
                
                results['feeds_updated'].append('abuseipdb')
                results['total_iocs_fetched'] += len(iocs)
                results['total_iocs_added'] += added
                
                logger.info(f"✅ AbuseIPDB: {added}/{len(iocs)} IOCs added")
            
            except Exception as e:
                error_msg = f"AbuseIPDB update failed: {e}"
                logger.error(error_msg)
                results['errors'].append(error_msg)
        
        # Update OTX
        if 'otx' in self.feeds:
            try:
                logger.info("Updating OTX feed...")
                iocs = self.feeds['otx'].get_pulses(limit=limit_per_feed)
                
                added = self._import_iocs(iocs)
                
                results['feeds_updated'].append('otx')
                results['total_iocs_fetched'] += len(iocs)
                results['total_iocs_added'] += added
                
                logger.info(f"✅ OTX: {added}/{len(iocs)} IOCs added")
            
            except Exception as e:
                error_msg = f"OTX update failed: {e}"
                logger.error(error_msg)
                results['errors'].append(error_msg)
        
        # Update stats
        self.update_stats['total_fetched'] = results['total_iocs_fetched']
        self.update_stats['total_added'] = results['total_iocs_added']
        self.update_stats['last_update'] = datetime.now().isoformat()
        
        logger.info(f"✅ Feed update complete: {results['total_iocs_added']} IOCs added")
        
        return results
    
    def _import_iocs(self, iocs: List[Dict]) -> int:
        """
        Import IOCs into database
        
        Args:
            iocs: List of IOC dicts
            
        Returns:
            Number of IOCs added
        """
        added_count = 0
        
        for ioc_data in iocs:
            try:
                ioc_id = db.add_ioc(**ioc_data)
                if ioc_id > 0:
                    added_count += 1
            except Exception as e:
                logger.debug(f"Failed to add IOC {ioc_data.get('ioc_value')}: {e}")
                continue
        
        return added_count
    
    def check_value(self, value: str, check_feeds: bool = True) -> Dict:
        """
        Check value against database and optionally live feeds
        
        Args:
            value: Value to check (IP, domain, hash)
            check_feeds: Also check live feeds if not in DB
            
        Returns:
            Threat information
        """
        # First check database
        db_result = db.check_ioc(value)
        
        if db_result['is_threat']:
            return db_result
        
        # If not in DB and live check enabled, query feeds
        if check_feeds:
            # Detect type and check appropriate feeds
            if self._is_ip(value):
                return self._check_ip_feeds(value)
            elif self._is_domain(value):
                return self._check_domain_feeds(value)
        
        return {
            'is_threat': False,
            'message': 'No threat found in database or feeds'
        }
    
    def _check_ip_feeds(self, ip: str) -> Dict:
        """Check IP against all feeds"""
        # Try AbuseIPDB
        if 'abuseipdb' in self.feeds:
            result = self.feeds['abuseipdb'].check_ip(ip)
            if result:
                # Add to database
                db.add_ioc(**result)
                return {
                    'is_threat': True,
                    'source': 'AbuseIPDB (Live)',
                    'threat_type': result['threat_type'],
                    'severity': result['severity'],
                    'confidence': result['confidence']
                }
        
        # Try OTX
        if 'otx' in self.feeds:
            result = self.feeds['otx'].check_ip(ip)
            if result:
                db.add_ioc(**result)
                return {
                    'is_threat': True,
                    'source': 'OTX (Live)',
                    'threat_type': result['threat_type'],
                    'severity': result['severity'],
                    'confidence': result['confidence']
                }
        
        return {'is_threat': False}
    
    def _check_domain_feeds(self, domain: str) -> Dict:
        """Check domain against all feeds"""
        # Try OTX
        if 'otx' in self.feeds:
            result = self.feeds['otx'].check_domain(domain)
            if result:
                db.add_ioc(**result)
                return {
                    'is_threat': True,
                    'source': 'OTX (Live)',
                    'threat_type': result['threat_type'],
                    'severity': result['severity'],
                    'confidence': result['confidence']
                }
        
        return {'is_threat': False}
    
    def _is_ip(self, value: str) -> bool:
        """Check if value is IP address"""
        import re
        return bool(re.match(r'^(\d{1,3}\.){3}\d{1,3}$', value))
    
    def _is_domain(self, value: str) -> bool:
        """Check if value is domain"""
        import re
        return bool(re.match(r'^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$', value))
    
    def get_statistics(self) -> Dict:
        """Get feed manager statistics"""
        db_stats = db.get_ioc_statistics()
        
        return {
            'database_iocs': db_stats['total_iocs'],
            'feeds_active': len(self.feeds),
            'feeds_available': list(self.feeds.keys()),
            'last_update': self.update_stats['last_update'],
            'total_fetched': self.update_stats['total_fetched'],
            'total_added': self.update_stats['total_added']
        }


# Example usage
if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    print("🔧 Testing Threat Feed Manager\n")
    
    manager = ThreatFeedManager()
    
    print("📊 Manager Statistics:")
    stats = manager.get_statistics()
    for key, value in stats.items():
        print(f"  {key}: {value}")
    
    print("\n🔄 Updating feeds (limiting to 10 IOCs per feed for test)...")
    results = manager.update_all_feeds(limit_per_feed=10)
    
    print(f"\n✅ Update Complete:")
    print(f"  Feeds updated: {', '.join(results['feeds_updated'])}")
    print(f"  IOCs fetched: {results['total_iocs_fetched']}")
    print(f"  IOCs added: {results['total_iocs_added']}")
    
    if results['errors']:
        print(f"\n⚠️ Errors:")
        for error in results['errors']:
            print(f"  - {error}")