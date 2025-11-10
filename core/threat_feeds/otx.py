"""
CyberGuardian AI - AlienVault OTX Threat Feed
Fetch threat intelligence from Open Threat Exchange
"""

from OTXv2 import OTXv2
import logging
from typing import List, Dict, Optional
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class OTXFeed:
    """
    AlienVault OTX Threat Feed Connector
    
    Free tier: Unlimited (with rate limiting)
    API: https://otx.alienvault.com/api
    """
    
    def __init__(self, api_key: Optional[str] = None):
        """Initialize OTX connector"""
        self.api_key = api_key or "YOUR_OTX_KEY_HERE"
        
        try:
            self.otx = OTXv2(self.api_key)
            self.connected = True
        except Exception as e:
            logger.error(f"Failed to initialize OTX: {e}")
            self.connected = False
    
    def get_pulses(self, modified_since: Optional[datetime] = None, limit: int = 50) -> List[Dict]:
        """
        Get threat pulses (collections of IOCs)
        
        Args:
            modified_since: Only get pulses modified after this date
            limit: Max number of pulses
            
        Returns:
            List of IOCs from pulses
        """
        if not self.connected:
            return []
        
        try:
            # Get subscribed pulses
            if modified_since:
                pulses = self.otx.getall(modified_since=modified_since.isoformat(), limit=limit)
            else:
                pulses = self.otx.getall(limit=limit)
            
            iocs = []
            
            for pulse in pulses:
                pulse_name = pulse.get('name', 'Unknown Pulse')
                pulse_tags = pulse.get('tags', [])
                
                # Extract IOCs from pulse
                for indicator in pulse.get('indicators', []):
                    ioc_type = self._map_indicator_type(indicator.get('type'))
                    
                    if ioc_type:
                        iocs.append({
                            'ioc_value': indicator.get('indicator'),
                            'ioc_type': ioc_type,
                            'threat_type': self._extract_threat_type(pulse_tags),
                            'threat_name': pulse_name,
                            'severity': self._calculate_severity(pulse),
                            'confidence': 75.0,  # Default confidence for OTX
                            'source': 'AlienVault OTX',
                            'source_url': f"https://otx.alienvault.com/pulse/{pulse.get('id', '')}",
                            'description': pulse.get('description', '')[:500],
                            'tags': pulse_tags[:5]  # Limit to 5 tags
                        })
            
            logger.info(f"Fetched {len(iocs)} IOCs from {len(pulses)} OTX pulses")
            return iocs
        
        except Exception as e:
            logger.error(f"OTX pulse fetch failed: {e}")
            return []
    
    def check_ip(self, ip_address: str) -> Optional[Dict]:
        """
        Check IP reputation
        
        Args:
            ip_address: IP to check
            
        Returns:
            Threat data or None
        """
        if not self.connected:
            return None
        
        try:
            indicators = self.otx.get_indicator_details_full(
                indicator_type='IPv4',
                indicator=ip_address
            )
            
            # Check if IP has malicious indicators
            general = indicators.get('general', {})
            pulse_count = general.get('pulse_info', {}).get('count', 0)
            
            if pulse_count > 0:
                pulses = general.get('pulse_info', {}).get('pulses', [])
                first_pulse = pulses[0] if pulses else {}
                
                return {
                    'ioc_value': ip_address,
                    'ioc_type': 'ip',
                    'threat_type': 'malicious_ip',
                    'threat_name': first_pulse.get('name', 'OTX Threat'),
                    'severity': 'high' if pulse_count > 5 else 'medium',
                    'confidence': min(pulse_count * 10, 100),
                    'source': 'AlienVault OTX',
                    'description': f"Found in {pulse_count} threat pulses"
                }
            
            return None
        
        except Exception as e:
            logger.error(f"OTX IP check failed for {ip_address}: {e}")
            return None
    
    def check_domain(self, domain: str) -> Optional[Dict]:
        """
        Check domain reputation
        
        Args:
            domain: Domain to check
            
        Returns:
            Threat data or None
        """
        if not self.connected:
            return None
        
        try:
            indicators = self.otx.get_indicator_details_full(
                indicator_type='domain',
                indicator=domain
            )
            
            general = indicators.get('general', {})
            pulse_count = general.get('pulse_info', {}).get('count', 0)
            
            if pulse_count > 0:
                pulses = general.get('pulse_info', {}).get('pulses', [])
                first_pulse = pulses[0] if pulses else {}
                
                return {
                    'ioc_value': domain,
                    'ioc_type': 'domain',
                    'threat_type': 'malicious_domain',
                    'threat_name': first_pulse.get('name', 'OTX Threat'),
                    'severity': 'high' if pulse_count > 5 else 'medium',
                    'confidence': min(pulse_count * 10, 100),
                    'source': 'AlienVault OTX',
                    'description': f"Found in {pulse_count} threat pulses"
                }
            
            return None
        
        except Exception as e:
            logger.error(f"OTX domain check failed for {domain}: {e}")
            return None
    
    def _map_indicator_type(self, otx_type: str) -> Optional[str]:
        """Map OTX indicator type to our IOC type"""
        mapping = {
            'IPv4': 'ip',
            'IPv6': 'ip',
            'domain': 'domain',
            'hostname': 'domain',
            'URL': 'url',
            'FileHash-MD5': 'hash',
            'FileHash-SHA1': 'hash',
            'FileHash-SHA256': 'hash',
            'email': 'email'
        }
        return mapping.get(otx_type)
    
    def _extract_threat_type(self, tags: List[str]) -> str:
        """Extract threat type from tags"""
        threat_keywords = {
            'malware': 'malware',
            'ransomware': 'ransomware',
            'trojan': 'trojan',
            'apt': 'apt',
            'phishing': 'phishing',
            'botnet': 'botnet',
            'c2': 'c2'
        }
        
        for tag in tags:
            tag_lower = tag.lower()
            for keyword, threat_type in threat_keywords.items():
                if keyword in tag_lower:
                    return threat_type
        
        return 'malicious'
    
    def _calculate_severity(self, pulse: Dict) -> str:
        """Calculate severity from pulse data"""
        tags = [t.lower() for t in pulse.get('tags', [])]
        
        critical_keywords = ['apt', 'ransomware', 'critical']
        high_keywords = ['malware', 'trojan', 'botnet']
        
        if any(kw in ' '.join(tags) for kw in critical_keywords):
            return 'critical'
        elif any(kw in ' '.join(tags) for kw in high_keywords):
            return 'high'
        else:
            return 'medium'
    
    def test_connection(self) -> bool:
        """Test OTX connection"""
        return self.connected


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    print("🔍 Testing AlienVault OTX Feed\n")
    
    feed = OTXFeed()
    
    if feed.test_connection():
        print("✅ Connected to OTX")
        
        # Get recent pulses
        print("\n📡 Fetching recent pulses...")
        iocs = feed.get_pulses(limit=5)
        print(f"✅ Fetched {len(iocs)} IOCs from pulses")
        
        if iocs:
            print(f"\nSample IOC:")
            sample = iocs[0]
            print(f"  Type: {sample['ioc_type']}")
            print(f"  Value: {sample['ioc_value']}")
            print(f"  Threat: {sample['threat_name']}")
            print(f"  Severity: {sample['severity']}")
    else:
        print("❌ Failed to connect to OTX")