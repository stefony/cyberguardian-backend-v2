"""
CyberGuardian AI - AbuseIPDB Threat Feed
Fetch malicious IPs from AbuseIPDB
"""

import requests
import logging
from typing import List, Dict, Optional
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class AbuseIPDBFeed:
    """
    AbuseIPDB Threat Feed Connector
    
    Free tier: 1000 requests/day
    API: https://www.abuseipdb.com/api/v2
    """
    
    BASE_URL = "https://api.abuseipdb.com/api/v2"
    
    def __init__(self, api_key: Optional[str] = None):
        """Initialize AbuseIPDB connector"""
        self.api_key = api_key or "YOUR_API_KEY_HERE"  # Will be configurable
        self.session = requests.Session()
        self.session.headers.update({
            'Key': self.api_key,
            'Accept': 'application/json'
        })
    
    def check_ip(self, ip_address: str, max_age_days: int = 90) -> Optional[Dict]:
        """
        Check if IP is malicious
        
        Args:
            ip_address: IP to check
            max_age_days: Max age of reports
            
        Returns:
            Threat data or None
        """
        try:
            response = self.session.get(
                f"{self.BASE_URL}/check",
                params={
                    'ipAddress': ip_address,
                    'maxAgeInDays': max_age_days,
                    'verbose': ''
                },
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('data', {}).get('abuseConfidenceScore', 0) > 0:
                    ip_data = data['data']
                    
                    # Convert to our IOC format
                    return {
                        'ioc_value': ip_address,
                        'ioc_type': 'ip',
                        'threat_type': 'malicious_ip',
                        'threat_name': f"AbuseIPDB Report ({ip_data.get('usageType', 'Unknown')})",
                        'severity': self._calculate_severity(ip_data.get('abuseConfidenceScore', 0)),
                        'confidence': float(ip_data.get('abuseConfidenceScore', 0)),
                        'source': 'AbuseIPDB',
                        'source_url': f"https://www.abuseipdb.com/check/{ip_address}",
                        'description': f"Total reports: {ip_data.get('totalReports', 0)}, "
                                     f"Country: {ip_data.get('countryCode', 'Unknown')}, "
                                     f"ISP: {ip_data.get('isp', 'Unknown')}"
                    }
            
            return None
        
        except Exception as e:
            logger.error(f"AbuseIPDB check failed for {ip_address}: {e}")
            return None
    
    def get_blacklist(self, confidence_minimum: int = 90, limit: int = 100) -> List[Dict]:
        """
        Get blacklisted IPs
        
        Args:
            confidence_minimum: Minimum confidence score (0-100)
            limit: Number of IPs to fetch
            
        Returns:
            List of IOCs
        """
        try:
            response = self.session.get(
                f"{self.BASE_URL}/blacklist",
                params={
                    'confidenceMinimum': confidence_minimum,
                    'limit': limit
                },
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                iocs = []
                
                for ip_data in data.get('data', []):
                    iocs.append({
                        'ioc_value': ip_data['ipAddress'],
                        'ioc_type': 'ip',
                        'threat_type': 'malicious_ip',
                        'threat_name': 'AbuseIPDB Blacklist',
                        'severity': self._calculate_severity(ip_data.get('abuseConfidenceScore', 0)),
                        'confidence': float(ip_data.get('abuseConfidenceScore', 0)),
                        'source': 'AbuseIPDB',
                        'source_url': f"https://www.abuseipdb.com/check/{ip_data['ipAddress']}",
                        'description': f"Country: {ip_data.get('countryCode', 'Unknown')}"
                    })
                
                logger.info(f"Fetched {len(iocs)} IPs from AbuseIPDB blacklist")
                return iocs
            
            return []
        
        except Exception as e:
            logger.error(f"AbuseIPDB blacklist fetch failed: {e}")
            return []
    
    def _calculate_severity(self, confidence_score: float) -> str:
        """Calculate severity from confidence score"""
        if confidence_score >= 90:
            return 'critical'
        elif confidence_score >= 75:
            return 'high'
        elif confidence_score >= 50:
            return 'medium'
        else:
            return 'low'
    
    def test_connection(self) -> bool:
        """Test API connection"""
        try:
            response = self.session.get(
                f"{self.BASE_URL}/check",
                params={'ipAddress': '8.8.8.8', 'maxAgeInDays': 90},
                timeout=10
            )
            return response.status_code in [200, 429]  # 429 = rate limited but valid
        except Exception as e:
            logger.error(f"AbuseIPDB connection test failed: {e}")
            return False


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    print("🔍 Testing AbuseIPDB Feed\n")
    
    feed = AbuseIPDBFeed()
    
    # Test connection
    print("Testing connection...")
    if feed.test_connection():
        print("✅ Connection successful")
    else:
        print("❌ Connection failed")
    
    # Check specific IP
    print("\n🔍 Checking IP: 45.142.212.61")
    result = feed.check_ip("45.142.212.61")
    if result:
        print(f"✅ Threat found:")
        print(f"  Severity: {result['severity']}")
        print(f"  Confidence: {result['confidence']}%")
        print(f"  Description: {result['description']}")
    else:
        print("✅ IP is clean or API key not configured")