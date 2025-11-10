"""
Seed IOC Database with sample threat intelligence data
"""

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

from database import db

def seed_iocs():
    """Add sample IOCs for testing"""
    
    sample_iocs = [
        # Malicious IPs
        {
            "ioc_value": "185.220.101.1",
            "ioc_type": "ip",
            "threat_type": "c2",
            "threat_name": "TOR Exit Node",
            "severity": "medium",
            "confidence": 85.0,
            "source": "AbuseIPDB",
            "description": "Known TOR exit node used for malicious activities"
        },
        {
            "ioc_value": "45.142.212.61",
            "ioc_type": "ip",
            "threat_type": "botnet",
            "threat_name": "Mirai Botnet",
            "severity": "high",
            "confidence": 95.0,
            "source": "Threat Feed",
            "description": "Active Mirai botnet C2 server"
        },
        
        # Malicious Domains
        {
            "ioc_value": "malware-distribution.com",
            "ioc_type": "domain",
            "threat_type": "malware",
            "threat_name": "Malware Distribution Site",
            "severity": "high",
            "confidence": 90.0,
            "source": "URLhaus",
            "description": "Known malware distribution domain"
        },
        {
            "ioc_value": "phishing-bank-login.net",
            "ioc_type": "domain",
            "threat_type": "phishing",
            "threat_name": "Banking Phishing",
            "severity": "critical",
            "confidence": 98.0,
            "source": "PhishTank",
            "description": "Active phishing site targeting banking credentials"
        },
        
        # Malware Hashes
        {
            "ioc_value": "44d88612fea8a8f36de82e1278abb02f",
            "ioc_type": "hash",
            "threat_type": "malware",
            "threat_name": "EICAR Test File",
            "severity": "low",
            "confidence": 100.0,
            "source": "Test",
            "description": "EICAR antivirus test file (harmless)"
        },
        {
            "ioc_value": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            "ioc_type": "hash",
            "threat_type": "ransomware",
            "threat_name": "WannaCry",
            "severity": "critical",
            "confidence": 100.0,
            "source": "VirusTotal",
            "description": "WannaCry ransomware sample",
            "mitre_tactics": ["Initial Access", "Impact"],
            "mitre_techniques": ["T1566", "T1486"]
        },
        
        # Malicious URLs
        {
            "ioc_value": "http://malicious-site.xyz/payload.exe",
            "ioc_type": "url",
            "threat_type": "malware",
            "threat_name": "Trojan Dropper",
            "severity": "high",
            "confidence": 92.0,
            "source": "URLhaus",
            "description": "URL distributing trojan dropper"
        },
        
        # APT-related
        {
            "ioc_value": "apt-command.control",
            "ioc_type": "domain",
            "threat_type": "apt",
            "threat_name": "APT28 Infrastructure",
            "severity": "critical",
            "confidence": 95.0,
            "source": "Mandiant",
            "description": "Known APT28 command and control domain",
            "mitre_tactics": ["Command and Control"],
            "mitre_techniques": ["T1071"],
            "tags": ["apt28", "russia", "espionage"]
        },
        
        # Cryptocurrency Mining
        {
            "ioc_value": "cryptominer-pool.net",
            "ioc_type": "domain",
            "threat_type": "cryptominer",
            "threat_name": "Coinhive Alternative",
            "severity": "medium",
            "confidence": 80.0,
            "source": "CryptoScamDB",
            "description": "Cryptomining pool used by malware"
        },
        
        # More IPs
        {
            "ioc_value": "192.0.2.123",
            "ioc_type": "ip",
            "threat_type": "scanner",
            "threat_name": "Port Scanner",
            "severity": "low",
            "confidence": 70.0,
            "source": "Honeypot",
            "description": "IP conducting port scanning activities"
        }
    ]
    
    print("🔧 Seeding IOC database...")
    
    for ioc_data in sample_iocs:
        try:
            ioc_id = db.add_ioc(**ioc_data)
            print(f"✅ Added: {ioc_data['ioc_type']}:{ioc_data['ioc_value']} (ID: {ioc_id})")
        except Exception as e:
            print(f"❌ Error adding {ioc_data['ioc_value']}: {e}")
    
    print("\n📊 IOC Statistics:")
    stats = db.get_ioc_statistics()
    print(f"  Total IOCs: {stats['total_iocs']}")
    print(f"  By Type: {stats['iocs_by_type']}")
    print(f"  By Severity: {stats['iocs_by_severity']}")
    print("\n✅ Seeding complete!")

if __name__ == "__main__":
    seed_iocs()