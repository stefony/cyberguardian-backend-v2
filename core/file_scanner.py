"""
CyberGuardian AI - Real File Scanner
VirusTotal Integration & Hash Analysis

Provides real file scanning capabilities:
- File hash calculation (MD5, SHA1, SHA256)
- VirusTotal API integration
- File type detection using puremagic (no system dependencies)
- Malware analysis
"""

import os
import hashlib
import puremagic
import vt
from typing import Dict, Any, Optional
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv
import nest_asyncio

nest_asyncio.apply()

# Load environment variables
load_dotenv()

# VirusTotal API Key
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")


class FileScanner:
    """Real file scanner with VirusTotal integration"""
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize file scanner
        
        Args:
            api_key: VirusTotal API key (optional, loads from .env if not provided)
        """
        self.api_key = api_key or VT_API_KEY
        
        if not self.api_key:
            raise ValueError("VirusTotal API key not found. Set VIRUSTOTAL_API_KEY in .env file")
        
        self.client = vt.Client(self.api_key)
    
    def calculate_hashes(self, file_path: str) -> Dict[str, str]:
        """
        Calculate file hashes (MD5, SHA1, SHA256)
        
        Args:
            file_path: Path to file
        
        Returns:
            Dictionary with hash values
        """
        md5_hash = hashlib.md5()
        sha1_hash = hashlib.sha1()
        sha256_hash = hashlib.sha256()
        
        try:
            with open(file_path, 'rb') as f:
                # Read file in chunks for large files
                for chunk in iter(lambda: f.read(4096), b''):
                    md5_hash.update(chunk)
                    sha1_hash.update(chunk)
                    sha256_hash.update(chunk)
            
            return {
                "md5": md5_hash.hexdigest(),
                "sha1": sha1_hash.hexdigest(),
                "sha256": sha256_hash.hexdigest()
            }
        except Exception as e:
            raise Exception(f"Error calculating hashes: {str(e)}")
    
    def detect_file_type(self, file_path: str) -> str:
        """
        Detect file MIME type using puremagic (no system dependencies)
        
        Args:
            file_path: Path to file
        
        Returns:
            File MIME type
        """
        try:
            # Use puremagic to detect file type
            result = puremagic.magic_file(file_path)
            if result:
                # Return the first match's mime type
                return result[0].mime_type if hasattr(result[0], 'mime_type') else result[0].extension
            return "application/octet-stream"
        except Exception as e:
            return "application/octet-stream"
    
    def scan_file(self, file_path: str) -> Dict[str, Any]:
        """
        Scan file with VirusTotal
        
        Args:
            file_path: Path to file to scan
        
        Returns:
            Scan results dictionary
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        try:
            # Calculate hashes
            hashes = self.calculate_hashes(file_path)
            sha256 = hashes["sha256"]
            
            # Get file info
            file_size = os.path.getsize(file_path)
            file_name = os.path.basename(file_path)
            file_type = self.detect_file_type(file_path)
            
            # First, check if file hash exists in VirusTotal
            try:
                file_obj = self.client.get_object(f"/files/{sha256}")
                
                # File already scanned, get results
                stats = file_obj.last_analysis_stats
                results = file_obj.last_analysis_results
                
                # Calculate threat score
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                total = sum(stats.values())
                
                threat_score = 0
                if total > 0:
                    threat_score = int(((malicious + suspicious * 0.5) / total) * 100)
                
                # Determine severity
                if malicious > 5:
                    severity = "critical"
                elif malicious > 0 or suspicious > 3:
                    severity = "high"
                elif suspicious > 0:
                    severity = "medium"
                else:
                    severity = "clean"
                
                # Extract detections
                detections = []
                for engine, result in results.items():
                    if result['category'] in ['malicious', 'suspicious']:
                        detections.append({
                            "engine": engine,
                            "category": result['category'],
                            "result": result.get('result', 'Unknown')
                        })
                
                return {
                    "success": True,
                    "file_name": file_name,
                    "file_size": file_size,
                    "file_type": file_type,
                    "hashes": hashes,
                    "scan_date": datetime.now().isoformat(),
                    "threat_score": threat_score,
                    "severity": severity,
                    "stats": {
                        "malicious": stats.get('malicious', 0),
                        "suspicious": stats.get('suspicious', 0),
                        "undetected": stats.get('undetected', 0),
                        "harmless": stats.get('harmless', 0),
                        "timeout": stats.get('timeout', 0),
                        "total_engines": total
                    },
                    "detections": detections[:10],  # Top 10 detections
                    "vt_link": f"https://www.virustotal.com/gui/file/{sha256}",
                    "scan_type": "hash_lookup"
                }
                
            except vt.error.APIError as e:
                if e.code == "NotFoundError":
                    # File not in VirusTotal database, upload and scan
                    with open(file_path, 'rb') as f:
                        analysis = self.client.scan_file(f)
                    
                    return {
                        "success": True,
                        "file_name": file_name,
                        "file_size": file_size,
                        "file_type": file_type,
                        "hashes": hashes,
                        "scan_date": datetime.now().isoformat(),
                        "threat_score": 0,
                        "severity": "pending",
                        "stats": {
                            "malicious": 0,
                            "suspicious": 0,
                            "undetected": 0,
                            "harmless": 0,
                            "timeout": 0,
                            "total_engines": 0
                        },
                        "detections": [],
                        "vt_link": f"https://www.virustotal.com/gui/file/{sha256}",
                        "scan_type": "upload",
                        "analysis_id": analysis.id,
                        "message": "File uploaded for analysis. Results will be available shortly."
                    }
                else:
                    raise
        
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "file_name": file_name if 'file_name' in locals() else "unknown",
                "scan_date": datetime.now().isoformat()
            }
    
    def get_analysis_results(self, analysis_id: str) -> Dict[str, Any]:
        """
        Get results of a pending analysis
        
        Args:
            analysis_id: VirusTotal analysis ID
        
        Returns:
            Analysis results
        """
        try:
            analysis = self.client.get_object(f"/analyses/{analysis_id}")
            
            if analysis.status == "completed":
                stats = analysis.stats
                
                # Calculate threat score
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                total = sum(stats.values())
                
                threat_score = 0
                if total > 0:
                    threat_score = int(((malicious + suspicious * 0.5) / total) * 100)
                
                # Determine severity
                if malicious > 5:
                    severity = "critical"
                elif malicious > 0 or suspicious > 3:
                    severity = "high"
                elif suspicious > 0:
                    severity = "medium"
                else:
                    severity = "clean"
                
                return {
                    "status": "completed",
                    "threat_score": threat_score,
                    "severity": severity,
                    "stats": {
                        "malicious": stats.get('malicious', 0),
                        "suspicious": stats.get('suspicious', 0),
                        "undetected": stats.get('undetected', 0),
                        "harmless": stats.get('harmless', 0),
                        "timeout": stats.get('timeout', 0),
                        "total_engines": total
                    }
                }
            else:
                return {
                    "status": analysis.status,
                    "message": "Analysis still in progress"
                }
        
        except Exception as e:
            return {
                "status": "error",
                "error": str(e)
            }
    
    def close(self):
        """Close VirusTotal client"""
        self.client.close()
    
    def __enter__(self):
        """Context manager entry"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()


# Convenience function for quick scanning
def scan_file(file_path: str) -> Dict[str, Any]:
    """
    Quick file scan function
    
    Args:
        file_path: Path to file
    
    Returns:
        Scan results
    """
    with FileScanner() as scanner:
        return scanner.scan_file(file_path)


# Example usage
if __name__ == "__main__":
    # Test scanner
    test_file = "test.txt"
    
    # Create test file
    with open(test_file, 'w') as f:
        f.write("This is a test file for scanning.")
    
    # Scan file
    with FileScanner() as scanner:
        result = scanner.scan_file(test_file)
        print("Scan Result:")
        print(f"File: {result['file_name']}")
        print(f"Threat Score: {result['threat_score']}")
        print(f"Severity: {result['severity']}")
        print(f"Stats: {result['stats']}")
    
    # Clean up
    os.remove(test_file)