"""
CyberGuardian AI - Quarantine Manager
Safely isolate and manage suspicious files
"""

import os
import shutil
import json
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any, List


# Quarantine directory structure
QUARANTINE_ROOT = Path.home() / ".cyberguardian_quarantine"
QUARANTINE_FILES = QUARANTINE_ROOT / "files"
QUARANTINE_META = QUARANTINE_ROOT / "metadata"

# Ensure directories exist
QUARANTINE_FILES.mkdir(parents=True, exist_ok=True)
QUARANTINE_META.mkdir(parents=True, exist_ok=True)


def _calculate_hash(file_path: str) -> str:
    """Calculate SHA256 hash of file"""
    sha256 = hashlib.sha256()
    
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        print(f"Error calculating hash: {e}")
        return ""


def quarantine_file(
    source_path: str,
    reason: str = "Suspicious file detected",
    threat_score: float = 0.0,
    threat_level: str = "unknown",
    detection_method: str = "manual"
) -> Optional[Dict[str, Any]]:
    """
    Move file to quarantine vault
    
    Args:
        source_path: Path to file to quarantine
        reason: Reason for quarantine
        threat_score: ML threat score
        threat_level: Threat level (low, medium, high, critical)
        detection_method: How threat was detected
    
    Returns:
        Metadata dict if successful, None if failed
    """
    source = Path(source_path)
    
    if not source.exists() or not source.is_file():
        print(f"❌ File not found: {source_path}")
        return None
    
    try:
        # Calculate file hash
        file_hash = _calculate_hash(source_path)
        if not file_hash:
            return None
        
        # Generate unique quarantine ID
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        quarantine_id = f"{timestamp}_{file_hash[:16]}"
        
        # Destination paths
        quarantined_file = QUARANTINE_FILES / quarantine_id
        metadata_file = QUARANTINE_META / f"{quarantine_id}.json"
        
        # Get file info before moving
        file_size = source.stat().st_size
        
        # Move file to quarantine
        shutil.move(str(source), str(quarantined_file))
        
        # Create metadata
        metadata = {
            "id": quarantine_id,
            "original_path": str(source.absolute()),
            "original_name": source.name,
            "file_hash": file_hash,
            "file_size": file_size,
            "quarantined_at": datetime.utcnow().isoformat() + "Z",
            "reason": reason,
            "threat_score": threat_score,
            "threat_level": threat_level,
            "detection_method": detection_method,
            "status": "quarantined"
        }
        
        # Save metadata
        with open(metadata_file, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)
        
        print(f"✅ File quarantined: {source.name} -> {quarantine_id}")
        
        return metadata
        
    except Exception as e:
        print(f"❌ Error quarantining file: {e}")
        return None


def list_quarantined_files() -> List[Dict[str, Any]]:
    """Get list of all quarantined files"""
    files = []
    
    try:
        for meta_file in QUARANTINE_META.glob("*.json"):
            try:
                with open(meta_file, "r", encoding="utf-8") as f:
                    metadata = json.load(f)
                    files.append(metadata)
            except Exception as e:
                print(f"Error reading metadata {meta_file}: {e}")
                continue
        
        # Sort by quarantine time (newest first)
        files.sort(key=lambda x: x.get("quarantined_at", ""), reverse=True)
        
    except Exception as e:
        print(f"Error listing quarantined files: {e}")
    
    return files


def get_quarantined_file(quarantine_id: str) -> Optional[Dict[str, Any]]:
    """Get metadata for specific quarantined file"""
    metadata_file = QUARANTINE_META / f"{quarantine_id}.json"
    
    if not metadata_file.exists():
        return None
    
    try:
        with open(metadata_file, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"Error reading metadata: {e}")
        return None


def restore_file(quarantine_id: str) -> bool:
    """
    Restore file from quarantine to original location
    
    Args:
        quarantine_id: ID of quarantined file
    
    Returns:
        True if successful, False otherwise
    """
    metadata = get_quarantined_file(quarantine_id)
    
    if not metadata:
        print(f"❌ Quarantine entry not found: {quarantine_id}")
        return False
    
    quarantined_file = QUARANTINE_FILES / quarantine_id
    metadata_file = QUARANTINE_META / f"{quarantine_id}.json"
    
    if not quarantined_file.exists():
        print(f"❌ Quarantined file not found: {quarantine_id}")
        return False
    
    try:
        original_path = Path(metadata["original_path"])
        
        # Ensure parent directory exists
        original_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Move file back
        shutil.move(str(quarantined_file), str(original_path))
        
        # Delete metadata
        metadata_file.unlink(missing_ok=True)
        
        print(f"✅ File restored: {original_path}")
        
        return True
        
    except Exception as e:
        print(f"❌ Error restoring file: {e}")
        return False


def delete_quarantined_file(quarantine_id: str) -> bool:
    """
    Permanently delete quarantined file
    
    Args:
        quarantine_id: ID of quarantined file
    
    Returns:
        True if successful, False otherwise
    """
    quarantined_file = QUARANTINE_FILES / quarantine_id
    metadata_file = QUARANTINE_META / f"{quarantine_id}.json"
    
    try:
        # Delete file
        if quarantined_file.exists():
            quarantined_file.unlink()
        
        # Delete metadata
        if metadata_file.exists():
            metadata_file.unlink()
        
        print(f"✅ Quarantined file deleted: {quarantine_id}")
        
        return True
        
    except Exception as e:
        print(f"❌ Error deleting quarantined file: {e}")
        return False


def get_quarantine_stats() -> Dict[str, Any]:
    """Get quarantine statistics"""
    files = list_quarantined_files()
    
    total_size = sum(f.get("file_size", 0) for f in files)
    
    # Count by threat level
    threat_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "unknown": 0
    }
    
    for f in files:
        level = f.get("threat_level", "unknown").lower()
        if level in threat_counts:
            threat_counts[level] += 1
        else:
            threat_counts["unknown"] += 1
    
    return {
        "total_files": len(files),
        "total_size_bytes": total_size,
        "threat_counts": threat_counts,
        "oldest_file": files[-1].get("quarantined_at") if files else None,
        "newest_file": files[0].get("quarantined_at") if files else None
    }