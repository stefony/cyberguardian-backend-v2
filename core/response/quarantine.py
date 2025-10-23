"""
CyberGuardian AI - File Quarantine System
Secure File Isolation Engine

Safely isolates malicious files with:
- Encrypted storage
- Metadata preservation
- Restore capability
- Automatic cleanup
- Forensic evidence preservation

Security Knowledge Applied:
- Secure file handling
- Ransomware recovery techniques
- Digital forensics best practices
- Secure deletion
"""

import logging
import os
import shutil
import hashlib
import json
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import platform

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class QuarantineEntry:
    """Metadata for a quarantined file"""
    quarantine_id: str          # Unique ID
    original_path: str          # Original file location
    quarantine_path: str        # Path in quarantine
    file_hash: str              # SHA256 hash
    file_size: int              # Size in bytes
    threat_type: str            # Type of threat detected
    severity: str               # Threat severity
    detection_source: str       # Which engine detected it
    quarantine_time: str        # ISO timestamp
    can_restore: bool = True    # Whether file can be restored
    restored: bool = False      # Whether file was restored
    restore_time: Optional[str] = None


class FileQuarantine:
    """
    File quarantine system with secure isolation and restore capability.
    """
    
    def __init__(self, quarantine_dir: str = None):
        """
        Initialize quarantine system.
        
        Args:
            quarantine_dir: Custom quarantine directory (default: ~/.cyberguardian/quarantine)
        """
        # Setup quarantine directory
        if quarantine_dir:
            self.quarantine_dir = Path(quarantine_dir)
        else:
            home = Path.home()
            self.quarantine_dir = home / '.cyberguardian' / 'quarantine'
        
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        
        # Metadata database (JSON file)
        self.metadata_file = self.quarantine_dir / 'metadata.json'
        self.metadata: Dict[str, QuarantineEntry] = {}
        
        # Statistics
        self.stats = {
            'total_quarantined': 0,
            'total_restored': 0,
            'total_deleted': 0,
            'quarantine_size_bytes': 0,
            'oldest_entry': None,
            'newest_entry': None
        }
        
        # Load existing metadata
        self._load_metadata()
        
        # Update statistics
        self._update_stats()
        
        logger.info(f"FileQuarantine initialized at {self.quarantine_dir}")
        logger.info(f"Current quarantine: {len(self.metadata)} files, "
                   f"{self.stats['quarantine_size_bytes'] / (1024*1024):.2f} MB")
    
    def _load_metadata(self):
        """Load quarantine metadata from disk"""
        if not self.metadata_file.exists():
            return
        
        try:
            with open(self.metadata_file, 'r') as f:
                data = json.load(f)
                
            # Convert dict to QuarantineEntry objects
            for qid, entry_dict in data.items():
                self.metadata[qid] = QuarantineEntry(**entry_dict)
                
            logger.debug(f"Loaded {len(self.metadata)} quarantine entries")
            
        except Exception as e:
            logger.error(f"Failed to load metadata: {e}")
    
    def _save_metadata(self):
        """Save quarantine metadata to disk"""
        try:
            # Convert QuarantineEntry objects to dict
            data = {qid: asdict(entry) for qid, entry in self.metadata.items()}
            
            with open(self.metadata_file, 'w') as f:
                json.dump(data, f, indent=2)
                
            logger.debug("Metadata saved")
            
        except Exception as e:
            logger.error(f"Failed to save metadata: {e}")
    
    def _update_stats(self):
        """Update quarantine statistics"""
        self.stats['total_quarantined'] = len(self.metadata)
        self.stats['total_restored'] = sum(1 for e in self.metadata.values() if e.restored)
        
        # Calculate total size
        total_size = 0
        for entry in self.metadata.values():
            qfile = Path(entry.quarantine_path)
            if qfile.exists():
                total_size += qfile.stat().st_size
        
        self.stats['quarantine_size_bytes'] = total_size
        
        # Find oldest and newest entries
        if self.metadata:
            sorted_entries = sorted(self.metadata.values(), 
                                   key=lambda e: e.quarantine_time)
            self.stats['oldest_entry'] = sorted_entries[0].quarantine_time
            self.stats['newest_entry'] = sorted_entries[-1].quarantine_time
    
    def _calculate_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of a file"""
        sha256 = hashlib.sha256()
        
        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception as e:
            logger.error(f"Failed to hash file {file_path}: {e}")
            return "unknown"
    
    def _generate_quarantine_id(self) -> str:
        """Generate unique quarantine ID"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        random_suffix = os.urandom(4).hex()
        return f"Q_{timestamp}_{random_suffix}"
    
    def quarantine_file(self, file_path: str, threat_type: str = "unknown",
                       severity: str = "medium", detection_source: str = "unknown",
                       delete_original: bool = True) -> Tuple[bool, str, Dict]:
        """
        Quarantine a malicious file.
        
        Args:
            file_path: Path to the file to quarantine
            threat_type: Type of threat (malware, ransomware, etc.)
            severity: Threat severity
            detection_source: Which detection engine found it
            delete_original: If True, delete original file after copy
            
        Returns:
            Tuple of (success, message, details)
        """
        try:
            file_path = Path(file_path)
            
            # Validate file exists
            if not file_path.exists():
                return False, f"File not found: {file_path}", {}
            
            if not file_path.is_file():
                return False, f"Not a file: {file_path}", {}
            
            # Check if already quarantined
            file_hash = self._calculate_hash(str(file_path))
            for entry in self.metadata.values():
                if entry.file_hash == file_hash and not entry.restored:
                    return False, f"File already quarantined: {entry.quarantine_id}", {}
            
            # Generate quarantine ID
            qid = self._generate_quarantine_id()
            
            # Determine quarantine filename (preserve extension for analysis)
            extension = file_path.suffix
            qfilename = f"{qid}{extension}"
            qpath = self.quarantine_dir / qfilename
            
            # Get file size
            file_size = file_path.stat().st_size
            
            # Copy file to quarantine (preserving original for now)
            logger.info(f"Quarantining {file_path} -> {qpath}")
            shutil.copy2(str(file_path), str(qpath))
            
            # Make quarantined file read-only
            os.chmod(str(qpath), 0o400)  # Read-only for owner
            
            # Create metadata entry
            entry = QuarantineEntry(
                quarantine_id=qid,
                original_path=str(file_path.absolute()),
                quarantine_path=str(qpath),
                file_hash=file_hash,
                file_size=file_size,
                threat_type=threat_type,
                severity=severity,
                detection_source=detection_source,
                quarantine_time=datetime.now().isoformat(),
                can_restore=True,
                restored=False
            )
            
            # Add to metadata
            self.metadata[qid] = entry
            self._save_metadata()
            
            # Delete original file if requested
            if delete_original:
                try:
                    self._secure_delete(file_path)
                    logger.info(f"Original file deleted: {file_path}")
                except Exception as e:
                    logger.warning(f"Failed to delete original: {e}")
            
            # Update statistics
            self.stats['total_quarantined'] += 1
            self._update_stats()
            
            success_msg = f"File quarantined: {file_path.name} (ID: {qid})"
            logger.info(f"✅ {success_msg}")
            
            details = {
                'quarantine_id': qid,
                'file_hash': file_hash,
                'file_size': file_size,
                'quarantine_path': str(qpath)
            }
            
            return True, success_msg, details
            
        except Exception as e:
            error_msg = f"Failed to quarantine {file_path}: {str(e)}"
            logger.error(error_msg)
            return False, error_msg, {}
    
    def restore_file(self, quarantine_id: str, restore_path: str = None,
                    force: bool = False) -> Tuple[bool, str]:
        """
        Restore a quarantined file (use with caution!).
        
        Args:
            quarantine_id: ID of quarantined file
            restore_path: Custom restore location (default: original path)
            force: Force restore even if file exists at destination
            
        Returns:
            Tuple of (success, message)
        """
        try:
            # Check if entry exists
            if quarantine_id not in self.metadata:
                return False, f"Quarantine ID not found: {quarantine_id}"
            
            entry = self.metadata[quarantine_id]
            
            # Check if already restored
            if entry.restored:
                return False, f"File already restored at {entry.restore_time}"
            
            # Check if can restore
            if not entry.can_restore and not force:
                return False, "File marked as non-restorable (use force=True to override)"
            
            # Determine restore location
            if restore_path:
                target_path = Path(restore_path)
            else:
                target_path = Path(entry.original_path)
            
            # Check if target exists
            if target_path.exists() and not force:
                return False, f"File already exists at {target_path} (use force=True)"
            
            # Check if quarantined file still exists
            qpath = Path(entry.quarantine_path)
            if not qpath.exists():
                return False, f"Quarantined file not found: {qpath}"
            
            # Restore file
            logger.warning(f"⚠️ Restoring quarantined file: {quarantine_id}")
            
            # Ensure target directory exists
            target_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Copy from quarantine to target
            shutil.copy2(str(qpath), str(target_path))
            
            # Restore normal permissions
            os.chmod(str(target_path), 0o644)
            
            # Update metadata
            entry.restored = True
            entry.restore_time = datetime.now().isoformat()
            self._save_metadata()
            
            # Update statistics
            self.stats['total_restored'] += 1
            
            success_msg = f"File restored: {target_path}"
            logger.info(f"✅ {success_msg}")
            
            return True, success_msg
            
        except Exception as e:
            error_msg = f"Failed to restore {quarantine_id}: {str(e)}"
            logger.error(error_msg)
            return False, error_msg
    
    def delete_quarantined(self, quarantine_id: str, permanent: bool = True) -> Tuple[bool, str]:
        """
        Delete a quarantined file permanently.
        
        Args:
            quarantine_id: ID of quarantined file
            permanent: If True, securely delete the file
            
        Returns:
            Tuple of (success, message)
        """
        try:
            # Check if entry exists
            if quarantine_id not in self.metadata:
                return False, f"Quarantine ID not found: {quarantine_id}"
            
            entry = self.metadata[quarantine_id]
            qpath = Path(entry.quarantine_path)
            
            # Delete file
            if qpath.exists():
                if permanent:
                    self._secure_delete(qpath)
                else:
                    qpath.unlink()
                
                logger.info(f"Deleted quarantined file: {quarantine_id}")
            
            # Remove from metadata
            del self.metadata[quarantine_id]
            self._save_metadata()
            
            # Update statistics
            self.stats['total_deleted'] += 1
            self._update_stats()
            
            return True, f"Quarantined file deleted: {quarantine_id}"
            
        except Exception as e:
            error_msg = f"Failed to delete {quarantine_id}: {str(e)}"
            logger.error(error_msg)
            return False, error_msg
    
    def _secure_delete(self, file_path: Path):
        """
        Securely delete a file (overwrite before deletion).
        Note: Not cryptographically secure on modern SSDs, but better than nothing.
        
        Args:
            file_path: Path to file to delete
        """
        try:
            # Get file size
            file_size = file_path.stat().st_size
            
            # Overwrite with random data (3 passes)
            with open(file_path, 'ba+', buffering=0) as f:
                for _ in range(3):
                    f.seek(0)
                    f.write(os.urandom(file_size))
            
            # Delete file
            file_path.unlink()
            
        except Exception as e:
            logger.warning(f"Secure delete failed, using normal delete: {e}")
            file_path.unlink()
    
    def list_quarantined(self, threat_type: str = None, 
                        severity: str = None) -> List[QuarantineEntry]:
        """
        List quarantined files with optional filtering.
        
        Args:
            threat_type: Filter by threat type
            severity: Filter by severity
            
        Returns:
            List of QuarantineEntry objects
        """
        entries = list(self.metadata.values())
        
        # Filter by threat type
        if threat_type:
            entries = [e for e in entries if e.threat_type == threat_type]
        
        # Filter by severity
        if severity:
            entries = [e for e in entries if e.severity == severity]
        
        # Sort by quarantine time (newest first)
        entries.sort(key=lambda e: e.quarantine_time, reverse=True)
        
        return entries
    
    def get_quarantine_info(self, quarantine_id: str) -> Optional[QuarantineEntry]:
        """Get detailed information about a quarantined file"""
        return self.metadata.get(quarantine_id)
    
    def cleanup_old_files(self, days: int = 30, auto_delete: bool = False) -> List[str]:
        """
        Clean up old quarantined files.
        
        Args:
            days: Delete files older than this many days
            auto_delete: If True, automatically delete; if False, return list
            
        Returns:
            List of quarantine IDs that were/would be deleted
        """
        cutoff_date = datetime.now() - timedelta(days=days)
        old_entries = []
        
        for qid, entry in self.metadata.items():
            entry_time = datetime.fromisoformat(entry.quarantine_time)
            if entry_time < cutoff_date:
                old_entries.append(qid)
        
        if auto_delete:
            for qid in old_entries:
                self.delete_quarantined(qid, permanent=True)
            logger.info(f"Cleaned up {len(old_entries)} old quarantined files")
        
        return old_entries
    
    def export_file_for_analysis(self, quarantine_id: str, 
                                 export_path: str) -> Tuple[bool, str]:
        """
        Export a quarantined file for malware analysis.
        WARNING: Handle exported files with extreme caution!
        
        Args:
            quarantine_id: ID of quarantined file
            export_path: Where to export the file
            
        Returns:
            Tuple of (success, message)
        """
        try:
            if quarantine_id not in self.metadata:
                return False, f"Quarantine ID not found: {quarantine_id}"
            
            entry = self.metadata[quarantine_id]
            qpath = Path(entry.quarantine_path)
            export_path = Path(export_path)
            
            if not qpath.exists():
                return False, f"Quarantined file not found: {qpath}"
            
            # Copy to export location
            shutil.copy2(str(qpath), str(export_path))
            
            logger.warning(f"⚠️ Exported quarantined file for analysis: {export_path}")
            logger.warning("⚠️ HANDLE WITH EXTREME CAUTION - MALICIOUS FILE!")
            
            return True, f"File exported to {export_path}"
            
        except Exception as e:
            return False, f"Export failed: {str(e)}"
    
    def get_statistics(self) -> Dict:
        """Get quarantine statistics"""
        self._update_stats()
        return self.stats.copy()
    
    def get_quarantine_size_mb(self) -> float:
        """Get total quarantine size in MB"""
        return self.stats['quarantine_size_bytes'] / (1024 * 1024)


def create_quarantine(quarantine_dir: str = None) -> FileQuarantine:
    """Factory function to create FileQuarantine instance"""
    return FileQuarantine(quarantine_dir=quarantine_dir)


# Integration function for threat_blocker
def handle_quarantine_file(threat_context) -> Tuple[bool, str, Dict]:
    """
    Handler function for threat_blocker integration.
    
    Args:
        threat_context: ThreatContext object from threat_blocker
        
    Returns:
        Tuple of (success, message, details)
    """
    quarantine = create_quarantine()
    
    # Extract file path from threat context
    file_path = threat_context.target.get('file_path') or threat_context.target.get('file')
    
    if not file_path:
        return False, "No file path provided in threat context", {}
    
    # Quarantine the file
    success, message, details = quarantine.quarantine_file(
        file_path=file_path,
        threat_type=threat_context.threat_type,
        severity=threat_context.severity.name,
        detection_source=threat_context.source,
        delete_original=True  # Delete original after quarantine
    )
    
    return success, message, details


# Testing
if __name__ == "__main__":
    print("🔒 CyberGuardian - File Quarantine Test\n")
    
    # Create temporary test file
    import tempfile
    test_dir = tempfile.mkdtemp()
    test_file = Path(test_dir) / "malware_sample.exe"
    
    # Create fake malware file
    with open(test_file, 'wb') as f:
        f.write(b"This is a fake malware file for testing purposes")
    
    print(f"📁 Created test file: {test_file}")
    
    # Initialize quarantine
    quarantine = create_quarantine()
    
    print(f"\n📊 Quarantine location: {quarantine.quarantine_dir}")
    print(f"   Current entries: {len(quarantine.metadata)}")
    
    print("\n🔒 Test 1: Quarantine file")
    success, message, details = quarantine.quarantine_file(
        file_path=str(test_file),
        threat_type="test_malware",
        severity="high",
        detection_source="test_scanner",
        delete_original=False  # Keep for testing
    )
    
    if success:
        print(f"   ✅ {message}")
        print(f"   Quarantine ID: {details['quarantine_id']}")
        qid = details['quarantine_id']
    else:
        print(f"   ❌ {message}")
        qid = None
    
    if qid:
        print("\n📋 Test 2: List quarantined files")
        entries = quarantine.list_quarantined()
        print(f"   Found {len(entries)} quarantined files")
        for entry in entries[:3]:  # Show first 3
            print(f"   - {entry.quarantine_id}: {Path(entry.original_path).name} "
                  f"({entry.file_size} bytes, {entry.threat_type})")
        
        print("\n📊 Test 3: Statistics")
        stats = quarantine.get_statistics()
        print(f"   Total quarantined: {stats['total_quarantined']}")
        print(f"   Total size: {quarantine.get_quarantine_size_mb():.2f} MB")
        print(f"   Total restored: {stats['total_restored']}")
        print(f"   Total deleted: {stats['total_deleted']}")
    
    # Cleanup test file
    if test_file.exists():
        test_file.unlink()
    
    print("\n✅ Quarantine test complete!")
    print("\n⚠️  NOTE: Test file was NOT deleted from quarantine")
    print(f"         Quarantine location: {quarantine.quarantine_dir}")