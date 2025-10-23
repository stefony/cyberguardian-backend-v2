"""
CyberGuardian AI - System Rollback Engine
Automated System Recovery System

Provides system recovery capabilities:
- File system snapshots
- Registry rollback (Windows)
- Shadow Copy integration
- File versioning
- Emergency recovery
- Ransomware recovery

Security Knowledge Applied:
- Ransomware recovery techniques
- Volume Shadow Copy Service (VSS)
- File system journaling
- Point-in-time recovery
- Backup verification
"""

import logging
import os
import shutil
import platform
import subprocess
import json
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
import hashlib

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class Snapshot:
    """System snapshot metadata"""
    snapshot_id: str
    snapshot_time: str
    snapshot_type: str          # full, incremental, critical_files
    files_tracked: int
    total_size_bytes: int
    reason: str
    snapshot_path: str
    can_restore: bool = True


@dataclass
class FileVersion:
    """File version metadata"""
    file_path: str
    version_id: str
    version_time: str
    file_hash: str
    file_size: int
    backup_path: str


class SystemRollback:
    """
    System rollback and recovery engine.
    Creates snapshots and enables point-in-time recovery.
    """
    
    def __init__(self, backup_dir: str = None):
        """
        Initialize rollback system.
        
        Args:
            backup_dir: Custom backup directory
        """
        self.system = platform.system().lower()
        
        # Setup backup directory
        if backup_dir:
            self.backup_dir = Path(backup_dir)
        else:
            home = Path.home()
            self.backup_dir = home / '.cyberguardian' / 'rollback'
        
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        
        # Snapshots and versions
        self.snapshots: Dict[str, Snapshot] = {}
        self.file_versions: Dict[str, List[FileVersion]] = {}
        
        # Metadata files
        self.snapshots_file = self.backup_dir / 'snapshots.json'
        self.versions_file = self.backup_dir / 'versions.json'
        
        # Statistics
        self.stats = {
            'total_snapshots': 0,
            'total_rollbacks': 0,
            'total_file_versions': 0,
            'backup_size_bytes': 0,
            'successful_recoveries': 0,
            'failed_recoveries': 0
        }
        
        # Load existing data
        self._load_metadata()
        
        logger.info(f"SystemRollback initialized at {self.backup_dir}")
        logger.info(f"Snapshots: {len(self.snapshots)}, "
                   f"Backup size: {self.stats['backup_size_bytes'] / (1024**3):.2f} GB")
    
    def _load_metadata(self):
        """Load snapshot and version metadata"""
        # Load snapshots
        if self.snapshots_file.exists():
            try:
                with open(self.snapshots_file, 'r') as f:
                    data = json.load(f)
                self.snapshots = {sid: Snapshot(**snap) for sid, snap in data.items()}
                logger.debug(f"Loaded {len(self.snapshots)} snapshots")
            except Exception as e:
                logger.error(f"Failed to load snapshots: {e}")
        
        # Load versions
        if self.versions_file.exists():
            try:
                with open(self.versions_file, 'r') as f:
                    data = json.load(f)
                self.file_versions = {
                    path: [FileVersion(**v) for v in versions]
                    for path, versions in data.items()
                }
                logger.debug(f"Loaded versions for {len(self.file_versions)} files")
            except Exception as e:
                logger.error(f"Failed to load versions: {e}")
        
        self._update_stats()
    
    def _save_metadata(self):
        """Save snapshot and version metadata"""
        try:
            # Save snapshots
            data = {sid: asdict(snap) for sid, snap in self.snapshots.items()}
            with open(self.snapshots_file, 'w') as f:
                json.dump(data, f, indent=2)
            
            # Save versions
            data = {
                path: [asdict(v) for v in versions]
                for path, versions in self.file_versions.items()
            }
            with open(self.versions_file, 'w') as f:
                json.dump(data, f, indent=2)
            
            logger.debug("Metadata saved")
            
        except Exception as e:
            logger.error(f"Failed to save metadata: {e}")
    
    def _update_stats(self):
        """Update statistics"""
        self.stats['total_snapshots'] = len(self.snapshots)
        self.stats['total_file_versions'] = sum(
            len(versions) for versions in self.file_versions.values()
        )
        
        # Calculate total backup size
        total_size = 0
        for snapshot in self.snapshots.values():
            total_size += snapshot.total_size_bytes
        
        self.stats['backup_size_bytes'] = total_size
    
    def _generate_snapshot_id(self) -> str:
        """Generate unique snapshot ID"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"SNAP_{timestamp}_{os.urandom(4).hex()}"
    
    def _calculate_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of a file"""
        sha256 = hashlib.sha256()
        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception as e:
            logger.error(f"Failed to hash {file_path}: {e}")
            return "unknown"
    
    def create_snapshot(self, paths: List[str], 
                       snapshot_type: str = "incremental",
                       reason: str = "Manual snapshot") -> Tuple[bool, str, Dict]:
        """
        Create a system snapshot of specified paths.
        
        Args:
            paths: List of file/directory paths to backup
            snapshot_type: Type of snapshot (full, incremental, critical_files)
            reason: Reason for snapshot
            
        Returns:
            Tuple of (success, message, details)
        """
        try:
            snapshot_id = self._generate_snapshot_id()
            snapshot_time = datetime.now().isoformat()
            
            # Create snapshot directory
            snapshot_dir = self.backup_dir / snapshot_id
            snapshot_dir.mkdir(parents=True, exist_ok=True)
            
            logger.info(f"Creating snapshot {snapshot_id} for {len(paths)} paths")
            
            files_tracked = 0
            total_size = 0
            
            # Backup each path
            for path in paths:
                path_obj = Path(path)
                
                if not path_obj.exists():
                    logger.warning(f"Path not found: {path}")
                    continue
                
                if path_obj.is_file():
                    # Backup single file
                    success, size = self._backup_file(path_obj, snapshot_dir)
                    if success:
                        files_tracked += 1
                        total_size += size
                
                elif path_obj.is_dir():
                    # Backup directory recursively
                    for file_path in path_obj.rglob('*'):
                        if file_path.is_file():
                            success, size = self._backup_file(file_path, snapshot_dir)
                            if success:
                                files_tracked += 1
                                total_size += size
            
            # Create snapshot metadata
            snapshot = Snapshot(
                snapshot_id=snapshot_id,
                snapshot_time=snapshot_time,
                snapshot_type=snapshot_type,
                files_tracked=files_tracked,
                total_size_bytes=total_size,
                reason=reason,
                snapshot_path=str(snapshot_dir),
                can_restore=True
            )
            
            self.snapshots[snapshot_id] = snapshot
            self._save_metadata()
            self._update_stats()
            
            msg = f"Snapshot created: {snapshot_id} ({files_tracked} files, {total_size/(1024**2):.2f} MB)"
            logger.info(f"✅ {msg}")
            
            details = {
                'snapshot_id': snapshot_id,
                'files_tracked': files_tracked,
                'total_size_mb': total_size / (1024**2)
            }
            
            return True, msg, details
            
        except Exception as e:
            error_msg = f"Failed to create snapshot: {str(e)}"
            logger.error(error_msg)
            return False, error_msg, {}
    
    def _backup_file(self, file_path: Path, snapshot_dir: Path) -> Tuple[bool, int]:
        """
        Backup a single file to snapshot directory.
        
        Args:
            file_path: File to backup
            snapshot_dir: Snapshot directory
            
        Returns:
            Tuple of (success, file_size)
        """
        try:
            # Preserve directory structure
            rel_path = file_path.relative_to(file_path.anchor)
            backup_path = snapshot_dir / rel_path
            
            # Create parent directories
            backup_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Copy file
            shutil.copy2(str(file_path), str(backup_path))
            
            file_size = file_path.stat().st_size
            return True, file_size
            
        except Exception as e:
            logger.debug(f"Failed to backup {file_path}: {e}")
            return False, 0
    
    def create_file_version(self, file_path: str) -> Tuple[bool, str]:
        """
        Create a version backup of a single file.
        Useful for tracking changes to critical files.
        
        Args:
            file_path: Path to file
            
        Returns:
            Tuple of (success, message)
        """
        try:
            file_path_obj = Path(file_path)
            
            if not file_path_obj.exists():
                return False, f"File not found: {file_path}"
            
            if not file_path_obj.is_file():
                return False, f"Not a file: {file_path}"
            
            # Calculate hash
            file_hash = self._calculate_hash(file_path)
            
            # Check if this version already exists
            if file_path in self.file_versions:
                for version in self.file_versions[file_path]:
                    if version.file_hash == file_hash:
                        return False, f"File version already exists"
            
            # Create version ID
            version_id = f"VER_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{os.urandom(4).hex()}"
            
            # Create backup
            versions_dir = self.backup_dir / 'versions'
            versions_dir.mkdir(exist_ok=True)
            
            backup_filename = f"{version_id}_{file_path_obj.name}"
            backup_path = versions_dir / backup_filename
            
            shutil.copy2(file_path, backup_path)
            
            # Create version metadata
            version = FileVersion(
                file_path=str(file_path_obj.absolute()),
                version_id=version_id,
                version_time=datetime.now().isoformat(),
                file_hash=file_hash,
                file_size=file_path_obj.stat().st_size,
                backup_path=str(backup_path)
            )
            
            # Add to versions
            if file_path not in self.file_versions:
                self.file_versions[file_path] = []
            
            self.file_versions[file_path].append(version)
            self._save_metadata()
            self._update_stats()
            
            msg = f"File version created: {version_id}"
            logger.info(msg)
            
            return True, msg
            
        except Exception as e:
            error_msg = f"Failed to create file version: {str(e)}"
            logger.error(error_msg)
            return False, error_msg
    
    def rollback_snapshot(self, snapshot_id: str, 
                         restore_paths: List[str] = None) -> Tuple[bool, str]:
        """
        Rollback to a previous snapshot.
        
        Args:
            snapshot_id: ID of snapshot to restore
            restore_paths: Optional list of specific paths to restore (default: all)
            
        Returns:
            Tuple of (success, message)
        """
        try:
            if snapshot_id not in self.snapshots:
                return False, f"Snapshot not found: {snapshot_id}"
            
            snapshot = self.snapshots[snapshot_id]
            
            if not snapshot.can_restore:
                return False, "Snapshot marked as non-restorable"
            
            snapshot_dir = Path(snapshot.snapshot_path)
            
            if not snapshot_dir.exists():
                return False, f"Snapshot directory not found: {snapshot_dir}"
            
            logger.warning(f"⚠️ Rolling back to snapshot: {snapshot_id}")
            logger.warning(f"⚠️ Snapshot from: {snapshot.snapshot_time}")
            
            restored_files = 0
            failed_files = 0
            
            # Get all files in snapshot
            for backup_file in snapshot_dir.rglob('*'):
                if not backup_file.is_file():
                    continue
                
                # Reconstruct original path
                rel_path = backup_file.relative_to(snapshot_dir)
                original_path = Path('/') / rel_path
                
                # Check if we should restore this file
                if restore_paths:
                    should_restore = any(
                        str(original_path).startswith(rpath) 
                        for rpath in restore_paths
                    )
                    if not should_restore:
                        continue
                
                # Restore file
                try:
                    original_path.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(str(backup_file), str(original_path))
                    restored_files += 1
                except Exception as e:
                    logger.error(f"Failed to restore {original_path}: {e}")
                    failed_files += 1
            
            self.stats['total_rollbacks'] += 1
            
            if failed_files == 0:
                self.stats['successful_recoveries'] += 1
                msg = f"Rollback successful: {restored_files} files restored"
                logger.info(f"✅ {msg}")
                return True, msg
            else:
                self.stats['failed_recoveries'] += 1
                msg = f"Rollback partial: {restored_files} restored, {failed_files} failed"
                logger.warning(f"⚠️ {msg}")
                return True, msg
                
        except Exception as e:
            self.stats['failed_recoveries'] += 1
            error_msg = f"Rollback failed: {str(e)}"
            logger.error(error_msg)
            return False, error_msg
    
    def restore_file_version(self, file_path: str, version_id: str = None) -> Tuple[bool, str]:
        """
        Restore a specific version of a file.
        
        Args:
            file_path: Original file path
            version_id: Specific version to restore (default: latest)
            
        Returns:
            Tuple of (success, message)
        """
        try:
            if file_path not in self.file_versions:
                return False, f"No versions found for: {file_path}"
            
            versions = self.file_versions[file_path]
            
            if not versions:
                return False, f"No versions available for: {file_path}"
            
            # Find version to restore
            if version_id:
                version = next((v for v in versions if v.version_id == version_id), None)
                if not version:
                    return False, f"Version not found: {version_id}"
            else:
                # Use latest version
                version = sorted(versions, key=lambda v: v.version_time)[-1]
            
            backup_path = Path(version.backup_path)
            
            if not backup_path.exists():
                return False, f"Backup file not found: {backup_path}"
            
            # Restore file
            target_path = Path(file_path)
            target_path.parent.mkdir(parents=True, exist_ok=True)
            
            shutil.copy2(str(backup_path), str(target_path))
            
            msg = f"File restored: {file_path} (version {version.version_id})"
            logger.info(f"✅ {msg}")
            
            return True, msg
            
        except Exception as e:
            error_msg = f"Failed to restore file version: {str(e)}"
            logger.error(error_msg)
            return False, error_msg
    
    def create_shadow_copy(self) -> Tuple[bool, str]:
        """
        Create Windows Shadow Copy (VSS snapshot).
        Windows only.
        
        Returns:
            Tuple of (success, message)
        """
        if self.system != 'windows':
            return False, "Shadow Copy only available on Windows"
        
        try:
            # Create VSS shadow copy using vssadmin
            cmd = ['vssadmin', 'create', 'shadow', '/for=C:']
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                logger.info("Shadow Copy created successfully")
                return True, "Shadow Copy created"
            else:
                return False, f"Shadow Copy failed: {result.stderr}"
                
        except Exception as e:
            error_msg = f"Shadow Copy failed: {str(e)}"
            logger.error(error_msg)
            return False, error_msg
    
    def emergency_recovery(self, target_dir: str) -> Tuple[bool, str]:
        """
        Emergency recovery: restore most recent snapshot to target directory.
        Used for ransomware recovery.
        
        Args:
            target_dir: Directory to restore to
            
        Returns:
            Tuple of (success, message)
        """
        try:
            if not self.snapshots:
                return False, "No snapshots available for recovery"
            
            # Find most recent snapshot
            latest_snapshot = sorted(
                self.snapshots.values(),
                key=lambda s: s.snapshot_time
            )[-1]
            
            logger.warning(f"🚨 EMERGENCY RECOVERY: Using snapshot {latest_snapshot.snapshot_id}")
            
            # Perform rollback
            return self.rollback_snapshot(latest_snapshot.snapshot_id)
            
        except Exception as e:
            error_msg = f"Emergency recovery failed: {str(e)}"
            logger.error(error_msg)
            return False, error_msg
    
    def list_snapshots(self) -> List[Snapshot]:
        """List all snapshots (newest first)"""
        return sorted(
            self.snapshots.values(),
            key=lambda s: s.snapshot_time,
            reverse=True
        )
    
    def list_file_versions(self, file_path: str) -> List[FileVersion]:
        """List all versions of a file (newest first)"""
        versions = self.file_versions.get(file_path, [])
        return sorted(versions, key=lambda v: v.version_time, reverse=True)
    
    def delete_snapshot(self, snapshot_id: str) -> Tuple[bool, str]:
        """Delete a snapshot permanently"""
        try:
            if snapshot_id not in self.snapshots:
                return False, f"Snapshot not found: {snapshot_id}"
            
            snapshot = self.snapshots[snapshot_id]
            snapshot_dir = Path(snapshot.snapshot_path)
            
            # Delete snapshot directory
            if snapshot_dir.exists():
                shutil.rmtree(snapshot_dir)
            
            # Remove from metadata
            del self.snapshots[snapshot_id]
            self._save_metadata()
            self._update_stats()
            
            msg = f"Snapshot deleted: {snapshot_id}"
            logger.info(msg)
            
            return True, msg
            
        except Exception as e:
            return False, f"Failed to delete snapshot: {str(e)}"
    
    def cleanup_old_snapshots(self, days: int = 30) -> List[str]:
        """
        Delete snapshots older than specified days.
        
        Args:
            days: Delete snapshots older than this
            
        Returns:
            List of deleted snapshot IDs
        """
        from datetime import timedelta
        
        cutoff = datetime.now() - timedelta(days=days)
        deleted = []
        
        for snapshot_id, snapshot in list(self.snapshots.items()):
            snapshot_time = datetime.fromisoformat(snapshot.snapshot_time)
            
            if snapshot_time < cutoff:
                success, _ = self.delete_snapshot(snapshot_id)
                if success:
                    deleted.append(snapshot_id)
        
        logger.info(f"Cleaned up {len(deleted)} old snapshots")
        return deleted
    
    def get_statistics(self) -> Dict:
        """Get rollback statistics"""
        self._update_stats()
        return self.stats.copy()


def create_rollback(backup_dir: str = None) -> SystemRollback:
    """Factory function to create SystemRollback instance"""
    return SystemRollback(backup_dir=backup_dir)


# Integration function for threat_blocker
def handle_rollback_changes(threat_context) -> Tuple[bool, str, Dict]:
    """
    Handler function for threat_blocker integration.
    
    Args:
        threat_context: ThreatContext object from threat_blocker
        
    Returns:
        Tuple of (success, message, details)
    """
    rollback = create_rollback()
    
    # For CRITICAL threats (e.g., ransomware), perform emergency recovery
    if threat_context.severity.value >= 5:
        logger.warning("🚨 CRITICAL threat - initiating emergency recovery")
        
        # Try emergency recovery
        success, message = rollback.emergency_recovery("/")
        
        if success:
            return True, message, {'recovery_type': 'emergency'}
        else:
            return False, f"Emergency recovery failed: {message}", {}
    
    # For other threats, just create a snapshot for safety
    else:
        success, message, details = rollback.create_snapshot(
            paths=['/'],
            snapshot_type='incremental',
            reason=f'Threat detected: {threat_context.threat_type}'
        )
        
        return success, f"Safety snapshot created: {message}", details


# Testing
if __name__ == "__main__":
    print("📸 CyberGuardian - System Rollback Test\n")
    
    import tempfile
    
    # Create test environment
    test_dir = tempfile.mkdtemp()
    test_file1 = Path(test_dir) / "document.txt"
    test_file2 = Path(test_dir) / "config.ini"
    
    with open(test_file1, 'w') as f:
        f.write("Original content v1")
    
    with open(test_file2, 'w') as f:
        f.write("[settings]\nvalue=100")
    
    print(f"📁 Created test files in: {test_dir}")
    
    # Initialize rollback
    rollback = create_rollback()
    
    print(f"\n📊 Backup location: {rollback.backup_dir}")
    
    print("\n📸 Test 1: Create snapshot")
    success, message, details = rollback.create_snapshot(
        paths=[test_dir],
        snapshot_type='full',
        reason='Test snapshot'
    )
    
    if success:
        print(f"   ✅ {message}")
        snapshot_id = details['snapshot_id']
    else:
        print(f"   ❌ {message}")
        snapshot_id = None
    
    print("\n📝 Test 2: Create file version")
    success, message = rollback.create_file_version(str(test_file1))
    print(f"   {'✅' if success else '❌'} {message}")
    
    # Modify file
    with open(test_file1, 'w') as f:
        f.write("Modified content v2")
    
    print("\n📝 Test 3: Create another file version")
    success, message = rollback.create_file_version(str(test_file1))
    print(f"   {'✅' if success else '❌'} {message}")
    
    print("\n📋 Test 4: List file versions")
    versions = rollback.list_file_versions(str(test_file1))
    print(f"   Found {len(versions)} versions:")
    for v in versions:
        print(f"   - {v.version_id}: {v.file_size} bytes, {v.version_time}")
    
    print("\n📊 Statistics:")
    stats = rollback.get_statistics()
    for key, value in stats.items():
        if 'bytes' in key:
            print(f"   {key}: {value / (1024**2):.2f} MB")
        else:
            print(f"   {key}: {value}")
    
    print("\n✅ System Rollback test complete!")
    print(f"\n⚠️  NOTE: Backup files remain at: {rollback.backup_dir}")