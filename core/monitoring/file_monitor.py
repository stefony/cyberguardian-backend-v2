"""
CyberGuardian - File System Monitor
====================================

Real-time file system monitoring for threat detection.

Monitors:
- File creation, modification, deletion
- File renames and moves
- Directory changes
- Attribute changes
- Suspicious file patterns

Detection capabilities:
- Ransomware early detection (mass file encryption)
- Malware dropper detection
- Suspicious file extensions
- Hidden file creation
- System file tampering

Platform support:
- Windows: ReadDirectoryChangesW
- macOS: FSEvents
- Linux: inotify

Security considerations:
- Kernel-level monitoring where possible
- Low performance impact
- No file content reading (privacy)
- Only metadata and hashes
"""

import os
import sys
import time
import hashlib
import threading
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Callable, Optional, Set
from dataclasses import dataclass
from enum import Enum
import logging

# Cross-platform file monitoring
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent


# ============================================================================
# CONFIGURATION
# ============================================================================

class FileEventType(Enum):
    """File system event types"""
    CREATED = "created"
    MODIFIED = "modified"
    DELETED = "deleted"
    MOVED = "moved"
    RENAMED = "renamed"


class SuspicionLevel(Enum):
    """Suspicion level for file events"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class FileEvent:
    """
    Represents a file system event.
    
    Attributes:
        event_type: Type of file event
        path: File path
        timestamp: When event occurred
        file_size: File size in bytes
        file_hash: SHA-256 hash (for new/modified files)
        suspicion_level: How suspicious this event is
        reason: Why this is suspicious
        metadata: Additional event metadata
    """
    event_type: FileEventType
    path: str
    timestamp: datetime
    file_size: Optional[int] = None
    file_hash: Optional[str] = None
    suspicion_level: SuspicionLevel = SuspicionLevel.LOW
    reason: str = ""
    metadata: Dict = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


# ============================================================================
# FILE SYSTEM MONITOR
# ============================================================================

class FileSystemMonitor(FileSystemEventHandler):
    """
    Cross-platform file system monitor.
    
    Uses watchdog library for cross-platform compatibility.
    Can be extended with platform-specific optimizations.
    """
    
    # Suspicious file extensions (malware, ransomware)
    SUSPICIOUS_EXTENSIONS = {
        # Executables
        '.exe', '.dll', '.sys', '.scr', '.com', '.bat', '.cmd', '.vbs', '.js', '.ps1',
        # Ransomware extensions
        '.encrypted', '.locked', '.crypto', '.crypt', '.crypted', '.enc', '.locky',
        '.cerber', '.zepto', '.odin', '.aesir', '.thor', '.cryptolocker',
        # Suspicious archives
        '.rar', '.zip', '.7z', '.tar', '.gz',
        # Scripts
        '.py', '.rb', '.sh', '.pl', '.vb',
        # Office macros
        '.docm', '.xlsm', '.pptm'
    }
    
    # System directories to monitor closely (Windows)
    CRITICAL_PATHS_WINDOWS = {
        'C:\\Windows\\System32',
        'C:\\Windows\\SysWOW64',
        'C:\\Program Files',
        'C:\\Program Files (x86)',
    }
    
    # System directories (Linux/macOS)
    CRITICAL_PATHS_UNIX = {
        '/bin', '/sbin', '/usr/bin', '/usr/sbin',
        '/etc', '/boot', '/lib', '/lib64'
    }
    
    # Ransomware indicators
    RANSOMWARE_INDICATORS = {
        'readme.txt', 'how_to_decrypt.txt', 'decrypt_instructions.txt',
        'your_files_are_encrypted.txt', 'help_decrypt.html',
        'recovery+*.txt', 'restore_files.txt'
    }
    
    def __init__(self, 
                 monitored_paths: List[str],
                 callback: Optional[Callable[[FileEvent], None]] = None,
                 recursive: bool = True):
        """
        Initialize file system monitor.
        
        Args:
            monitored_paths: List of paths to monitor
            callback: Function to call when suspicious event detected
            recursive: Whether to monitor subdirectories
        """
        super().__init__()
        
        self.monitored_paths = [Path(p) for p in monitored_paths]
        self.callback = callback
        self.recursive = recursive
        
        self.logger = logging.getLogger(__name__)
        self.observer = Observer()
        
        # Statistics
        self.events_processed = 0
        self.suspicious_events = 0
        self.start_time = None
        
        # Ransomware detection
        self.file_changes_per_second: Dict[str, int] = {}
        self.last_check_time = time.time()
        
        # File extension tracking (detect mass encryption)
        self.recent_extensions: List[str] = []
        self.max_extension_history = 100
        
        # Event deduplication
        self.recent_events: Set[str] = set()
        self.event_cache_size = 1000
        
    # ========================================================================
    # MONITORING CONTROL
    # ========================================================================
    
    def start(self):
        """Start monitoring file system"""
        self.logger.info("Starting file system monitor...")
        self.start_time = datetime.now()
        
        # Schedule monitoring for each path
        for path in self.monitored_paths:
            if path.exists():
                self.observer.schedule(self, str(path), recursive=self.recursive)
                self.logger.info(f"Monitoring: {path}")
            else:
                self.logger.warning(f"Path does not exist: {path}")
        
        # Start observer thread
        self.observer.start()
        self.logger.info("File system monitor started")
    
    def stop(self):
        """Stop monitoring"""
        self.logger.info("Stopping file system monitor...")
        self.observer.stop()
        self.observer.join()
        self.logger.info("File system monitor stopped")
        
        # Print statistics
        self._print_statistics()
    
    def _print_statistics(self):
        """Print monitoring statistics"""
        if self.start_time:
            duration = (datetime.now() - self.start_time).total_seconds()
            self.logger.info(f"""
            === File Monitor Statistics ===
            Runtime: {duration:.1f} seconds
            Events processed: {self.events_processed}
            Suspicious events: {self.suspicious_events}
            Events per second: {self.events_processed / max(duration, 1):.2f}
            """)
    
    # ========================================================================
    # EVENT HANDLERS (watchdog callbacks)
    # ========================================================================
    
    def on_created(self, event: FileSystemEvent):
        """Handle file creation event"""
        if not event.is_directory:
            self._process_event(FileEventType.CREATED, event.src_path)
    
    def on_modified(self, event: FileSystemEvent):
        """Handle file modification event"""
        if not event.is_directory:
            self._process_event(FileEventType.MODIFIED, event.src_path)
    
    def on_deleted(self, event: FileSystemEvent):
        """Handle file deletion event"""
        if not event.is_directory:
            self._process_event(FileEventType.DELETED, event.src_path)
    
    def on_moved(self, event: FileSystemEvent):
        """Handle file move/rename event"""
        if not event.is_directory:
            self._process_event(
                FileEventType.MOVED, 
                event.dest_path,
                metadata={'old_path': event.src_path}
            )
    
    # ========================================================================
    # EVENT PROCESSING
    # ========================================================================
    
    def _process_event(self, 
                       event_type: FileEventType, 
                       file_path: str,
                       metadata: Optional[Dict] = None):
        """
        Process a file system event.
        
        Args:
            event_type: Type of event
            file_path: Path to file
            metadata: Additional event data
        """
        self.events_processed += 1
        
        # Deduplication (ignore duplicate events within short time)
        event_key = f"{event_type.value}:{file_path}:{int(time.time())}"
        if event_key in self.recent_events:
            return
        
        self.recent_events.add(event_key)
        if len(self.recent_events) > self.event_cache_size:
            self.recent_events.clear()
        
        # Analyze event
        suspicion_level, reason = self._analyze_event(event_type, file_path)
        
        # Create event object
        file_event = FileEvent(
            event_type=event_type,
            path=file_path,
            timestamp=datetime.now(),
            suspicion_level=suspicion_level,
            reason=reason,
            metadata=metadata or {}
        )
        
        # Add file details if file exists
        if os.path.exists(file_path) and event_type != FileEventType.DELETED:
            try:
                file_event.file_size = os.path.getsize(file_path)
                
                # Compute hash for suspicious files
                if suspicion_level.value >= SuspicionLevel.MEDIUM.value:
                    file_event.file_hash = self._compute_file_hash(file_path)
            except Exception as e:
                self.logger.debug(f"Error getting file details: {e}")
        
        # Log suspicious events
        if suspicion_level.value >= SuspicionLevel.MEDIUM.value:
            self.suspicious_events += 1
            self.logger.warning(
                f"[{suspicion_level.name}] {event_type.value.upper()}: {file_path} - {reason}"
            )
        
        # Callback for suspicious events
        if self.callback and suspicion_level.value >= SuspicionLevel.MEDIUM.value:
            try:
                self.callback(file_event)
            except Exception as e:
                self.logger.error(f"Error in callback: {e}")
        
        # Ransomware detection
        self._check_ransomware_activity(file_path)
    
    # ========================================================================
    # THREAT ANALYSIS
    # ========================================================================
    
    def _analyze_event(self, event_type: FileEventType, file_path: str) -> tuple:
        """
        Analyze event for suspicious activity.
        
        Returns:
            tuple: (SuspicionLevel, reason_string)
        """
        reasons = []
        max_suspicion = SuspicionLevel.LOW
        
        path_obj = Path(file_path)
        extension = path_obj.suffix.lower()
        filename = path_obj.name.lower()
        
        # Check 1: Suspicious file extension
        if extension in self.SUSPICIOUS_EXTENSIONS:
            reasons.append(f"Suspicious extension: {extension}")
            max_suspicion = max(max_suspicion, SuspicionLevel.MEDIUM)
        
        # Check 2: Ransomware indicator filenames
        if filename in self.RANSOMWARE_INDICATORS:
            reasons.append(f"Ransomware indicator: {filename}")
            max_suspicion = SuspicionLevel.CRITICAL
        
        # Check 3: Hidden files in suspicious locations
        if filename.startswith('.') and sys.platform != 'win32':
            reasons.append("Hidden file created")
            max_suspicion = max(max_suspicion, SuspicionLevel.LOW)
        
        # Check 4: System directory modification
        if self._is_critical_path(file_path):
            reasons.append("System directory modification")
            max_suspicion = max(max_suspicion, SuspicionLevel.HIGH)
        
        # Check 5: Double extensions (common malware trick)
        if filename.count('.') > 1:
            reasons.append("Multiple file extensions")
            max_suspicion = max(max_suspicion, SuspicionLevel.MEDIUM)
        
        # Check 6: Executable in user documents/downloads
        if extension in {'.exe', '.dll', '.sys', '.scr'} and \
           any(x in file_path.lower() for x in ['documents', 'downloads', 'desktop', 'temp']):
            reasons.append("Executable in user directory")
            max_suspicion = max(max_suspicion, SuspicionLevel.HIGH)
        
        # Check 7: Very long filename (obfuscation technique)
        if len(filename) > 100:
            reasons.append("Unusually long filename")
            max_suspicion = max(max_suspicion, SuspicionLevel.MEDIUM)
        
        # Check 8: Script files
        if extension in {'.ps1', '.bat', '.cmd', '.vbs', '.js'}:
            reasons.append("Script file")
            max_suspicion = max(max_suspicion, SuspicionLevel.MEDIUM)
        
        reason_str = "; ".join(reasons) if reasons else "Normal activity"
        return max_suspicion, reason_str
    
    def _is_critical_path(self, file_path: str) -> bool:
        """Check if path is in critical system directories"""
        file_path_lower = file_path.lower()
        
        if sys.platform == 'win32':
            return any(
                file_path_lower.startswith(p.lower()) 
                for p in self.CRITICAL_PATHS_WINDOWS
            )
        else:
            return any(
                file_path_lower.startswith(p.lower()) 
                for p in self.CRITICAL_PATHS_UNIX
            )
    
    # ========================================================================
    # RANSOMWARE DETECTION
    # ========================================================================
    
    def _check_ransomware_activity(self, file_path: str):
        """
        Detect potential ransomware activity.
        
        Ransomware indicators:
        1. Mass file modifications (many files changed quickly)
        2. Extension changes (mass rename to .encrypted, etc.)
        3. Creation of ransom notes
        """
        current_time = time.time()
        
        # Track file changes per second
        second_key = int(current_time)
        self.file_changes_per_second[second_key] = \
            self.file_changes_per_second.get(second_key, 0) + 1
        
        # Track extensions
        extension = Path(file_path).suffix.lower()
        if extension:
            self.recent_extensions.append(extension)
            if len(self.recent_extensions) > self.max_extension_history:
                self.recent_extensions.pop(0)
        
        # Check every 5 seconds
        if current_time - self.last_check_time > 5:
            self._analyze_ransomware_indicators()
            self.last_check_time = current_time
    
    def _analyze_ransomware_indicators(self):
        """Analyze collected data for ransomware patterns"""
        
        # Check 1: Too many file changes per second
        recent_changes = sum(
            count for timestamp, count in self.file_changes_per_second.items()
            if time.time() - timestamp < 10  # Last 10 seconds
        )
        
        if recent_changes > 50:  # More than 50 files in 10 seconds
            self.logger.critical(
                f"⚠️  RANSOMWARE ALERT: Mass file modification detected! "
                f"{recent_changes} files changed in 10 seconds"
            )
        
        # Check 2: Mass extension changes
        if len(self.recent_extensions) > 20:
            unique_extensions = set(self.recent_extensions[-20:])
            
            # If many files changed to same suspicious extension
            for ext in unique_extensions:
                count = self.recent_extensions[-20:].count(ext)
                if count > 15 and ext in {'.encrypted', '.locked', '.crypto', '.crypt'}:
                    self.logger.critical(
                        f"⚠️  RANSOMWARE ALERT: Mass encryption detected! "
                        f"{count} files with {ext} extension"
                    )
    
    # ========================================================================
    # UTILITIES
    # ========================================================================
    
    def _compute_file_hash(self, file_path: str, max_size_mb: int = 10) -> Optional[str]:
        """
        Compute SHA-256 hash of file.
        
        Args:
            file_path: Path to file
            max_size_mb: Maximum file size to hash (MB)
            
        Returns:
            str: SHA-256 hex digest or None
        """
        try:
            file_size = os.path.getsize(file_path)
            
            # Don't hash very large files (performance)
            if file_size > max_size_mb * 1024 * 1024:
                return None
            
            sha256_hash = hashlib.sha256()
            
            with open(file_path, 'rb') as f:
                # Read in chunks
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            
            return sha256_hash.hexdigest()
            
        except Exception as e:
            self.logger.debug(f"Error hashing file {file_path}: {e}")
            return None


# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================

def start_monitoring(paths: List[str], 
                    callback: Optional[Callable[[FileEvent], None]] = None,
                    recursive: bool = True) -> FileSystemMonitor:
    """
    Start monitoring file system paths.
    
    Args:
        paths: List of paths to monitor
        callback: Function to call on suspicious events
        recursive: Monitor subdirectories
        
    Returns:
        FileSystemMonitor: Monitor instance
        
    Example:
        def on_threat(event):
            print(f"Threat detected: {event.path}")
        
        monitor = start_monitoring(['/home/user'], callback=on_threat)
        # ... do other work ...
        monitor.stop()
    """
    monitor = FileSystemMonitor(paths, callback, recursive)
    monitor.start()
    return monitor


# ============================================================================
# TESTING & DEMO
# ============================================================================

if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    print("🔍 CyberGuardian File System Monitor - Demo\n")
    
    # Callback for suspicious events
    def alert_callback(event: FileEvent):
        print(f"\n🚨 ALERT!")
        print(f"   Type: {event.event_type.value}")
        print(f"   Path: {event.path}")
        print(f"   Level: {event.suspicion_level.name}")
        print(f"   Reason: {event.reason}")
        if event.file_hash:
            print(f"   Hash: {event.file_hash[:16]}...")
    
    # Monitor current directory
    monitor = start_monitoring(
        paths=[os.getcwd()],
        callback=alert_callback,
        recursive=True
    )
    
    print(f"Monitoring: {os.getcwd()}")
    print("Create/modify/delete files to see detection in action...")
    print("Press Ctrl+C to stop\n")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\nStopping monitor...")
        monitor.stop()
        print("✅ Monitor stopped")