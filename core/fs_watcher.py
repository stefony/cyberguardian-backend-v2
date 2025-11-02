"""
CyberGuardian AI - File System Watcher
Real-time file monitoring with threat detection
"""

import os
import queue
import hashlib
from datetime import datetime
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Suspicious file extensions
DEFAULT_EXTS = {
    ".exe", ".dll", ".js", ".vbs", ".ps1", ".bat", ".cmd", 
    ".py", ".jar", ".scr", ".docm", ".xlsm", ".lnk", ".hta",
    ".msi", ".com", ".pif", ".gadget", ".application", ".cpl",
    ".sh", ".bash", ".ksh", ".zsh"
}


class _EventHandler(FileSystemEventHandler):
    """Handle file system events"""
    
    def __init__(self, work_q, include_ext=None, max_mb=50):
        self.work_q = work_q
        self.include_ext = include_ext or DEFAULT_EXTS
        self.max_bytes = max_mb * 1024 * 1024
    
    def _maybe_enqueue(self, path: str, kind: str):
        """Check file and enqueue if suspicious"""
        if not os.path.isfile(path):
            return
        
        # Check extension
        _, ext = os.path.splitext(path.lower())
        if self.include_ext and ext not in self.include_ext:
            return
        
        # Check size
        try:
            size = os.path.getsize(path)
            if size > self.max_bytes:
                return
        except Exception:
            return
        
        # Calculate file hash
        file_hash = None
        try:
            file_hash = self._hash_file(path)
        except Exception:
            pass
        
        self.work_q.put({
            "path": path,
            "event": kind,
            "size": size,
            "hash": file_hash,
            "ts": datetime.utcnow().isoformat() + "Z",
        })
    
    def _hash_file(self, path: str) -> str:
        """Calculate SHA256 hash of file"""
        h = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(1024 * 1024), b""):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return ""
    
    def on_created(self, event):
        if not event.is_directory:
            self._maybe_enqueue(event.src_path, "created")
    
    def on_modified(self, event):
        if not event.is_directory:
            self._maybe_enqueue(event.src_path, "modified")


class FSWatcher:
    """File system watcher manager"""
    
    def __init__(self):
        self.observer = None
        self.work_q = queue.Queue()
        self.paths = set()
        self.enabled = False
    
    def start(self, paths: list):
        """Start watching specified paths"""
        if self.enabled:
            return
        
        # Validate paths
        valid = [p for p in paths if os.path.exists(p)]
        if not valid:
            raise ValueError("No valid watch paths provided")
        
        # Create observer
        handler = _EventHandler(self.work_q)
        self.observer = Observer()
        
        for p in valid:
            self.observer.schedule(handler, p, recursive=True)
        
        self.observer.start()
        self.paths = set(valid)
        self.enabled = True
        
        print(f"✅ File system watcher started: {len(valid)} paths")
    
    def stop(self):
        """Stop watching"""
        if self.observer:
            self.observer.stop()
            self.observer.join(timeout=5)
        
        self.observer = None
        self.enabled = False
        self.paths = set()
        
        print("🛑 File system watcher stopped")
    
    def get_queue(self):
        """Get event queue"""
        return self.work_q
    
    def is_enabled(self):
        """Check if watcher is enabled"""
        return self.enabled
    
    def get_paths(self):
        """Get watched paths"""
        return list(self.paths)