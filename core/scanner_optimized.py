"""
CyberGuardian AI - Optimized Scanner
PHASE 6.2: Scan Performance Optimization

Enhanced scanner with:
- Multi-threaded scanning
- Hash caching
- Batch processing
- Priority queue
- Progress callbacks
"""

import os
import time
from pathlib import Path
from typing import List, Dict, Any, Optional, Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from queue import PriorityQueue
import logging

from core.hash_cache import get_hash_cache, FileHasher
from core.ml_threat_detector import MLThreatDetector

logger = logging.getLogger(__name__)


class ScanProgress:
    """Track scan progress"""
    
    def __init__(self, total_files: int = 0):
        self.total_files = total_files
        self.scanned_files = 0
        self.threats_found = 0
        self.errors = 0
        self.start_time = time.time()
        self.lock = threading.Lock()
    
    def increment(self, found_threat: bool = False, error: bool = False):
        """Increment counters"""
        with self.lock:
            self.scanned_files += 1
            if found_threat:
                self.threats_found += 1
            if error:
                self.errors += 1
    
    def get_progress(self) -> Dict[str, Any]:
        """Get progress info"""
        with self.lock:
            elapsed = time.time() - self.start_time
            percent = (self.scanned_files / self.total_files * 100) if self.total_files > 0 else 0
            speed = self.scanned_files / elapsed if elapsed > 0 else 0
            
            return {
                "total_files": self.total_files,
                "scanned_files": self.scanned_files,
                "threats_found": self.threats_found,
                "errors": self.errors,
                "percent": round(percent, 2),
                "elapsed_seconds": round(elapsed, 2),
                "files_per_second": round(speed, 2)
            }


class OptimizedScanner:
    """
    Optimized file scanner with multi-threading and caching
    """
    
    def __init__(
        self, 
        max_workers: int = 4,
        use_cache: bool = True,
        batch_size: int = 100
    ):
        """
        Initialize optimized scanner
        
        Args:
            max_workers: Number of worker threads
            use_cache: Enable hash caching
            batch_size: Batch size for processing
        """
        self.max_workers = max_workers
        self.use_cache = use_cache
        self.batch_size = batch_size
        
        # ML threat detector
        self.ml_detector = MLThreatDetector()
        
        # Hash cache
        self.hash_cache = get_hash_cache() if use_cache else None
        
        # Statistics
        self.stats = {
            "total_scans": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "total_time": 0.0
        }
    
    def _should_scan_file(self, file_path: str) -> bool:
        """
        Check if file should be scanned
        
        Args:
            file_path: Path to file
            
        Returns:
            True if should scan
        """
        try:
            # Skip if too large (>100MB)
            if os.path.getsize(file_path) > 100 * 1024 * 1024:
                return False
            
            # Skip certain extensions
            skip_extensions = {'.log', '.tmp', '.cache', '.bak'}
            if Path(file_path).suffix.lower() in skip_extensions:
                return False
            
            return True
            
        except Exception:
            return False
    
    def _scan_single_file(
        self, 
        file_path: str,
        progress: Optional[ScanProgress] = None
    ) -> Dict[str, Any]:
        """
        Scan single file with caching
        
        Args:
            file_path: Path to file
            progress: Progress tracker
            
        Returns:
            Scan result
        """
        try:
            # Check cache first
            if self.use_cache and self.hash_cache:
                cached_result = self.hash_cache.get(file_path)
                if cached_result:
                    self.stats["cache_hits"] += 1
                    if progress:
                        progress.increment()
                    return cached_result
                else:
                    self.stats["cache_misses"] += 1
            
            # Calculate file hash
            file_hash = FileHasher.hash_file(file_path)
            if not file_hash:
                if progress:
                    progress.increment(error=True)
                return {
                    "file": file_path,
                    "is_threat": False,
                    "error": "Failed to hash file"
                }
            
            # Get file info
            file_size = os.path.getsize(file_path)
            
            # ML threat detection
            threat_score = self.ml_detector.predict_threat(file_path)
            is_threat = threat_score > 0.7
            
            # Build result
            result = {
                "file": file_path,
                "hash": file_hash,
                "size": file_size,
                "is_threat": is_threat,
                "threat_score": round(threat_score, 3),
                "threat_level": self._get_threat_level(threat_score),
                "scanned_at": time.time()
            }
            
            # Cache result
            if self.use_cache and self.hash_cache:
                self.hash_cache.set(file_path, result)
            
            # Update progress
            if progress:
                progress.increment(found_threat=is_threat)
            
            return result
            
        except Exception as e:
            logger.error(f"Error scanning {file_path}: {e}")
            if progress:
                progress.increment(error=True)
            return {
                "file": file_path,
                "is_threat": False,
                "error": str(e)
            }
    
    def _get_threat_level(self, score: float) -> str:
        """Get threat level from score"""
        if score >= 0.9:
            return "critical"
        elif score >= 0.7:
            return "high"
        elif score >= 0.5:
            return "medium"
        else:
            return "low"
    
    def scan_directory(
        self,
        directory: str,
        recursive: bool = True,
        progress_callback: Optional[Callable] = None
    ) -> Dict[str, Any]:
        """
        Scan directory with multi-threading
        
        Args:
            directory: Directory to scan
            recursive: Scan subdirectories
            progress_callback: Callback for progress updates
            
        Returns:
            Scan results
        """
        start_time = time.time()
        
        # Collect files to scan
        files_to_scan = []
        
        if recursive:
            for root, dirs, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    if self._should_scan_file(file_path):
                        files_to_scan.append(file_path)
        else:
            for file in os.listdir(directory):
                file_path = os.path.join(directory, file)
                if os.path.isfile(file_path) and self._should_scan_file(file_path):
                    files_to_scan.append(file_path)
        
        # Initialize progress
        progress = ScanProgress(total_files=len(files_to_scan))
        
        # Scan files in parallel
        results = []
        threats = []
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all tasks
            future_to_file = {
                executor.submit(self._scan_single_file, file_path, progress): file_path
                for file_path in files_to_scan
            }
            
            # Process completed tasks
            for future in as_completed(future_to_file):
                try:
                    result = future.result()
                    results.append(result)
                    
                    if result.get("is_threat"):
                        threats.append(result)
                    
                    # Progress callback
                    if progress_callback:
                        progress_callback(progress.get_progress())
                        
                except Exception as e:
                    logger.error(f"Error processing scan result: {e}")
        
        # Calculate statistics
        duration = time.time() - start_time
        self.stats["total_scans"] += 1
        self.stats["total_time"] += duration
        
        return {
            "success": True,
            "directory": directory,
            "total_files": len(files_to_scan),
            "scanned_files": progress.scanned_files,
            "threats_found": progress.threats_found,
            "errors": progress.errors,
            "duration_seconds": round(duration, 2),
            "files_per_second": round(len(files_to_scan) / duration, 2) if duration > 0 else 0,
            "cache_hit_rate": round(
                (self.stats["cache_hits"] / (self.stats["cache_hits"] + self.stats["cache_misses"]) * 100)
                if (self.stats["cache_hits"] + self.stats["cache_misses"]) > 0 else 0,
                2
            ),
            "threats": threats,
            "results": results
        }
    
    def scan_files(
        self,
        file_paths: List[str],
        progress_callback: Optional[Callable] = None
    ) -> Dict[str, Any]:
        """
        Scan specific files with multi-threading
        
        Args:
            file_paths: List of file paths
            progress_callback: Callback for progress updates
            
        Returns:
            Scan results
        """
        start_time = time.time()
        
        # Filter files
        files_to_scan = [f for f in file_paths if self._should_scan_file(f)]
        
        # Initialize progress
        progress = ScanProgress(total_files=len(files_to_scan))
        
        # Scan files in parallel
        results = []
        threats = []
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_file = {
                executor.submit(self._scan_single_file, file_path, progress): file_path
                for file_path in files_to_scan
            }
            
            for future in as_completed(future_to_file):
                try:
                    result = future.result()
                    results.append(result)
                    
                    if result.get("is_threat"):
                        threats.append(result)
                    
                    if progress_callback:
                        progress_callback(progress.get_progress())
                        
                except Exception as e:
                    logger.error(f"Error processing scan result: {e}")
        
        duration = time.time() - start_time
        
        return {
            "success": True,
            "total_files": len(files_to_scan),
            "scanned_files": progress.scanned_files,
            "threats_found": progress.threats_found,
            "errors": progress.errors,
            "duration_seconds": round(duration, 2),
            "files_per_second": round(len(files_to_scan) / duration, 2) if duration > 0 else 0,
            "threats": threats,
            "results": results
        }
    
    def scan_batch(
        self,
        file_paths: List[str],
        batch_size: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Scan files in batches
        
        Args:
            file_paths: List of file paths
            batch_size: Size of each batch
            
        Returns:
            Scan results
        """
        batch_size = batch_size or self.batch_size
        
        all_results = []
        all_threats = []
        total_time = 0.0
        
        # Process in batches
        for i in range(0, len(file_paths), batch_size):
            batch = file_paths[i:i + batch_size]
            
            result = self.scan_files(batch)
            
            all_results.extend(result.get("results", []))
            all_threats.extend(result.get("threats", []))
            total_time += result.get("duration_seconds", 0)
        
        return {
            "success": True,
            "total_files": len(file_paths),
            "scanned_files": len(all_results),
            "threats_found": len(all_threats),
            "duration_seconds": round(total_time, 2),
            "batches": len(range(0, len(file_paths), batch_size)),
            "threats": all_threats,
            "results": all_results
        }
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get scanner statistics"""
        cache_stats = self.hash_cache.get_stats() if self.hash_cache else {}
        
        return {
            "scanner": {
                "max_workers": self.max_workers,
                "use_cache": self.use_cache,
                "batch_size": self.batch_size,
                "total_scans": self.stats["total_scans"],
                "total_time": round(self.stats["total_time"], 2),
                "avg_scan_time": round(
                    self.stats["total_time"] / self.stats["total_scans"],
                    2
                ) if self.stats["total_scans"] > 0 else 0
            },
            "cache": cache_stats
        }
    
    def clear_cache(self):
        """Clear hash cache"""
        if self.hash_cache:
            self.hash_cache.invalidate()
            self.hash_cache.reset_stats()


# Global scanner instance
_optimized_scanner = None

def get_optimized_scanner(max_workers: int = 4) -> OptimizedScanner:
    """Get global optimized scanner instance"""
    global _optimized_scanner
    if _optimized_scanner is None:
        _optimized_scanner = OptimizedScanner(
            max_workers=max_workers,
            use_cache=True,
            batch_size=100
        )
    return _optimized_scanner