"""
CyberGuardian AI - Parallel Scanner
PHASE 6.2: Scan Performance Optimization

Multi-process scanner for maximum CPU utilization.
Uses all available CPU cores for parallel scanning.
"""

import os
import time
import multiprocessing as mp
from pathlib import Path
from typing import List, Dict, Any, Optional, Callable
from concurrent.futures import ProcessPoolExecutor, as_completed
import logging

from core.hash_cache import FileHasher
from core.ml_threat_detector import MLThreatDetector

logger = logging.getLogger(__name__)


def scan_file_worker(file_path: str) -> Dict[str, Any]:
    """
    Worker function for scanning a single file
    Runs in separate process
    
    Args:
        file_path: Path to file
        
    Returns:
        Scan result
    """
    try:
        # Initialize ML detector in worker process
        ml_detector = MLThreatDetector()
        
        # Calculate file hash
        file_hash = FileHasher.hash_file(file_path)
        if not file_hash:
            return {
                "file": file_path,
                "is_threat": False,
                "error": "Failed to hash file"
            }
        
        # Get file info
        file_size = os.path.getsize(file_path)
        file_name = os.path.basename(file_path)
        file_ext = Path(file_path).suffix.lower()
        
        # ML threat detection
        threat_score = ml_detector.predict_threat(file_path)
        is_threat = threat_score > 0.7
        
        # Determine threat level
        if threat_score >= 0.9:
            threat_level = "critical"
        elif threat_score >= 0.7:
            threat_level = "high"
        elif threat_score >= 0.5:
            threat_level = "medium"
        else:
            threat_level = "low"
        
        return {
            "file": file_path,
            "file_name": file_name,
            "file_ext": file_ext,
            "hash": file_hash,
            "size": file_size,
            "is_threat": is_threat,
            "threat_score": round(threat_score, 3),
            "threat_level": threat_level,
            "scanned_at": time.time()
        }
        
    except Exception as e:
        logger.error(f"Error in worker scanning {file_path}: {e}")
        return {
            "file": file_path,
            "is_threat": False,
            "error": str(e)
        }


def scan_batch_worker(file_batch: List[str]) -> List[Dict[str, Any]]:
    """
    Worker function for scanning a batch of files
    
    Args:
        file_batch: List of file paths
        
    Returns:
        List of scan results
    """
    results = []
    
    for file_path in file_batch:
        result = scan_file_worker(file_path)
        results.append(result)
    
    return results


class ParallelScanner:
    """
    Multi-process file scanner for maximum performance
    """
    
    def __init__(self, max_workers: Optional[int] = None):
        """
        Initialize parallel scanner
        
        Args:
            max_workers: Number of worker processes (default: CPU count)
        """
        self.max_workers = max_workers or mp.cpu_count()
        
        # Statistics
        self.stats = {
            "total_scans": 0,
            "total_files": 0,
            "total_threats": 0,
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
            skip_extensions = {
                '.log', '.tmp', '.cache', '.bak', '.swp',
                '.dll', '.so', '.dylib'  # System libraries
            }
            if Path(file_path).suffix.lower() in skip_extensions:
                return False
            
            # Skip system directories
            skip_dirs = {'__pycache__', '.git', '.svn', 'node_modules'}
            if any(skip_dir in file_path for skip_dir in skip_dirs):
                return False
            
            return True
            
        except Exception:
            return False
    
    def _collect_files(self, directory: str, recursive: bool = True) -> List[str]:
        """
        Collect files to scan from directory
        
        Args:
            directory: Directory path
            recursive: Scan subdirectories
            
        Returns:
            List of file paths
        """
        files = []
        
        try:
            if recursive:
                for root, dirs, filenames in os.walk(directory):
                    # Skip hidden directories
                    dirs[:] = [d for d in dirs if not d.startswith('.')]
                    
                    for filename in filenames:
                        file_path = os.path.join(root, filename)
                        if self._should_scan_file(file_path):
                            files.append(file_path)
            else:
                for item in os.listdir(directory):
                    file_path = os.path.join(directory, item)
                    if os.path.isfile(file_path) and self._should_scan_file(file_path):
                        files.append(file_path)
        
        except Exception as e:
            logger.error(f"Error collecting files from {directory}: {e}")
        
        return files
    
    def scan_directory(
        self,
        directory: str,
        recursive: bool = True,
        progress_callback: Optional[Callable] = None
    ) -> Dict[str, Any]:
        """
        Scan directory using multiple processes
        
        Args:
            directory: Directory to scan
            recursive: Scan subdirectories
            progress_callback: Callback for progress updates
            
        Returns:
            Scan results
        """
        start_time = time.time()
        
        # Collect files
        logger.info(f"Collecting files from {directory}...")
        files_to_scan = self._collect_files(directory, recursive)
        logger.info(f"Found {len(files_to_scan)} files to scan")
        
        if not files_to_scan:
            return {
                "success": True,
                "directory": directory,
                "total_files": 0,
                "scanned_files": 0,
                "threats_found": 0,
                "duration_seconds": 0,
                "threats": [],
                "results": []
            }
        
        # Scan files in parallel
        results = []
        threats = []
        scanned_count = 0
        
        with ProcessPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all tasks
            future_to_file = {
                executor.submit(scan_file_worker, file_path): file_path
                for file_path in files_to_scan
            }
            
            # Process completed tasks
            for future in as_completed(future_to_file):
                try:
                    result = future.result()
                    results.append(result)
                    
                    if result.get("is_threat"):
                        threats.append(result)
                    
                    scanned_count += 1
                    
                    # Progress callback
                    if progress_callback and scanned_count % 10 == 0:
                        progress = {
                            "total": len(files_to_scan),
                            "scanned": scanned_count,
                            "threats": len(threats),
                            "percent": round(scanned_count / len(files_to_scan) * 100, 2)
                        }
                        progress_callback(progress)
                        
                except Exception as e:
                    logger.error(f"Error processing scan result: {e}")
        
        # Calculate statistics
        duration = time.time() - start_time
        
        self.stats["total_scans"] += 1
        self.stats["total_files"] += len(files_to_scan)
        self.stats["total_threats"] += len(threats)
        self.stats["total_time"] += duration
        
        return {
            "success": True,
            "directory": directory,
            "total_files": len(files_to_scan),
            "scanned_files": scanned_count,
            "threats_found": len(threats),
            "duration_seconds": round(duration, 2),
            "files_per_second": round(len(files_to_scan) / duration, 2) if duration > 0 else 0,
            "workers_used": self.max_workers,
            "threats": threats,
            "results": results
        }
    
    def scan_files(
        self,
        file_paths: List[str],
        progress_callback: Optional[Callable] = None
    ) -> Dict[str, Any]:
        """
        Scan specific files using multiple processes
        
        Args:
            file_paths: List of file paths
            progress_callback: Callback for progress updates
            
        Returns:
            Scan results
        """
        start_time = time.time()
        
        # Filter files
        files_to_scan = [f for f in file_paths if self._should_scan_file(f)]
        
        if not files_to_scan:
            return {
                "success": True,
                "total_files": 0,
                "scanned_files": 0,
                "threats_found": 0,
                "duration_seconds": 0,
                "threats": [],
                "results": []
            }
        
        # Scan files in parallel
        results = []
        threats = []
        scanned_count = 0
        
        with ProcessPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_file = {
                executor.submit(scan_file_worker, file_path): file_path
                for file_path in files_to_scan
            }
            
            for future in as_completed(future_to_file):
                try:
                    result = future.result()
                    results.append(result)
                    
                    if result.get("is_threat"):
                        threats.append(result)
                    
                    scanned_count += 1
                    
                    if progress_callback and scanned_count % 10 == 0:
                        progress = {
                            "total": len(files_to_scan),
                            "scanned": scanned_count,
                            "threats": len(threats),
                            "percent": round(scanned_count / len(files_to_scan) * 100, 2)
                        }
                        progress_callback(progress)
                        
                except Exception as e:
                    logger.error(f"Error processing scan result: {e}")
        
        duration = time.time() - start_time
        
        return {
            "success": True,
            "total_files": len(files_to_scan),
            "scanned_files": scanned_count,
            "threats_found": len(threats),
            "duration_seconds": round(duration, 2),
            "files_per_second": round(len(files_to_scan) / duration, 2) if duration > 0 else 0,
            "workers_used": self.max_workers,
            "threats": threats,
            "results": results
        }
    
    def scan_in_batches(
        self,
        file_paths: List[str],
        batch_size: int = 100,
        progress_callback: Optional[Callable] = None
    ) -> Dict[str, Any]:
        """
        Scan files in batches using multiple processes
        Each process handles a batch of files
        
        Args:
            file_paths: List of file paths
            batch_size: Number of files per batch
            progress_callback: Callback for progress updates
            
        Returns:
            Scan results
        """
        start_time = time.time()
        
        # Filter files
        files_to_scan = [f for f in file_paths if self._should_scan_file(f)]
        
        if not files_to_scan:
            return {
                "success": True,
                "total_files": 0,
                "scanned_files": 0,
                "threats_found": 0,
                "duration_seconds": 0,
                "threats": [],
                "results": []
            }
        
        # Create batches
        batches = [
            files_to_scan[i:i + batch_size]
            for i in range(0, len(files_to_scan), batch_size)
        ]
        
        # Scan batches in parallel
        all_results = []
        all_threats = []
        processed_batches = 0
        
        with ProcessPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_batch = {
                executor.submit(scan_batch_worker, batch): batch
                for batch in batches
            }
            
            for future in as_completed(future_to_batch):
                try:
                    batch_results = future.result()
                    
                    for result in batch_results:
                        all_results.append(result)
                        if result.get("is_threat"):
                            all_threats.append(result)
                    
                    processed_batches += 1
                    
                    if progress_callback:
                        progress = {
                            "total_batches": len(batches),
                            "processed_batches": processed_batches,
                            "scanned_files": len(all_results),
                            "threats": len(all_threats),
                            "percent": round(processed_batches / len(batches) * 100, 2)
                        }
                        progress_callback(progress)
                        
                except Exception as e:
                    logger.error(f"Error processing batch result: {e}")
        
        duration = time.time() - start_time
        
        return {
            "success": True,
            "total_files": len(files_to_scan),
            "scanned_files": len(all_results),
            "threats_found": len(all_threats),
            "duration_seconds": round(duration, 2),
            "files_per_second": round(len(files_to_scan) / duration, 2) if duration > 0 else 0,
            "workers_used": self.max_workers,
            "batches": len(batches),
            "batch_size": batch_size,
            "threats": all_threats,
            "results": all_results
        }
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get scanner statistics"""
        avg_time = (
            self.stats["total_time"] / self.stats["total_scans"]
            if self.stats["total_scans"] > 0 else 0
        )
        
        avg_speed = (
            self.stats["total_files"] / self.stats["total_time"]
            if self.stats["total_time"] > 0 else 0
        )
        
        return {
            "max_workers": self.max_workers,
            "cpu_count": mp.cpu_count(),
            "total_scans": self.stats["total_scans"],
            "total_files": self.stats["total_files"],
            "total_threats": self.stats["total_threats"],
            "total_time": round(self.stats["total_time"], 2),
            "avg_scan_time": round(avg_time, 2),
            "avg_files_per_second": round(avg_speed, 2)
        }


# Global parallel scanner instance
_parallel_scanner = None

def get_parallel_scanner(max_workers: Optional[int] = None) -> ParallelScanner:
    """Get global parallel scanner instance"""
    global _parallel_scanner
    if _parallel_scanner is None:
        _parallel_scanner = ParallelScanner(max_workers=max_workers)
    return _parallel_scanner