"""
CyberGuardian AI - Hash Cache Manager
PHASE 6.2: Scan Performance Optimization

File hash caching to avoid re-scanning unchanged files.
Dramatically speeds up subsequent scans.
"""

import hashlib
import time
import os
from typing import Dict, Optional, Any
from pathlib import Path
from collections import OrderedDict
import threading
import json
import logging

logger = logging.getLogger(__name__)


class HashCache:
    """
    LRU Cache for file hashes and scan results
    Stores scan results based on file hash + modification time
    """
    
    def __init__(self, max_size: int = 10000, ttl: int = 3600):
        """
        Initialize hash cache
        
        Args:
            max_size: Maximum number of cached entries
            ttl: Time to live in seconds (default 1 hour)
        """
        self.max_size = max_size
        self.ttl = ttl
        self.cache = OrderedDict()
        self.lock = threading.Lock()
        
        # Statistics
        self.stats = {
            "hits": 0,
            "misses": 0,
            "evictions": 0,
            "total_requests": 0
        }
    
    def _get_file_hash(self, file_path: str) -> Optional[str]:
        """
        Calculate SHA256 hash of file
        
        Args:
            file_path: Path to file
            
        Returns:
            SHA256 hash or None if error
        """
        try:
            sha256_hash = hashlib.sha256()
            
            with open(file_path, "rb") as f:
                # Read in chunks for large files
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            
            return sha256_hash.hexdigest()
            
        except Exception as e:
            logger.error(f"Error hashing file {file_path}: {e}")
            return None
    
    def _get_file_mtime(self, file_path: str) -> Optional[float]:
        """
        Get file modification time
        
        Args:
            file_path: Path to file
            
        Returns:
            Modification time or None
        """
        try:
            return os.path.getmtime(file_path)
        except Exception as e:
            logger.error(f"Error getting mtime for {file_path}: {e}")
            return None
    
    def _make_cache_key(self, file_path: str, file_hash: str, mtime: float) -> str:
        """
        Generate cache key
        
        Args:
            file_path: Path to file
            file_hash: File hash
            mtime: Modification time
            
        Returns:
            Cache key
        """
        return f"{file_path}:{file_hash}:{mtime}"
    
    def get(self, file_path: str) -> Optional[Dict[str, Any]]:
        """
        Get cached scan result for file
        
        Args:
            file_path: Path to file
            
        Returns:
            Cached scan result or None
        """
        with self.lock:
            self.stats["total_requests"] += 1
            
            # Get current file info
            file_hash = self._get_file_hash(file_path)
            mtime = self._get_file_mtime(file_path)
            
            if not file_hash or mtime is None:
                self.stats["misses"] += 1
                return None
            
            # Generate cache key
            cache_key = self._make_cache_key(file_path, file_hash, mtime)
            
            # Check if in cache
            if cache_key in self.cache:
                entry = self.cache[cache_key]
                
                # Check if expired
                if time.time() - entry["cached_at"] > self.ttl:
                    del self.cache[cache_key]
                    self.stats["misses"] += 1
                    return None
                
                # Cache hit - move to end (most recently used)
                self.cache.move_to_end(cache_key)
                self.stats["hits"] += 1
                
                return entry["result"]
            
            # Cache miss
            self.stats["misses"] += 1
            return None
    
    def set(self, file_path: str, result: Dict[str, Any]):
        """
        Cache scan result for file
        
        Args:
            file_path: Path to file
            result: Scan result to cache
        """
        with self.lock:
            # Get file info
            file_hash = self._get_file_hash(file_path)
            mtime = self._get_file_mtime(file_path)
            
            if not file_hash or mtime is None:
                return
            
            # Generate cache key
            cache_key = self._make_cache_key(file_path, file_hash, mtime)
            
            # Check if at capacity
            if len(self.cache) >= self.max_size:
                # Remove oldest entry (LRU)
                oldest_key = next(iter(self.cache))
                del self.cache[oldest_key]
                self.stats["evictions"] += 1
            
            # Add to cache
            self.cache[cache_key] = {
                "result": result,
                "cached_at": time.time(),
                "file_path": file_path,
                "file_hash": file_hash,
                "mtime": mtime
            }
    
    def invalidate(self, file_path: Optional[str] = None):
        """
        Invalidate cache entries
        
        Args:
            file_path: Specific file to invalidate, or None for all
        """
        with self.lock:
            if file_path is None:
                # Clear all
                self.cache.clear()
            else:
                # Remove entries for specific file
                keys_to_remove = [
                    k for k, v in self.cache.items()
                    if v["file_path"] == file_path
                ]
                for key in keys_to_remove:
                    del self.cache[key]
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics
        
        Returns:
            Statistics dictionary
        """
        with self.lock:
            total = self.stats["total_requests"]
            hits = self.stats["hits"]
            misses = self.stats["misses"]
            
            hit_rate = (hits / total * 100) if total > 0 else 0
            
            return {
                "total_requests": total,
                "hits": hits,
                "misses": misses,
                "hit_rate": round(hit_rate, 2),
                "cache_size": len(self.cache),
                "max_size": self.max_size,
                "evictions": self.stats["evictions"],
                "ttl_seconds": self.ttl
            }
    
    def reset_stats(self):
        """Reset statistics"""
        with self.lock:
            self.stats = {
                "hits": 0,
                "misses": 0,
                "evictions": 0,
                "total_requests": 0
            }
    
    def save_to_disk(self, file_path: str):
        """
        Save cache to disk
        
        Args:
            file_path: Path to save cache
        """
        with self.lock:
            try:
                cache_data = {
                    "entries": list(self.cache.values()),
                    "stats": self.stats,
                    "saved_at": time.time()
                }
                
                with open(file_path, 'w') as f:
                    json.dump(cache_data, f)
                
                logger.info(f"Cache saved to {file_path}")
                
            except Exception as e:
                logger.error(f"Error saving cache: {e}")
    
    def load_from_disk(self, file_path: str):
        """
        Load cache from disk
        
        Args:
            file_path: Path to load cache from
        """
        with self.lock:
            try:
                if not os.path.exists(file_path):
                    logger.warning(f"Cache file not found: {file_path}")
                    return
                
                with open(file_path, 'r') as f:
                    cache_data = json.load(f)
                
                # Reconstruct cache
                self.cache.clear()
                for entry in cache_data.get("entries", []):
                    file_hash = entry.get("file_hash")
                    mtime = entry.get("mtime")
                    file_path_entry = entry.get("file_path")
                    
                    if file_hash and mtime and file_path_entry:
                        cache_key = self._make_cache_key(file_path_entry, file_hash, mtime)
                        
                        # Only add if not expired
                        if time.time() - entry.get("cached_at", 0) <= self.ttl:
                            self.cache[cache_key] = entry
                
                logger.info(f"Cache loaded from {file_path} ({len(self.cache)} entries)")
                
            except Exception as e:
                logger.error(f"Error loading cache: {e}")


class FileHasher:
    """
    Utility class for fast file hashing
    """
    
    @staticmethod
    def hash_file(file_path: str, algorithm: str = "sha256") -> Optional[str]:
        """
        Calculate hash of file
        
        Args:
            file_path: Path to file
            algorithm: Hash algorithm (sha256, md5, sha1)
            
        Returns:
            Hash string or None
        """
        try:
            if algorithm == "sha256":
                hasher = hashlib.sha256()
            elif algorithm == "md5":
                hasher = hashlib.md5()
            elif algorithm == "sha1":
                hasher = hashlib.sha1()
            else:
                raise ValueError(f"Unsupported algorithm: {algorithm}")
            
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    hasher.update(chunk)
            
            return hasher.hexdigest()
            
        except Exception as e:
            logger.error(f"Error hashing file {file_path}: {e}")
            return None
    
    @staticmethod
    def hash_multiple_files(file_paths: list, algorithm: str = "sha256") -> Dict[str, Optional[str]]:
        """
        Hash multiple files
        
        Args:
            file_paths: List of file paths
            algorithm: Hash algorithm
            
        Returns:
            Dictionary mapping file paths to hashes
        """
        results = {}
        
        for file_path in file_paths:
            results[file_path] = FileHasher.hash_file(file_path, algorithm)
        
        return results
    
    @staticmethod
    def quick_hash(file_path: str, sample_size: int = 1024 * 1024) -> Optional[str]:
        """
        Quick hash by sampling file (for very large files)
        
        Args:
            file_path: Path to file
            sample_size: Number of bytes to sample
            
        Returns:
            Hash of sample or None
        """
        try:
            file_size = os.path.getsize(file_path)
            
            hasher = hashlib.sha256()
            
            with open(file_path, "rb") as f:
                # Hash beginning
                hasher.update(f.read(min(sample_size // 2, file_size)))
                
                # Hash end (if file is large enough)
                if file_size > sample_size:
                    f.seek(-sample_size // 2, os.SEEK_END)
                    hasher.update(f.read())
            
            return hasher.hexdigest()
            
        except Exception as e:
            logger.error(f"Error quick hashing {file_path}: {e}")
            return None


# Global hash cache instance
_hash_cache = None

def get_hash_cache() -> HashCache:
    """Get global hash cache instance"""
    global _hash_cache
    if _hash_cache is None:
        _hash_cache = HashCache(max_size=10000, ttl=3600)
    return _hash_cache


def clear_hash_cache():
    """Clear global hash cache"""
    cache = get_hash_cache()
    cache.invalidate()
    cache.reset_stats()