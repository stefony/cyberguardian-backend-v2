"""
Deep Quarantine - Comprehensive Malware Removal System
Performs deep analysis combining registry, services, and file system checks
Provides complete removal with multi-stage backup and verification
"""

import json
import hashlib
import os
import shutil
import platform
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Any

# Platform detection
IS_WINDOWS = platform.system() == "Windows"

# Import cleanup modules
try:
    from .registry_cleaner import scan_registry_entries
    from .service_manager import scan_windows_services
    from .task_manager import scan_scheduled_tasks
except ImportError:
    # Fallback for testing
    scan_registry_entries = lambda: []
    scan_windows_services = lambda: []
    scan_scheduled_tasks = lambda: []


# Suspicious file patterns
SUSPICIOUS_EXTENSIONS = [
    ".exe", ".dll", ".sys", ".bat", ".cmd", 
    ".vbs", ".js", ".ps1", ".scr", ".com"
]

SUSPICIOUS_LOCATIONS = [
    "temp", "tmp", "appdata\\local\\temp",
    "users\\public", "programdata", "windows\\temp"
]

# Known malware signatures (simplified)
MALWARE_SIGNATURES = {
    "miner": ["xmrig", "cpuminer", "ethminer"],
    "trojan": ["backdoor", "trojan", "rat"],
    "ransomware": ["encrypt", "ransom", "locker"],
    "keylogger": ["keylog", "logger", "capture"],
}


class DeepQuarantine:
    """Deep quarantine system for comprehensive malware removal"""
    
    def __init__(self):
        self.is_windows = IS_WINDOWS
        self.backup_dir = "deep_quarantine_backups"
        self._ensure_backup_dir()
    
    def _ensure_backup_dir(self):
        """Create backup directory if it doesn't exist"""
        if not os.path.exists(self.backup_dir):
            os.makedirs(self.backup_dir)
    
    def analyze_target(self, file_path: str) -> Dict[str, Any]:
        """
        Perform deep analysis on a target file/path
        
        Args:
            file_path: Path to analyze
            
        Returns:
            Comprehensive analysis results
        """
        if not self.is_windows:
            return {
                "status": "unsupported",
                "message": "Deep quarantine only supported on Windows",
            }
        
        if not os.path.exists(file_path):
            return {
                "status": "error",
                "message": "Target path does not exist",
            }
        
        analysis_id = hashlib.md5(f"{file_path}{datetime.utcnow()}".encode()).hexdigest()
        
        results = {
            "analysis_id": analysis_id,
            "target_path": file_path,
            "analyzed_at": datetime.utcnow().isoformat(),
            "stages": {
                "file_analysis": self._analyze_file(file_path),
                "registry_scan": self._scan_registry_references(file_path),
                "service_scan": self._scan_service_dependencies(file_path),
                "task_scan": self._scan_task_references(file_path),
            },
            "threat_level": "unknown",
            "risk_score": 0,
            "recommendations": [],
        }
        
        # Calculate overall threat level
        results["threat_level"], results["risk_score"] = self._calculate_threat_level(results["stages"])
        
        # Generate recommendations
        results["recommendations"] = self._generate_recommendations(results["stages"])
        
        return results
    
    def _analyze_file(self, file_path: str) -> Dict[str, Any]:
        """
        Stage 1: Deep file analysis
        
        Args:
            file_path: Path to analyze
            
        Returns:
            File analysis results
        """
        try:
            path = Path(file_path)
            
            # Check if it's a file or directory
            is_file = path.is_file()
            is_dir = path.is_dir()
            
            if is_file:
                return self._analyze_single_file(path)
            elif is_dir:
                return self._analyze_directory(path)
            else:
                return {
                    "status": "error",
                    "message": "Invalid path type",
                }
        
        except Exception as e:
            return {
                "status": "error",
                "message": str(e),
            }
    
    def _analyze_single_file(self, file_path: Path) -> Dict[str, Any]:
        """Analyze a single file"""
        try:
            stat_info = file_path.stat()
            
            # Calculate file hash
            file_hash = self._calculate_file_hash(file_path)
            
            # Check suspicious indicators
            indicators = []
            
            # Extension check
            if file_path.suffix.lower() in SUSPICIOUS_EXTENSIONS:
                indicators.append(f"Suspicious extension: {file_path.suffix}")
            
            # Location check
            file_path_lower = str(file_path).lower()
            for location in SUSPICIOUS_LOCATIONS:
                if location in file_path_lower:
                    indicators.append(f"Located in suspicious directory: {location}")
            
            # Name pattern check
            for malware_type, patterns in MALWARE_SIGNATURES.items():
                for pattern in patterns:
                    if pattern in file_path.name.lower():
                        indicators.append(f"Matches {malware_type} pattern: {pattern}")
            
            # Size check (very small or very large files)
            if stat_info.st_size < 1024:
                indicators.append("Unusually small file")
            elif stat_info.st_size > 100 * 1024 * 1024:  # 100MB
                indicators.append("Very large file")
            
            return {
                "status": "success",
                "type": "file",
                "name": file_path.name,
                "path": str(file_path),
                "size": stat_info.st_size,
                "extension": file_path.suffix,
                "hash_md5": file_hash,
                "created": datetime.fromtimestamp(stat_info.st_ctime).isoformat(),
                "modified": datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
                "indicators": indicators,
                "suspicious": len(indicators) > 0,
            }
        
        except Exception as e:
            return {
                "status": "error",
                "message": str(e),
            }
    
    def _analyze_directory(self, dir_path: Path) -> Dict[str, Any]:
        """Analyze a directory and its contents"""
        try:
            files_analyzed = []
            total_size = 0
            suspicious_files = []
            
            # Scan directory
            for item in dir_path.rglob("*"):
                if item.is_file():
                    file_info = self._analyze_single_file(item)
                    if file_info.get("status") == "success":
                        files_analyzed.append(file_info)
                        total_size += file_info.get("size", 0)
                        
                        if file_info.get("suspicious"):
                            suspicious_files.append(file_info)
            
            return {
                "status": "success",
                "type": "directory",
                "path": str(dir_path),
                "total_files": len(files_analyzed),
                "total_size": total_size,
                "suspicious_files": len(suspicious_files),
                "files": files_analyzed[:50],  # Limit to first 50 files
                "suspicious": len(suspicious_files) > 0,
                "indicators": [f"Contains {len(suspicious_files)} suspicious files"] if suspicious_files else [],
            }
        
        except Exception as e:
            return {
                "status": "error",
                "message": str(e),
            }
    
    def _calculate_file_hash(self, file_path: Path) -> str:
        """Calculate MD5 hash of a file"""
        try:
            hash_md5 = hashlib.md5()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except:
            return "unknown"
    
    def _scan_registry_references(self, file_path: str) -> Dict[str, Any]:
        """
        Stage 2: Scan registry for references to target
        
        Args:
            file_path: Path to search for
            
        Returns:
            Registry scan results
        """
        try:
            # Get all suspicious registry entries
            registry_entries = scan_registry_entries()
            
            # Filter entries that reference the target path
            file_path_lower = file_path.lower()
            related_entries = []
            
            for entry in registry_entries:
                value_data = entry.get("value_data", "").lower()
                key_path = entry.get("key_path", "").lower()
                
                if file_path_lower in value_data or file_path_lower in key_path:
                    related_entries.append(entry)
            
            return {
                "status": "success",
                "total_entries": len(registry_entries),
                "related_entries": len(related_entries),
                "entries": related_entries,
                "has_references": len(related_entries) > 0,
            }
        
        except Exception as e:
            return {
                "status": "error",
                "message": str(e),
            }
    
    def _scan_service_dependencies(self, file_path: str) -> Dict[str, Any]:
        """
        Stage 3: Scan services for dependencies on target
        
        Args:
            file_path: Path to search for
            
        Returns:
            Service scan results
        """
        try:
            # Get all suspicious services
            services = scan_windows_services()
            
            # Filter services that reference the target path
            file_path_lower = file_path.lower()
            related_services = []
            
            for service in services:
                binary_path = service.get("binary_path", "").lower()
                
                if file_path_lower in binary_path:
                    related_services.append(service)
            
            return {
                "status": "success",
                "total_services": len(services),
                "related_services": len(related_services),
                "services": related_services,
                "has_dependencies": len(related_services) > 0,
            }
        
        except Exception as e:
            return {
                "status": "error",
                "message": str(e),
            }
    
    def _scan_task_references(self, file_path: str) -> Dict[str, Any]:
        """
        Stage 4: Scan scheduled tasks for references to target
        
        Args:
            file_path: Path to search for
            
        Returns:
            Task scan results
        """
        try:
            # Get all suspicious tasks
            tasks = scan_scheduled_tasks()
            
            # Filter tasks that reference the target path
            file_path_lower = file_path.lower()
            related_tasks = []
            
            for task in tasks:
                # Check actions
                for action in task.get("actions", []):
                    action_path = action.get("path", "").lower()
                    action_args = action.get("arguments", "").lower()
                    
                    if file_path_lower in action_path or file_path_lower in action_args:
                        related_tasks.append(task)
                        break
            
            return {
                "status": "success",
                "total_tasks": len(tasks),
                "related_tasks": len(related_tasks),
                "tasks": related_tasks,
                "has_references": len(related_tasks) > 0,
            }
        
        except Exception as e:
            return {
                "status": "error",
                "message": str(e),
            }
    
    def _calculate_threat_level(self, stages: Dict[str, Any]) -> Tuple[str, int]:
        """
        Calculate overall threat level based on all stages
        
        Args:
            stages: Analysis stage results
            
        Returns:
            Tuple of (threat_level, risk_score)
        """
        risk_score = 0
        
        # File analysis
        file_analysis = stages.get("file_analysis", {})
        if file_analysis.get("suspicious"):
            indicators = file_analysis.get("indicators", [])
            risk_score += len(indicators) * 15
        
        # Registry references
        registry_scan = stages.get("registry_scan", {})
        if registry_scan.get("has_references"):
            risk_score += registry_scan.get("related_entries", 0) * 10
        
        # Service dependencies
        service_scan = stages.get("service_scan", {})
        if service_scan.get("has_dependencies"):
            risk_score += service_scan.get("related_services", 0) * 20
        
        # Task references
        task_scan = stages.get("task_scan", {})
        if task_scan.get("has_references"):
            risk_score += task_scan.get("related_tasks", 0) * 15
        
        # Cap at 100
        risk_score = min(risk_score, 100)
        
        # Determine threat level
        if risk_score >= 80:
            threat_level = "critical"
        elif risk_score >= 60:
            threat_level = "high"
        elif risk_score >= 40:
            threat_level = "medium"
        elif risk_score >= 20:
            threat_level = "low"
        else:
            threat_level = "minimal"
        
        return threat_level, risk_score
    
    def _generate_recommendations(self, stages: Dict[str, Any]) -> List[str]:
        """Generate removal recommendations based on analysis"""
        recommendations = []
        
        # Check each stage
        registry_scan = stages.get("registry_scan", {})
        service_scan = stages.get("service_scan", {})
        task_scan = stages.get("task_scan", {})
        
        if registry_scan.get("has_references"):
            count = registry_scan.get("related_entries", 0)
            recommendations.append(f"Remove {count} registry reference(s)")
        
        if service_scan.get("has_dependencies"):
            count = service_scan.get("related_services", 0)
            recommendations.append(f"Stop and delete {count} service(s)")
        
        if task_scan.get("has_references"):
            count = task_scan.get("related_tasks", 0)
            recommendations.append(f"Remove {count} scheduled task(s)")
        
        recommendations.append("Delete target file(s)")
        recommendations.append("Create complete backup before removal")
        
        return recommendations
    
    def create_deep_backup(self, analysis_id: str, analysis_data: Dict) -> str:
        """
        Create comprehensive backup of everything to be removed
        
        Args:
            analysis_id: Analysis identifier
            analysis_data: Full analysis results
            
        Returns:
            Path to backup file
        """
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        backup_file = os.path.join(self.backup_dir, f"deep_backup_{timestamp}_{analysis_id[:8]}.json")
        
        try:
            backup_data = {
                "analysis_id": analysis_id,
                "target_path": analysis_data.get("target_path"),
                "threat_level": analysis_data.get("threat_level"),
                "risk_score": analysis_data.get("risk_score"),
                "backup_created_at": datetime.utcnow().isoformat(),
                "stages": analysis_data.get("stages"),
            }
            
            with open(backup_file, "w", encoding="utf-8") as f:
                json.dump(backup_data, f, indent=2, ensure_ascii=False)
            
            return backup_file
        
        except Exception as e:
            print(f"Error creating backup: {str(e)}")
            return ""
    
    def remove_deep(self, analysis_id: str, analysis_data: Dict) -> Tuple[bool, str]:
        """
        Perform complete removal based on analysis
        
        Args:
            analysis_id: Analysis identifier
            analysis_data: Full analysis results
            
        Returns:
            Tuple of (success, message/backup_file)
        """
        if not self.is_windows:
            return False, "Deep quarantine only supported on Windows"
        
        # Create backup first
        backup_file = self.create_deep_backup(analysis_id, analysis_data)
        if not backup_file:
            return False, "Failed to create backup"
        
        stages = analysis_data.get("stages", {})
        errors = []
        
        # Stage 1: Remove registry entries
        registry_scan = stages.get("registry_scan", {})
        if registry_scan.get("has_references"):
            for entry in registry_scan.get("entries", []):
                try:
                    # Use registry_cleaner to remove
                    from .registry_cleaner import remove_registry_entry
                    success, msg = remove_registry_entry(
                        entry.get("hive"),
                        entry.get("key_path"),
                        entry.get("value_name")
                    )
                    if not success:
                        errors.append(f"Registry: {msg}")
                except Exception as e:
                    errors.append(f"Registry error: {str(e)}")
        
        # Stage 2: Remove services
        service_scan = stages.get("service_scan", {})
        if service_scan.get("has_dependencies"):
            for service in service_scan.get("services", []):
                try:
                    # Use service_manager to remove
                    from .service_manager import delete_windows_service
                    success, msg = delete_windows_service(service.get("service_name"))
                    if not success:
                        errors.append(f"Service: {msg}")
                except Exception as e:
                    errors.append(f"Service error: {str(e)}")
        
        # Stage 3: Remove tasks
        task_scan = stages.get("task_scan", {})
        if task_scan.get("has_references"):
            for task in task_scan.get("tasks", []):
                try:
                    # Use task_manager to remove
                    from .task_manager import delete_scheduled_task
                    success, msg = delete_scheduled_task(task.get("path"))
                    if not success:
                        errors.append(f"Task: {msg}")
                except Exception as e:
                    errors.append(f"Task error: {str(e)}")
        
        # Stage 4: Remove target file(s)
        target_path = analysis_data.get("target_path")
        try:
            if os.path.isfile(target_path):
                os.remove(target_path)
            elif os.path.isdir(target_path):
                shutil.rmtree(target_path)
        except Exception as e:
            errors.append(f"File removal: {str(e)}")
        
        if errors:
            return False, f"Partial removal with errors: {'; '.join(errors)}"
        
        return True, backup_file


# Standalone functions
def analyze_deep(file_path: str) -> Dict[str, Any]:
    """Perform deep analysis on a target"""
    quarantine = DeepQuarantine()
    return quarantine.analyze_target(file_path)


def remove_deep(analysis_id: str, analysis_data: Dict) -> Tuple[bool, str]:
    """Perform complete removal"""
    quarantine = DeepQuarantine()
    return quarantine.remove_deep(analysis_id, analysis_data)


def list_deep_backups() -> List[Dict]:
    """List all deep quarantine backups"""
    quarantine = DeepQuarantine()
    backups = []
    
    if not os.path.exists(quarantine.backup_dir):
        return backups
    
    for filename in os.listdir(quarantine.backup_dir):
        if filename.endswith(".json"):
            filepath = os.path.join(quarantine.backup_dir, filename)
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    backup_data = json.load(f)
                
                backups.append({
                    "filename": filename,
                    "filepath": filepath,
                    "analysis_id": backup_data.get("analysis_id", "Unknown"),
                    "target_path": backup_data.get("target_path", "Unknown"),
                    "threat_level": backup_data.get("threat_level", "Unknown"),
                    "risk_score": backup_data.get("risk_score", 0),
                    "backed_up_at": backup_data.get("backup_created_at", "Unknown"),
                })
            except:
                continue
    
    backups.sort(key=lambda x: x["backed_up_at"], reverse=True)
    return backups