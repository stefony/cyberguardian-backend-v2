"""
CyberGuardian AI - File Integrity Checker
Calculates SHA256 checksums and verifies file integrity
"""

import hashlib
import os
import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from datetime import datetime
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Base directory (project root)
BASE_DIR = Path(__file__).resolve().parent.parent

# Critical files to monitor
CRITICAL_FILES = [
    "main.py",
    "core/detection_engine.py",
    "core/yara_engine.py",
    "core/heuristics.py",
    "core/ml_engine.py",
    "core/ioc_manager.py",
    "core/quarantine.py",
    "core/scheduler.py",
    "database/db.py",
    "api/auth.py",
    "api/threats.py",
    "api/detection.py",
    "api/quarantine.py",
    "api/protection.py",
]

# Manifest file location
MANIFEST_FILE = BASE_DIR / "integrity_manifest.json"


def calculate_file_checksum(file_path: str) -> Optional[str]:
    """
    Calculate SHA256 checksum of a file
    
    Args:
        file_path: Path to file
        
    Returns:
        SHA256 checksum as hex string, or None if file doesn't exist
    """
    try:
        full_path = BASE_DIR / file_path
        
        if not full_path.exists():
            logger.warning(f"File not found: {file_path}")
            return None
        
        sha256_hash = hashlib.sha256()
        
        with open(full_path, "rb") as f:
            # Read file in chunks to handle large files
            for chunk in iter(lambda: f.read(8192), b""):
                sha256_hash.update(chunk)
        
        checksum = sha256_hash.hexdigest()
        logger.debug(f"Calculated checksum for {file_path}: {checksum}")
        
        return checksum
        
    except Exception as e:
        logger.error(f"Error calculating checksum for {file_path}: {e}")
        return None


def calculate_directory_checksums(directory: str, extensions: List[str] = None) -> Dict[str, str]:
    """
    Calculate checksums for all files in a directory
    
    Args:
        directory: Directory path relative to BASE_DIR
        extensions: List of file extensions to include (e.g., ['.py', '.js'])
        
    Returns:
        Dictionary mapping file paths to checksums
    """
    checksums = {}
    dir_path = BASE_DIR / directory
    
    if not dir_path.exists():
        logger.warning(f"Directory not found: {directory}")
        return checksums
    
    try:
        for root, _, files in os.walk(dir_path):
            for file in files:
                # Filter by extension if specified
                if extensions and not any(file.endswith(ext) for ext in extensions):
                    continue
                
                file_path = Path(root) / file
                relative_path = file_path.relative_to(BASE_DIR)
                
                checksum = calculate_file_checksum(str(relative_path))
                if checksum:
                    checksums[str(relative_path)] = checksum
        
        logger.info(f"Calculated checksums for {len(checksums)} files in {directory}")
        
    except Exception as e:
        logger.error(f"Error scanning directory {directory}: {e}")
    
    return checksums


def generate_manifest() -> Dict[str, any]:
    """
    Generate integrity manifest for all critical files
    
    Returns:
        Manifest dictionary with checksums and metadata
    """
    logger.info("Generating integrity manifest...")
    
    manifest = {
        "version": "1.0.0",
        "generated_at": datetime.utcnow().isoformat(),
        "checksums": {}
    }
    
    # Calculate checksums for critical files
    for file_path in CRITICAL_FILES:
        checksum = calculate_file_checksum(file_path)
        if checksum:
            manifest["checksums"][file_path] = checksum
    
    # Calculate checksums for all Python files in core/
    core_checksums = calculate_directory_checksums("core", [".py"])
    manifest["checksums"].update(core_checksums)
    
    # Calculate checksums for all Python files in api/
    api_checksums = calculate_directory_checksums("api", [".py"])
    manifest["checksums"].update(api_checksums)
    
    # Calculate checksums for database module
    db_checksums = calculate_directory_checksums("database", [".py"])
    manifest["checksums"].update(db_checksums)
    
    logger.info(f"Generated manifest with {len(manifest['checksums'])} files")
    
    return manifest


def save_manifest(manifest: Dict[str, any], file_path: str = None) -> bool:
    """
    Save manifest to JSON file
    
    Args:
        manifest: Manifest dictionary
        file_path: Path to save manifest (default: MANIFEST_FILE)
        
    Returns:
        True if successful, False otherwise
    """
    try:
        save_path = Path(file_path) if file_path else MANIFEST_FILE
        
        with open(save_path, "w") as f:
            json.dump(manifest, f, indent=2)
        
        logger.info(f"Manifest saved to {save_path}")
        return True
        
    except Exception as e:
        logger.error(f"Error saving manifest: {e}")
        return False


def load_manifest(file_path: str = None) -> Optional[Dict[str, any]]:
    """
    Load manifest from JSON file
    
    Args:
        file_path: Path to manifest file (default: MANIFEST_FILE)
        
    Returns:
        Manifest dictionary, or None if not found
    """
    try:
        load_path = Path(file_path) if file_path else MANIFEST_FILE
        
        if not load_path.exists():
            logger.warning(f"Manifest not found: {load_path}")
            return None
        
        with open(load_path, "r") as f:
            manifest = json.load(f)
        
        logger.info(f"Loaded manifest from {load_path}")
        return manifest
        
    except Exception as e:
        logger.error(f"Error loading manifest: {e}")
        return None


def verify_file_integrity(file_path: str, expected_checksum: str) -> Tuple[bool, str]:
    """
    Verify integrity of a single file
    
    Args:
        file_path: Path to file
        expected_checksum: Expected SHA256 checksum
        
    Returns:
        Tuple of (is_valid, status_message)
    """
    try:
        actual_checksum = calculate_file_checksum(file_path)
        
        if actual_checksum is None:
            return False, "MISSING"
        
        if actual_checksum == expected_checksum:
            return True, "OK"
        else:
            return False, "MODIFIED"
            
    except Exception as e:
        logger.error(f"Error verifying {file_path}: {e}")
        return False, "ERROR"


def verify_all_files() -> Dict[str, any]:
    """
    Verify integrity of all files in manifest
    
    Returns:
        Verification report with status for each file
    """
    logger.info("Starting integrity verification...")
    
    manifest = load_manifest()
    
    if not manifest:
        return {
            "success": False,
            "error": "Manifest not found. Run generate_manifest() first.",
            "total": 0,
            "ok": 0,
            "modified": 0,
            "missing": 0,
            "errors": 0
        }
    
    report = {
        "success": True,
        "verified_at": datetime.utcnow().isoformat(),
        "manifest_version": manifest.get("version", "unknown"),
        "manifest_generated_at": manifest.get("generated_at", "unknown"),
        "total": 0,
        "ok": 0,
        "modified": 0,
        "missing": 0,
        "errors": 0,
        "files": {}
    }
    
    checksums = manifest.get("checksums", {})
    report["total"] = len(checksums)
    
    for file_path, expected_checksum in checksums.items():
        is_valid, status = verify_file_integrity(file_path, expected_checksum)
        
        report["files"][file_path] = {
            "status": status,
            "expected_checksum": expected_checksum,
            "actual_checksum": calculate_file_checksum(file_path) if status != "MISSING" else None
        }
        
        # Update counters
        if status == "OK":
            report["ok"] += 1
        elif status == "MODIFIED":
            report["modified"] += 1
            logger.warning(f"⚠️ File modified: {file_path}")
        elif status == "MISSING":
            report["missing"] += 1
            logger.error(f"❌ File missing: {file_path}")
        else:
            report["errors"] += 1
    
    # Overall status
    if report["modified"] > 0 or report["missing"] > 0:
        report["overall_status"] = "COMPROMISED"
        logger.error(f"🚨 INTEGRITY CHECK FAILED: {report['modified']} modified, {report['missing']} missing")
    else:
        report["overall_status"] = "HEALTHY"
        logger.info(f"✅ INTEGRITY CHECK PASSED: All {report['ok']} files verified")
    
    return report


def get_modified_files() -> List[Dict[str, str]]:
    """
    Get list of modified files
    
    Returns:
        List of dictionaries with file details
    """
    report = verify_all_files()
    
    if not report.get("success"):
        return []
    
    modified_files = []
    
    for file_path, details in report.get("files", {}).items():
        if details["status"] in ["MODIFIED", "MISSING"]:
            modified_files.append({
                "path": file_path,
                "status": details["status"],
                "expected_checksum": details.get("expected_checksum"),
                "actual_checksum": details.get("actual_checksum")
            })
    
    return modified_files


def check_critical_files_only() -> bool:
    """
    Quick check of only critical system files
    
    Returns:
        True if all critical files are intact, False otherwise
    """
    manifest = load_manifest()
    
    if not manifest:
        logger.warning("No manifest found for quick check")
        return False
    
    checksums = manifest.get("checksums", {})
    
    for file_path in CRITICAL_FILES:
        if file_path not in checksums:
            continue
        
        expected_checksum = checksums[file_path]
        is_valid, status = verify_file_integrity(file_path, expected_checksum)
        
        if not is_valid:
            logger.error(f"🚨 Critical file compromised: {file_path} ({status})")
            return False
    
    logger.info("✅ All critical files intact")
    return True


# CLI functions for manual testing
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python integrity_checker.py generate    - Generate manifest")
        print("  python integrity_checker.py verify      - Verify all files")
        print("  python integrity_checker.py check       - Quick check critical files")
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == "generate":
        manifest = generate_manifest()
        save_manifest(manifest)
        print(f"✅ Generated manifest with {len(manifest['checksums'])} files")
        
    elif command == "verify":
        report = verify_all_files()
        print(f"\n📊 Integrity Report:")
        print(f"   Total files: {report['total']}")
        print(f"   ✅ OK: {report['ok']}")
        print(f"   ⚠️  Modified: {report['modified']}")
        print(f"   ❌ Missing: {report['missing']}")
        print(f"   Status: {report['overall_status']}")
        
    elif command == "check":
        result = check_critical_files_only()
        if result:
            print("✅ All critical files intact")
        else:
            print("🚨 Critical files compromised!")
            sys.exit(1)
    
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)