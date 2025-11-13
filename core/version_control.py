"""
CyberGuardian AI - Version Control
Semantic versioning and version comparison
"""

import re
from typing import Optional, Tuple, Dict, Any
from datetime import datetime
from pathlib import Path
import json
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Current version
CURRENT_VERSION = "1.4.0"  # Phase 4 complete!
VERSION_CODENAME = "Fortress"
BUILD_DATE = "2025-01-13"

BASE_DIR = Path(__file__).resolve().parent.parent
VERSION_FILE = BASE_DIR / "version.json"


class Version:
    """
    Represents a semantic version (MAJOR.MINOR.PATCH)
    """
    
    def __init__(self, version_string: str):
        self.original = version_string
        self.major, self.minor, self.patch = self._parse(version_string)
        
    def _parse(self, version_string: str) -> Tuple[int, int, int]:
        """
        Parse version string into components
        
        Args:
            version_string: Version in format "MAJOR.MINOR.PATCH"
            
        Returns:
            Tuple of (major, minor, patch)
        """
        # Remove 'v' prefix if present
        version_string = version_string.lstrip('v')
        
        # Extract version numbers
        match = re.match(r'^(\d+)\.(\d+)\.(\d+)', version_string)
        
        if not match:
            raise ValueError(f"Invalid version format: {version_string}")
        
        major = int(match.group(1))
        minor = int(match.group(2))
        patch = int(match.group(3))
        
        return major, minor, patch
    
    def __str__(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}"
    
    def __repr__(self) -> str:
        return f"Version({self})"
    
    def __eq__(self, other) -> bool:
        if not isinstance(other, Version):
            other = Version(str(other))
        return (self.major, self.minor, self.patch) == (other.major, other.minor, other.patch)
    
    def __lt__(self, other) -> bool:
        if not isinstance(other, Version):
            other = Version(str(other))
        return (self.major, self.minor, self.patch) < (other.major, other.minor, other.patch)
    
    def __le__(self, other) -> bool:
        return self == other or self < other
    
    def __gt__(self, other) -> bool:
        if not isinstance(other, Version):
            other = Version(str(other))
        return (self.major, self.minor, self.patch) > (other.major, other.minor, other.patch)
    
    def __ge__(self, other) -> bool:
        return self == other or self > other
    
    def is_major_update(self, other) -> bool:
        """Check if other version is a major update"""
        if not isinstance(other, Version):
            other = Version(str(other))
        return other.major > self.major
    
    def is_minor_update(self, other) -> bool:
        """Check if other version is a minor update"""
        if not isinstance(other, Version):
            other = Version(str(other))
        return other.major == self.major and other.minor > self.minor
    
    def is_patch_update(self, other) -> bool:
        """Check if other version is a patch update"""
        if not isinstance(other, Version):
            other = Version(str(other))
        return (other.major == self.major and 
                other.minor == self.minor and 
                other.patch > self.patch)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "version": str(self),
            "major": self.major,
            "minor": self.minor,
            "patch": self.patch
        }


class VersionControl:
    """
    Manages application versioning
    """
    
    def __init__(self):
        self.current_version = Version(CURRENT_VERSION)
        self.version_info = self._load_version_info()
    
    def _load_version_info(self) -> Dict[str, Any]:
        """
        Load version information from file
        
        Returns:
            Version info dictionary
        """
        try:
            if VERSION_FILE.exists():
                with open(VERSION_FILE, "r") as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"Error loading version info: {e}")
        
        # Default version info
        return {
            "version": CURRENT_VERSION,
            "codename": VERSION_CODENAME,
            "build_date": BUILD_DATE,
            "release_notes": "Initial release with Phase 4 complete",
            "changelog": []
        }
    
    def _save_version_info(self):
        """Save version information to file"""
        try:
            with open(VERSION_FILE, "w") as f:
                json.dump(self.version_info, f, indent=2)
            logger.info(f"✅ Version info saved to {VERSION_FILE}")
        except Exception as e:
            logger.error(f"❌ Error saving version info: {e}")
    
    def get_current_version(self) -> str:
        """Get current version string"""
        return str(self.current_version)
    
    def get_version_info(self) -> Dict[str, Any]:
        """
        Get complete version information
        
        Returns:
            Dictionary with version details
        """
        return {
            "version": str(self.current_version),
            "major": self.current_version.major,
            "minor": self.current_version.minor,
            "patch": self.current_version.patch,
            "codename": self.version_info.get("codename", VERSION_CODENAME),
            "build_date": self.version_info.get("build_date", BUILD_DATE),
            "release_notes": self.version_info.get("release_notes", ""),
            "changelog": self.version_info.get("changelog", [])
        }
    
    def compare_versions(self, version1: str, version2: str) -> int:
        """
        Compare two versions
        
        Args:
            version1: First version
            version2: Second version
            
        Returns:
            -1 if version1 < version2
             0 if version1 == version2
             1 if version1 > version2
        """
        v1 = Version(version1)
        v2 = Version(version2)
        
        if v1 < v2:
            return -1
        elif v1 > v2:
            return 1
        else:
            return 0
    
    def is_newer(self, version: str) -> bool:
        """
        Check if given version is newer than current
        
        Args:
            version: Version to check
            
        Returns:
            True if newer
        """
        other = Version(version)
        return other > self.current_version
    
    def get_update_type(self, new_version: str) -> str:
        """
        Determine update type
        
        Args:
            new_version: New version string
            
        Returns:
            'major', 'minor', 'patch', or 'none'
        """
        other = Version(new_version)
        
        if self.current_version.is_major_update(other):
            return "major"
        elif self.current_version.is_minor_update(other):
            return "minor"
        elif self.current_version.is_patch_update(other):
            return "patch"
        else:
            return "none"
    
    def update_version(self, new_version: str, release_notes: str = ""):
        """
        Update to new version
        
        Args:
            new_version: New version string
            release_notes: Release notes
        """
        old_version = str(self.current_version)
        self.current_version = Version(new_version)
        
        # Update version info
        self.version_info["version"] = new_version
        self.version_info["release_notes"] = release_notes
        self.version_info["build_date"] = datetime.now().strftime("%Y-%m-%d")
        
        # Add to changelog
        if "changelog" not in self.version_info:
            self.version_info["changelog"] = []
        
        self.version_info["changelog"].insert(0, {
            "version": new_version,
            "previous_version": old_version,
            "date": datetime.now().isoformat(),
            "notes": release_notes
        })
        
        # Keep only last 10 changelog entries
        self.version_info["changelog"] = self.version_info["changelog"][:10]
        
        self._save_version_info()
        
        logger.info(f"✅ Updated from {old_version} to {new_version}")
    
    def get_changelog(self, limit: int = 10) -> list:
        """
        Get version changelog
        
        Args:
            limit: Maximum number of entries
            
        Returns:
            List of changelog entries
        """
        changelog = self.version_info.get("changelog", [])
        return changelog[:limit]
    
    def create_version_manifest(self) -> Dict[str, Any]:
        """
        Create version manifest for distribution
        
        Returns:
            Version manifest dictionary
        """
        return {
            "version": str(self.current_version),
            "codename": self.version_info.get("codename", VERSION_CODENAME),
            "build_date": self.version_info.get("build_date", BUILD_DATE),
            "release_notes": self.version_info.get("release_notes", ""),
            "requirements": {
                "python": ">=3.8",
                "platform": ["Windows", "Linux"],
                "dependencies": [
                    "fastapi>=0.104.0",
                    "uvicorn>=0.24.0",
                    "psutil>=5.9.0",
                    "cryptography>=41.0.0",
                    "yara-python>=4.3.0"
                ]
            },
            "changelog": self.get_changelog(5)
        }


# Global version control instance
version_control = VersionControl()


# Convenience functions
def get_current_version() -> str:
    """Get current version string"""
    return version_control.get_current_version()


def get_version_info() -> Dict[str, Any]:
    """Get complete version information"""
    return version_control.get_version_info()


def is_newer_version(version: str) -> bool:
    """Check if version is newer than current"""
    return version_control.is_newer(version)


def compare_versions(v1: str, v2: str) -> int:
    """Compare two versions"""
    return version_control.compare_versions(v1, v2)


# CLI for testing
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python version_control.py info          - Show version info")
        print("  python version_control.py compare v1 v2 - Compare versions")
        print("  python version_control.py check v       - Check if v is newer")
        print("  python version_control.py manifest      - Show version manifest")
        sys.exit(1)
    
    command = sys.argv[1]
    vc = VersionControl()
    
    if command == "info":
        info = vc.get_version_info()
        print(json.dumps(info, indent=2))
        
    elif command == "compare":
        if len(sys.argv) < 4:
            print("Please provide two versions to compare")
            sys.exit(1)
        
        v1 = sys.argv[2]
        v2 = sys.argv[3]
        result = vc.compare_versions(v1, v2)
        
        if result < 0:
            print(f"{v1} < {v2}")
        elif result > 0:
            print(f"{v1} > {v2}")
        else:
            print(f"{v1} == {v2}")
        
    elif command == "check":
        if len(sys.argv) < 3:
            print("Please provide a version to check")
            sys.exit(1)
        
        version = sys.argv[2]
        is_newer = vc.is_newer(version)
        update_type = vc.get_update_type(version)
        
        print(f"Current: {vc.get_current_version()}")
        print(f"Check: {version}")
        print(f"Is newer: {is_newer}")
        print(f"Update type: {update_type}")
        
    elif command == "manifest":
        manifest = vc.create_version_manifest()
        print(json.dumps(manifest, indent=2))
    
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)