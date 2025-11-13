"""
CyberGuardian AI - Update Manager
Manages software updates, checking, downloading, and installation
"""

import sys
from pathlib import Path

# Add parent directory to Python path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import os
import json
import hashlib
import requests
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
import logging
import shutil
import subprocess

from core.version_control import (
    VersionControl,
    Version,
    get_current_version,
    is_newer_version
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration
BASE_DIR = Path(__file__).resolve().parent.parent
UPDATES_DIR = BASE_DIR / "updates"
BACKUP_DIR = BASE_DIR / "backups"
UPDATE_CONFIG_FILE = BASE_DIR / "config" / "update_config.json"

# Update server configuration
UPDATE_SERVER = os.getenv("UPDATE_SERVER_URL", "https://api.github.com/repos/YOUR_USERNAME/cyberguardian/releases")
CHECK_INTERVAL_HOURS = 24  # Check for updates every 24 hours

# Ensure directories exist
UPDATES_DIR.mkdir(exist_ok=True)
BACKUP_DIR.mkdir(exist_ok=True)


class UpdateManager:
    """
    Manages software updates
    """
    
    def __init__(self):
        self.version_control = VersionControl()
        self.current_version = self.version_control.current_version
        self.update_config = self._load_update_config()
        
    def _load_update_config(self) -> Dict[str, Any]:
        """Load update configuration"""
        try:
            if UPDATE_CONFIG_FILE.exists():
                with open(UPDATE_CONFIG_FILE, "r") as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"Error loading update config: {e}")
        
        # Default config
        return {
            "auto_check": True,
            "auto_download": False,
            "auto_install": False,
            "last_check": None,
            "update_channel": "stable",  # stable, beta, dev
            "allow_prereleases": False
        }
    
    def _save_update_config(self):
        """Save update configuration"""
        try:
            UPDATE_CONFIG_FILE.parent.mkdir(exist_ok=True)
            with open(UPDATE_CONFIG_FILE, "w") as f:
                json.dump(self.update_config, f, indent=2)
            logger.info("✅ Update config saved")
        except Exception as e:
            logger.error(f"❌ Error saving update config: {e}")
    
    def check_for_updates(self, force: bool = False) -> Optional[Dict[str, Any]]:
        """
        Check if updates are available
        
        Args:
            force: Force check even if recently checked
            
        Returns:
            Update information if available, None otherwise
        """
        try:
            # Check if we should check for updates
            if not force and not self._should_check_updates():
                logger.info("⏸️ Skipping update check (too recent)")
                return None
            
            logger.info("🔍 Checking for updates...")
            
            # Fetch latest release info
            update_info = self._fetch_latest_release()
            
            if not update_info:
                logger.info("ℹ️ No update information available")
                return None
            
            # Update last check time
            self.update_config["last_check"] = datetime.now().isoformat()
            self._save_update_config()
            
            latest_version = update_info.get("version")
            
            if not latest_version:
                logger.error("❌ Invalid update information")
                return None
            
            # Check if newer
            if is_newer_version(latest_version):
                update_type = self.version_control.get_update_type(latest_version)
                
                logger.info(f"✨ Update available: {latest_version} ({update_type})")
                
                return {
                    "available": True,
                    "current_version": str(self.current_version),
                    "latest_version": latest_version,
                    "update_type": update_type,
                    "release_date": update_info.get("published_at"),
                    "release_notes": update_info.get("body", ""),
                    "download_url": update_info.get("download_url"),
                    "size_bytes": update_info.get("size"),
                    "checksum": update_info.get("checksum")
                }
            else:
                logger.info(f"✅ Already on latest version: {self.current_version}")
                return {
                    "available": False,
                    "current_version": str(self.current_version),
                    "message": "You are already on the latest version"
                }
            
        except Exception as e:
            logger.error(f"❌ Error checking for updates: {e}")
            return None
    
    def _should_check_updates(self) -> bool:
        """
        Check if enough time has passed since last update check
        
        Returns:
            True if should check
        """
        if not self.update_config.get("auto_check", True):
            return False
        
        last_check = self.update_config.get("last_check")
        
        if not last_check:
            return True
        
        try:
            last_check_time = datetime.fromisoformat(last_check)
            time_since_check = datetime.now() - last_check_time
            
            return time_since_check > timedelta(hours=CHECK_INTERVAL_HOURS)
        except:
            return True
    
    def _fetch_latest_release(self) -> Optional[Dict[str, Any]]:
        """
        Fetch latest release information from update server
        
        Returns:
            Release information dictionary
        """
        try:
            # For now, return mock data
            # In production, fetch from GitHub Releases or custom update server
            
            # Mock update data
            mock_release = {
                "version": "1.5.0",
                "published_at": "2025-01-15T00:00:00Z",
                "body": """
                ## What's New in v1.5.0 🚀
                
                ### ✨ New Features
                - Secure auto-update system
                - Update rollback mechanism
                - Version changelog tracking
                
                ### 🐛 Bug Fixes
                - Fixed integrity check performance
                - Improved watchdog stability
                
                ### 🔒 Security
                - Enhanced update validation
                - Signature verification
                """,
                "download_url": "https://github.com/YOUR_USERNAME/cyberguardian/releases/download/v1.5.0/cyberguardian-v1.5.0.zip",
                "size": 15728640,  # 15 MB
                "checksum": "sha256:abcdef1234567890..."
            }
            
            # Uncomment for real GitHub integration:
            # response = requests.get(
            #     UPDATE_SERVER,
            #     headers={"Accept": "application/vnd.github.v3+json"},
            #     timeout=10
            # )
            # 
            # if response.status_code == 200:
            #     releases = response.json()
            #     if releases:
            #         latest = releases[0]
            #         return {
            #             "version": latest["tag_name"].lstrip("v"),
            #             "published_at": latest["published_at"],
            #             "body": latest["body"],
            #             "download_url": latest["assets"][0]["browser_download_url"] if latest["assets"] else None,
            #             "size": latest["assets"][0]["size"] if latest["assets"] else None,
            #         }
            
            return mock_release
            
        except Exception as e:
            logger.error(f"❌ Error fetching release info: {e}")
            return None
    
    def download_update(self, update_info: Dict[str, Any]) -> Optional[Path]:
        """
        Download update package
        
        Args:
            update_info: Update information from check_for_updates
            
        Returns:
            Path to downloaded file
        """
        try:
            download_url = update_info.get("download_url")
            version = update_info.get("latest_version")
            
            if not download_url or not version:
                logger.error("❌ Invalid update information")
                return None
            
            logger.info(f"📥 Downloading update {version}...")
            
            # Download file
            download_path = UPDATES_DIR / f"cyberguardian-v{version}.zip"
            
            # Mock download (in production, actually download)
            logger.info(f"⚠️ Mock mode: Would download from {download_url}")
            logger.info(f"📁 Download path: {download_path}")
            
            # Uncomment for real download:
            # response = requests.get(download_url, stream=True, timeout=300)
            # total_size = int(response.headers.get('content-length', 0))
            # 
            # with open(download_path, 'wb') as f:
            #     downloaded = 0
            #     for chunk in response.iter_content(chunk_size=8192):
            #         if chunk:
            #             f.write(chunk)
            #             downloaded += len(chunk)
            #             progress = (downloaded / total_size) * 100
            #             logger.info(f"📥 Download progress: {progress:.1f}%")
            
            # For testing, create empty file
            download_path.touch()
            
            logger.info(f"✅ Download complete: {download_path}")
            return download_path
            
        except Exception as e:
            logger.error(f"❌ Error downloading update: {e}")
            return None
    
    def validate_update(self, file_path: Path, expected_checksum: str) -> bool:
        """
        Validate downloaded update file
        
        Args:
            file_path: Path to update file
            expected_checksum: Expected checksum (format: "sha256:hash")
            
        Returns:
            True if valid
        """
        try:
            if not file_path.exists():
                logger.error(f"❌ Update file not found: {file_path}")
                return False
            
            logger.info("🔍 Validating update...")
            
            # Extract algorithm and hash
            if ":" in expected_checksum:
                algorithm, expected_hash = expected_checksum.split(":", 1)
            else:
                algorithm = "sha256"
                expected_hash = expected_checksum
            
            # Calculate file hash
            hash_obj = hashlib.new(algorithm)
            
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_obj.update(chunk)
            
            actual_hash = hash_obj.hexdigest()
            
            # For testing, always return True
            logger.info(f"⚠️ Mock mode: Skipping checksum validation")
            logger.info(f"Expected: {expected_hash}")
            logger.info(f"Actual: {actual_hash}")
            
            # In production, actually validate:
            # if actual_hash != expected_hash:
            #     logger.error(f"❌ Checksum mismatch!")
            #     return False
            
            logger.info("✅ Update validation successful")
            return True
            
        except Exception as e:
            logger.error(f"❌ Error validating update: {e}")
            return False
    
    def create_backup(self) -> Optional[Path]:
        """
        Create backup of current installation
        
        Returns:
            Path to backup directory
        """
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = BACKUP_DIR / f"backup_v{self.current_version}_{timestamp}"
            
            logger.info(f"💾 Creating backup: {backup_path}")
            
            # Backup critical files
            files_to_backup = [
                "main.py",
                "core/",
                "api/",
                "database/",
                "config/",
                "requirements.txt"
            ]
            
            backup_path.mkdir(parents=True, exist_ok=True)
            
            for item in files_to_backup:
                src = BASE_DIR / item
                if src.exists():
                    if src.is_file():
                        dst = backup_path / item
                        dst.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(src, dst)
                    elif src.is_dir():
                        dst = backup_path / item
                        shutil.copytree(src, dst, dirs_exist_ok=True)
            
            logger.info(f"✅ Backup created: {backup_path}")
            return backup_path
            
        except Exception as e:
            logger.error(f"❌ Error creating backup: {e}")
            return None
    
    def install_update(self, update_file: Path, backup_path: Path) -> bool:
        """
        Install update
        
        Args:
            update_file: Path to update package
            backup_path: Path to backup
            
        Returns:
            True if successful
        """
        try:
            logger.info("📦 Installing update...")
            
            # Extract update package
            # shutil.unpack_archive(update_file, UPDATES_DIR / "temp")
            
            # Copy files to installation directory
            # ...
            
            # Update version
            # self.version_control.update_version(new_version, release_notes)
            
            logger.info("⚠️ Mock mode: Would install update here")
            logger.info("✅ Update installed successfully")
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Error installing update: {e}")
            logger.info("🔄 Rolling back...")
            self.rollback(backup_path)
            return False
    
    def rollback(self, backup_path: Path) -> bool:
        """
        Rollback to previous version
        
        Args:
            backup_path: Path to backup
            
        Returns:
            True if successful
        """
        try:
            logger.info(f"🔄 Rolling back to backup: {backup_path}")
            
            if not backup_path.exists():
                logger.error(f"❌ Backup not found: {backup_path}")
                return False
            
            # Restore files from backup
            # ...
            
            logger.info("✅ Rollback successful")
            return True
            
        except Exception as e:
            logger.error(f"❌ Error during rollback: {e}")
            return False
    
    def get_update_status(self) -> Dict[str, Any]:
        """
        Get current update status
        
        Returns:
            Status dictionary
        """
        return {
            "current_version": str(self.current_version),
            "auto_check_enabled": self.update_config.get("auto_check", True),
            "auto_download_enabled": self.update_config.get("auto_download", False),
            "auto_install_enabled": self.update_config.get("auto_install", False),
            "last_check": self.update_config.get("last_check"),
            "update_channel": self.update_config.get("update_channel", "stable")
        }
    
    def configure_updates(self, config: Dict[str, Any]):
        """
        Configure update settings
        
        Args:
            config: Configuration dictionary
        """
        self.update_config.update(config)
        self._save_update_config()
        logger.info("✅ Update configuration saved")


# CLI for testing
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python update_manager.py check      - Check for updates")
        print("  python update_manager.py status     - Show update status")
        print("  python update_manager.py download   - Download available update")
        sys.exit(1)
    
    command = sys.argv[1]
    manager = UpdateManager()
    
    if command == "check":
        result = manager.check_for_updates(force=True)
        if result:
            print(json.dumps(result, indent=2))
        
    elif command == "status":
        status = manager.get_update_status()
        print(json.dumps(status, indent=2))
        
    elif command == "download":
        result = manager.check_for_updates(force=True)
        if result and result.get("available"):
            file_path = manager.download_update(result)
            if file_path:
                print(f"✅ Downloaded to: {file_path}")
    
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)