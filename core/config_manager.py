"""
CyberGuardian AI - Configuration Manager
Export/Import system configuration
"""

import sys
from pathlib import Path

# Add parent directory to Python path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import json
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime
import shutil

from database.db import (
    get_protection_settings,
    get_exclusions,
    get_scan_schedules
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration
BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_DIR = BASE_DIR / "config"
BACKUPS_DIR = BASE_DIR / "config_backups"

# Ensure directories exist
CONFIG_DIR.mkdir(exist_ok=True)
BACKUPS_DIR.mkdir(exist_ok=True)

class ConfigurationManager:
    """
    Manages system configuration export/import
    """
    
    def __init__(self):
        self.config_version = "1.0"
    
    def export_configuration(
        self,
        include_protection: bool = True,
        include_exclusions: bool = True,
        include_schedules: bool = True,
        include_update_settings: bool = True
    ) -> Dict[str, Any]:
        """
        Export system configuration
        
        Args:
            include_protection: Include protection settings
            include_exclusions: Include exclusions
            include_schedules: Include scan schedules
            include_update_settings: Include update settings
            
        Returns:
            Configuration dictionary
        """
        try:
            logger.info("📤 Exporting configuration...")
            
            config = {
                "config_version": self.config_version,
                "exported_at": datetime.now().isoformat(),
                "cyberguardian_version": self._get_app_version(),
                "sections": {}
            }
            
            # Protection settings
            if include_protection:
                try:
                    protection = get_protection_settings()
                    config["sections"]["protection"] = {
                        "enabled": bool(protection.get("enabled", False)),
                        "watch_paths": protection.get("watch_paths", []),
                        "auto_quarantine": bool(protection.get("auto_quarantine", False)),
                        "threat_threshold": protection.get("threat_threshold", 80)
                    }
                    logger.info("✅ Protection settings exported")
                except Exception as e:
                    logger.error(f"❌ Error exporting protection settings: {e}")
                    config["sections"]["protection"] = None
            
            # Exclusions
            if include_exclusions:
                try:
                    exclusions = get_exclusions()
                    config["sections"]["exclusions"] = [
                        {
                            "type": exc["type"],
                            "value": exc["value"],
                            "reason": exc.get("reason")
                        }
                        for exc in exclusions
                    ]
                    logger.info(f"✅ {len(exclusions)} exclusions exported")
                except Exception as e:
                    logger.error(f"❌ Error exporting exclusions: {e}")
                    config["sections"]["exclusions"] = []
            
            # Scan schedules
            if include_schedules:
                try:
                    schedules = get_scan_schedules()
                    config["sections"]["scan_schedules"] = [
                        {
                            "name": sched["name"],
                            "scan_type": sched["scan_type"],
                            "target_path": sched["target_path"],
                            "schedule_type": sched["schedule_type"],
                            "cron_expression": sched.get("cron_expression"),
                            "interval_days": sched.get("interval_days"),
                            "enabled": bool(sched["enabled"])
                        }
                        for sched in schedules
                    ]
                    logger.info(f"✅ {len(schedules)} scan schedules exported")
                except Exception as e:
                    logger.error(f"❌ Error exporting scan schedules: {e}")
                    config["sections"]["scan_schedules"] = []
            
            # Update settings
            if include_update_settings:
                try:
                    update_config_file = CONFIG_DIR / "update_config.json"
                    if update_config_file.exists():
                        with open(update_config_file, "r") as f:
                            update_settings = json.load(f)
                        
                        config["sections"]["update_settings"] = {
                            "auto_check": update_settings.get("auto_check", True),
                            "auto_download": update_settings.get("auto_download", False),
                            "auto_install": update_settings.get("auto_install", False),
                            "update_channel": update_settings.get("update_channel", "stable")
                        }
                        logger.info("✅ Update settings exported")
                    else:
                        config["sections"]["update_settings"] = None
                except Exception as e:
                    logger.error(f"❌ Error exporting update settings: {e}")
                    config["sections"]["update_settings"] = None
            
            logger.info("✅ Configuration export complete")
            return config
            
        except Exception as e:
            logger.error(f"❌ Error exporting configuration: {e}")
            raise
    
    def save_configuration(
        self,
        config: Dict[str, Any],
        filename: Optional[str] = None
    ) -> Path:
        """
        Save configuration to file
        
        Args:
            config: Configuration dictionary
            filename: Optional filename (default: auto-generated)
            
        Returns:
            Path to saved file
        """
        try:
            if not filename:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"cyberguardian_config_{timestamp}.json"
            
            filepath = CONFIG_DIR / filename
            
            with open(filepath, "w") as f:
                json.dump(config, f, indent=2)
            
            logger.info(f"✅ Configuration saved: {filepath}")
            return filepath
            
        except Exception as e:
            logger.error(f"❌ Error saving configuration: {e}")
            raise
    
    def load_configuration(self, filepath: Path) -> Dict[str, Any]:
        """
        Load configuration from file
        
        Args:
            filepath: Path to configuration file
            
        Returns:
            Configuration dictionary
        """
        try:
            if not filepath.exists():
                raise FileNotFoundError(f"Configuration file not found: {filepath}")
            
            with open(filepath, "r") as f:
                config = json.load(f)
            
            # Validate config
            if not self._validate_configuration(config):
                raise ValueError("Invalid configuration format")
            
            logger.info(f"✅ Configuration loaded: {filepath}")
            return config
            
        except Exception as e:
            logger.error(f"❌ Error loading configuration: {e}")
            raise
    
    def import_configuration(
        self,
        config: Dict[str, Any],
        import_protection: bool = True,
        import_exclusions: bool = True,
        import_schedules: bool = True,
        import_update_settings: bool = True,
        create_backup: bool = True
    ) -> Dict[str, Any]:
        """
        Import configuration
        
        Args:
            config: Configuration dictionary
            import_protection: Import protection settings
            import_exclusions: Import exclusions
            import_schedules: Import scan schedules
            import_update_settings: Import update settings
            create_backup: Create backup before import
            
        Returns:
            Import results
        """
        try:
            logger.info("📥 Importing configuration...")
            
            results = {
                "success": True,
                "sections_imported": [],
                "sections_failed": [],
                "backup_path": None
            }
            
            # Create backup
            if create_backup:
                try:
                    current_config = self.export_configuration()
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    backup_filename = f"backup_before_import_{timestamp}.json"
                    backup_path = self.save_backup(current_config, backup_filename)
                    results["backup_path"] = str(backup_path)
                    logger.info(f"✅ Backup created: {backup_path}")
                except Exception as e:
                    logger.error(f"⚠️ Could not create backup: {e}")
            
            sections = config.get("sections", {})
            
            # Import protection settings
            if import_protection and "protection" in sections:
                try:
                    protection = sections["protection"]
                    if protection:
                        from database.db import update_protection_settings
                        update_protection_settings(
                            enabled=protection["enabled"],
                            watch_paths=protection["watch_paths"],
                            auto_quarantine=protection.get("auto_quarantine"),
                            threat_threshold=protection.get("threat_threshold")
                        )
                        results["sections_imported"].append("protection")
                        logger.info("✅ Protection settings imported")
                except Exception as e:
                    logger.error(f"❌ Error importing protection settings: {e}")
                    results["sections_failed"].append({"section": "protection", "error": str(e)})
            
            # Import exclusions
            if import_exclusions and "exclusions" in sections:
                try:
                    from database.db import add_exclusion
                    imported_count = 0
                    
                    for exc in sections["exclusions"]:
                        try:
                            add_exclusion(
                                exclusion_type=exc["type"],
                                value=exc["value"],
                                reason=exc.get("reason"),
                                created_by="import"
                            )
                            imported_count += 1
                        except Exception as e:
                            logger.warning(f"⚠️ Could not import exclusion {exc['value']}: {e}")
                    
                    results["sections_imported"].append(f"exclusions ({imported_count})")
                    logger.info(f"✅ {imported_count} exclusions imported")
                except Exception as e:
                    logger.error(f"❌ Error importing exclusions: {e}")
                    results["sections_failed"].append({"section": "exclusions", "error": str(e)})
            
            # Import scan schedules
            if import_schedules and "scan_schedules" in sections:
                try:
                    from database.db import add_scan_schedule
                    imported_count = 0
                    
                    for sched in sections["scan_schedules"]:
                        try:
                            add_scan_schedule(
                                name=sched["name"],
                                scan_type=sched["scan_type"],
                                target_path=sched["target_path"],
                                schedule_type=sched["schedule_type"],
                                cron_expression=sched.get("cron_expression"),
                                interval_days=sched.get("interval_days"),
                                enabled=sched["enabled"]
                            )
                            imported_count += 1
                        except Exception as e:
                            logger.warning(f"⚠️ Could not import schedule {sched['name']}: {e}")
                    
                    results["sections_imported"].append(f"scan_schedules ({imported_count})")
                    logger.info(f"✅ {imported_count} scan schedules imported")
                except Exception as e:
                    logger.error(f"❌ Error importing scan schedules: {e}")
                    results["sections_failed"].append({"section": "scan_schedules", "error": str(e)})
            
            # Import update settings
            if import_update_settings and "update_settings" in sections:
                try:
                    update_settings = sections["update_settings"]
                    if update_settings:
                        update_config_file = CONFIG_DIR / "update_config.json"
                        with open(update_config_file, "w") as f:
                            json.dump(update_settings, f, indent=2)
                        
                        results["sections_imported"].append("update_settings")
                        logger.info("✅ Update settings imported")
                except Exception as e:
                    logger.error(f"❌ Error importing update settings: {e}")
                    results["sections_failed"].append({"section": "update_settings", "error": str(e)})
            
            results["success"] = len(results["sections_failed"]) == 0
            
            logger.info("✅ Configuration import complete")
            return results
            
        except Exception as e:
            logger.error(f"❌ Error importing configuration: {e}")
            raise
    
    def save_backup(self, config: Dict[str, Any], filename: str) -> Path:
        """
        Save configuration backup
        
        Args:
            config: Configuration dictionary
            filename: Backup filename
            
        Returns:
            Path to backup file
        """
        filepath = BACKUPS_DIR / filename
        
        with open(filepath, "w") as f:
            json.dump(config, f, indent=2)
        
        return filepath
    
    def list_backups(self) -> List[Dict[str, Any]]:
        """
        List all configuration backups
        
        Returns:
            List of backup info
        """
        backups = []
        
        for file in BACKUPS_DIR.glob("*.json"):
            try:
                stat = file.stat()
                backups.append({
                    "filename": file.name,
                    "path": str(file),
                    "size_bytes": stat.st_size,
                    "created_at": datetime.fromtimestamp(stat.st_ctime).isoformat()
                })
            except Exception as e:
                logger.error(f"Error reading backup {file}: {e}")
        
        # Sort by creation time (newest first)
        backups.sort(key=lambda x: x["created_at"], reverse=True)
        
        return backups
    
    def restore_backup(self, backup_filename: str) -> Dict[str, Any]:
        """
        Restore configuration from backup
        
        Args:
            backup_filename: Backup filename
            
        Returns:
            Restore results
        """
        backup_path = BACKUPS_DIR / backup_filename
        
        if not backup_path.exists():
            raise FileNotFoundError(f"Backup not found: {backup_filename}")
        
        config = self.load_configuration(backup_path)
        return self.import_configuration(config, create_backup=True)
    
    def _validate_configuration(self, config: Dict[str, Any]) -> bool:
        """
        Validate configuration format
        
        Args:
            config: Configuration dictionary
            
        Returns:
            True if valid
        """
        required_keys = ["config_version", "exported_at", "sections"]
        
        for key in required_keys:
            if key not in config:
                logger.error(f"Missing required key: {key}")
                return False
        
        return True
    
    def _get_app_version(self) -> str:
        """Get application version"""
        try:
            from core.version_control import get_current_version
            return str(get_current_version())
        except:
            return "unknown"


# CLI for testing
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python config_manager.py export     - Export configuration")
        print("  python config_manager.py list       - List backups")
        sys.exit(1)
    
    command = sys.argv[1]
    manager = ConfigurationManager()
    
    if command == "export":
        config = manager.export_configuration()
        filepath = manager.save_configuration(config)
        print(f"✅ Configuration exported to: {filepath}")
        
    elif command == "list":
        backups = manager.list_backups()
        print(f"Found {len(backups)} backups:")
        for backup in backups:
            print(f"  - {backup['filename']} ({backup['size_bytes']} bytes)")
    
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)