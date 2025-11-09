"""
CyberGuardian AI - Settings API
Configuration and Preferences Management

Provides endpoints for:
- User preferences
- System settings
- Theme configuration
- Notification settings
- License information
"""

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from typing import Optional, Dict, Any
import json
import platform
import psutil
import sqlite3
from pathlib import Path
from datetime import datetime
from middleware.rate_limiter import limiter, SETTINGS_LIMIT

router = APIRouter()

# Settings file path
SETTINGS_FILE = Path("backend/settings.json")

# ============================================
# DATABASE HELPER
# ============================================

def get_db_connection():
    """Get direct database connection"""
    db_path = Path(__file__).parent.parent / "database" / "cyberguardian.db"
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    return conn

# ============================================
# PYDANTIC MODELS
# ============================================

class NotificationSettings(BaseModel):
    """Notification preferences"""
    email_alerts: bool = True
    desktop_alerts: bool = True
    critical_only: bool = False
    alert_sound: bool = True

class AppearanceSettings(BaseModel):
    """Appearance preferences"""
    theme: str = "dark"  # dark, light, auto
    compact_mode: bool = False
    animations_enabled: bool = True

class SecuritySettings(BaseModel):
    """Security configuration"""
    auto_block_threats: bool = True
    honeypots_enabled: bool = True
    real_time_scanning: bool = True
    quarantine_auto: bool = True

class Settings(BaseModel):
    """Complete settings model"""
    notifications: NotificationSettings = NotificationSettings()
    appearance: AppearanceSettings = AppearanceSettings()
    security: SecuritySettings = SecuritySettings()
    last_updated: str = datetime.now().isoformat()

class SystemInfo(BaseModel):
    """System information"""
    os: str
    os_version: str
    python_version: str
    cpu_count: int
    total_memory_gb: float
    hostname: str

class LicenseInfo(BaseModel):
    """License information"""
    license_type: str
    status: str
    expires_at: Optional[str]
    features: list[str]

# ============================================
# HELPER FUNCTIONS
# ============================================

def load_settings() -> Settings:
    """Load settings from file"""
    try:
        if SETTINGS_FILE.exists():
            with open(SETTINGS_FILE, 'r') as f:
                data = json.load(f)
                return Settings(**data)
    except Exception as e:
        print(f"Error loading settings: {e}")
    
    # Return default settings if file doesn't exist or error
    return Settings()

def save_settings(settings: Settings) -> bool:
    """Save settings to file"""
    try:
        SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
        
        with open(SETTINGS_FILE, 'w') as f:
            json.dump(settings.model_dump(), f, indent=2)
        
        return True
    except Exception as e:
        print(f"Error saving settings: {e}")
        return False

# ============================================
# API ENDPOINTS
# ============================================

@router.get("/settings", response_model=Settings)
@limiter.limit(SETTINGS_LIMIT)  # 20 requests per minute
async def get_settings(request: Request):
    """
    Get current settings
    
    Returns all user preferences and configuration
    """
    try:
        settings = load_settings()
        return settings
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load settings: {str(e)}")


@router.post("/settings", response_model=Settings)
@limiter.limit(SETTINGS_LIMIT)  # 20 requests per minute
async def update_settings(request: Request, settings: Settings):
    """
    Update settings
    
    Args:
        settings: New settings configuration
    
    Returns:
        Updated settings
    """
    try:
        # Update timestamp
        settings.last_updated = datetime.now().isoformat()
        
        # Save to file
        success = save_settings(settings)
        
        if not success:
            raise HTTPException(status_code=500, detail="Failed to save settings")
        
        return settings
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update settings: {str(e)}")


@router.get("/settings/system-info", response_model=SystemInfo)
@limiter.limit(SETTINGS_LIMIT)  # 20 requests per minute
async def get_system_info(request: Request):
    """
    Get system information
    
    Returns details about the host system
    """
    try:
        import sys
        
        # Get memory in GB
        total_memory = psutil.virtual_memory().total / (1024 ** 3)
        
        system_info = SystemInfo(
            os=platform.system(),
            os_version=platform.version(),
            python_version=sys.version.split()[0],
            cpu_count=psutil.cpu_count(),
            total_memory_gb=round(total_memory, 2),
            hostname=platform.node()
        )
        
        return system_info
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get system info: {str(e)}")


@router.get("/settings/license", response_model=LicenseInfo)
@limiter.limit(SETTINGS_LIMIT)  # 20 requests per minute
async def get_license_info(request: Request):
    """
    Get license information
    
    Returns current license status and features
    """
    try:
        # Mock license info for demo
        # In production, this would query a real license system
        license_info = LicenseInfo(
            license_type="Professional",
            status="active",
            expires_at="2025-12-31T23:59:59",
            features=[
                "Real-time threat detection",
                "Advanced AI analysis",
                "Honeypot deception layer",
                "Unlimited scans",
                "Priority support",
                "Custom alerts"
            ]
        )
        
        return license_info
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get license info: {str(e)}")


@router.post("/settings/reset")
@limiter.limit(SETTINGS_LIMIT)  # 20 requests per minute
async def reset_settings(request: Request):
    """
    Reset settings to default
    
    Returns:
        Success message
    """
    try:
        default_settings = Settings()
        success = save_settings(default_settings)
        
        if not success:
            raise HTTPException(status_code=500, detail="Failed to reset settings")
        
        return {
            "message": "Settings reset to default successfully",
            "settings": default_settings
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to reset settings: {str(e)}")


# ============================================
# EXPORT/IMPORT CONFIG
# ============================================

@router.get("/settings/export")
@limiter.limit(SETTINGS_LIMIT)
async def export_config(request: Request):
    """
    Export complete system configuration
    
    Returns a JSON file with all settings, exclusions, schedules, etc.
    """
    try:
        # Gather all configuration data
        config = {
            "version": "1.0",
            "exported_at": datetime.now().isoformat() + "Z",
            "settings": {},
            "exclusions": [],
            "scan_schedules": [],
            "auto_purge_policy": {}
        }
        
        # 1. App Settings
        app_settings = load_settings()
        config["settings"] = app_settings.model_dump()
        
        # 2. Exclusions
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT type, value, reason FROM exclusions")
            exclusions = cursor.fetchall()
            config["exclusions"] = [
                {"type": row[0], "value": row[1], "reason": row[2]}
                for row in exclusions
            ]
            conn.close()
        except Exception as e:
            print(f"Could not load exclusions: {e}")
        
        # 3. Scan Schedules
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
                SELECT name, scan_type, target_path, schedule_type, 
                       interval_days, enabled
                FROM scan_schedules
            """)
            schedules = cursor.fetchall()
            config["scan_schedules"] = [
                {
                    "name": row[0],
                    "scan_type": row[1],
                    "target_path": row[2],
                    "schedule_type": row[3],
                    "interval_days": row[4],
                    "enabled": bool(row[5])
                }
                for row in schedules
            ]
            conn.close()
        except Exception as e:
            print(f"Could not load scan schedules: {e}")
        
        # 4. Auto-Purge Policy
        try:
            from api import quarantine
            config["auto_purge_policy"] = quarantine._auto_purge_settings.dict()
        except Exception as e:
            print(f"Could not load auto-purge settings: {e}")
        
        return {
            "success": True,
            "data": config,
            "filename": f"cyberguardian-config-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to export configuration: {str(e)}"
        )


@router.post("/settings/import")
@limiter.limit(SETTINGS_LIMIT)
async def import_config(request: Request, config: Dict[str, Any]):
    """
    Import system configuration from JSON
    
    Args:
        config: Complete configuration data
    
    Returns:
        Import status and results
    """
    try:
        results = {
            "success": True,
            "imported": [],
            "failed": [],
            "warnings": []
        }
        
        # Validate config structure
        if "version" not in config:
            results["warnings"].append("Config version not specified")
        
        # 1. Import App Settings
        try:
            if "settings" in config:
                settings = Settings(**config["settings"])
                settings.last_updated = datetime.now().isoformat()
                save_settings(settings)
                results["imported"].append("App Settings")
        except Exception as e:
            results["failed"].append(f"App Settings: {str(e)}")
        
        # 2. Import Exclusions
        try:
            if "exclusions" in config and config["exclusions"]:
                conn = get_db_connection()
                cursor = conn.cursor()
                
                # Clear existing exclusions
                cursor.execute("DELETE FROM exclusions")
                
                # Insert new exclusions
                for excl in config["exclusions"]:
                    cursor.execute("""
                        INSERT INTO exclusions (type, value, reason, created_at)
                        VALUES (?, ?, ?, ?)
                    """, (
                        excl["type"],
                        excl["value"],
                        excl.get("reason"),
                        datetime.now().isoformat() + "Z"
                    ))
                
                conn.commit()
                conn.close()
                results["imported"].append(f"Exclusions ({len(config['exclusions'])} items)")
        except Exception as e:
            results["failed"].append(f"Exclusions: {str(e)}")
        
        # 3. Import Scan Schedules
        try:
            if "scan_schedules" in config and config["scan_schedules"]:
                conn = get_db_connection()
                cursor = conn.cursor()
                
                # Note: Don't delete existing schedules, just add new ones
                for schedule in config["scan_schedules"]:
                    cursor.execute("""
                        INSERT INTO scan_schedules 
                        (name, scan_type, target_path, schedule_type, 
                         interval_days, enabled, created_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (
                        schedule["name"],
                        schedule["scan_type"],
                        schedule["target_path"],
                        schedule["schedule_type"],
                        schedule.get("interval_days"),
                        schedule.get("enabled", True),
                        datetime.now().isoformat() + "Z"
                    ))
                
                conn.commit()
                conn.close()
                results["imported"].append(f"Scan Schedules ({len(config['scan_schedules'])} items)")
        except Exception as e:
            results["failed"].append(f"Scan Schedules: {str(e)}")
        
        # 4. Import Auto-Purge Policy
        try:
            if "auto_purge_policy" in config:
                from api import quarantine
                quarantine._auto_purge_settings = quarantine.AutoPurgeSettings(**config["auto_purge_policy"])
                results["imported"].append("Auto-Purge Policy")
        except Exception as e:
            results["failed"].append(f"Auto-Purge Policy: {str(e)}")
        
        # Determine overall success
        if results["failed"]:
            results["success"] = False
            results["message"] = f"Imported {len(results['imported'])} items with {len(results['failed'])} failures"
        else:
            results["message"] = f"Successfully imported {len(results['imported'])} configuration items"
        
        return results
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to import configuration: {str(e)}"
        )