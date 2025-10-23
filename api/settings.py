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

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, Dict, Any
import json
import platform
import psutil
from pathlib import Path
from datetime import datetime

router = APIRouter()

# Settings file path
SETTINGS_FILE = Path("backend/settings.json")

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
async def get_settings():
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
async def update_settings(settings: Settings):
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
async def get_system_info():
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
async def get_license_info():
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
async def reset_settings():
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