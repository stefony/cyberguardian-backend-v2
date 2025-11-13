"""
CyberGuardian AI - Configuration API
Endpoints for configuration export/import
"""

import sys
from pathlib import Path

# Add parent directory to Python path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi import APIRouter, HTTPException, Request, UploadFile, File
from fastapi.responses import FileResponse
from typing import Optional, Dict, Any
import logging
import json

from middleware.rate_limiter import limiter, READ_LIMIT, WRITE_LIMIT
from core.config_manager import ConfigurationManager

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/configuration", tags=["Configuration"])

# Global config manager
_config_manager: Optional[ConfigurationManager] = None


def get_config_manager() -> ConfigurationManager:
    """Get or create config manager instance"""
    global _config_manager
    if not _config_manager:
        _config_manager = ConfigurationManager()
    return _config_manager


# ============================================================================
# EXPORT
# ============================================================================

@router.get("/export")
@limiter.limit(READ_LIMIT)
async def export_configuration(
    request: Request,
    include_protection: bool = True,
    include_exclusions: bool = True,
    include_schedules: bool = True,
    include_update_settings: bool = True
):
    """
    Export system configuration
    
    Query params:
        include_protection: Include protection settings
        include_exclusions: Include exclusions
        include_schedules: Include scan schedules
        include_update_settings: Include update settings
    """
    try:
        manager = get_config_manager()
        
        config = manager.export_configuration(
            include_protection=include_protection,
            include_exclusions=include_exclusions,
            include_schedules=include_schedules,
            include_update_settings=include_update_settings
        )
        
        return {
            "success": True,
            "config": config
        }
        
    except Exception as e:
        logger.error(f"Error exporting configuration: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/export/download")
@limiter.limit(READ_LIMIT)
async def download_configuration(
    request: Request,
    include_protection: bool = True,
    include_exclusions: bool = True,
    include_schedules: bool = True,
    include_update_settings: bool = True
):
    """
    Export and download configuration as JSON file
    """
    try:
        manager = get_config_manager()
        
        config = manager.export_configuration(
            include_protection=include_protection,
            include_exclusions=include_exclusions,
            include_schedules=include_schedules,
            include_update_settings=include_update_settings
        )
        
        filepath = manager.save_configuration(config)
        
        return FileResponse(
            path=str(filepath),
            media_type="application/json",
            filename=filepath.name
        )
        
    except Exception as e:
        logger.error(f"Error downloading configuration: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# IMPORT
# ============================================================================

@router.post("/import")
@limiter.limit(WRITE_LIMIT)
async def import_configuration(
    request: Request,
    config: Dict[str, Any],
    import_protection: bool = True,
    import_exclusions: bool = True,
    import_schedules: bool = True,
    import_update_settings: bool = True,
    create_backup: bool = True
):
    """
    Import configuration
    
    Body:
        config: Configuration object (from export)
    
    Query params:
        import_protection: Import protection settings
        import_exclusions: Import exclusions
        import_schedules: Import scan schedules
        import_update_settings: Import update settings
        create_backup: Create backup before import
    """
    try:
        manager = get_config_manager()
        
        results = manager.import_configuration(
            config=config,
            import_protection=import_protection,
            import_exclusions=import_exclusions,
            import_schedules=import_schedules,
            import_update_settings=import_update_settings,
            create_backup=create_backup
        )
        
        return {
            "success": results["success"],
            "message": "Configuration imported successfully" if results["success"] else "Configuration import completed with errors",
            "results": results
        }
        
    except Exception as e:
        logger.error(f"Error importing configuration: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/import/upload")
@limiter.limit(WRITE_LIMIT)
async def upload_configuration(
    request: Request,
    file: UploadFile = File(...),
    import_protection: bool = True,
    import_exclusions: bool = True,
    import_schedules: bool = True,
    import_update_settings: bool = True,
    create_backup: bool = True
):
    """
    Upload and import configuration file
    """
    try:
        # Validate file type
        if not file.filename.endswith('.json'):
            raise HTTPException(status_code=400, detail="Only JSON files are allowed")
        
        # Read file content
        content = await file.read()
        config = json.loads(content.decode('utf-8'))
        
        manager = get_config_manager()
        
        results = manager.import_configuration(
            config=config,
            import_protection=import_protection,
            import_exclusions=import_exclusions,
            import_schedules=import_schedules,
            import_update_settings=import_update_settings,
            create_backup=create_backup
        )
        
        return {
            "success": results["success"],
            "message": f"Configuration from {file.filename} imported successfully" if results["success"] else "Configuration import completed with errors",
            "results": results
        }
        
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON file")
    except Exception as e:
        logger.error(f"Error uploading configuration: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# BACKUPS
# ============================================================================

@router.get("/backups")
@limiter.limit(READ_LIMIT)
async def list_backups(request: Request):
    """
    List all configuration backups
    """
    try:
        manager = get_config_manager()
        backups = manager.list_backups()
        
        return {
            "success": True,
            "total": len(backups),
            "backups": backups
        }
        
    except Exception as e:
        logger.error(f"Error listing backups: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/backups/{filename}/download")
@limiter.limit(READ_LIMIT)
async def download_backup(request: Request, filename: str):
    """
    Download a specific backup file
    """
    try:
        manager = get_config_manager()
        backup_path = manager.BACKUPS_DIR / filename
        
        if not backup_path.exists():
            raise HTTPException(status_code=404, detail="Backup not found")
        
        return FileResponse(
            path=str(backup_path),
            media_type="application/json",
            filename=filename
        )
        
    except Exception as e:
        logger.error(f"Error downloading backup: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/backups/{filename}/restore")
@limiter.limit(WRITE_LIMIT)
async def restore_backup(request: Request, filename: str):
    """
    Restore configuration from backup
    """
    try:
        manager = get_config_manager()
        results = manager.restore_backup(filename)
        
        return {
            "success": results["success"],
            "message": f"Configuration restored from {filename}",
            "results": results
        }
        
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Backup not found")
    except Exception as e:
        logger.error(f"Error restoring backup: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# VALIDATION
# ============================================================================

@router.post("/validate")
@limiter.limit(READ_LIMIT)
async def validate_configuration(request: Request, config: Dict[str, Any]):
    """
    Validate configuration without importing
    """
    try:
        manager = get_config_manager()
        is_valid = manager._validate_configuration(config)
        
        if not is_valid:
            return {
                "success": False,
                "valid": False,
                "message": "Invalid configuration format"
            }
        
        # Additional validation
        sections = config.get("sections", {})
        warnings = []
        
        # Check for empty sections
        if sections.get("protection") is None:
            warnings.append("Protection settings are missing")
        
        if not sections.get("exclusions"):
            warnings.append("No exclusions configured")
        
        if not sections.get("scan_schedules"):
            warnings.append("No scan schedules configured")
        
        return {
            "success": True,
            "valid": True,
            "message": "Configuration is valid",
            "warnings": warnings,
            "config_version": config.get("config_version"),
            "cyberguardian_version": config.get("cyberguardian_version"),
            "exported_at": config.get("exported_at")
        }
        
    except Exception as e:
        logger.error(f"Error validating configuration: {e}")
        raise HTTPException(status_code=500, detail=str(e))