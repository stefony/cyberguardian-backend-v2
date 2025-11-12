"""
Remediation API - Endpoints for malware cleanup and removal
Handles registry cleanup, services management, scheduled tasks, etc.
"""

from fastapi import APIRouter, HTTPException, Depends, Request
from pydantic import BaseModel
from typing import List, Dict, Optional
from datetime import datetime
import sys
import os

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.response.registry_cleaner import (
    scan_registry_entries,
    remove_registry_entry,
    restore_registry_entry,
    get_registry_statistics,
)
from core.response.service_manager import (
    scan_windows_services,
    stop_windows_service,
    delete_windows_service,
    get_service_statistics,
)
from core.response.task_manager import (
    scan_scheduled_tasks,
    delete_scheduled_task,
    get_task_statistics,
)
from middleware.rate_limiter import limiter, WRITE_LIMIT, READ_LIMIT

router = APIRouter(prefix="/api/remediation", tags=["remediation"])


# ===== REQUEST/RESPONSE MODELS =====

class RegistryEntryResponse(BaseModel):
    """Response model for a registry entry"""
    id: str
    hive: str
    key_path: str
    value_name: str
    value_data: str
    value_type: str
    risk_score: int
    indicators: List[str]
    scanned_at: str


class RegistryStatisticsResponse(BaseModel):
    """Response model for registry scan statistics"""
    total_suspicious: int
    critical_risk: int
    high_risk: int
    medium_risk: int
    low_risk: int
    by_hive: Dict[str, int]


class RegistryScanResponse(BaseModel):
    """Response model for full registry scan"""
    entries: List[RegistryEntryResponse]
    statistics: RegistryStatisticsResponse
    scanned_at: str


class RemoveRegistryRequest(BaseModel):
    """Request model for removing a registry entry"""
    hive: str
    key_path: str
    value_name: str


class RemoveRegistryResponse(BaseModel):
    """Response model for registry removal"""
    success: bool
    message: str
    backup_file: Optional[str] = None


class RestoreRegistryRequest(BaseModel):
    """Request model for restoring a registry entry"""
    backup_file: str


class RestoreRegistryResponse(BaseModel):
    """Response model for registry restoration"""
    success: bool
    message: str


class RemediationActionLog(BaseModel):
    """Log entry for remediation action"""
    action: str
    target: str
    success: bool
    message: str
    timestamp: str


# ===== REGISTRY CLEANUP ENDPOINTS =====

@router.get("/registry/scan", response_model=RegistryScanResponse)
@limiter.limit(READ_LIMIT)
async def scan_registry(request: Request):
    """
    Scan Windows registry for suspicious autorun entries
    
    Returns:
        List of suspicious registry entries with statistics
    """
    try:
        # Scan registry
        entries = scan_registry_entries()
        
        # Get statistics
        statistics = get_registry_statistics(entries)
        
        return {
            "entries": entries,
            "statistics": statistics,
            "scanned_at": datetime.utcnow().isoformat(),
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Registry scan failed: {str(e)}")


@router.get("/registry/statistics", response_model=RegistryStatisticsResponse)
@limiter.limit(READ_LIMIT)
async def get_registry_stats(request: Request):
    """
    Get statistics from the last registry scan
    
    Returns:
        Registry scan statistics
    """
    try:
        # Scan registry
        entries = scan_registry_entries()
        
        # Get statistics
        statistics = get_registry_statistics(entries)
        
        return statistics
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get statistics: {str(e)}")


@router.post("/registry/remove", response_model=RemoveRegistryResponse)
@limiter.limit(WRITE_LIMIT)
async def remove_registry(request: Request, data: RemoveRegistryRequest):
    """
    Remove a suspicious registry entry (with automatic backup)
    
    Args:
        hive: Registry hive name (e.g., "HKEY_LOCAL_MACHINE")
        key_path: Path to the registry key
        value_name: Name of the value to remove
    
    Returns:
        Success status and backup file path
    """
    try:
        success, result = remove_registry_entry(
            data.hive,
            data.key_path,
            data.value_name
        )
        
        if success:
            # Log the action (will implement database logging later)
            return {
                "success": True,
                "message": "Registry entry removed successfully",
                "backup_file": result,
            }
        else:
            return {
                "success": False,
                "message": result,
                "backup_file": None,
            }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to remove registry entry: {str(e)}")


@router.post("/registry/restore", response_model=RestoreRegistryResponse)
@limiter.limit(WRITE_LIMIT)
async def restore_registry(request: Request, data: RestoreRegistryRequest):
    """
    Restore a registry entry from backup
    
    Args:
        backup_file: Path to the backup file
    
    Returns:
        Success status and message
    """
    try:
        success, message = restore_registry_entry(data.backup_file)
        
        return {
            "success": success,
            "message": message,
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to restore registry entry: {str(e)}")


@router.get("/registry/backups")
@limiter.limit(READ_LIMIT)
async def list_registry_backups(request: Request):
    """
    List all registry backup files
    
    Returns:
        List of backup files with metadata
    """
    try:
        import json
        backup_dir = "registry_backups"
        
        if not os.path.exists(backup_dir):
            return {"backups": []}
        
        backups = []
        for filename in os.listdir(backup_dir):
            if filename.endswith(".json"):
                filepath = os.path.join(backup_dir, filename)
                
                # Read backup metadata
                try:
                    with open(filepath, "r") as f:
                        backup_data = json.load(f)
                    
                    backups.append({
                        "filename": filename,
                        "filepath": filepath,
                        "hive": backup_data.get("hive", "Unknown"),
                        "key_path": backup_data.get("key_path", "Unknown"),
                        "value_name": backup_data.get("value_name", "Unknown"),
                        "backed_up_at": backup_data.get("backed_up_at", "Unknown"),
                    })
                except:
                    # Skip corrupted backups
                    continue
        
        # Sort by backup time (newest first)
        backups.sort(key=lambda x: x["backed_up_at"], reverse=True)
        
        return {"backups": backups}
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list backups: {str(e)}")


# ===== SERVICES CLEANUP ENDPOINTS =====

@router.get("/services/scan")
@limiter.limit(READ_LIMIT)
async def scan_services(request: Request):
    """
    Scan Windows services for suspicious entries
    
    Returns:
        List of suspicious services with statistics
    """
    try:
        # Scan services
        services = scan_windows_services()
        
        # Get statistics
        statistics = get_service_statistics(services)
        
        return {
            "services": services,
            "statistics": statistics,
            "scanned_at": datetime.utcnow().isoformat(),
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Service scan failed: {str(e)}")


@router.get("/services/statistics")
@limiter.limit(READ_LIMIT)
async def get_service_stats(request: Request):
    """
    Get statistics from the last service scan
    
    Returns:
        Service scan statistics
    """
    try:
        # Scan services
        services = scan_windows_services()
        
        # Get statistics
        statistics = get_service_statistics(services)
        
        return statistics
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get statistics: {str(e)}")


@router.post("/services/stop")
@limiter.limit(WRITE_LIMIT)
async def stop_service(request: Request, data: dict):
    """
    Stop a Windows service
    
    Args:
        service_name: Name of the service to stop
    
    Returns:
        Success status and message
    """
    try:
        service_name = data.get("service_name")
        if not service_name:
            raise HTTPException(status_code=400, detail="service_name is required")
        
        success, message = stop_windows_service(service_name)
        
        return {
            "success": success,
            "message": message,
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to stop service: {str(e)}")


@router.post("/services/remove")
@limiter.limit(WRITE_LIMIT)
async def remove_service(request: Request, data: dict):
    """
    Remove a suspicious Windows service (with automatic backup)
    
    Args:
        service_name: Name of the service to remove
    
    Returns:
        Success status and backup file path
    """
    try:
        service_name = data.get("service_name")
        if not service_name:
            raise HTTPException(status_code=400, detail="service_name is required")
        
        success, result = delete_windows_service(service_name)
        
        if success:
            return {
                "success": True,
                "message": "Service removed successfully",
                "backup_file": result,
            }
        else:
            return {
                "success": False,
                "message": result,
                "backup_file": None,
            }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to remove service: {str(e)}")


@router.get("/services/backups")
@limiter.limit(READ_LIMIT)
async def list_service_backups(request: Request):
    """
    List all service backup files
    
    Returns:
        List of backup files with metadata
    """
    try:
        import json
        backup_dir = "service_backups"
        
        if not os.path.exists(backup_dir):
            return {"backups": []}
        
        backups = []
        for filename in os.listdir(backup_dir):
            if filename.endswith(".json"):
                filepath = os.path.join(backup_dir, filename)
                
                # Read backup metadata
                try:
                    with open(filepath, "r") as f:
                        backup_data = json.load(f)
                    
                    backups.append({
                        "filename": filename,
                        "filepath": filepath,
                        "service_name": backup_data.get("service_name", "Unknown"),
                        "binary_path": backup_data.get("binary_path", "Unknown"),
                        "startup_type": backup_data.get("startup_type", "Unknown"),
                        "backed_up_at": backup_data.get("backed_up_at", "Unknown"),
                    })
                except:
                    # Skip corrupted backups
                    continue
        
        # Sort by backup time (newest first)
        backups.sort(key=lambda x: x["backed_up_at"], reverse=True)
        
        return {"backups": backups}
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list backups: {str(e)}")


# ===== SCHEDULED TASKS CLEANUP ENDPOINTS =====

@router.get("/tasks/scan")
@limiter.limit(READ_LIMIT)
async def scan_tasks(request: Request):
    """
    Scan Windows scheduled tasks for suspicious entries
    
    Returns:
        List of suspicious tasks with statistics
    """
    try:
        # Scan tasks
        tasks = scan_scheduled_tasks()
        
        # Get statistics
        statistics = get_task_statistics(tasks)
        
        return {
            "tasks": tasks,
            "statistics": statistics,
            "scanned_at": datetime.utcnow().isoformat(),
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Task scan failed: {str(e)}")


@router.get("/tasks/statistics")
@limiter.limit(READ_LIMIT)
async def get_task_stats(request: Request):
    """
    Get statistics from the last task scan
    
    Returns:
        Task scan statistics
    """
    try:
        # Scan tasks
        tasks = scan_scheduled_tasks()
        
        # Get statistics
        statistics = get_task_statistics(tasks)
        
        return statistics
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get statistics: {str(e)}")


@router.post("/tasks/remove")
@limiter.limit(WRITE_LIMIT)
async def remove_task(request: Request, data: dict):
    """
    Remove a suspicious scheduled task (with automatic backup)
    
    Args:
        task_path: Full path to the task
    
    Returns:
        Success status and backup file path
    """
    try:
        task_path = data.get("task_path")
        if not task_path:
            raise HTTPException(status_code=400, detail="task_path is required")
        
        success, result = delete_scheduled_task(task_path)
        
        if success:
            return {
                "success": True,
                "message": "Task removed successfully",
                "backup_file": result,
            }
        else:
            return {
                "success": False,
                "message": result,
                "backup_file": None,
            }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to remove task: {str(e)}")


@router.get("/tasks/backups")
@limiter.limit(READ_LIMIT)
async def list_task_backups(request: Request):
    """
    List all task backup files
    
    Returns:
        List of backup files with metadata
    """
    try:
        import json
        backup_dir = "task_backups"
        
        if not os.path.exists(backup_dir):
            return {"backups": []}
        
        backups = []
        for filename in os.listdir(backup_dir):
            if filename.endswith(".json"):
                filepath = os.path.join(backup_dir, filename)
                
                # Read backup metadata
                try:
                    with open(filepath, "r", encoding="utf-8") as f:
                        backup_data = json.load(f)
                    
                    backups.append({
                        "filename": filename,
                        "filepath": filepath,
                        "task_path": backup_data.get("task_path", "Unknown"),
                        "task_name": backup_data.get("task_name", "Unknown"),
                        "author": backup_data.get("author", "Unknown"),
                        "backed_up_at": backup_data.get("backed_up_at", "Unknown"),
                    })
                except:
                    # Skip corrupted backups
                    continue
        
        # Sort by backup time (newest first)
        backups.sort(key=lambda x: x["backed_up_at"], reverse=True)
        
        return {"backups": backups}
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list backups: {str(e)}")


# ===== LINUX CLEANUP ENDPOINTS (Placeholder for Phase 3.2) =====

@router.get("/cron/scan")
@limiter.limit(READ_LIMIT)
async def scan_cron_jobs(request: Request):
    """
    Scan Linux cron jobs for suspicious entries
    
    TODO: Implement cron scanner (Phase 3.2)
    """
    return {
        "message": "Cron scanning will be implemented in Phase 3.2",
        "cron_jobs": [],
    }


@router.post("/cron/remove")
@limiter.limit(WRITE_LIMIT)
async def remove_cron_job(request: Request):
    """
    Remove a suspicious cron job
    
    TODO: Implement cron removal (Phase 3.2)
    """
    return {
        "success": False,
        "message": "Cron removal will be implemented in Phase 3.2",
    }


@router.get("/systemd/scan")
@limiter.limit(READ_LIMIT)
async def scan_systemd_services(request: Request):
    """
    Scan Linux systemd services for suspicious entries
    
    TODO: Implement systemd scanner (Phase 3.2)
    """
    return {
        "message": "Systemd scanning will be implemented in Phase 3.2",
        "services": [],
    }


@router.post("/systemd/remove")
@limiter.limit(WRITE_LIMIT)
async def remove_systemd_service(request: Request):
    """
    Remove a suspicious systemd service
    
    TODO: Implement systemd removal (Phase 3.2)
    """
    return {
        "success": False,
        "message": "Systemd removal will be implemented in Phase 3.2",
    }


# ===== DEEP QUARANTINE ENDPOINTS (Placeholder for Phase 3.3) =====

@router.post("/quarantine/deep-scan")
@limiter.limit(WRITE_LIMIT)
async def deep_scan_before_quarantine(request: Request):
    """
    Perform deep scan before quarantining a file
    Checks for registry references, services, scheduled tasks
    
    TODO: Implement deep scan (Phase 3.3)
    """
    return {
        "message": "Deep scan will be implemented in Phase 3.3",
        "findings": {
            "registry_references": [],
            "services": [],
            "scheduled_tasks": [],
            "autorun_entries": [],
        },
    }


@router.post("/quarantine/complete-removal")
@limiter.limit(WRITE_LIMIT)
async def complete_malware_removal(request: Request):
    """
    Complete malware removal (file + registry + services + tasks)
    
    TODO: Implement complete removal (Phase 3.3)
    """
    return {
        "success": False,
        "message": "Complete removal will be implemented in Phase 3.3",
        "actions": [],
    }


# ===== HEALTH CHECK =====

@router.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "remediation",
        "features": {
            "registry_cleanup": "available",
            "services_cleanup": "planned",
            "tasks_cleanup": "planned",
            "linux_cleanup": "planned",
            "deep_quarantine": "planned",
        },
    }