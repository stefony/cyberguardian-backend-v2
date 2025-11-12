"""
CyberGuardian AI - Integrity Monitoring API
Endpoints for file integrity checks and tamper detection
"""

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from typing import Optional, Dict, Any, List
from datetime import datetime
import logging

from middleware.rate_limiter import limiter, READ_LIMIT, WRITE_LIMIT
from database.db import (
    log_integrity_check,
    get_integrity_logs,
    save_manifest_to_db,
    get_latest_manifest,
    get_all_manifests,
    create_integrity_alert,
    get_integrity_alerts,
    resolve_integrity_alert,
    get_integrity_statistics,
    delete_old_integrity_logs
)
from core.integrity_checker import (
    generate_manifest,
    save_manifest,
    load_manifest,
    verify_all_files,
    verify_file_integrity,
    check_critical_files_only,
    get_modified_files,
    calculate_file_checksum
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/integrity", tags=["Integrity Monitoring"])


# ============================================================================
# MANIFEST MANAGEMENT
# ============================================================================

@router.post("/manifest/generate")
@limiter.limit(WRITE_LIMIT)
async def generate_manifest_endpoint(request: Request):
    """
    Generate new integrity manifest
    
    Creates checksums for all critical files and saves manifest
    """
    try:
        logger.info("Generating integrity manifest...")
        
        # Generate manifest
        manifest = generate_manifest()
        
        if not manifest or not manifest.get("checksums"):
            raise HTTPException(
                status_code=500,
                detail="Failed to generate manifest"
            )
        
        # Save to file
        save_success = save_manifest(manifest)
        
        if not save_success:
            raise HTTPException(
                status_code=500,
                detail="Failed to save manifest to file"
            )
        
        # Save to database
        save_manifest_to_db(
            version=manifest["version"],
            manifest_data=manifest
        )
        
        logger.info(f"✅ Manifest generated with {len(manifest['checksums'])} files")
        
        return {
            "success": True,
            "message": "Manifest generated successfully",
            "manifest": {
                "version": manifest["version"],
                "generated_at": manifest["generated_at"],
                "total_files": len(manifest["checksums"])
            }
        }
        
    except Exception as e:
        logger.error(f"Error generating manifest: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/manifest/latest")
@limiter.limit(READ_LIMIT)
async def get_latest_manifest_endpoint(request: Request):
    """
    Get latest integrity manifest
    """
    try:
        manifest = get_latest_manifest()
        
        if not manifest:
            return {
                "success": False,
                "message": "No manifest found. Generate one first.",
                "manifest": None
            }
        
        # Don't return full checksums in API response (too large)
        manifest_summary = {
            "id": manifest["id"],
            "version": manifest["version"],
            "created_at": manifest["created_at"],
            "total_files": len(manifest["manifest_data"].get("checksums", {}))
        }
        
        return {
            "success": True,
            "manifest": manifest_summary
        }
        
    except Exception as e:
        logger.error(f"Error getting latest manifest: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/manifest/history")
@limiter.limit(READ_LIMIT)
async def get_manifest_history_endpoint(
    request: Request,
    limit: int = 10
):
    """
    Get manifest generation history
    """
    try:
        manifests = get_all_manifests(limit=limit)
        
        return {
            "success": True,
            "total": len(manifests),
            "manifests": manifests
        }
        
    except Exception as e:
        logger.error(f"Error getting manifest history: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# INTEGRITY VERIFICATION
# ============================================================================

@router.post("/verify/all")
@limiter.limit(WRITE_LIMIT)
async def verify_all_files_endpoint(request: Request):
    """
    Verify integrity of all files in manifest
    
    Checks all files against stored checksums and logs results
    """
    try:
        logger.info("Starting full integrity verification...")
        
        # Run verification
        report = verify_all_files()
        
        if not report.get("success"):
            return {
                "success": False,
                "error": report.get("error", "Verification failed")
            }
        
        # Log results to database
        for file_path, details in report.get("files", {}).items():
            log_integrity_check(
                file_path=file_path,
                expected_checksum=details["expected_checksum"],
                actual_checksum=details.get("actual_checksum"),
                status=details["status"],
                details=None
            )
        
        # Create alerts for compromised files
        if report["modified"] > 0 or report["missing"] > 0:
            severity = "CRITICAL" if report["missing"] > 0 else "HIGH"
            
            create_integrity_alert(
                alert_type="INTEGRITY_CHECK_FAILED",
                severity=severity,
                message=f"Integrity check failed: {report['modified']} modified, {report['missing']} missing files",
                file_path=None
            )
            
            # Alert for each modified file
            for file_path, details in report.get("files", {}).items():
                if details["status"] in ["MODIFIED", "MISSING"]:
                    create_integrity_alert(
                        alert_type=f"FILE_{details['status']}",
                        severity="HIGH" if details["status"] == "MODIFIED" else "CRITICAL",
                        message=f"File {details['status'].lower()}: {file_path}",
                        file_path=file_path
                    )
        
        logger.info(f"✅ Verification complete: {report['overall_status']}")
        
        return {
            "success": True,
            "report": {
                "overall_status": report["overall_status"],
                "total_files": report["total"],
                "ok": report["ok"],
                "modified": report["modified"],
                "missing": report["missing"],
                "errors": report["errors"],
                "verified_at": report["verified_at"],
                "manifest_version": report["manifest_version"]
            }
        }
        
    except Exception as e:
        logger.error(f"Error verifying files: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/verify/critical")
@limiter.limit(WRITE_LIMIT)
async def verify_critical_files_endpoint(request: Request):
    """
    Quick verification of only critical system files
    """
    try:
        logger.info("Checking critical files...")
        
        result = check_critical_files_only()
        
        if result:
            return {
                "success": True,
                "status": "HEALTHY",
                "message": "All critical files intact"
            }
        else:
            # Create alert
            create_integrity_alert(
                alert_type="CRITICAL_FILE_COMPROMISED",
                severity="CRITICAL",
                message="One or more critical system files are compromised",
                file_path=None
            )
            
            return {
                "success": True,
                "status": "COMPROMISED",
                "message": "Critical files compromised! Check logs for details."
            }
        
    except Exception as e:
        logger.error(f"Error checking critical files: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/verify/file")
@limiter.limit(WRITE_LIMIT)
async def verify_single_file_endpoint(
    request: Request,
    file_path: str
):
    """
    Verify integrity of a single file
    """
    try:
        # Load manifest
        manifest = load_manifest()
        
        if not manifest:
            raise HTTPException(
                status_code=404,
                detail="No manifest found. Generate one first."
            )
        
        checksums = manifest.get("checksums", {})
        
        if file_path not in checksums:
            raise HTTPException(
                status_code=404,
                detail=f"File {file_path} not in manifest"
            )
        
        expected_checksum = checksums[file_path]
        is_valid, status = verify_file_integrity(file_path, expected_checksum)
        
        # Log result
        actual_checksum = calculate_file_checksum(file_path) if status != "MISSING" else None
        log_integrity_check(
            file_path=file_path,
            expected_checksum=expected_checksum,
            actual_checksum=actual_checksum,
            status=status,
            details=None
        )
        
        return {
            "success": True,
            "file_path": file_path,
            "status": status,
            "is_valid": is_valid,
            "expected_checksum": expected_checksum,
            "actual_checksum": actual_checksum
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error verifying file: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/verify/modified")
@limiter.limit(READ_LIMIT)
async def get_modified_files_endpoint(request: Request):
    """
    Get list of modified or missing files
    """
    try:
        modified_files = get_modified_files()
        
        return {
            "success": True,
            "total": len(modified_files),
            "files": modified_files
        }
        
    except Exception as e:
        logger.error(f"Error getting modified files: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# LOGS & ALERTS
# ============================================================================

@router.get("/logs")
@limiter.limit(READ_LIMIT)
async def get_integrity_logs_endpoint(
    request: Request,
    limit: int = 100,
    status: Optional[str] = None
):
    """
    Get integrity check logs
    
    Query params:
        - limit: Max number of logs (default: 100)
        - status: Filter by status (OK, MODIFIED, MISSING, ERROR)
    """
    try:
        logs = get_integrity_logs(limit=limit, status_filter=status)
        
        return {
            "success": True,
            "total": len(logs),
            "logs": logs
        }
        
    except Exception as e:
        logger.error(f"Error getting integrity logs: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/alerts")
@limiter.limit(READ_LIMIT)
async def get_integrity_alerts_endpoint(
    request: Request,
    resolved: Optional[bool] = None,
    limit: int = 50
):
    """
    Get integrity alerts
    
    Query params:
        - resolved: Filter by resolved status (true/false/null for all)
        - limit: Max number of alerts (default: 50)
    """
    try:
        alerts = get_integrity_alerts(resolved=resolved, limit=limit)
        
        return {
            "success": True,
            "total": len(alerts),
            "alerts": alerts
        }
        
    except Exception as e:
        logger.error(f"Error getting integrity alerts: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/alerts/{alert_id}/resolve")
@limiter.limit(WRITE_LIMIT)
async def resolve_alert_endpoint(
    request: Request,
    alert_id: int
):
    """
    Mark an integrity alert as resolved
    """
    try:
        resolve_integrity_alert(alert_id)
        
        return {
            "success": True,
            "message": f"Alert {alert_id} marked as resolved"
        }
        
    except Exception as e:
        logger.error(f"Error resolving alert: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/logs/cleanup")
@limiter.limit(WRITE_LIMIT)
async def cleanup_old_logs_endpoint(
    request: Request,
    days: int = 30
):
    """
    Delete integrity logs older than specified days
    """
    try:
        deleted_count = delete_old_integrity_logs(days=days)
        
        return {
            "success": True,
            "message": f"Deleted {deleted_count} old log entries",
            "deleted_count": deleted_count
        }
        
    except Exception as e:
        logger.error(f"Error cleaning up logs: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# STATISTICS
# ============================================================================

@router.get("/statistics")
@limiter.limit(READ_LIMIT)
async def get_statistics_endpoint(request: Request):
    """
    Get integrity monitoring statistics
    """
    try:
        stats = get_integrity_statistics()
        
        return {
            "success": True,
            "statistics": stats
        }
        
    except Exception as e:
        logger.error(f"Error getting statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))