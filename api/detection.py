"""
CyberGuardian AI - Detection API
Real File Scanning & Threat Detection

Provides endpoints for:
- Real file scanning with VirusTotal
- File upload and analysis
- Scan history and results
- Detection statistics
"""

from fastapi import APIRouter, HTTPException, UploadFile, File, Request
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime
import os
import tempfile
from pathlib import Path
from middleware.rate_limiter import limiter, THREAT_INTEL_LIMIT, WRITE_LIMIT

# Import our real file scanner
from core.file_scanner import FileScanner

# Import database functions
import sys
sys.path.append(str(Path(__file__).parent.parent))
from database.db import add_scan, get_scans, get_scan_by_id, get_detection_stats

router = APIRouter()

# ============================================
# PYDANTIC MODELS
# ============================================

class ScanRequest(BaseModel):
    """Scan request model"""
    scan_type: str
    target: Optional[str] = None


class ScanResult(BaseModel):
    """Scan result model"""
    id: int
    scan_type: str
    status: str
    started_at: str
    completed_at: Optional[str]
    duration_seconds: Optional[float]
    items_scanned: int
    threats_found: int
    results: Optional[dict]


class ScanStats(BaseModel):
    """Scan statistics"""
    total_scans: int
    status_breakdown: dict
    scan_type_breakdown: dict
    total_threats_found: int
    average_duration_seconds: float
    last_updated: str


# ============================================
# HELPER FUNCTIONS
# ============================================

def save_upload_file(upload_file: UploadFile) -> str:
    """
    Save uploaded file to temp directory

    Returns: Path to saved file
    """
    try:
        # Create temp file
        suffix = Path(upload_file.filename).suffix
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)

        # Write uploaded content
        content = upload_file.file.read()
        temp_file.write(content)
        temp_file.close()

        return temp_file.name
    except Exception as e:
        raise Exception(f"Error saving file: {str(e)}")


# ============================================
# API ENDPOINTS
# ============================================

@router.get("/detection/status")
@limiter.limit(THREAT_INTEL_LIMIT)  # 60 requests per minute
async def get_status(request: Request):
    """
    Lightweight status endpoint expected by the frontend.
    Maps internal stats to a simple status payload.
    """
    try:
        stats = get_detection_stats()
        return {
            "engine_status": "online",
            "last_update": stats.get("last_updated", datetime.utcnow().isoformat()),
            "signatures_count": 0,  # plug value unless you track signatures elsewhere
            "scans_today": stats.get("total_scans", 0),
            "threats_blocked": stats.get("total_threats_found", 0),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get status: {str(e)}")


@router.post("/detection/scan")
@limiter.limit(WRITE_LIMIT)  # 30 requests per minute
async def start_scan(request: Request, scan_type: str):
    """
    Upload and scan a file with VirusTotal

    Args:
        file: Uploaded file

    Returns:
        Scan results
    """
    temp_path = None

    try:
        # Validate file
        if not file.filename:
            raise HTTPException(status_code=400, detail="No file provided")

        # Check file size (max 32MB for VirusTotal free tier)
        file.file.seek(0, 2)  # Seek to end
        file_size = file.file.tell()
        file.file.seek(0)  # Reset to start

        if file_size > 32 * 1024 * 1024:  # 32MB
            raise HTTPException(
                status_code=400,
                detail="File too large. Maximum size is 32MB for free tier.",
            )

        # Save uploaded file
        temp_path = save_upload_file(file)

        # Start scan
        start_time = datetime.now()

        # Scan with VirusTotal
        with FileScanner() as scanner:
            scan_result = scanner.scan_file(temp_path)

        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()

        # Determine threats found
        threats_found = scan_result.get("stats", {}).get("malicious", 0)

        # Save to database
        scan_id = add_scan(
            scan_type="file_upload",
            status="completed",
            started_at=start_time.isoformat(),
            completed_at=end_time.isoformat(),
            duration_seconds=duration,
            items_scanned=1,
            threats_found=threats_found,
            results=scan_result,
        )

        # If malicious, also add to threats table
        if threats_found > 0:
            from database.db import add_threat

            add_threat(
                source_ip="local_upload",
                threat_type="malware",
                severity=scan_result.get("severity", "medium"),
                description=f"Malicious file detected: {file.filename}",
                details={
                    "file_name": file.filename,
                    "file_size": file_size,
                    "threat_score": scan_result.get("threat_score", 0),
                    "detections": scan_result.get("detections", []),
                    "vt_link": scan_result.get("vt_link", ""),
                },
            )

        return {
            "success": True,
            "scan_id": scan_id,
            "file_name": file.filename,
            "file_size": file_size,
            "scan_type": "file_upload",
            "duration_seconds": duration,
            "threat_score": scan_result.get("threat_score", 0),
            "severity": scan_result.get("severity", "clean"),
            "threats_found": threats_found,
            "stats": scan_result.get("stats", {}),
            "detections": scan_result.get("detections", [])[:5],  # Top 5
            "vt_link": scan_result.get("vt_link", ""),
            "hashes": scan_result.get("hashes", {}),
            "completed_at": end_time.isoformat(),
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")
    finally:
        # Clean up temp file
        if temp_path and os.path.exists(temp_path):
            try:
                os.unlink(temp_path)
            except:
                pass


@router.post("/detection/scan/upload")
@limiter.limit(WRITE_LIMIT)  # 30 requests per minute
async def scan_uploaded_file(request: Request, file: UploadFile = File(...)):
    """
    Start a detection scan

    Args:
        scan_type: Type of scan (quick, full, network, custom)
        request: Optional scan parameters

    Returns:
        Scan initiation response
    """
    try:
        # Validate scan type
        valid_types = ["quick", "full", "network", "custom"]
        if scan_type not in valid_types:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid scan type. Must be one of: {', '.join(valid_types)}",
            )

        # For now, create a simulated scan entry
        # In a real implementation, this would start an actual scan process
        start_time = datetime.now()

        # Add scan to database
        scan_id = add_scan(
            scan_type=scan_type,
            status="running",
            started_at=start_time.isoformat(),
            items_scanned=0,
            threats_found=0,
        )

        return {
            "success": True,
            "scan_id": scan_id,
            "scan_type": scan_type,
            "status": "running",
            "started_at": start_time.isoformat(),
            "message": f"{scan_type.capitalize()} scan initiated successfully",
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start scan: {str(e)}")


@router.get("/detection/scans", response_model=List[ScanResult])
@limiter.limit(THREAT_INTEL_LIMIT)  # 60 requests per minute
async def get_all_scans(
    request: Request,
    status: Optional[str] = None, 
    scan_type: Optional[str] = None, 
    limit: int = 50
):
    """
    Get all scans with optional filters

    Args:
        status: Filter by status (running, completed, failed)
        scan_type: Filter by scan type
        limit: Maximum number of results

    Returns:
        List of scans
    """
    try:
        scans = get_scans(status=status, scan_type=scan_type, limit=limit)

        return [
            ScanResult(
                id=scan["id"],
                scan_type=scan["scan_type"],
                status=scan["status"],
                started_at=scan["started_at"],
                completed_at=scan.get("completed_at"),
                duration_seconds=scan.get("duration_seconds"),
                items_scanned=scan["items_scanned"],
                threats_found=scan["threats_found"],
                results=scan.get("results"),
            )
            for scan in scans
        ]

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get scans: {str(e)}")


@router.get("/detection/stats")
@limiter.limit(THREAT_INTEL_LIMIT)  # 60 requests per minute
async def get_stats(request: Request):
    """
    Get specific scan details

    Args:
        scan_id: Scan ID

    Returns:
        Scan details
    """
    try:
        scan = get_scan_by_id(scan_id)

        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        return ScanResult(
            id=scan["id"],
            scan_type=scan["scan_type"],
            status=scan["status"],
            started_at=scan["started_at"],
            completed_at=scan.get("completed_at"),
            duration_seconds=scan.get("duration_seconds"),
            items_scanned=scan["items_scanned"],
            threats_found=scan["threats_found"],
            results=scan.get("results"),
        )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get scan: {str(e)}")


@router.get("/detection/scans/{scan_id}", response_model=ScanResult)
@limiter.limit(THREAT_INTEL_LIMIT)  # 60 requests per minute
async def get_scan(request: Request, scan_id: int):
    """
    Get detection statistics

    Returns:
        Detection statistics
    """
    try:
        stats = get_detection_stats()

        return ScanStats(
            total_scans=stats["total_scans"],
            status_breakdown=stats["status_breakdown"],
            scan_type_breakdown=stats["scan_type_breakdown"],
            total_threats_found=stats["total_threats_found"],
            average_duration_seconds=stats["average_duration_seconds"],
            last_updated=stats["last_updated"],
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get stats: {str(e)}")
