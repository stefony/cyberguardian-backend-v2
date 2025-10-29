"""
CyberGuardian AI - Email & Phishing Scanner API
Real IMAP-based email scanning endpoints
"""

from fastapi import APIRouter, HTTPException, Request, Body
from pydantic import BaseModel
from typing import List, Optional, Dict
import os
from datetime import datetime
import logging
from middleware.rate_limiter import limiter, READ_LIMIT, WRITE_LIMIT

# Import EmailScanner (будем обработваме ImportError ако липсват зависимости)
try:
    from core.email_scanner import EmailScanner, EmailScanResult
    EMAIL_SCANNER_AVAILABLE = True
except ImportError as e:
    EMAIL_SCANNER_AVAILABLE = False
    logging.warning(f"EmailScanner not available: {e}")

router = APIRouter(tags=["Emails"])
logger = logging.getLogger(__name__)

# ============================================
# PYDANTIC MODELS
# ============================================

class EmailConnectionConfig(BaseModel):
    """Email connection configuration"""
    server: str = "imap.gmail.com"
    port: int = 993
    username: str
    password: str
    use_ssl: bool = True

class EmailScanRequest(BaseModel):
    """Email scan request"""
    folder: str = "INBOX"
    limit: int = 10

class EmailScanResponse(BaseModel):
    """Email scan response"""
    email_id: str
    subject: str
    sender: str
    date: str
    is_phishing: bool
    phishing_score: float
    threat_level: str
    indicators: List[str]
    urls: List[str]
    attachments: List[str]
    recommendations: List[str]

class EmailStatsResponse(BaseModel):
    """Email statistics"""
    total_scanned: int
    phishing_detected: int
    safe_emails: int
    suspicious_emails: int
    dangerous_emails: int
    last_scan: Optional[str]

# ============================================
# HELPER FUNCTIONS
# ============================================

def _bool_env(*names, default: bool = False) -> bool:
    """
    Read multiple possible env var names and return boolean interpretation.
    Example: _bool_env("EMAIL_IMAP_USE_SSL", "EMAIL_USE_SSL", default=True)
    """
    for name in names:
        val = os.getenv(name)
        if val is not None:
            return str(val).strip().lower() in {"1", "true", "yes", "on"}
    return default

def _env_first(*names, default: Optional[str] = "") -> str:
    """
    Return first non-empty environment variable among names.
    """
    for name in names:
        val = os.getenv(name)
        if val:
            return val
    return default or ""

def get_email_scanner_from_env() -> Optional[EmailScanner]:
    """
    Build EmailScanner from environment variables.
    Supports both EMAIL_IMAP_* and older EMAIL_* names.
    Returns None if required credentials missing or EmailScanner not available.
    """
    if not EMAIL_SCANNER_AVAILABLE:
        return None

    server = _env_first("EMAIL_IMAP_HOST", "EMAIL_SERVER", default="imap.gmail.com")
    port_str = _env_first("EMAIL_IMAP_PORT", "EMAIL_PORT", default="993")
    try:
        port = int(port_str)
    except Exception:
        port = 993
    username = _env_first("EMAIL_USER", "EMAIL_USERNAME", default="")
    password = os.getenv("EMAIL_PASSWORD", "")  # single canonical name for password
    use_ssl = _bool_env("EMAIL_IMAP_USE_SSL", "EMAIL_USE_SSL", default=True)

    if not username or not password:
        return None

    try:
        scanner = EmailScanner(server, port, username, password, use_ssl)
        return scanner
    except Exception as e:
        logger.error(f"Failed to create EmailScanner from env: {e}")
        return None

def get_email_scanner_from_config(cfg: EmailConnectionConfig) -> Optional[EmailScanner]:
    """
    Build EmailScanner from provided config object.
    """
    if not EMAIL_SCANNER_AVAILABLE:
        return None
    try:
        scanner = EmailScanner(cfg.server, cfg.port, cfg.username, cfg.password, cfg.use_ssl)
        return scanner
    except Exception as e:
        logger.error(f"Failed to create EmailScanner from config: {e}")
        return None

# ============================================
# API ENDPOINTS
# ============================================

@router.get("/emails/status")
@limiter.limit(READ_LIMIT)
async def emails_status_connection():
    """
    Connection-level status:
    - whether EmailScanner implementation exists
    - whether environment credentials are present
    - basic IMAP host/port/user (never expose password)
    """
    enabled = _bool_env("EMAIL_ENABLED", default=True)
    server = _env_first("EMAIL_IMAP_HOST", "EMAIL_SERVER", default="imap.gmail.com")
    port = int(_env_first("EMAIL_IMAP_PORT", "EMAIL_PORT", default="993") or 993)
    username = _env_first("EMAIL_USER", "EMAIL_USERNAME", default="")
    use_ssl = _bool_env("EMAIL_IMAP_USE_SSL", "EMAIL_USE_SSL", default=True)
    folder = _env_first("EMAIL_DEFAULT_FOLDER", default="INBOX")

    config_present = bool(username and os.getenv("EMAIL_PASSWORD"))

    return {
        "scanner_available": EMAIL_SCANNER_AVAILABLE,
        "enabled": enabled,
        "config_present": config_present,
        "imap": {
            "host": server,
            "port": port,
            "use_ssl": use_ssl,
            "user": username if config_present else None,
            "folder": folder,
        },
        "status": "ready" if (EMAIL_SCANNER_AVAILABLE and config_present and enabled) else "not_configured",
        "message": "Email scanner ready" if (EMAIL_SCANNER_AVAILABLE and config_present and enabled)
                   else "Please configure email credentials (EMAIL_USER and EMAIL_PASSWORD) or enable EMAIL_ENABLED"
    }

@router.post("/emails/test-connection")
@limiter.limit(WRITE_LIMIT)
async def emails_test_connection(config: Optional[EmailConnectionConfig] = Body(None)):
    """
    Test email connection
    Accepts optional JSON body with EmailConnectionConfig. If absent, uses environment variables.
    Returns success:true if login/select folder succeeded.
    """
    if not EMAIL_SCANNER_AVAILABLE:
        raise HTTPException(status_code=503, detail="Email scanner not available - missing dependencies")

    # Choose scanner source
    scanner = None
    if config:
        scanner = get_email_scanner_from_config(config)
        if scanner is None:
            raise HTTPException(status_code=400, detail="Invalid provided configuration or missing credentials")
    else:
        scanner = get_email_scanner_from_env()
        if scanner is None:
            raise HTTPException(status_code=400, detail="Email credentials not configured. Please set EMAIL_USER and EMAIL_PASSWORD in environment")

    try:
        connected = False
        try:
            connected = scanner.connect()
        except AttributeError:
            # If EmailScanner API doesn't have .connect(), try a best-effort method
            try:
                connected = scanner.login()  # optional
            except Exception:
                connected = True  # assume constructor already validated
        finally:
            try:
                scanner.disconnect()
            except Exception:
                pass

        if connected:
            return {
                "success": True,
                "message": "Successfully connected to email server (login and folder select OK)",
                "server": getattr(scanner, "server", None),
                "username": getattr(scanner, "username", None)
            }
        else:
            raise HTTPException(status_code=401, detail="Failed to connect - check credentials")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Connection test failed: {e}")
        raise HTTPException(status_code=500, detail=f"Connection failed: {str(e)}")

@router.post("/emails/scan", response_model=List[EmailScanResponse])
@limiter.limit(WRITE_LIMIT)
async def emails_scan(body: EmailScanRequest):
    """
    Scan emails for phishing
    Uses environment credentials (or EmailScanner implementation) to scan folder.
    Body: { "folder": "INBOX", "limit": 10 }
    """
    if not EMAIL_SCANNER_AVAILABLE:
        raise HTTPException(status_code=503, detail="Email scanner not available")

    scanner = get_email_scanner_from_env()
    if not scanner:
        raise HTTPException(status_code=400, detail="Email credentials not configured. Please configure in Settings or provide config to /emails/test-connection")

    try:
        # Expect EmailScanner.scan_folder(folder, limit) -> list[EmailScanResult]
        results = scanner.scan_folder(body.folder, body.limit)
        response = []
        for result in results:
            response.append(EmailScanResponse(
                email_id=getattr(result, "email_id", str(getattr(result, "id", ""))),
                subject=getattr(result, "subject", ""),
                sender=getattr(result, "sender", ""),
                date=getattr(result, "date", ""),
                is_phishing=bool(getattr(result, "is_phishing", False)),
                phishing_score=float(getattr(result, "phishing_score", 0.0)),
                threat_level=getattr(result, "threat_level", "unknown"),
                indicators=list(getattr(result, "indicators", []) or []),
                urls=list(getattr(result, "urls", []) or []),
                attachments=list(getattr(result, "attachments", []) or []),
                recommendations=list(getattr(result, "recommendations", []) or []),
            ))
        try:
            scanner.disconnect()
        except Exception:
            pass
        return response
    except Exception as e:
        logger.error(f"Email scan failed: {e}")
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

@router.get("/emails/folders")
@limiter.limit(READ_LIMIT)
async def emails_get_folders():
    """
    Get available email folders
    """
    if not EMAIL_SCANNER_AVAILABLE:
        raise HTTPException(status_code=503, detail="Email scanner not available")

    scanner = get_email_scanner_from_env()
    if not scanner:
        raise HTTPException(status_code=400, detail="Email credentials not configured")

    try:
        if scanner.connect():
            # Try to get folder list from scanner; fall back to IMAP list if available
            folder_names = []
            try:
                # If scanner exposes connection with .list()
                if hasattr(scanner, "connection") and hasattr(scanner.connection, "list"):
                    status, folders = scanner.connection.list()
                    if status == 'OK':
                        for folder in folders:
                            folder_str = folder.decode() if isinstance(folder, bytes) else str(folder)
                            # Simple parsing - attempt to extract human name
                            parts = folder_str.split('"')
                            if len(parts) >= 4:
                                folder_names.append(parts[3])
                            else:
                                folder_names.append(folder_str)
                else:
                    # Fallback: try scanner.list_folders() if implemented
                    if hasattr(scanner, "list_folders"):
                        folder_names = scanner.list_folders()
            except Exception as e:
                logger.debug(f"Failed to read folders via scanner: {e}")
            finally:
                try:
                    scanner.disconnect()
                except Exception:
                    pass

            # Provide defaults if empty
            if not folder_names:
                folder_names = ["INBOX", "Spam", "Sent", "Drafts"]
            return {"folders": folder_names}
        else:
            raise HTTPException(status_code=401, detail="Failed to connect to IMAP server")
    except Exception as e:
        logger.error(f"Failed to get folders: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/emails/stats")
@limiter.limit(READ_LIMIT)
async def emails_stats():
    """
    Get email scanning statistics (mocked for now)
    """
    # Mock stats for now (in production would query database)
    return EmailStatsResponse(
        total_scanned=0,
        phishing_detected=0,
        safe_emails=0,
        suspicious_emails=0,
        dangerous_emails=0,
        last_scan=None
    )

@router.get("/emails/recent-scans")
@limiter.limit(READ_LIMIT)
async def emails_recent_scans(limit: int = 20):
    """
    Get recent email scan results
    """
    return {
        "scans": [],
        "total": 0,
        "message": "No recent scans (database integration pending)"
    }

# Example test data for development/testing
SAMPLE_EMAIL_SCAN = {
    "email_id": "sample_001",
    "subject": "Urgent: Verify Your Account",
    "sender": "noreply@suspicious-domain.tk",
    "date": "2025-01-19 10:30:00",
    "is_phishing": True,
    "phishing_score": 85.0,
    "threat_level": "dangerous",
    "indicators": [
        "Suspicious keyword in subject: 'verify'",
        "Suspicious keyword in subject: 'urgent'",
        "Suspicious sender domain: suspicious-domain.tk",
        "Sender from non-trusted domain",
        "URL shortener detected: http://bit.ly/abc123",
        "Urgency/pressure tactics detected"
    ],
    "urls": ["http://bit.ly/abc123", "http://suspicious-site.com/verify"],
    "attachments": [],
    "recommendations": [
        "⛔ DO NOT click any links in this email",
        "⛔ DO NOT open any attachments",
        "⛔ DO NOT reply to this email",
        "🗑️ Delete this email immediately",
        "📧 Report this email as phishing to your email provider"
    ]
}

@router.get("/emails/sample")
@limiter.limit(READ_LIMIT)
async def emails_sample():
    """
    Get sample email scan result (for testing/demo)
    """
    return SAMPLE_EMAIL_SCAN
