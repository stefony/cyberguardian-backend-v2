"""
CyberGuardian AI - Email & Phishing Scanner API
Real IMAP-based email scanning endpoints
"""

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from typing import List, Optional
import os
from datetime import datetime
import logging
from middleware.rate_limiter import limiter, READ_LIMIT, WRITE_LIMIT

# Import EmailScanner (graceful fallback if deps are missing)
try:
    from core.email_scanner import EmailScanner, EmailScanResult
    EMAIL_SCANNER_AVAILABLE = True
except ImportError as e:
    EMAIL_SCANNER_AVAILABLE = False
    logging.warning(f"EmailScanner not available: {e}")

router = APIRouter()
logger = logging.getLogger(__name__)

# ============================================
# MODELS
# ============================================

class EmailConnectionConfig(BaseModel):
    server: str = "imap.gmail.com"
    port: int = 993
    username: str
    password: str
    use_ssl: bool = True

class EmailScanRequest(BaseModel):
    folder: str = "INBOX"
    limit: int = 10

class EmailScanResponse(BaseModel):
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
    total_scanned: int
    phishing_detected: int
    safe_emails: int
    suspicious_emails: int
    dangerous_emails: int
    last_scan: Optional[str]

# ============================================
# HELPERS
# ============================================

def get_email_scanner() -> Optional["EmailScanner"]:
    """
    Create EmailScanner from env vars. Returns None if not configured.
    """
    if not EMAIL_SCANNER_AVAILABLE:
        return None

    server = os.getenv("EMAIL_IMAP_HOST", os.getenv("EMAIL_SERVER", "imap.gmail.com"))
    port = int(os.getenv("EMAIL_IMAP_PORT", os.getenv("EMAIL_PORT", 993)))
    username = os.getenv("EMAIL_USER", os.getenv("EMAIL_USERNAME", ""))
    password = os.getenv("EMAIL_PASSWORD", "")
    use_ssl = (os.getenv("EMAIL_IMAP_USE_SSL", os.getenv("EMAIL_USE_SSL", "true")) or "true").lower() == "true"

    if not username or not password:
        return None

    try:
        scanner = EmailScanner(server, port, username, password, use_ssl)
        return scanner
    except Exception as e:
        logger.error(f"Failed to create EmailScanner: {e}")
        return None

# ============================================
# ENDPOINTS
# Mounted under /api (main.py) -> full path /api/emails/...
# ============================================

@router.get("/emails/status")
@limiter.limit(READ_LIMIT)
async def emails_status(request: Request):
    """
    Configuration / readiness status of the Email Scanner.
    """
    server = os.getenv("EMAIL_IMAP_HOST", os.getenv("EMAIL_SERVER", "imap.gmail.com"))
    username = os.getenv("EMAIL_USER", os.getenv("EMAIL_USERNAME", ""))

    is_configured = bool(username and os.getenv("EMAIL_PASSWORD"))
    return {
        "scanner_available": EMAIL_SCANNER_AVAILABLE,
        "configured": is_configured,
        "server": server if is_configured else "Not configured",
        "username": username if is_configured else "Not configured",
        "status": "ready" if (EMAIL_SCANNER_AVAILABLE and is_configured) else "not_configured",
        "message": "Email scanner ready" if (EMAIL_SCANNER_AVAILABLE and is_configured)
                   else "Please configure EMAIL_USER and EMAIL_PASSWORD in environment variables"
    }

@router.post("/emails/test-connection")
@limiter.limit(WRITE_LIMIT)
async def emails_test_connection(
    request: Request,
    config: Optional[EmailConnectionConfig] = None
):
    """
    Tests IMAP connection using provided body or environment credentials.
    """
    if not EMAIL_SCANNER_AVAILABLE:
        raise HTTPException(status_code=503, detail="Email scanner not available - missing dependency")

    try:
        if config:
            scanner = EmailScanner(config.server, config.port, config.username, config.password, config.use_ssl)
        else:
            scanner = get_email_scanner()
            if not scanner:
                raise HTTPException(status_code=400, detail="Email credentials not configured")

        if scanner.connect():
            scanner.disconnect()
            return {
                "success": True,
                "message": "Successfully connected to email server",
                "server": scanner.server,
                "username": scanner.username
            }
        raise HTTPException(status_code=401, detail="Failed to connect - check credentials")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Connection test failed: {e}")
        raise HTTPException(status_code=500, detail=f"Connection failed: {str(e)}")

@router.post("/emails/scan", response_model=List[EmailScanResponse])
@limiter.limit(WRITE_LIMIT)
async def emails_scan(request: Request, body: EmailScanRequest):
    """
    Fetches emails from a folder and scans them for phishing indicators.
    """
    if not EMAIL_SCANNER_AVAILABLE:
        raise HTTPException(status_code=503, detail="Email scanner not available")

    scanner = get_email_scanner()
    if not scanner:
        raise HTTPException(status_code=400, detail="Email credentials not configured")

    try:
        results: List[EmailScanResult] = scanner.scan_folder(body.folder, body.limit)
        response: List[EmailScanResponse] = [
            EmailScanResponse(
                email_id=r.email_id,
                subject=r.subject,
                sender=r.sender,
                date=r.date,
                is_phishing=r.is_phishing,
                phishing_score=r.phishing_score,
                threat_level=r.threat_level,
                indicators=r.indicators,
                urls=r.urls,
                attachments=r.attachments,
                recommendations=r.recommendations
            )
            for r in results
        ]
        scanner.disconnect()
        return response
    except Exception as e:
        logger.error(f"Email scan failed: {e}")
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

@router.get("/emails/folders")
@limiter.limit(READ_LIMIT)
async def emails_folders(request: Request):
    """
    Returns list of folders in the email account.
    """
    if not EMAIL_SCANNER_AVAILABLE:
        raise HTTPException(status_code=503, detail="Email scanner not available")

    scanner = get_email_scanner()
    if not scanner:
        raise HTTPException(status_code=400, detail="Email credentials not configured")

    try:
        if scanner.connect():
            status, folders = scanner.connection.list()
            folder_names: List[str] = []
            if status == "OK" and folders:
                for folder in folders:
                    s = folder.decode() if isinstance(folder, bytes) else str(folder)
                    parts = s.split('"')
                    if len(parts) >= 4:
                        folder_names.append(parts[3])
            scanner.disconnect()
            return {"folders": folder_names or ["INBOX", "Spam", "Sent", "Drafts"]}
        raise HTTPException(status_code=401, detail="Failed to connect")
    except Exception as e:
        logger.error(f"Failed to get folders: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/emails/stats")
@limiter.limit(READ_LIMIT)
async def emails_stats(request: Request) -> EmailStatsResponse:
    """
    Mock statistics endpoint (DB integration can be added later).
    """
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
async def emails_recent_scans(request: Request, limit: int = 20):
    """
    Mock recent scans (placeholder until DB history is implemented).
    """
    return {"scans": [], "total": 0, "message": "No recent scans (database integration pending)"}

# Sample (for demo)
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
async def emails_sample(request: Request):
    return SAMPLE_EMAIL_SCAN
