"""
CyberGuardian AI - Email & Phishing Scanner API
Real IMAP-based email scanning endpoints
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel, EmailStr
from typing import List, Optional, Dict
import os
from datetime import datetime
import logging

# Import EmailScanner (будем обработваме ImportError ако липсват зависимости)
try:
    from core.email_scanner import EmailScanner, EmailScanResult
    EMAIL_SCANNER_AVAILABLE = True
except ImportError as e:
    EMAIL_SCANNER_AVAILABLE = False
    logging.warning(f"EmailScanner not available: {e}")

router = APIRouter()
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

def get_email_scanner() -> Optional[EmailScanner]:
    """
    Get EmailScanner instance from environment variables
    Returns None if credentials not configured
    """
    if not EMAIL_SCANNER_AVAILABLE:
        return None
    
    server = os.getenv("EMAIL_SERVER", "imap.gmail.com")
    port = int(os.getenv("EMAIL_PORT", 993))
    username = os.getenv("EMAIL_USERNAME", "")
    password = os.getenv("EMAIL_PASSWORD", "")
    use_ssl = os.getenv("EMAIL_USE_SSL", "True").lower() == "true"
    
    if not username or not password or username == "your_email@gmail.com":
        return None
    
    try:
        scanner = EmailScanner(server, port, username, password, use_ssl)
        return scanner
    except Exception as e:
        logger.error(f"Failed to create EmailScanner: {e}")
        return None

# ============================================
# API ENDPOINTS
# ============================================

@router.get("/emails/status")
async def get_email_scanner_status():
    """
    Get email scanner status
    
    Returns connection status and configuration
    """
    server = os.getenv("EMAIL_SERVER", "imap.gmail.com")
    username = os.getenv("EMAIL_USERNAME", "")
    
    is_configured = bool(username and username != "your_email@gmail.com")
    
    return {
        "scanner_available": EMAIL_SCANNER_AVAILABLE,
        "configured": is_configured,
        "server": server if is_configured else "Not configured",
        "username": username if is_configured else "Not configured",
        "status": "ready" if (EMAIL_SCANNER_AVAILABLE and is_configured) else "not_configured",
        "message": "Email scanner ready" if (EMAIL_SCANNER_AVAILABLE and is_configured) 
                   else "Please configure email credentials in .env file"
    }

@router.post("/emails/test-connection")
async def test_email_connection(config: Optional[EmailConnectionConfig] = None):
    """
    Test email connection
    
    Tests IMAP connection with provided or environment credentials
    """
    if not EMAIL_SCANNER_AVAILABLE:
        raise HTTPException(status_code=503, detail="Email scanner not available - missing dependencies")
    
    try:
        if config:
            # Use provided credentials
            scanner = EmailScanner(
                config.server,
                config.port,
                config.username,
                config.password,
                config.use_ssl
            )
        else:
            # Use environment credentials
            scanner = get_email_scanner()
            if not scanner:
                raise HTTPException(
                    status_code=400, 
                    detail="Email credentials not configured. Please set EMAIL_USERNAME and EMAIL_PASSWORD in .env"
                )
        
        # Test connection
        if scanner.connect():
            scanner.disconnect()
            return {
                "success": True,
                "message": "Successfully connected to email server",
                "server": scanner.server,
                "username": scanner.username
            }
        else:
            raise HTTPException(status_code=401, detail="Failed to connect - check credentials")
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Connection test failed: {e}")
        raise HTTPException(status_code=500, detail=f"Connection failed: {str(e)}")

@router.post("/emails/scan", response_model=List[EmailScanResponse])
async def scan_emails(request: EmailScanRequest):
    """
    Scan emails for phishing
    
    Fetches emails from specified folder and scans them for phishing indicators
    """
    if not EMAIL_SCANNER_AVAILABLE:
        raise HTTPException(status_code=503, detail="Email scanner not available")
    
    scanner = get_email_scanner()
    if not scanner:
        raise HTTPException(
            status_code=400,
            detail="Email credentials not configured. Please configure in Settings."
        )
    
    try:
        # Scan emails
        results = scanner.scan_folder(request.folder, request.limit)
        
        # Convert to response format
        response = []
        for result in results:
            response.append(EmailScanResponse(
                email_id=result.email_id,
                subject=result.subject,
                sender=result.sender,
                date=result.date,
                is_phishing=result.is_phishing,
                phishing_score=result.phishing_score,
                threat_level=result.threat_level,
                indicators=result.indicators,
                urls=result.urls,
                attachments=result.attachments,
                recommendations=result.recommendations
            ))
        
        scanner.disconnect()
        return response
    
    except Exception as e:
        logger.error(f"Email scan failed: {e}")
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

@router.get("/emails/folders")
async def get_email_folders():
    """
    Get available email folders
    
    Returns list of folders in the email account
    """
    if not EMAIL_SCANNER_AVAILABLE:
        raise HTTPException(status_code=503, detail="Email scanner not available")
    
    scanner = get_email_scanner()
    if not scanner:
        raise HTTPException(status_code=400, detail="Email credentials not configured")
    
    try:
        if scanner.connect():
            # Get folder list
            status, folders = scanner.connection.list()
            
            folder_names = []
            if status == 'OK':
                for folder in folders:
                    # Parse folder name
                    folder_str = folder.decode() if isinstance(folder, bytes) else str(folder)
                    # Extract folder name (simple parsing)
                    parts = folder_str.split('"')
                    if len(parts) >= 4:
                        folder_names.append(parts[3])
            
            scanner.disconnect()
            
            return {
                "folders": folder_names if folder_names else ["INBOX", "Spam", "Sent", "Drafts"]
            }
        else:
            raise HTTPException(status_code=401, detail="Failed to connect")
    
    except Exception as e:
        logger.error(f"Failed to get folders: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/emails/stats", response_model=EmailStatsResponse)
async def get_email_stats():
    """
    Get email scanning statistics
    
    Returns statistics about scanned emails
    """
    # Mock stats for now (в production would query database)
    return EmailStatsResponse(
        total_scanned=0,
        phishing_detected=0,
        safe_emails=0,
        suspicious_emails=0,
        dangerous_emails=0,
        last_scan=None
    )

@router.get("/emails/recent-scans")
async def get_recent_scans(limit: int = 20):
    """
    Get recent email scan results
    
    Returns history of recent scans (would be stored in database in production)
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
async def get_sample_scan():
    """
    Get sample email scan result (for testing/demo)
    
    Returns example of what a phishing email scan looks like
    """
    return SAMPLE_EMAIL_SCAN