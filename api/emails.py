"""
CyberGuardian AI - Email & Phishing Scanner API
Multi-tenant IMAP-based email scanning endpoints
"""

from fastapi import APIRouter, HTTPException, Request, Depends
from pydantic import BaseModel, EmailStr
from typing import List, Optional
import os
from datetime import datetime
import logging
from middleware.rate_limiter import limiter, READ_LIMIT, WRITE_LIMIT

# Database functions
from database.db import (
    add_email_account, get_user_email_accounts, get_email_account,
    delete_email_account, update_email_account, update_email_scan_stats,
    add_email_scan_history, update_email_scan_history, get_email_scan_history,
    add_scanned_email, get_scanned_emails
)

# Encryption
from core.encryption import encrypt_password, decrypt_password

# Auth
from api.auth import get_current_user

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

class EmailAccountRequest(BaseModel):
    email_address: EmailStr
    provider: str  # 'gmail', 'outlook', 'yahoo', 'other'
    imap_host: str
    imap_port: int = 993
    password: str
    auto_scan_enabled: bool = True
    scan_interval_hours: int = 24
    folders_to_scan: str = "INBOX"

class EmailAccountResponse(BaseModel):
    id: int
    email_address: str
    provider: str
    auth_method: str
    imap_host: str
    imap_port: int
    auto_scan_enabled: bool
    scan_interval_hours: int
    folders_to_scan: str
    total_scanned: int
    phishing_detected: int
    last_scan_date: Optional[str]
    created_at: str

class EmailAccountUpdateRequest(BaseModel):
    auto_scan_enabled: Optional[bool] = None
    scan_interval_hours: Optional[int] = None
    folders_to_scan: Optional[str] = None

class EmailScanRequest(BaseModel):
    account_id: int
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

def create_email_scanner_from_account(account: dict) -> Optional["EmailScanner"]:
    """
    Create EmailScanner from account credentials
    """
    if not EMAIL_SCANNER_AVAILABLE:
        return None

    try:
        # Decrypt password
        password = decrypt_password(account["encrypted_password"])
        
        scanner = EmailScanner(
            server=account["imap_host"],
            port=account["imap_port"],
            username=account["email_address"],
            password=password,
            use_ssl=True
        )
        return scanner
    except Exception as e:
        logger.error(f"Failed to create EmailScanner: {e}")
        return None

# ============================================
# ENDPOINTS
# ============================================

@router.get("/status")
@limiter.limit(READ_LIMIT)
async def emails_status(request: Request, current_user: dict = Depends(get_current_user)):
    """
    Get email scanner status for current user
    """
    user_id = current_user["id"]
    
    # Get user's email accounts
    accounts = get_user_email_accounts(user_id)
    
    if not accounts:
        return {
            "scanner_available": EMAIL_SCANNER_AVAILABLE,
            "configured": False,
            "accounts_count": 0,
            "status": "not_configured",
            "message": "No email accounts configured. Add an account in Settings."
        }
    
    # Calculate total stats
    total_scanned = sum(acc["total_scanned"] for acc in accounts)
    total_phishing = sum(acc["phishing_detected"] for acc in accounts)
    
    return {
        "scanner_available": EMAIL_SCANNER_AVAILABLE,
        "configured": True,
        "accounts_count": len(accounts),
        "total_scanned": total_scanned,
        "phishing_detected": total_phishing,
        "status": "ready",
        "message": f"{len(accounts)} email account(s) configured"
    }


@router.post("/accounts/add")
@limiter.limit(WRITE_LIMIT)
async def add_email_account_endpoint(
    request: Request,
    body: EmailAccountRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Add email account for current user
    """
    if not EMAIL_SCANNER_AVAILABLE:
        raise HTTPException(status_code=503, detail="Email scanner not available")
    
    user_id = current_user["id"]
    
    # Test connection first
    try:
        test_scanner = EmailScanner(
            server=body.imap_host,
            port=body.imap_port,
            username=body.email_address,
            password=body.password,
            use_ssl=True
        )
        
        if not test_scanner.connect():
            raise HTTPException(status_code=401, detail="Failed to connect - check credentials")
        
        test_scanner.disconnect()
    except Exception as e:
        logger.error(f"Connection test failed: {e}")
        raise HTTPException(status_code=500, detail=f"Connection failed: {str(e)}")
    
    # Encrypt password
    encrypted_pwd = encrypt_password(body.password)
    
    # Add to database
    try:
        account_id = add_email_account(
            user_id=user_id,
            email_address=body.email_address,
            provider=body.provider,
            auth_method="app_password",
            imap_host=body.imap_host,
            imap_port=body.imap_port,
            encrypted_password=encrypted_pwd
        )
        
        # Update settings
        update_email_account(
            account_id=account_id,
            auto_scan_enabled=body.auto_scan_enabled,
            scan_interval_hours=body.scan_interval_hours,
            folders_to_scan=body.folders_to_scan
        )
        
        return {
            "success": True,
            "message": "Email account added successfully",
            "account_id": account_id
        }
    except Exception as e:
        logger.error(f"Failed to add email account: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/accounts", response_model=List[EmailAccountResponse])
@limiter.limit(READ_LIMIT)
async def get_email_accounts(
    request: Request,
    current_user: dict = Depends(get_current_user)
):
    """
    Get all email accounts for current user
    """
    user_id = current_user["id"]
    accounts = get_user_email_accounts(user_id)
    
    # Remove sensitive data
    response = []
    for acc in accounts:
        response.append(EmailAccountResponse(
            id=acc["id"],
            email_address=acc["email_address"],
            provider=acc["provider"],
            auth_method=acc["auth_method"],
            imap_host=acc["imap_host"],
            imap_port=acc["imap_port"],
            auto_scan_enabled=bool(acc["auto_scan_enabled"]),
            scan_interval_hours=acc["scan_interval_hours"],
            folders_to_scan=acc["folders_to_scan"],
            total_scanned=acc["total_scanned"],
            phishing_detected=acc["phishing_detected"],
            last_scan_date=acc["last_scan_date"],
            created_at=acc["created_at"]
        ))
    
    return response


@router.put("/accounts/{account_id}")
@limiter.limit(WRITE_LIMIT)
async def update_email_account_endpoint(
    request: Request,
    account_id: int,
    body: EmailAccountUpdateRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Update email account settings
    """
    user_id = current_user["id"]
    
    # Verify ownership
    account = get_email_account(account_id)
    if not account or account["user_id"] != user_id:
        raise HTTPException(status_code=404, detail="Account not found")
    
    # Update
    success = update_email_account(
        account_id=account_id,
        auto_scan_enabled=body.auto_scan_enabled,
        scan_interval_hours=body.scan_interval_hours,
        folders_to_scan=body.folders_to_scan
    )
    
    if not success:
        raise HTTPException(status_code=500, detail="Failed to update account")
    
    return {"success": True, "message": "Account updated successfully"}


@router.delete("/accounts/{account_id}")
@limiter.limit(WRITE_LIMIT)
async def delete_email_account_endpoint(
    request: Request,
    account_id: int,
    current_user: dict = Depends(get_current_user)
):
    """
    Delete email account
    """
    user_id = current_user["id"]
    
    # Verify ownership
    account = get_email_account(account_id)
    if not account or account["user_id"] != user_id:
        raise HTTPException(status_code=404, detail="Account not found")
    
    # Delete
    success = delete_email_account(account_id)
    
    if not success:
        raise HTTPException(status_code=500, detail="Failed to delete account")
    
    return {"success": True, "message": "Account deleted successfully"}


@router.post("/scan", response_model=List[EmailScanResponse])
@limiter.limit(WRITE_LIMIT)
async def scan_emails(
    request: Request,
    body: EmailScanRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Scan emails from user's email account
    """
    if not EMAIL_SCANNER_AVAILABLE:
        raise HTTPException(status_code=503, detail="Email scanner not available")
    
    user_id = current_user["id"]
    
    # Verify ownership
    account = get_email_account(body.account_id)
    if not account or account["user_id"] != user_id:
        raise HTTPException(status_code=404, detail="Account not found")
    
    # Create scanner
    scanner = create_email_scanner_from_account(account)
    if not scanner:
        raise HTTPException(status_code=500, detail="Failed to create email scanner")
    
    # Start scan history
    now = datetime.now().isoformat()
    scan_history_id = add_email_scan_history(
        email_account_id=body.account_id,
        scan_started_at=now,
        scan_status="running"
    )
    
    try:
        # Scan emails
        results: List[EmailScanResult] = scanner.scan_folder(body.folder, body.limit)
        scanner.disconnect()
        
        # Calculate stats
        phishing_count = sum(1 for r in results if r.is_phishing)
        safe_count = sum(1 for r in results if not r.is_phishing and r.threat_level == "safe")
        suspicious_count = sum(1 for r in results if r.threat_level == "suspicious")
        dangerous_count = sum(1 for r in results if r.threat_level == "dangerous")
        
        # Save results to database
        for result in results:
            add_scanned_email(
                scan_history_id=scan_history_id,
                email_account_id=body.account_id,
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
            )
        
        # Update scan history
        completed_at = datetime.now().isoformat()
        update_email_scan_history(
            history_id=scan_history_id,
            scan_completed_at=completed_at,
            emails_scanned=len(results),
            phishing_detected=phishing_count,
            safe_emails=safe_count,
            suspicious_emails=suspicious_count,
            dangerous_emails=dangerous_count,
            scan_status="completed"
        )
        
        # Update account stats
        update_email_scan_stats(
            account_id=body.account_id,
            emails_scanned=len(results),
            phishing_detected=phishing_count
        )
        
        # Return results
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
        
        return response
        
    except Exception as e:
        logger.error(f"Email scan failed: {e}")
        
        # Update scan history with error
        update_email_scan_history(
            history_id=scan_history_id,
            scan_completed_at=datetime.now().isoformat(),
            scan_status="failed",
            error_message=str(e)
        )
        
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


@router.get("/stats")
@limiter.limit(READ_LIMIT)
async def get_email_stats(
    request: Request,
    current_user: dict = Depends(get_current_user)
) -> EmailStatsResponse:
    """
    Get email statistics for current user
    """
    user_id = current_user["id"]
    accounts = get_user_email_accounts(user_id)
    
    if not accounts:
        return EmailStatsResponse(
            total_scanned=0,
            phishing_detected=0,
            safe_emails=0,
            suspicious_emails=0,
            dangerous_emails=0,
            last_scan=None
        )
    
    # Aggregate stats from all accounts
    total_scanned = sum(acc["total_scanned"] for acc in accounts)
    phishing_detected = sum(acc["phishing_detected"] for acc in accounts)
    safe_emails = total_scanned - phishing_detected
    
    # Get last scan date
    last_scan = max((acc["last_scan_date"] for acc in accounts if acc["last_scan_date"]), default=None)
    
    return EmailStatsResponse(
        total_scanned=total_scanned,
        phishing_detected=phishing_detected,
        safe_emails=safe_emails,
        suspicious_emails=0,  # TODO: Calculate from scanned_emails table
        dangerous_emails=0,   # TODO: Calculate from scanned_emails table
        last_scan=last_scan
    )


@router.get("/history")
@limiter.limit(READ_LIMIT)
async def get_scan_history_endpoint(
    request: Request,
    account_id: int,
    limit: int = 20,
    current_user: dict = Depends(get_current_user)
):
    """
    Get scan history for email account
    """
    user_id = current_user["id"]
    
    # Verify ownership
    account = get_email_account(account_id)
    if not account or account["user_id"] != user_id:
        raise HTTPException(status_code=404, detail="Account not found")
    
    history = get_email_scan_history(account_id, limit)
    return {"scans": history, "total": len(history)}


@router.get("/results")
@limiter.limit(READ_LIMIT)
async def get_scanned_emails_endpoint(
    request: Request,
    account_id: int,
    limit: int = 100,
    current_user: dict = Depends(get_current_user)
):
    """
    Get scanned emails for account
    """
    user_id = current_user["id"]
    
    # Verify ownership
    account = get_email_account(account_id)
    if not account or account["user_id"] != user_id:
        raise HTTPException(status_code=404, detail="Account not found")
    
    emails = get_scanned_emails(account_id, limit)
    return {"emails": emails, "total": len(emails)}