"""
Rate Limiting Middleware for CyberGuardian AI
Uses slowapi for rate limiting with different strategies per endpoint type
"""

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi import Request
from typing import Callable
import os

# ============================================
# Rate Limiter Configuration
# ============================================

def get_client_ip(request: Request) -> str:
    """
    Get client IP address, handling proxies (Vercel, Railway, etc.)
    """
    # Check X-Forwarded-For header first (for proxies)
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        # Get first IP in the chain
        return forwarded_for.split(",")[0].strip()
    
    # Check X-Real-IP header
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip
    
    # Fallback to direct client IP
    if request.client:
        return request.client.host
    
    return "unknown"

# Initialize limiter
limiter = Limiter(
    key_func=get_client_ip,
    default_limits=["1000 per day", "200 per hour"],  # Global defaults
    storage_uri=os.getenv("REDIS_URL", "memory://"),  # Use Redis in production, memory for dev
)

# ============================================
# Rate Limit Decorators by Endpoint Type
# ============================================

# 🔐 Authentication Endpoints - Very Strict
AUTH_LIMIT = "5 per 15 minutes"  # 5 attempts per 15 minutes

# 📊 Read Endpoints - Liberal
READ_LIMIT = "100 per minute"  # 100 requests per minute

# ✍️ Write Endpoints - Medium Strict  
WRITE_LIMIT = "30 per minute"  # 30 requests per minute

# 🔥 Threat Intelligence - Medium
THREAT_INTEL_LIMIT = "60 per minute"  # 60 requests per minute

# 🔍 Analytics/Insights - Medium
ANALYTICS_LIMIT = "60 per minute"  # 60 requests per minute

# ⚙️ Settings/Config - Strict
SETTINGS_LIMIT = "20 per minute"  # 20 requests per minute

# ============================================
# Custom Rate Limit Exception Handler
# ============================================

def rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded):
    """
    Custom handler for rate limit exceeded errors
    Returns JSON with retry information
    """
    return {
        "error": "Rate limit exceeded",
        "message": f"Too many requests from {get_client_ip(request)}",
        "detail": str(exc.detail),
        "retry_after": exc.headers.get("Retry-After", "60") if exc.headers else "60",
        "type": "rate_limit"
    }

# ============================================
# Helper Functions
# ============================================

def get_rate_limit_key(request: Request, suffix: str = "") -> str:
    """
    Generate a unique rate limit key for a request
    Useful for custom rate limiting scenarios
    """
    client_ip = get_client_ip(request)
    path = request.url.path
    return f"{client_ip}:{path}:{suffix}" if suffix else f"{client_ip}:{path}"

# ============================================
# Export
# ============================================

__all__ = [
    "limiter",
    "get_client_ip",
    "rate_limit_exceeded_handler",
    "AUTH_LIMIT",
    "READ_LIMIT", 
    "WRITE_LIMIT",
    "THREAT_INTEL_LIMIT",
    "ANALYTICS_LIMIT",
    "SETTINGS_LIMIT",
]