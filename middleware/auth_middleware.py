"""
CyberGuardian AI - Auth Middleware
PHASE 7: Enterprise Features

Extracts user_id from JWT token and sets it in request.state
This allows tenant_context_middleware to access user info.
"""

from fastapi import Request
from typing import Optional
import logging

logger = logging.getLogger(__name__)


async def auth_middleware(request: Request, call_next):
    """
    Extract user_id from JWT token and set in request.state
    This runs BEFORE tenant_context_middleware
    """
    try:
        print(f"🔐 Auth middleware called for: {request.url.path}")  # DEBUG
        
        # Get Authorization header
        auth_header = request.headers.get("Authorization")
        
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.replace("Bearer ", "")
            
            print(f"🔑 Token found: {token[:20]}...")  # DEBUG
            
            # Decode token
            from core.auth import decode_access_token
            payload = decode_access_token(token)
            
            if payload and "user_id" in payload:
                # Set user_id in request.state
                request.state.user_id = payload["user_id"]
                request.state.email = payload.get("email")
                
                print(f"✅ Auth middleware: user_id={payload['user_id']}, email={payload.get('email')}")
                logger.debug(f"Auth middleware: user_id={payload['user_id']}")
            else:
                print(f"⚠️ Token decoded but no user_id found")
        else:
            print(f"ℹ️ No Authorization header found")
        
        # Process request
        response = await call_next(request)
        return response
        
    except Exception as e:
        print(f"❌ Error in auth middleware: {e}")
        logger.error(f"Error in auth middleware: {e}")
        # Continue even if auth fails - let endpoints handle auth errors
        response = await call_next(request)
        return response