"""
Authentication API Router
"""

from fastapi import APIRouter, HTTPException, Depends, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import timedelta

from database.db import (
    create_user, 
    get_user_by_email, 
    get_user_by_username,
    get_user_by_id,
    update_last_login
)
from core.auth import (
    hash_password,
    verify_password,
    create_access_token,
    decode_access_token,
    ACCESS_TOKEN_EXPIRE_MINUTES
)
from fastapi import Request  # Добави Request към съществуващия FastAPI import
from middleware.rate_limiter import limiter, AUTH_LIMIT

from pydantic import BaseModel, EmailStr, validator, Field
import re

router = APIRouter(prefix="/auth", tags=["Authentication"])

# OAuth2 scheme for token authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


# ========== REQUEST/RESPONSE MODELS ==========

class RegisterRequest(BaseModel):
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=30, pattern=r'^[a-zA-Z0-9_]+$')
    password: str = Field(..., min_length=8, max_length=128)
    full_name: Optional[str] = Field(None, max_length=100)
    company: Optional[str] = Field(None, max_length=100)
    
    @validator('password')
    def validate_password(cls, v):
        """
        Password must contain:
        - At least 8 characters
        - At least one uppercase letter
        - At least one lowercase letter
        - At least one number
        - At least one special character
        """
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        
        if not re.search(r'[A-Z]', v):
            raise ValueError('Password must contain at least one uppercase letter')
        
        if not re.search(r'[a-z]', v):
            raise ValueError('Password must contain at least one lowercase letter')
        
        if not re.search(r'\d', v):
            raise ValueError('Password must contain at least one number')
        
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', v):
            raise ValueError('Password must contain at least one special character')
        
        return v
    
    @validator('username')
    def validate_username(cls, v):
        """Username must be alphanumeric with underscores only"""
        if not re.match(r'^[a-zA-Z0-9_]+$', v):
            raise ValueError('Username can only contain letters, numbers, and underscores')
        
        # Reserved usernames
        reserved = ['admin', 'root', 'system', 'api', 'www', 'test']
        if v.lower() in reserved:
            raise ValueError('This username is reserved')
        
        return v
    
    @validator('full_name')
    def validate_full_name(cls, v):
        """Sanitize full name"""
        if v is None:
            return v
        
        # Remove any HTML/script tags
        v = re.sub(r'<[^>]+>', '', v)
        
        # Only allow letters, spaces, hyphens, apostrophes
        if not re.match(r"^[a-zA-Z\s\-']+$", v):
            raise ValueError('Full name can only contain letters, spaces, hyphens, and apostrophes')
        
        return v.strip()
    
    @validator('company')
    def validate_company(cls, v):
        """Sanitize company name"""
        if v is None:
            return v
        
        # Remove any HTML/script tags
        v = re.sub(r'<[^>]+>', '', v)
        
        return v.strip()


class LoginRequest(BaseModel):
    email: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: dict


class UserResponse(BaseModel):
    id: str
    email: str
    username: str
    full_name: Optional[str]
    company: Optional[str]
    is_active: bool
    is_verified: bool
    is_admin: bool
    created_at: str
    last_login: Optional[str]


# ========== DEPENDENCY: GET CURRENT USER ==========

def get_current_user(token: str = Depends(oauth2_scheme)):
    """
    Dependency to extract current user from JWT token
    """
    payload = decode_access_token(token)
    
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    user_id = payload.get("user_id")
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    user = get_user_by_id(user_id)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return user


# ========== ENDPOINTS ==========

@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit(AUTH_LIMIT)  # 5 requests per 15 minutes
async def register(request: Request, data: RegisterRequest):
    """
    Register a new user
    """
    # Check if email already exists
    existing_user = get_user_by_email(data.email)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    # Check if username already exists
    existing_username = get_user_by_username(data.username)
    if existing_username:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already taken"
        )
    
    # Hash password
    hashed_pwd = hash_password(data.password)
    
    # Create user (using hashed password)
    user_id = create_user(
        email=data.email,
        username=data.username,
        password=hashed_pwd,  # Already hashed!
        full_name=data.full_name,
        company=data.company,
        is_admin=False
    )
    
    # Get created user
    user = get_user_by_id(user_id)
    
    # Create access token
    access_token = create_access_token(
        data={"user_id": user_id, "email": data.email}
    )
    
    # Remove password from response
    user_data = {k: v for k, v in user.items() if k != "hashed_password"}
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": user_data
    }


@router.post("/login", response_model=TokenResponse)
@limiter.limit(AUTH_LIMIT)  # 5 requests per 15 minutes
async def login(request: Request, data: LoginRequest):
    """
    Login and get JWT token with brute force protection
    """
    from database.db import (
        is_account_locked,
        increment_failed_login,
        reset_failed_login,
        lock_account,
        get_failed_login_count
    )
    
    # Check if account is locked
    if is_account_locked(data.email):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is temporarily locked due to multiple failed login attempts. Please try again later."
        )
    
    # Get user by email
    user = get_user_by_email(data.email)
    
    if not user:
        # Don't reveal if email exists - generic error
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )
    
    # Verify password
    if not verify_password(data.password, user["hashed_password"]):
        # Increment failed attempts
        failed_count = increment_failed_login(data.email)
        
        # Lock account after 5 failed attempts
        if failed_count >= 5:
            lock_account(data.email, duration_minutes=15)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account locked due to multiple failed login attempts. Please try again in 15 minutes."
            )
        
        # Generic error message
        remaining_attempts = 5 - failed_count
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid email or password. {remaining_attempts} attempts remaining before account lock."
        )
    
    # Check if user is active
    if not user["is_active"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated"
        )
    
    # Successful login - reset failed attempts
    reset_failed_login(data.email)
    
    # Update last login
    update_last_login(user["id"])
    
    # Create access token
    access_token = create_access_token(
        data={"user_id": user["id"], "email": user["email"]}
    )
    
    # Remove password from response
    user_data = {k: v for k, v in user.items() if k != "hashed_password"}
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": user_data
    }


@router.get("/me", response_model=UserResponse)
@limiter.limit("60 per minute")  # Liberal - just checking user info
async def get_current_user_info(request: Request, current_user: dict = Depends(get_current_user)):
    """
    Get current authenticated user info
    """
    # Remove password from response
    user_data = {k: v for k, v in current_user.items() if k != "hashed_password"}
    return user_data


@router.post("/logout")
@limiter.limit("30 per minute")  # Liberal for logout
async def logout(request: Request):
    """
    Logout (client-side only - remove token)
    """
    return {"message": "Logged out successfully"}