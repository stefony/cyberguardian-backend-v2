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

router = APIRouter(prefix="/auth", tags=["Authentication"])

# OAuth2 scheme for token authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


# ========== REQUEST/RESPONSE MODELS ==========

class RegisterRequest(BaseModel):
    email: EmailStr
    username: str
    password: str
    full_name: Optional[str] = None
    company: Optional[str] = None


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
    Login and get JWT token
    """
    # Get user by email
    user = get_user_by_email(data.email)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )
    
    # Verify password
    if not verify_password(data.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )
    
    # Check if user is active
    if not user["is_active"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated"
        )
    
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