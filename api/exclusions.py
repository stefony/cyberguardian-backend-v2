"""
CyberGuardian AI - Exclusions API
Manage file/folder/process exclusions for real-time protection
"""

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from typing import List, Optional
from database import db
from middleware.rate_limiter import limiter, READ_LIMIT, WRITE_LIMIT

router = APIRouter()


class ExclusionCreate(BaseModel):
    type: str  # 'path', 'extension', 'process'
    value: str
    reason: Optional[str] = None


class ExclusionResponse(BaseModel):
    id: int
    type: str
    value: str
    reason: Optional[str]
    created_at: str
    created_by: Optional[str]


@router.get("/api/exclusions", response_model=List[ExclusionResponse])
@limiter.limit(READ_LIMIT)
async def get_exclusions(request: Request, type: Optional[str] = None):
    """Get all exclusions or filter by type"""
    try:
        exclusions = db.get_exclusions(type)
        return exclusions
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/exclusions")
@limiter.limit(WRITE_LIMIT)
async def create_exclusion(request: Request, exclusion: ExclusionCreate):
    """Add new exclusion"""
    try:
        # Validate type
        valid_types = ['path', 'extension', 'process']
        if exclusion.type not in valid_types:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid type. Must be one of: {', '.join(valid_types)}"
            )
        
        exclusion_id = db.add_exclusion(
            exclusion_type=exclusion.type,
            value=exclusion.value,
            reason=exclusion.reason,
            created_by="admin"  # TODO: Get from auth context
        )
        
        if exclusion_id == -1:
            raise HTTPException(status_code=409, detail="Exclusion already exists")
        
        return {
            "success": True,
            "id": exclusion_id,
            "message": "Exclusion added successfully"
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/api/exclusions/{exclusion_id}")
@limiter.limit(WRITE_LIMIT)
async def delete_exclusion(request: Request, exclusion_id: int):
    """Delete exclusion"""
    try:
        success = db.delete_exclusion(exclusion_id)
        
        if not success:
            raise HTTPException(status_code=404, detail="Exclusion not found")
        
        return {
            "success": True,
            "message": "Exclusion deleted successfully"
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/exclusions/check/{type}/{value}")
@limiter.limit(READ_LIMIT)
async def check_exclusion(request: Request, type: str, value: str):
    """Check if a value is excluded"""
    try:
        is_excluded = db.is_excluded(type, value)
        
        return {
            "excluded": is_excluded,
            "type": type,
            "value": value
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    