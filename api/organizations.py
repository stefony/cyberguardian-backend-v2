"""
CyberGuardian AI - Organizations API
PHASE 7: Enterprise Features

API endpoints for managing organizations (multi-tenant companies).
Handles organization CRUD, members, settings, and invitations.
"""

from fastapi import APIRouter, HTTPException, Depends, Request
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
import uuid
import secrets
import logging

from database.schema_enterprise import (
    get_connection,
    create_organization,
    get_organization,
    get_user_organizations,
    assign_user_role,
)
from middleware.tenant_context import (
    require_organization,
    get_current_organization,
    get_current_user_id,
)
from middleware.rbac import (
    RequireAdmin,
    RequireOrganizationsRead,
    RequireOrganizationsWrite,
    RequireUsersInvite,
    has_permission,
)

# 🔐 Auth dependency – задължително, за да имаме user_id в request.state
from api.auth import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/organizations", tags=["Organizations"])


# ============================================
# MODELS
# ============================================

class OrganizationCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    slug: str = Field(..., min_length=2, max_length=50, pattern="^[a-z0-9-]+$")
    description: Optional[str] = None
    plan: str = Field(default="free", pattern="^(free|pro|enterprise)$")
    max_users: int = Field(default=5, ge=1, le=1000)
    max_devices: int = Field(default=10, ge=1, le=10000)
    max_scans_per_day: int = Field(default=100, ge=1, le=100000)


class OrganizationUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=2, max_length=100)
    description: Optional[str] = None
    plan: Optional[str] = Field(None, pattern="^(free|pro|enterprise)$")
    max_users: Optional[int] = Field(None, ge=1, le=1000)
    max_devices: Optional[int] = Field(None, ge=1, le=10000)
    max_scans_per_day: Optional[int] = Field(None, ge=1, le=100000)
    logo_url: Optional[str] = None
    website: Optional[str] = None
    contact_email: Optional[str] = None
    contact_phone: Optional[str] = None
    address: Optional[str] = None


class OrganizationSettings(BaseModel):
    settings: Dict[str, Any]


class OrganizationInvite(BaseModel):
    email: str = Field(
        ...,
        pattern=r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$",
    )
    role: str = Field(..., pattern="^(admin|manager|analyst|viewer)$")


class OrganizationMemberUpdate(BaseModel):
    role: str = Field(..., pattern="^(admin|manager|analyst|viewer)$")


# ============================================
# HELPERS
# ============================================

def _extract_user_id(current_user: Any, request: Request) -> Optional[str]:
    """
    Опитва да извлече user_id:
    - от current_user.id
    - от current_user["id"]
    - от request.state.user_id (get_current_user_id)
    """
    user_id = getattr(current_user, "id", None)
    if user_id is None and isinstance(current_user, dict):
        user_id = current_user.get("id")

    if not user_id:
        user_id = get_current_user_id(request)

    return user_id


# ============================================
# ORGANIZATION CRUD
# ============================================

@router.post("/", status_code=201)
async def create_new_organization(
    org_data: OrganizationCreate,
    request: Request,
    current_user: Any = Depends(get_current_user),
):
    """
    Create new organization.
    Всеки логнат потребител може да създаде организация – става admin в нея.
    """
    try:
        user_id = _extract_user_id(current_user, request)
        if not user_id:
            raise HTTPException(status_code=401, detail="Authentication required")

        # Check slug uniqueness
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM organizations WHERE slug = ?", (org_data.slug,))
        if cursor.fetchone():
            conn.close()
            raise HTTPException(status_code=400, detail="Organization slug already exists")
        conn.close()

        # Generate org id
        org_id = f"org_{uuid.uuid4().hex[:16]}"

        success = create_organization(
            org_id=org_id,
            name=org_data.name,
            slug=org_data.slug,
            plan=org_data.plan,
            description=org_data.description,
            max_users=org_data.max_users,
            max_devices=org_data.max_devices,
            max_scans_per_day=org_data.max_scans_per_day,
        )

        if not success:
            raise HTTPException(status_code=500, detail="Failed to create organization")

        # Assign creator as admin
        assign_user_role(user_id, org_id, "admin", assigned_by=user_id)

        org = get_organization(org_id)

        logger.info(f"Organization created: {org_id} by user {user_id}")

        return {
            "success": True,
            "message": "Organization created successfully",
            "organization": org,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating organization: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/")
async def list_user_organizations(
    request: Request,
    current_user: Any = Depends(get_current_user),
):
    """
    Списък с организации за текущия потребител.

    Важно: ако не успеем да вземем user_id → връщаме 200 с празен списък,
    за да не чупим UI с 401/500.
    """
    try:
        user_id = _extract_user_id(current_user, request)

        if not user_id:
            return {
                "success": True,
                "count": 0,
                "organizations": [],
            }

        organizations = get_user_organizations(user_id)

        return {
            "success": True,
            "count": len(organizations),
            "organizations": organizations,
        }

    except Exception as e:
        logger.error(f"Error listing organizations: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{org_id}")
async def get_organization_details(
    org_id: str,
    request: Request,
    current_user: Any = Depends(get_current_user),
):
    """
    Get organization details for a specific org_id.
    """
    try:
        user_id = _extract_user_id(current_user, request)
        if not user_id:
            raise HTTPException(status_code=401, detail="Authentication required")

        org = get_organization(org_id)
        if not org:
            raise HTTPException(status_code=404, detail="Organization not found")

        # Check membership
        user_orgs = get_user_organizations(user_id)
        org_ids = [o["id"] for o in user_orgs]
        if org_id not in org_ids:
            raise HTTPException(status_code=403, detail="Access denied to this organization")

        return {
            "success": True,
            "organization": org,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting organization: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/{org_id}")
async def update_organization(
    org_id: str,
    org_data: OrganizationUpdate,
    request: Request,
    _: bool = Depends(RequireAdmin),  # тук оставяме Admin check – това е по-критично
):
    """
    Update organization details (admin only).
    """
    try:
        org = get_organization(org_id)
        if not org:
            raise HTTPException(status_code=404, detail="Organization not found")

        conn = get_connection()
        cursor = conn.cursor()

        updates = []
        params: list[Any] = []

        if org_data.name is not None:
            updates.append("name = ?")
            params.append(org_data.name)

        if org_data.description is not None:
            updates.append("description = ?")
            params.append(org_data.description)

        if org_data.plan is not None:
            updates.append("plan = ?")
            params.append(org_data.plan)

        if org_data.max_users is not None:
            updates.append("max_users = ?")
            params.append(org_data.max_users)

        if org_data.max_devices is not None:
            updates.append("max_devices = ?")
            params.append(org_data.max_devices)

        if org_data.max_scans_per_day is not None:
            updates.append("max_scans_per_day = ?")
            params.append(org_data.max_scans_per_day)

        if org_data.logo_url is not None:
            updates.append("logo_url = ?")
            params.append(org_data.logo_url)

        if org_data.website is not None:
            updates.append("website = ?")
            params.append(org_data.website)

        if org_data.contact_email is not None:
            updates.append("contact_email = ?")
            params.append(org_data.contact_email)

        if org_data.contact_phone is not None:
            updates.append("contact_phone = ?")
            params.append(org_data.contact_phone)

        if org_data.address is not None:
            updates.append("address = ?")
            params.append(org_data.address)

        if not updates:
            conn.close()
            raise HTTPException(status_code=400, detail="No updates provided")

        updates.append("updated_at = ?")
        params.append(datetime.now().isoformat())
        params.append(org_id)

        query = f"UPDATE organizations SET {', '.join(updates)} WHERE id = ?"
        cursor.execute(query, params)
        conn.commit()
        conn.close()

        org = get_organization(org_id)

        logger.info(f"Organization updated: {org_id}")

        return {
            "success": True,
            "message": "Organization updated successfully",
            "organization": org,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating organization: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# -------- Settings --------

@router.get("/{org_id}/settings")
async def get_organization_settings(
    org_id: str,
    request: Request,
    current_user: Any = Depends(get_current_user),
):
    """
    Get organization settings (auth required).
    """
    try:
        user_id = _extract_user_id(current_user, request)
        if not user_id:
            raise HTTPException(status_code=401, detail="Authentication required")

        org = get_organization(org_id)
        if not org:
            raise HTTPException(status_code=404, detail="Organization not found")

        user_orgs = get_user_organizations(user_id)
        org_ids = [o["id"] for o in user_orgs]
        if org_id not in org_ids:
            raise HTTPException(status_code=403, detail="Access denied")

        settings = org.get("settings") or {}

        return {
            "success": True,
            "settings": settings,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting org settings: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/{org_id}/settings")
async def update_organization_settings(
    org_id: str,
    data: OrganizationSettings,
    request: Request,
    _: bool = Depends(RequireAdmin),
):
    """
    Update organization settings (admin).
    """
    try:
        org = get_organization(org_id)
        if not org:
            raise HTTPException(status_code=404, detail="Organization not found")

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            UPDATE organizations
            SET settings = ?, updated_at = ?
            WHERE id = ?
            """,
            (json.dumps(data.settings), datetime.now().isoformat(), org_id),
        )

        conn.commit()
        conn.close()

        org = get_organization(org_id)

        return {
            "success": True,
            "message": "Settings updated successfully",
            "organization": org,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating org settings: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# -------- Members & Invites (по-рядко ползвани в UI, но ги оставям) --------

@router.get("/{org_id}/members")
async def list_organization_members(
    org_id: str,
    request: Request,
    current_user: Any = Depends(get_current_user),
):
    """
    List members of an organization.
    """
    try:
        user_id = _extract_user_id(current_user, request)
        if not user_id:
            raise HTTPException(status_code=401, detail="Authentication required")

        # check membership
        user_orgs = get_user_organizations(user_id)
        org_ids = [o["id"] for o in user_orgs]
        if org_id not in org_ids:
            raise HTTPException(status_code=403, detail="Access denied")

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT 
                u.id,
                u.username,
                u.email,
                u.full_name,
                u.is_active,
                r.name as role,
                r.display_name as role_display,
                ur.assigned_at
            FROM users u
            JOIN user_roles ur ON u.id = ur.user_id
            JOIN roles r ON ur.role_id = r.id
            WHERE ur.organization_id = ?
            ORDER BY u.username
            """,
            (org_id,),
        )

        rows = cursor.fetchall()
        conn.close()

        members = [dict(row) for row in rows]

        return {
            "success": True,
            "count": len(members),
            "members": members,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error listing org members: {e}")
        raise HTTPException(status_code=500, detail=str(e))



@router.put("/{org_id}/members/{user_id}")
async def update_member_role(
    org_id: str,
    user_id: str,
    member_data: OrganizationMemberUpdate,
    request: Request,
    _: bool = Depends(RequireAdmin),
):
    """
    Update member's role in organization
    Requires: admin role
    """
    try:
        current_user = get_current_user_id(request)

        # Assign new role
        success = assign_user_role(
            user_id=user_id,
            organization_id=org_id,
            role_name=member_data.role,
            assigned_by=current_user,
        )

        if not success:
            raise HTTPException(status_code=500, detail="Failed to update member role")

        logger.info(f"Member role updated: {user_id} in {org_id} to {member_data.role}")

        return {
            "success": True,
            "message": "Member role updated successfully",
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating member role: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/{org_id}/members/{user_id}")
async def remove_member(
    org_id: str,
    user_id: str,
    request: Request,
    _: bool = Depends(RequireAdmin),
):
    """
    Remove member from organization
    Requires: admin role
    """
    try:
        conn = get_connection()
        cursor = conn.cursor()

        # Check if user is the last admin
        cursor.execute(
            """
            SELECT COUNT(*) 
            FROM user_roles ur
            JOIN roles r ON ur.role_id = r.id
            WHERE ur.organization_id = ? AND r.name = 'admin'
        """,
            (org_id,),
        )

        admin_count = cursor.fetchone()[0]

        # Check if user being removed is admin
        cursor.execute(
            """
            SELECT r.name
            FROM user_roles ur
            JOIN roles r ON ur.role_id = r.id
            WHERE ur.user_id = ? AND ur.organization_id = ?
        """,
            (user_id, org_id),
        )

        role_row = cursor.fetchone()
        if role_row and role_row[0] == "admin" and admin_count <= 1:
            conn.close()
            raise HTTPException(
                status_code=400,
                detail="Cannot remove the last admin from organization",
            )

        # Remove user
        cursor.execute(
            """
            DELETE FROM user_roles 
            WHERE user_id = ? AND organization_id = ?
        """,
            (user_id, org_id),
        )

        conn.commit()
        conn.close()

        logger.info(f"Member removed: {user_id} from {org_id}")

        return {
            "success": True,
            "message": "Member removed successfully",
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error removing member: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================
# ORGANIZATION SETTINGS
# ============================================

@router.get("/{org_id}/settings")
async def get_organization_settings(
    org_id: str,
    request: Request,
    _: bool = Depends(RequireOrganizationsRead),
):
    """
    Get organization settings
    Requires: organizations.read permission
    """
    try:
        org = get_organization(org_id)

        if not org:
            raise HTTPException(status_code=404, detail="Organization not found")

        return {
            "success": True,
            "settings": org.get("settings", {}),
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting settings: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/{org_id}/settings")
async def update_organization_settings(
    org_id: str,
    settings_data: OrganizationSettings,
    request: Request,
    _: bool = Depends(RequireOrganizationsWrite),
):
    """
    Update organization settings
    Requires: organizations.write permission
    """
    try:
        import json

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            UPDATE organizations 
            SET settings = ?, updated_at = ?
            WHERE id = ?
        """,
            (
                json.dumps(settings_data.settings),
                datetime.now().isoformat(),
                org_id,
            ),
        )

        conn.commit()
        conn.close()

        logger.info(f"Organization settings updated: {org_id}")

        return {
            "success": True,
            "message": "Settings updated successfully",
            "settings": settings_data.settings,
        }

    except Exception as e:
        logger.error(f"Error updating settings: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================
# ORGANIZATION STATISTICS
# ============================================

@router.get("/{org_id}/stats")
async def get_organization_stats(
    org_id: str,
    request: Request,
    _: bool = Depends(RequireOrganizationsRead),
):
    """
    Get organization statistics
    Requires: organizations.read permission
    """
    try:
        conn = get_connection()
        cursor = conn.cursor()

        # Get member count
        cursor.execute(
            """
            SELECT COUNT(*) FROM user_roles WHERE organization_id = ?
        """,
            (org_id,),
        )
        member_count = cursor.fetchone()[0]

        # For now, mock scans / threats
        scan_count = 0
        threat_count = 0

        conn.close()

        return {
            "success": True,
            "stats": {
                "members": member_count,
                "scans": scan_count,
                "threats": threat_count,
            },
        }

    except Exception as e:
        logger.error(f"Error getting stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))
