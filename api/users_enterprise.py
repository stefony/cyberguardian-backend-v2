"""
CyberGuardian AI - Enhanced Users API
PHASE 7: Enterprise Features

Enhanced user management with:
- Multi-tenant organization support
- Role-based access control
- User invitations
- Organization membership
"""

from fastapi import APIRouter, HTTPException, Depends, Request
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
import uuid
import secrets
import logging

from database.schema_enterprise import (
    get_connection,
    assign_user_role,
    get_user_role,
    get_user_organizations,
)
from middleware.rbac import (
    RequireAdmin,
    # RequireUsersRead,
    # RequireUsersWrite,
    # RequireUsersDelete,
    # RequireUsersInvite,
    has_permission,
)
from middleware.tenant_context import (
    get_current_organization,
    get_current_user_id,
    get_current_role,
)

# 🔐 Auth dependency
from api.auth import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/users", tags=["Users"])


# ============================================
# MODELS
# ============================================

class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(..., min_length=8)
    full_name: Optional[str] = None
    role: str = Field(default="viewer", pattern="^(admin|manager|analyst|viewer)$")


class UserUpdate(BaseModel):
    username: Optional[str] = Field(None, min_length=3, max_length=50)
    email: Optional[EmailStr] = None
    full_name: Optional[str] = None
    is_active: Optional[bool] = None


class UserRoleUpdate(BaseModel):
    role: str = Field(..., pattern="^(admin|manager|analyst|viewer)$")


class UserInvite(BaseModel):
    email: EmailStr
    role: str = Field(..., pattern="^(admin|manager|analyst|viewer)$")
    message: Optional[str] = None


class UserPasswordChange(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=8)


# ============================================
# USER MANAGEMENT
# ============================================

@router.get("/")
async def list_users(
    request: Request,
    org_id: Optional[str] = None,
    current_user: Any = Depends(get_current_user),
):
    """
    List all users in organization.
    В момента: само auth е задължително, без строги RBAC permissions.
    """
    try:
        organization_id = org_id or get_current_organization(request)

        if not organization_id:
            return {
                "success": True,
                "count": 0,
                "organization_id": None,
                "users": [],
            }

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
                u.created_at,
                r.name as role,
                r.display_name as role_display,
                ur.assigned_at
            FROM users u
            JOIN user_roles ur ON u.id = ur.user_id
            JOIN roles r ON ur.role_id = r.id
            WHERE ur.organization_id = ?
            ORDER BY u.username
            """,
            (organization_id,),
        )

        rows = cursor.fetchall()
        conn.close()

        users: List[Dict[str, Any]] = []
        for row in rows:
            user = dict(row)
            user.pop("password", None)
            users.append(user)

        return {
            "success": True,
            "count": len(users),
            "organization_id": organization_id,
            "users": users,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error listing users: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{user_id}")
async def get_user_details(
    user_id: str,
    request: Request,
    current_user: Any = Depends(get_current_user),
):
    """
    Get user details (auth required).
    """
    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT id, username, email, full_name, is_active, created_at, updated_at
            FROM users
            WHERE id = ?
            """,
            (user_id,),
        )

        row = cursor.fetchone()

        if not row:
            conn.close()
            raise HTTPException(status_code=404, detail="User not found")

        user = dict(row)

        orgs = get_user_organizations(user_id)
        user["organizations"] = orgs

        conn.close()

        return {
            "success": True,
            "user": user,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting user: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/", status_code=201)
async def create_user(
    user_data: UserCreate,
    request: Request,
    current_user: Any = Depends(get_current_user),
):
    """
    Create new user in organization (auth required).
    """
    try:
        import hashlib

        org_id = get_current_organization(request)
        if not org_id:
            raise HTTPException(status_code=400, detail="Organization context required")

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT id FROM users WHERE username = ?", (user_data.username,))
        if cursor.fetchone():
            conn.close()
            raise HTTPException(status_code=400, detail="Username already exists")

        cursor.execute("SELECT id FROM users WHERE email = ?", (user_data.email,))
        if cursor.fetchone():
            conn.close()
            raise HTTPException(status_code=400, detail="Email already exists")

        user_id = f"user_{uuid.uuid4().hex[:16]}"

        password_hash = hashlib.sha256(user_data.password.encode()).hexdigest()
        now = datetime.now().isoformat()

        cursor.execute(
            """
            INSERT INTO users (id, username, email, password, full_name, is_active, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, 1, ?, ?)
            """,
            (
                user_id,
                user_data.username,
                user_data.email,
                password_hash,
                user_data.full_name,
                now,
                now,
            ),
        )

        conn.commit()
        conn.close()

        current_user_id = get_current_user_id(request)
        assign_user_role(user_id, org_id, user_data.role, assigned_by=current_user_id)

        logger.info(f"User created: {user_id} in org {org_id} with role {user_data.role}")

        return {
            "success": True,
            "message": "User created successfully",
            "user_id": user_id,
            "username": user_data.username,
            "role": user_data.role,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating user: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/{user_id}")
async def update_user(
    user_id: str,
    user_data: UserUpdate,
    request: Request,
    current_user: Any = Depends(get_current_user),
):
    """
    Update user details (auth required).
    """
    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT id FROM users WHERE id = ?", (user_id,))
        if not cursor.fetchone():
            conn.close()
            raise HTTPException(status_code=404, detail="User not found")

        updates: List[str] = []
        params: List[Any] = []

        if user_data.username is not None:
            cursor.execute(
                "SELECT id FROM users WHERE username = ? AND id != ?",
                (user_data.username, user_id),
            )
            if cursor.fetchone():
                conn.close()
                raise HTTPException(status_code=400, detail="Username already exists")
            updates.append("username = ?")
            params.append(user_data.username)

        if user_data.email is not None:
            cursor.execute(
                "SELECT id FROM users WHERE email = ? AND id != ?",
                (user_data.email, user_id),
            )
            if cursor.fetchone():
                conn.close()
                raise HTTPException(status_code=400, detail="Email already exists")
            updates.append("email = ?")
            params.append(user_data.email)

        if user_data.full_name is not None:
            updates.append("full_name = ?")
            params.append(user_data.full_name)

        if user_data.is_active is not None:
            updates.append("is_active = ?")
            params.append(1 if user_data.is_active else 0)

        if not updates:
            conn.close()
            raise HTTPException(status_code=400, detail="No updates provided")

        updates.append("updated_at = ?")
        params.append(datetime.now().isoformat())
        params.append(user_id)

        query = f"UPDATE users SET {', '.join(updates)} WHERE id = ?"
        cursor.execute(query, params)
        conn.commit()
        conn.close()

        logger.info(f"User updated: {user_id}")

        return {
            "success": True,
            "message": "User updated successfully",
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating user: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/{user_id}")
async def delete_user(
    user_id: str,
    request: Request,
    current_user: Any = Depends(get_current_user),
):
    """
    Delete user (soft delete).
    """
    try:
        current_user_id = get_current_user_id(request)

        if user_id == current_user_id:
            raise HTTPException(status_code=400, detail="Cannot delete your own account")

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT id FROM users WHERE id = ?", (user_id,))
        if not cursor.fetchone():
            conn.close()
            raise HTTPException(status_code=404, detail="User not found")

        cursor.execute(
            """
            UPDATE users
            SET is_active = 0, updated_at = ?
            WHERE id = ?
            """,
            (datetime.now().isoformat(), user_id),
        )

        conn.commit()
        conn.close()

        logger.info(f"User deleted: {user_id}")

        return {
            "success": True,
            "message": "User deleted successfully",
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting user: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================
# USER ROLE MANAGEMENT
# ============================================

@router.put("/{user_id}/role")
async def update_user_role(
    user_id: str,
    role_data: UserRoleUpdate,
    request: Request,
    current_user: Any = Depends(get_current_user),
    _: bool = Depends(RequireAdmin),
):
    """
    Update user's role in current organization (admin only).
    """
    try:
        org_id = get_current_organization(request)
        if not org_id:
            raise HTTPException(status_code=400, detail="Organization context required")

        current_user_id = get_current_user_id(request)
        if user_id == current_user_id:
            raise HTTPException(status_code=400, detail="Cannot change your own role")

        success = assign_user_role(
            user_id=user_id,
            organization_id=org_id,
            role_name=role_data.role,
            assigned_by=current_user_id,
        )

        if not success:
            raise HTTPException(status_code=500, detail="Failed to update user role")

        logger.info(f"User role updated: {user_id} to {role_data.role} in org {org_id}")

        return {
            "success": True,
            "message": "User role updated successfully",
            "user_id": user_id,
            "role": role_data.role,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating user role: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{user_id}/role")
async def get_user_role_info(
    user_id: str,
    request: Request,
    current_user: Any = Depends(get_current_user),
):
    """
    Get user's role in current organization (auth required).
    """
    try:
        org_id = get_current_organization(request)
        if not org_id:
            raise HTTPException(status_code=400, detail="Organization context required")

        role = get_user_role(user_id, org_id)
        if not role:
            raise HTTPException(
                status_code=404, detail="User role not found in this organization"
            )

        return {
            "success": True,
            "user_id": user_id,
            "organization_id": org_id,
            "role": role,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting user role: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================
# USER INVITATIONS
# ============================================

@router.post("/invite")
async def invite_user(
    invite_data: UserInvite,
    request: Request,
    current_user: Any = Depends(get_current_user),
):
    """
    Invite user to organization.
    В момента – изискваме само auth, не и users.invite permission.
    """
    try:
        org_id = get_current_organization(request)
        if not org_id:
            raise HTTPException(status_code=400, detail="Organization context required")

        current_user_id = get_current_user_id(request)

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT id FROM users WHERE email = ?", (invite_data.email,))
        existing_user = cursor.fetchone()

        if existing_user:
            cursor.execute(
                """
                SELECT id FROM user_roles
                WHERE user_id = ? AND organization_id = ?
                """,
                (existing_user[0], org_id),
            )
            if cursor.fetchone():
                conn.close()
                raise HTTPException(status_code=400, detail="User already in organization")

        cursor.execute(
            "SELECT id FROM roles WHERE name = ?",
            (invite_data.role,),
        )
        role_row = cursor.fetchone()
        if not role_row:
            conn.close()
            raise HTTPException(status_code=404, detail="Role not found")
        role_id = role_row[0]

        invite_token = secrets.token_urlsafe(32)
        now = datetime.now().isoformat()
        expires_at = (datetime.now() + timedelta(days=7)).isoformat()

        cursor.execute(
            """
            INSERT INTO organization_invites
            (organization_id, email, role_id, invite_token, invited_by, status, expires_at, created_at)
            VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)
            """,
            (org_id, invite_data.email, role_id, invite_token, current_user_id, expires_at, now),
        )

        invite_id = cursor.lastrowid

        conn.commit()
        conn.close()

        logger.info(f"User invited: {invite_data.email} to org {org_id}")

        invite_link = f"https://cyberguardian.ai/accept-invite?token={invite_token}"

        return {
            "success": True,
            "message": "User invited successfully",
            "invite_id": invite_id,
            "email": invite_data.email,
            "role": invite_data.role,
            "invite_link": invite_link,
            "expires_at": expires_at,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error inviting user: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/invites/pending")
async def list_pending_invites(
    request: Request,
    current_user: Any = Depends(get_current_user),
):
    """
    List pending invitations for organization (auth required).
    """
    try:
        org_id = get_current_organization(request)
        if not org_id:
            raise HTTPException(status_code=400, detail="Organization context required")

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT 
                i.id,
                i.email,
                r.name as role,
                r.display_name as role_display,
                i.invited_by,
                i.status,
                i.expires_at,
                i.created_at
            FROM organization_invites i
            JOIN roles r ON i.role_id = r.id
            WHERE i.organization_id = ? AND i.status = 'pending'
            ORDER BY i.created_at DESC
            """,
            (org_id,),
        )

        rows = cursor.fetchall()
        conn.close()

        invites = [dict(row) for row in rows]

        return {
            "success": True,
            "count": len(invites),
            "invites": invites,
        }

    except Exception as e:
        logger.error(f"Error listing invites: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/invites/{invite_id}")
async def cancel_invite(
    invite_id: int,
    request: Request,
    current_user: Any = Depends(get_current_user),
    _: bool = Depends(RequireAdmin),
):
    """
    Cancel pending invitation (admin only).
    """
    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            UPDATE organization_invites
            SET status = 'cancelled'
            WHERE id = ? AND status = 'pending'
            """,
            (invite_id,),
        )

        if cursor.rowcount == 0:
            conn.close()
            raise HTTPException(
                status_code=404, detail="Invite not found or already processed"
            )

        conn.commit()
        conn.close()

        logger.info(f"Invite cancelled: {invite_id}")

        return {
            "success": True,
            "message": "Invitation cancelled successfully",
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error cancelling invite: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================
# USER PROFILE
# ============================================

@router.get("/me/profile")
async def get_my_profile(
    request: Request,
    current_user: Any = Depends(get_current_user),
):
    """
    Get current user's profile.
    """
    try:
        user_id = get_current_user_id(request)
        if not user_id:
            raise HTTPException(status_code=401, detail="Authentication required")

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT id, username, email, full_name, is_active, created_at
            FROM users
            WHERE id = ?
            """,
            (user_id,),
        )

        row = cursor.fetchone()
        if not row:
            conn.close()
            raise HTTPException(status_code=404, detail="User not found")

        user = dict(row)
        orgs = get_user_organizations(user_id)
        user["organizations"] = orgs

        conn.close()

        return {
            "success": True,
            "user": user,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting profile: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/me/change-password")
async def change_my_password(
    password_data: UserPasswordChange,
    request: Request,
    current_user: Any = Depends(get_current_user),
):
    """
    Change current user's password.
    """
    try:
        import hashlib

        user_id = get_current_user_id(request)
        if not user_id:
            raise HTTPException(status_code=401, detail="Authentication required")

        conn = get_connection()
        cursor = conn.cursor()

        current_hash = hashlib.sha256(password_data.current_password.encode()).hexdigest()

        cursor.execute("SELECT password FROM users WHERE id = ?", (user_id,))
        row = cursor.fetchone()

        if not row or row[0] != current_hash:
            conn.close()
            raise HTTPException(status_code=400, detail="Current password is incorrect")

        new_hash = hashlib.sha256(password_data.new_password.encode()).hexdigest()

        cursor.execute(
            """
            UPDATE users
            SET password = ?, updated_at = ?
            WHERE id = ?
            """,
            (new_hash, datetime.now().isoformat(), user_id),
        )

        conn.commit()
        conn.close()

        logger.info(f"Password changed for user: {user_id}")

        return {
            "success": True,
            "message": "Password changed successfully",
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error changing password: {e}")
        raise HTTPException(status_code=500, detail=str(e))
