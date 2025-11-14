"""
CyberGuardian AI - Roles API
PHASE 7: Enterprise Features

API endpoints for managing roles and permissions (RBAC system).
Handles role CRUD, permission management, and role assignments.
"""

from fastapi import APIRouter, HTTPException, Depends, Request
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime
import json
import logging

from database.schema_enterprise import (
    get_connection,
    get_all_roles,
    get_role_by_name,
    assign_user_role,
    get_user_role
)
from middleware.rbac import (
    RequireAdmin,
    RequireRolesRead,
    RequireRolesWrite,
    can_assign_role
)
from middleware.tenant_context import (
    get_current_user_id,
    get_current_organization
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/roles", tags=["Roles"])


# ============================================
# PYDANTIC MODELS
# ============================================

class RoleCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=50, pattern="^[a-z_]+$")
    display_name: str = Field(..., min_length=2, max_length=100)
    description: Optional[str] = None
    permissions: Dict[str, Any] = Field(...)


class RoleUpdate(BaseModel):
    display_name: Optional[str] = Field(None, min_length=2, max_length=100)
    description: Optional[str] = None
    permissions: Optional[Dict[str, Any]] = None


class PermissionCheck(BaseModel):
    resource: str = Field(..., min_length=1)
    action: str = Field(..., min_length=1)


class RoleAssignment(BaseModel):
    user_id: str = Field(..., min_length=1)
    role_name: str = Field(..., pattern="^(admin|manager|analyst|viewer|[a-z_]+)$")


# ============================================
# ROLES CRUD
# ============================================

@router.get("/")
async def list_roles(
    request: Request,
    _: bool = Depends(RequireRolesRead)
):
    """
    List all available roles
    Requires: roles.read permission
    """
    try:
        roles = get_all_roles()
        
        return {
            "success": True,
            "count": len(roles),
            "roles": roles
        }
        
    except Exception as e:
        logger.error(f"Error listing roles: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{role_name}")
async def get_role_details(
    role_name: str,
    request: Request,
    _: bool = Depends(RequireRolesRead)
):
    """
    Get role details by name
    Requires: roles.read permission
    """
    try:
        role = get_role_by_name(role_name)
        
        if not role:
            raise HTTPException(status_code=404, detail="Role not found")
        
        return {
            "success": True,
            "role": role
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting role: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/", status_code=201)
async def create_role(
    role_data: RoleCreate,
    request: Request,
    _: bool = Depends(RequireRolesWrite)
):
    """
    Create custom role
    Requires: roles.write permission
    Note: Only non-system roles can be created
    """
    try:
        conn = get_connection()
        cursor = conn.cursor()
        
        # Check if role already exists
        cursor.execute("SELECT id FROM roles WHERE name = ?", (role_data.name,))
        if cursor.fetchone():
            conn.close()
            raise HTTPException(status_code=400, detail="Role already exists")
        
        now = datetime.now().isoformat()
        
        # Create role
        cursor.execute("""
            INSERT INTO roles (name, display_name, description, permissions, is_system, created_at, updated_at)
            VALUES (?, ?, ?, ?, 0, ?, ?)
        """, (
            role_data.name,
            role_data.display_name,
            role_data.description,
            json.dumps(role_data.permissions),
            now,
            now
        ))
        
        conn.commit()
        conn.close()
        
        # Get created role
        role = get_role_by_name(role_data.name)
        
        logger.info(f"Role created: {role_data.name}")
        
        return {
            "success": True,
            "message": "Role created successfully",
            "role": role
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating role: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/{role_name}")
async def update_role(
    role_name: str,
    role_data: RoleUpdate,
    request: Request,
    _: bool = Depends(RequireRolesWrite)
):
    """
    Update role details
    Requires: roles.write permission
    Note: System roles cannot be modified
    """
    try:
        conn = get_connection()
        cursor = conn.cursor()
        
        # Check if role exists and is not a system role
        cursor.execute("SELECT id, is_system FROM roles WHERE name = ?", (role_name,))
        row = cursor.fetchone()
        
        if not row:
            conn.close()
            raise HTTPException(status_code=404, detail="Role not found")
        
        if row[1] == 1:  # is_system
            conn.close()
            raise HTTPException(status_code=400, detail="Cannot modify system roles")
        
        # Build update query
        updates = []
        params = []
        
        if role_data.display_name is not None:
            updates.append("display_name = ?")
            params.append(role_data.display_name)
        
        if role_data.description is not None:
            updates.append("description = ?")
            params.append(role_data.description)
        
        if role_data.permissions is not None:
            updates.append("permissions = ?")
            params.append(json.dumps(role_data.permissions))
        
        if not updates:
            conn.close()
            raise HTTPException(status_code=400, detail="No updates provided")
        
        # Add updated_at
        updates.append("updated_at = ?")
        params.append(datetime.now().isoformat())
        
        # Add role_name for WHERE clause
        params.append(role_name)
        
        query = f"UPDATE roles SET {', '.join(updates)} WHERE name = ?"
        cursor.execute(query, params)
        conn.commit()
        conn.close()
        
        # Get updated role
        role = get_role_by_name(role_name)
        
        logger.info(f"Role updated: {role_name}")
        
        return {
            "success": True,
            "message": "Role updated successfully",
            "role": role
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating role: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/{role_name}")
async def delete_role(
    role_name: str,
    request: Request,
    _: bool = Depends(RequireRolesWrite)
):
    """
    Delete custom role
    Requires: roles.write permission
    Note: System roles cannot be deleted
    """
    try:
        conn = get_connection()
        cursor = conn.cursor()
        
        # Check if role exists and is not a system role
        cursor.execute("SELECT id, is_system FROM roles WHERE name = ?", (role_name,))
        row = cursor.fetchone()
        
        if not row:
            conn.close()
            raise HTTPException(status_code=404, detail="Role not found")
        
        if row[1] == 1:  # is_system
            conn.close()
            raise HTTPException(status_code=400, detail="Cannot delete system roles")
        
        role_id = row[0]
        
        # Check if role is assigned to any users
        cursor.execute("SELECT COUNT(*) FROM user_roles WHERE role_id = ?", (role_id,))
        user_count = cursor.fetchone()[0]
        
        if user_count > 0:
            conn.close()
            raise HTTPException(
                status_code=400,
                detail=f"Cannot delete role. {user_count} users are assigned to this role."
            )
        
        # Delete role
        cursor.execute("DELETE FROM roles WHERE id = ?", (role_id,))
        conn.commit()
        conn.close()
        
        logger.info(f"Role deleted: {role_name}")
        
        return {
            "success": True,
            "message": "Role deleted successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting role: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================
# PERMISSIONS
# ============================================

@router.get("/permissions/list")
async def list_all_permissions(
    request: Request,
    _: bool = Depends(RequireRolesRead)
):
    """
    List all available permissions
    Requires: roles.read permission
    """
    try:
        conn = get_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM permissions ORDER BY resource, action")
        rows = cursor.fetchall()
        conn.close()
        
        permissions = [dict(row) for row in rows]
        
        # Group by resource
        grouped = {}
        for perm in permissions:
            resource = perm['resource']
            if resource not in grouped:
                grouped[resource] = []
            grouped[resource].append({
                'action': perm['action'],
                'description': perm['description']
            })
        
        return {
            "success": True,
            "count": len(permissions),
            "permissions": permissions,
            "grouped": grouped
        }
        
    except Exception as e:
        logger.error(f"Error listing permissions: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/permissions/check")
async def check_permission(
    perm_check: PermissionCheck,
    request: Request
):
    """
    Check if current user has specific permission
    """
    try:
        from middleware.rbac import has_permission
        
        has_perm = has_permission(request, perm_check.resource, perm_check.action)
        
        return {
            "success": True,
            "has_permission": has_perm,
            "resource": perm_check.resource,
            "action": perm_check.action
        }
        
    except Exception as e:
        logger.error(f"Error checking permission: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{role_name}/permissions")
async def get_role_permissions(
    role_name: str,
    request: Request,
    _: bool = Depends(RequireRolesRead)
):
    """
    Get all permissions for a specific role
    Requires: roles.read permission
    """
    try:
        role = get_role_by_name(role_name)
        
        if not role:
            raise HTTPException(status_code=404, detail="Role not found")
        
        permissions = role.get('permissions', {})
        
        return {
            "success": True,
            "role": role_name,
            "permissions": permissions
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting role permissions: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================
# ROLE ASSIGNMENTS
# ============================================

@router.post("/assign")
async def assign_role_to_user(
    assignment: RoleAssignment,
    request: Request,
    _: bool = Depends(RequireAdmin)
):
    """
    Assign role to user in current organization
    Requires: admin role
    """
    try:
        org_id = get_current_organization(request)
        
        if not org_id:
            raise HTTPException(status_code=400, detail="Organization context required")
        
        current_user = get_current_user_id(request)
        
        # Check if current user can assign this role
        if not can_assign_role(request, assignment.role_name):
            raise HTTPException(
                status_code=403,
                detail="You cannot assign a role higher than or equal to your own"
            )
        
        # Assign role
        success = assign_user_role(
            user_id=assignment.user_id,
            organization_id=org_id,
            role_name=assignment.role_name,
            assigned_by=current_user
        )
        
        if not success:
            raise HTTPException(status_code=500, detail="Failed to assign role")
        
        logger.info(f"Role assigned: {assignment.role_name} to user {assignment.user_id} in org {org_id}")
        
        return {
            "success": True,
            "message": "Role assigned successfully",
            "user_id": assignment.user_id,
            "role": assignment.role_name,
            "organization_id": org_id
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error assigning role: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/user/{user_id}/role")
async def get_user_role_in_org(
    user_id: str,
    request: Request,
    _: bool = Depends(RequireRolesRead)
):
    """
    Get user's role in current organization
    Requires: roles.read permission
    """
    try:
        org_id = get_current_organization(request)
        
        if not org_id:
            raise HTTPException(status_code=400, detail="Organization context required")
        
        role = get_user_role(user_id, org_id)
        
        if not role:
            raise HTTPException(status_code=404, detail="User role not found in this organization")
        
        return {
            "success": True,
            "user_id": user_id,
            "organization_id": org_id,
            "role": role
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting user role: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================
# ROLE COMPARISON
# ============================================

@router.get("/compare/{role1}/{role2}")
async def compare_roles(
    role1: str,
    role2: str,
    request: Request,
    _: bool = Depends(RequireRolesRead)
):
    """
    Compare permissions between two roles
    Requires: roles.read permission
    """
    try:
        role1_data = get_role_by_name(role1)
        role2_data = get_role_by_name(role2)
        
        if not role1_data:
            raise HTTPException(status_code=404, detail=f"Role not found: {role1}")
        
        if not role2_data:
            raise HTTPException(status_code=404, detail=f"Role not found: {role2}")
        
        perms1 = role1_data.get('permissions', {})
        perms2 = role2_data.get('permissions', {})
        
        # Find differences
        all_resources = set(list(perms1.keys()) + list(perms2.keys()))
        
        differences = {}
        for resource in all_resources:
            actions1 = set(perms1.get(resource, []))
            actions2 = set(perms2.get(resource, []))
            
            if actions1 != actions2:
                differences[resource] = {
                    role1: list(actions1),
                    role2: list(actions2),
                    'only_in_' + role1: list(actions1 - actions2),
                    'only_in_' + role2: list(actions2 - actions1)
                }
        
        return {
            "success": True,
            "role1": {
                "name": role1,
                "display_name": role1_data.get('display_name'),
                "permissions": perms1
            },
            "role2": {
                "name": role2,
                "display_name": role2_data.get('display_name'),
                "permissions": perms2
            },
            "differences": differences
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error comparing roles: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================
# ROLE TEMPLATES
# ============================================

@router.get("/templates/list")
async def list_role_templates(
    request: Request,
    _: bool = Depends(RequireRolesRead)
):
    """
    Get predefined role templates for quick role creation
    Requires: roles.read permission
    """
    templates = [
        {
            "name": "security_admin",
            "display_name": "Security Administrator",
            "description": "Full security management access",
            "permissions": {
                "threats": ["read", "write", "delete"],
                "scans": ["read", "write", "delete", "execute"],
                "reports": ["read", "write", "export"],
                "settings": ["read", "write"]
            }
        },
        {
            "name": "read_only_analyst",
            "display_name": "Read-Only Analyst",
            "description": "View-only access to all security data",
            "permissions": {
                "threats": ["read"],
                "scans": ["read"],
                "reports": ["read"]
            }
        },
        {
            "name": "scan_operator",
            "display_name": "Scan Operator",
            "description": "Can execute and manage scans",
            "permissions": {
                "scans": ["read", "write", "execute"],
                "reports": ["read"]
            }
        },
        {
            "name": "report_viewer",
            "display_name": "Report Viewer",
            "description": "Can view and export reports",
            "permissions": {
                "reports": ["read", "export"]
            }
        }
    ]
    
    return {
        "success": True,
        "count": len(templates),
        "templates": templates
    }


# ============================================
# ROLE STATISTICS
# ============================================

@router.get("/stats/usage")
async def get_role_usage_stats(
    request: Request,
    _: bool = Depends(RequireRolesRead)
):
    """
    Get statistics about role usage across organizations
    Requires: roles.read permission
    """
    try:
        conn = get_connection()
        cursor = conn.cursor()
        
        # Get user count per role
        cursor.execute("""
            SELECT 
                r.name,
                r.display_name,
                COUNT(ur.user_id) as user_count
            FROM roles r
            LEFT JOIN user_roles ur ON r.id = ur.role_id
            GROUP BY r.id, r.name, r.display_name
            ORDER BY user_count DESC
        """)
        
        rows = cursor.fetchall()
        conn.close()
        
        stats = [dict(row) for row in rows]
        
        return {
            "success": True,
            "stats": stats,
            "total_roles": len(stats)
        }
        
    except Exception as e:
        logger.error(f"Error getting role stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))