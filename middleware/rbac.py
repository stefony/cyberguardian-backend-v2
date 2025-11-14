"""
CyberGuardian AI - RBAC (Role-Based Access Control) Middleware
PHASE 7: Enterprise Features

Provides role-based access control with decorators for endpoint protection.
Checks user permissions before allowing access to resources.
"""

from fastapi import Request, HTTPException, Depends
from functools import wraps
from typing import List, Optional, Callable
import logging

from middleware.tenant_context import (
    get_current_organization,
    get_current_user_id,
    get_current_role,
    get_current_permissions
)

logger = logging.getLogger(__name__)


# ============================================
# PERMISSION CHECKING
# ============================================

def has_permission(
    request: Request,
    resource: str,
    action: str
) -> bool:
    """
    Check if current user has specific permission
    
    Args:
        request: FastAPI request
        resource: Resource name (threats, scans, users, etc)
        action: Action name (read, write, delete, etc)
        
    Returns:
        True if user has permission
    """
    permissions = get_current_permissions(request)
    
    # Admin has all permissions
    if permissions.get('all'):
        return True
    
    # Check specific resource permission
    resource_perms = permissions.get(resource, [])
    return action in resource_perms


def has_role(request: Request, role: str) -> bool:
    """
    Check if current user has specific role
    
    Args:
        request: FastAPI request
        role: Role name (admin, manager, analyst, viewer)
        
    Returns:
        True if user has role
    """
    current_role = get_current_role(request)
    return current_role == role


def has_any_role(request: Request, roles: List[str]) -> bool:
    """
    Check if current user has any of the specified roles
    
    Args:
        request: FastAPI request
        roles: List of role names
        
    Returns:
        True if user has any of the roles
    """
    current_role = get_current_role(request)
    return current_role in roles


# ============================================
# DEPENDENCIES FOR FASTAPI
# ============================================

def require_permission(resource: str, action: str):
    """
    Dependency to require specific permission
    
    Usage:
        @app.get("/threats", dependencies=[Depends(require_permission("threats", "read"))])
    
    Args:
        resource: Resource name
        action: Action name
        
    Raises:
        HTTPException: 403 if permission denied
    """
    def permission_checker(request: Request):
        if not has_permission(request, resource, action):
            raise HTTPException(
                status_code=403,
                detail=f"Permission denied. Required: {resource}.{action}"
            )
        return True
    
    return permission_checker


def require_role(role: str):
    """
    Dependency to require specific role
    
    Usage:
        @app.get("/admin", dependencies=[Depends(require_role("admin"))])
    
    Args:
        role: Role name
        
    Raises:
        HTTPException: 403 if role not matched
    """
    def role_checker(request: Request):
        if not has_role(request, role):
            raise HTTPException(
                status_code=403,
                detail=f"Access denied. Required role: {role}"
            )
        return True
    
    return role_checker


def require_any_role(roles: List[str]):
    """
    Dependency to require any of specified roles
    
    Usage:
        @app.get("/reports", dependencies=[Depends(require_any_role(["admin", "manager"]))])
    
    Args:
        roles: List of role names
        
    Raises:
        HTTPException: 403 if no matching role
    """
    def role_checker(request: Request):
        if not has_any_role(request, roles):
            raise HTTPException(
                status_code=403,
                detail=f"Access denied. Required roles: {', '.join(roles)}"
            )
        return True
    
    return role_checker


# ============================================
# PERMISSION CLASSES
# ============================================

class Permission:
    """Permission constants"""
    
    # Threats
    THREATS_READ = ("threats", "read")
    THREATS_WRITE = ("threats", "write")
    THREATS_DELETE = ("threats", "delete")
    
    # Scans
    SCANS_READ = ("scans", "read")
    SCANS_WRITE = ("scans", "write")
    SCANS_DELETE = ("scans", "delete")
    SCANS_EXECUTE = ("scans", "execute")
    
    # Users
    USERS_READ = ("users", "read")
    USERS_WRITE = ("users", "write")
    USERS_DELETE = ("users", "delete")
    USERS_INVITE = ("users", "invite")
    
    # Settings
    SETTINGS_READ = ("settings", "read")
    SETTINGS_WRITE = ("settings", "write")
    
    # Reports
    REPORTS_READ = ("reports", "read")
    REPORTS_WRITE = ("reports", "write")
    REPORTS_EXPORT = ("reports", "export")
    
    # Organizations
    ORGANIZATIONS_READ = ("organizations", "read")
    ORGANIZATIONS_WRITE = ("organizations", "write")
    
    # Roles
    ROLES_READ = ("roles", "read")
    ROLES_WRITE = ("roles", "write")


class Role:
    """Role constants"""
    
    ADMIN = "admin"
    MANAGER = "manager"
    ANALYST = "analyst"
    VIEWER = "viewer"


# ============================================
# CONVENIENT DEPENDENCIES
# ============================================

# Threats permissions
RequireThreatsRead = Depends(require_permission("threats", "read"))
RequireThreatsWrite = Depends(require_permission("threats", "write"))
RequireThreatsDelete = Depends(require_permission("threats", "delete"))

# Scans permissions
RequireScansRead = Depends(require_permission("scans", "read"))
RequireScansWrite = Depends(require_permission("scans", "write"))
RequireScansDelete = Depends(require_permission("scans", "delete"))
RequireScansExecute = Depends(require_permission("scans", "execute"))

# Users permissions
RequireUsersRead = Depends(require_permission("users", "read"))
RequireUsersWrite = Depends(require_permission("users", "write"))
RequireUsersDelete = Depends(require_permission("users", "delete"))
RequireUsersInvite = Depends(require_permission("users", "invite"))

# Settings permissions
RequireSettingsRead = Depends(require_permission("settings", "read"))
RequireSettingsWrite = Depends(require_permission("settings", "write"))

# Reports permissions
RequireReportsRead = Depends(require_permission("reports", "read"))
RequireReportsWrite = Depends(require_permission("reports", "write"))
RequireReportsExport = Depends(require_permission("reports", "export"))

# Organizations permissions
RequireOrganizationsRead = Depends(require_permission("organizations", "read"))
RequireOrganizationsWrite = Depends(require_permission("organizations", "write"))

# Roles permissions
RequireRolesRead = Depends(require_permission("roles", "read"))
RequireRolesWrite = Depends(require_permission("roles", "write"))

# Role-based
RequireAdmin = Depends(require_role("admin"))
RequireManager = Depends(require_any_role(["admin", "manager"]))
RequireAnalyst = Depends(require_any_role(["admin", "manager", "analyst"]))


# ============================================
# HELPER FUNCTIONS
# ============================================

def check_resource_access(
    request: Request,
    resource_type: str,
    resource_id: str,
    action: str
) -> bool:
    """
    Check if user can access specific resource
    
    Args:
        request: FastAPI request
        resource_type: Type of resource (threat, scan, etc)
        resource_id: Resource ID
        action: Action (read, write, delete)
        
    Returns:
        True if access allowed
    """
    # First check permission
    if not has_permission(request, resource_type, action):
        return False
    
    # TODO: Add resource-level access control
    # Check if resource belongs to user's organization
    
    return True


def can_modify_resource(
    request: Request,
    resource_type: str,
    created_by: str
) -> bool:
    """
    Check if user can modify a resource
    Users can modify their own resources or if they have write permission
    
    Args:
        request: FastAPI request
        resource_type: Type of resource
        created_by: User ID who created the resource
        
    Returns:
        True if can modify
    """
    current_user = get_current_user_id(request)
    
    # Admin and Manager can modify any resource
    if has_any_role(request, [Role.ADMIN, Role.MANAGER]):
        return True
    
    # Check if user owns the resource
    if current_user == created_by:
        return has_permission(request, resource_type, "write")
    
    return False


def can_delete_resource(
    request: Request,
    resource_type: str,
    created_by: str
) -> bool:
    """
    Check if user can delete a resource
    Only admins and resource owners can delete
    
    Args:
        request: FastAPI request
        resource_type: Type of resource
        created_by: User ID who created the resource
        
    Returns:
        True if can delete
    """
    current_user = get_current_user_id(request)
    
    # Admin can delete anything
    if has_role(request, Role.ADMIN):
        return True
    
    # Check if user owns the resource and has delete permission
    if current_user == created_by:
        return has_permission(request, resource_type, "delete")
    
    return False


# ============================================
# PERMISSION VALIDATORS
# ============================================

class PermissionValidator:
    """
    Helper class for validating permissions
    """
    
    @staticmethod
    def validate_threats_access(request: Request, action: str = "read"):
        """Validate threats access"""
        if not has_permission(request, "threats", action):
            raise HTTPException(
                status_code=403,
                detail=f"Permission denied: threats.{action}"
            )
    
    @staticmethod
    def validate_scans_access(request: Request, action: str = "read"):
        """Validate scans access"""
        if not has_permission(request, "scans", action):
            raise HTTPException(
                status_code=403,
                detail=f"Permission denied: scans.{action}"
            )
    
    @staticmethod
    def validate_users_access(request: Request, action: str = "read"):
        """Validate users access"""
        if not has_permission(request, "users", action):
            raise HTTPException(
                status_code=403,
                detail=f"Permission denied: users.{action}"
            )
    
    @staticmethod
    def validate_settings_access(request: Request, action: str = "read"):
        """Validate settings access"""
        if not has_permission(request, "settings", action):
            raise HTTPException(
                status_code=403,
                detail=f"Permission denied: settings.{action}"
            )
    
    @staticmethod
    def validate_admin_access(request: Request):
        """Validate admin access"""
        if not has_role(request, Role.ADMIN):
            raise HTTPException(
                status_code=403,
                detail="Admin access required"
            )
    
    @staticmethod
    def validate_manager_access(request: Request):
        """Validate manager access"""
        if not has_any_role(request, [Role.ADMIN, Role.MANAGER]):
            raise HTTPException(
                status_code=403,
                detail="Manager access required"
            )


# ============================================
# AUDIT LOGGING
# ============================================

def log_access_attempt(
    request: Request,
    resource: str,
    action: str,
    success: bool,
    details: Optional[str] = None
):
    """
    Log access attempt for audit trail
    
    Args:
        request: FastAPI request
        resource: Resource being accessed
        action: Action attempted
        success: Whether access was granted
        details: Additional details
    """
    user_id = get_current_user_id(request)
    org_id = get_current_organization(request)
    role = get_current_role(request)
    
    status = "GRANTED" if success else "DENIED"
    
    log_message = (
        f"Access {status} - "
        f"User: {user_id} | "
        f"Org: {org_id} | "
        f"Role: {role} | "
        f"Resource: {resource} | "
        f"Action: {action}"
    )
    
    if details:
        log_message += f" | Details: {details}"
    
    if success:
        logger.info(log_message)
    else:
        logger.warning(log_message)


# ============================================
# ROLE HIERARCHY
# ============================================

ROLE_HIERARCHY = {
    Role.ADMIN: 4,      # Highest
    Role.MANAGER: 3,
    Role.ANALYST: 2,
    Role.VIEWER: 1      # Lowest
}


def has_higher_or_equal_role(
    request: Request,
    target_role: str
) -> bool:
    """
    Check if user has higher or equal role than target
    
    Args:
        request: FastAPI request
        target_role: Target role to compare
        
    Returns:
        True if user has higher or equal role
    """
    current_role = get_current_role(request)
    
    if not current_role:
        return False
    
    current_level = ROLE_HIERARCHY.get(current_role, 0)
    target_level = ROLE_HIERARCHY.get(target_role, 0)
    
    return current_level >= target_level


def can_assign_role(
    request: Request,
    role_to_assign: str
) -> bool:
    """
    Check if user can assign a specific role
    Only users with higher role can assign lower roles
    
    Args:
        request: FastAPI request
        role_to_assign: Role to be assigned
        
    Returns:
        True if user can assign the role
    """
    current_role = get_current_role(request)
    
    if not current_role:
        return False
    
    # Admin can assign any role
    if current_role == Role.ADMIN:
        return True
    
    # Others can only assign roles lower than their own
    current_level = ROLE_HIERARCHY.get(current_role, 0)
    target_level = ROLE_HIERARCHY.get(role_to_assign, 0)
    
    return current_level > target_level