"""
CyberGuardian AI - Tenant Context Middleware
PHASE 7: Enterprise Features

Manages tenant/organization context for multi-tenant isolation.
Ensures data is properly scoped to the current organization.
"""

from fastapi import Request, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Optional
import logging

logger = logging.getLogger(__name__)

# Security scheme for JWT tokens
security = HTTPBearer()


class TenantContext:
    """
    Tenant context holder
    Stores current organization and user info for the request
    """
    
    def __init__(self):
        self.organization_id: Optional[str] = None
        self.user_id: Optional[str] = None
        self.role: Optional[str] = None
        self.permissions: dict = {}
    
    def set_context(
        self, 
        organization_id: str, 
        user_id: str, 
        role: str,
        permissions: dict
    ):
        """Set tenant context"""
        self.organization_id = organization_id
        self.user_id = user_id
        self.role = role
        self.permissions = permissions
    
    def clear_context(self):
        """Clear tenant context"""
        self.organization_id = None
        self.user_id = None
        self.role = None
        self.permissions = {}
    
    def is_set(self) -> bool:
        """Check if context is set"""
        return self.organization_id is not None and self.user_id is not None
    
    def has_permission(self, resource: str, action: str) -> bool:
        """Check if current user has permission"""
        # Admin has all permissions
        if self.permissions.get('all'):
            return True
        
        # Check specific resource permission
        resource_perms = self.permissions.get(resource, [])
        return action in resource_perms


# Global tenant context (request-scoped)
_tenant_context = TenantContext()


def get_tenant_context() -> TenantContext:
    """Get current tenant context"""
    return _tenant_context


async def extract_tenant_from_request(request: Request) -> Optional[str]:
    """
    Extract organization ID from request
    Can come from:
    1. Header: X-Organization-ID
    2. Query param: org_id
    3. User's default organization (first org from DB)
    """
    # 1) Header
    org_id = request.headers.get("X-Organization-ID")
    if org_id:
        return org_id
    
    # 2) Query param
    org_id = request.query_params.get("org_id")
    if org_id:
        return org_id
    
    # 3) Fallback: първата организация на потребителя
    user_id = getattr(request.state, "user_id", None)
    if user_id:
        try:
            from database.schema_enterprise import get_user_organizations
            orgs = get_user_organizations(user_id)
            if orgs:
                return orgs[0]["id"]
        except Exception as e:
            logger.error(f"Error getting default organization for user {user_id}: {e}")
    
    # Няма организация
    return None


async def tenant_context_middleware(request: Request, call_next):
    """
    Middleware to set tenant context for each request
    """
    context = get_tenant_context()
    
    try:
        # Extract organization ID from request
        org_id = await extract_tenant_from_request(request)
        
        # Try to get user info from request state (set by auth middleware)
        user_id = getattr(request.state, "user_id", None)
        
        if user_id and org_id:
            from database.schema_enterprise import get_user_role
            
            role_info = get_user_role(user_id, org_id)
            
            if role_info:
                context.set_context(
                    organization_id=org_id,
                    user_id=user_id,
                    role=role_info.get('name'),
                    permissions=role_info.get('permissions', {})
                )
                
                # Store in request state for easy access
                request.state.organization_id = org_id
                request.state.role = role_info.get('name')
                request.state.permissions = role_info.get('permissions', {})
        
        # Process request
        response = await call_next(request)
        return response
        
    finally:
        # Clear context after request
        context.clear_context()


def require_organization(request: Request) -> str:
    """
    Dependency to require organization context
    Raises 400 if no organization in context
    """
    org_id = getattr(request.state, "organization_id", None)
    
    if not org_id:
        raise HTTPException(
            status_code=400,
            detail="Organization context required. Please specify organization ID."
        )
    
    return org_id


def get_current_organization(request: Request) -> Optional[str]:
    """
    Get current organization ID from request
    Returns None if not set
    """
    return getattr(request.state, "organization_id", None)


def get_current_user_id(request: Request) -> Optional[str]:
    """
    Get current user ID from request
    Returns None if not set
    """
    return getattr(request.state, "user_id", None)


def get_current_role(request: Request) -> Optional[str]:
    """
    Get current user's role in organization
    Returns None if not set
    """
    return getattr(request.state, "role", None)


def get_current_permissions(request: Request) -> dict:
    """
    Get current user's permissions
    Returns empty dict if not set
    """
    return getattr(request.state, "permissions", {})


# ============================================
# SCOPED QUERY HELPERS
# ============================================

def add_org_filter(query: str, table_alias: Optional[str] = None) -> str:
    """
    Add organization filter to SQL query
    """
    context = get_tenant_context()
    
    if not context.is_set():
        return query
    
    prefix = f"{table_alias}." if table_alias else ""
    
    # Check if WHERE clause exists
    if "WHERE" in query.upper():
        return f"{query} AND {prefix}organization_id = '{context.organization_id}'"
    else:
        return f"{query} WHERE {prefix}organization_id = '{context.organization_id}'"


def get_org_params(base_params: tuple = ()) -> tuple:
    """
    Add organization ID to query parameters
    """
    context = get_tenant_context()
    
    if context.is_set():
        return base_params + (context.organization_id,)
    
    return base_params


# ============================================
# TENANT UTILITIES
# ============================================

class TenantIsolation:
    """
    Utility class for tenant data isolation
    """
    
    @staticmethod
    def filter_by_org(data: list, org_field: str = "organization_id") -> list:
        """
        Filter list of items by current organization
        """
        context = get_tenant_context()
        
        if not context.is_set():
            return data
        
        return [
            item for item in data
            if item.get(org_field) == context.organization_id
        ]
    
    @staticmethod
    def validate_org_access(org_id: str) -> bool:
        """
        Validate that current user has access to organization
        """
        context = get_tenant_context()
        
        if not context.is_set():
            return False
        
        return context.organization_id == org_id
    
    @staticmethod
    def get_user_organizations(user_id: str) -> list:
        """
        Get all organizations for a user
        """
        from database.schema_enterprise import get_user_organizations
        
        orgs = get_user_organizations(user_id)
        return [org['id'] for org in orgs]


# ============================================
# CROSS-TENANT ACCESS CONTROL
# ============================================

def allow_cross_tenant_access(
    requested_org_id: str,
    request: Request
) -> bool:
    """
    Check if user can access data from another organization
    """
    current_org_id = get_current_organization(request)
    
    # Same organization - always allowed
    if current_org_id == requested_org_id:
        return True
    
    # Check if user has access to requested organization
    user_id = get_current_user_id(request)
    if user_id:
        user_orgs = TenantIsolation.get_user_organizations(user_id)
        return requested_org_id in user_orgs
    
    return False


def switch_organization_context(
    request: Request,
    new_org_id: str
) -> bool:
    """
    Switch to a different organization context
    Validates user has access first
    """
    if not allow_cross_tenant_access(new_org_id, request):
        return False
    
    context = get_tenant_context()
    user_id = get_current_user_id(request)
    
    if user_id:
        from database.schema_enterprise import get_user_role
        
        role_info = get_user_role(user_id, new_org_id)
        
        if role_info:
            context.set_context(
                organization_id=new_org_id,
                user_id=user_id,
                role=role_info.get('name'),
                permissions=role_info.get('permissions', {})
            )
            
            request.state.organization_id = new_org_id
            request.state.role = role_info.get('name')
            request.state.permissions = role_info.get('permissions', {})
            
            return True
    
    return False


# ============================================
# LOGGING HELPERS
# ============================================

def log_with_tenant_context(message: str, level: str = "info"):
    """
    Log message with tenant context information
    """
    context = get_tenant_context()
    
    if context.is_set():
        prefix = f"[Org: {context.organization_id}] [User: {context.user_id}] [Role: {context.role}]"
        full_message = f"{prefix} {message}"
    else:
        full_message = f"[No Context] {message}"
    
    if level == "info":
        logger.info(full_message)
    elif level == "warning":
        logger.warning(full_message)
    elif level == "error":
        logger.error(full_message)
