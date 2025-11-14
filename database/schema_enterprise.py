"""
CyberGuardian AI - Enterprise Database Schema
PHASE 7: Enterprise Features

Database tables for:
- Multi-tenant support (Organizations)
- Role-Based Access Control (RBAC)
- Permissions management
- User-Organization-Role mapping
"""

import sqlite3
from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path
import json
import logging

logger = logging.getLogger(__name__)

# Database file path
DB_PATH = Path(__file__).parent / "cyberguardian.db"


def get_connection():
    """Get database connection"""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_enterprise_tables():
    """
    Initialize enterprise tables for multi-tenant and RBAC
    """
    conn = get_connection()
    cursor = conn.cursor()
    
    try:
        # ============================================
        # ORGANIZATIONS TABLE (Multi-tenant)
        # ============================================
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS organizations (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                slug TEXT NOT NULL UNIQUE,
                description TEXT,
                plan TEXT NOT NULL DEFAULT 'free',
                max_users INTEGER NOT NULL DEFAULT 5,
                max_devices INTEGER NOT NULL DEFAULT 10,
                max_scans_per_day INTEGER NOT NULL DEFAULT 100,
                settings TEXT,
                logo_url TEXT,
                website TEXT,
                contact_email TEXT,
                contact_phone TEXT,
                address TEXT,
                is_active INTEGER NOT NULL DEFAULT 1,
                trial_ends_at TEXT,
                subscription_ends_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        
        # ============================================
        # ROLES TABLE (RBAC)
        # ============================================
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS roles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                display_name TEXT NOT NULL,
                description TEXT,
                permissions TEXT NOT NULL,
                is_system INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        
        # ============================================
        # USER_ROLES TABLE (User-Organization-Role mapping)
        # ============================================
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_roles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                organization_id TEXT NOT NULL,
                role_id INTEGER NOT NULL,
                assigned_by TEXT,
                assigned_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (organization_id) REFERENCES organizations(id),
                FOREIGN KEY (role_id) REFERENCES roles(id),
                UNIQUE(user_id, organization_id)
            )
        """)
        
        # ============================================
        # PERMISSIONS TABLE (Granular permissions)
        # ============================================
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS permissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                resource TEXT NOT NULL,
                action TEXT NOT NULL,
                description TEXT,
                created_at TEXT NOT NULL,
                UNIQUE(resource, action)
            )
        """)
        
        # ============================================
        # ORGANIZATION_INVITES TABLE
        # ============================================
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS organization_invites (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                organization_id TEXT NOT NULL,
                email TEXT NOT NULL,
                role_id INTEGER NOT NULL,
                invite_token TEXT NOT NULL UNIQUE,
                invited_by TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                expires_at TEXT NOT NULL,
                accepted_at TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (organization_id) REFERENCES organizations(id),
                FOREIGN KEY (role_id) REFERENCES roles(id)
            )
        """)
        
        # ============================================
        # INDEXES
        # ============================================
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_organizations_slug 
            ON organizations(slug)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_organizations_plan 
            ON organizations(plan)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_user_roles_user 
            ON user_roles(user_id)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_user_roles_org 
            ON user_roles(organization_id)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_permissions_resource 
            ON permissions(resource)
        """)
        
        # ============================================
        # INSERT DEFAULT ROLES
        # ============================================
        now = datetime.now().isoformat()
        
        # Check if roles exist
        cursor.execute("SELECT COUNT(*) FROM roles")
        if cursor.fetchone()[0] == 0:
            
            # Admin role
            cursor.execute("""
                INSERT INTO roles (name, display_name, description, permissions, is_system, created_at, updated_at)
                VALUES (?, ?, ?, ?, 1, ?, ?)
            """, (
                'admin',
                'Administrator',
                'Full system access with all permissions',
                json.dumps({
                    'threats': ['read', 'write', 'delete'],
                    'scans': ['read', 'write', 'delete', 'execute'],
                    'users': ['read', 'write', 'delete', 'invite'],
                    'settings': ['read', 'write'],
                    'reports': ['read', 'write', 'export'],
                    'organizations': ['read', 'write'],
                    'roles': ['read', 'write'],
                    'all': True
                }),
                now,
                now
            ))
            
            # Manager role
            cursor.execute("""
                INSERT INTO roles (name, display_name, description, permissions, is_system, created_at, updated_at)
                VALUES (?, ?, ?, ?, 1, ?, ?)
            """, (
                'manager',
                'Manager',
                'Can manage threats, scans, and view users',
                json.dumps({
                    'threats': ['read', 'write', 'delete'],
                    'scans': ['read', 'write', 'execute'],
                    'users': ['read'],
                    'settings': ['read'],
                    'reports': ['read', 'write', 'export']
                }),
                now,
                now
            ))
            
            # Analyst role
            cursor.execute("""
                INSERT INTO roles (name, display_name, description, permissions, is_system, created_at, updated_at)
                VALUES (?, ?, ?, ?, 1, ?, ?)
            """, (
                'analyst',
                'Security Analyst',
                'Can analyze threats and run scans',
                json.dumps({
                    'threats': ['read', 'write'],
                    'scans': ['read', 'write', 'execute'],
                    'reports': ['read', 'export']
                }),
                now,
                now
            ))
            
            # Viewer role
            cursor.execute("""
                INSERT INTO roles (name, display_name, description, permissions, is_system, created_at, updated_at)
                VALUES (?, ?, ?, ?, 1, ?, ?)
            """, (
                'viewer',
                'Viewer',
                'Read-only access to threats and reports',
                json.dumps({
                    'threats': ['read'],
                    'scans': ['read'],
                    'reports': ['read']
                }),
                now,
                now
            ))
            
            logger.info("✅ Default roles created")
        
        # ============================================
        # INSERT DEFAULT PERMISSIONS
        # ============================================
        cursor.execute("SELECT COUNT(*) FROM permissions")
        if cursor.fetchone()[0] == 0:
            
            permissions_data = [
                ('threats', 'read', 'View threats'),
                ('threats', 'write', 'Create and update threats'),
                ('threats', 'delete', 'Delete threats'),
                
                ('scans', 'read', 'View scans'),
                ('scans', 'write', 'Create and update scans'),
                ('scans', 'delete', 'Delete scans'),
                ('scans', 'execute', 'Execute scans'),
                
                ('users', 'read', 'View users'),
                ('users', 'write', 'Create and update users'),
                ('users', 'delete', 'Delete users'),
                ('users', 'invite', 'Invite users'),
                
                ('settings', 'read', 'View settings'),
                ('settings', 'write', 'Modify settings'),
                
                ('reports', 'read', 'View reports'),
                ('reports', 'write', 'Create reports'),
                ('reports', 'export', 'Export reports'),
                
                ('organizations', 'read', 'View organization'),
                ('organizations', 'write', 'Modify organization'),
                
                ('roles', 'read', 'View roles'),
                ('roles', 'write', 'Manage roles')
            ]
            
            for resource, action, description in permissions_data:
                cursor.execute("""
                    INSERT INTO permissions (resource, action, description, created_at)
                    VALUES (?, ?, ?, ?)
                """, (resource, action, description, now))
            
            logger.info("✅ Default permissions created")
        
        conn.commit()
        logger.info("✅ Enterprise tables initialized successfully")
        
    except Exception as e:
        conn.rollback()
        logger.error(f"❌ Error initializing enterprise tables: {e}")
        raise
    
    finally:
        conn.close()


# ============================================
# ORGANIZATIONS FUNCTIONS
# ============================================

def create_organization(
    org_id: str,
    name: str,
    slug: str,
    plan: str = 'free',
    description: Optional[str] = None,
    max_users: int = 5,
    max_devices: int = 10,
    max_scans_per_day: int = 100
) -> bool:
    """Create new organization"""
    conn = get_connection()
    cursor = conn.cursor()
    
    try:
        now = datetime.now().isoformat()
        
        cursor.execute("""
            INSERT INTO organizations 
            (id, name, slug, description, plan, max_users, max_devices, 
             max_scans_per_day, settings, is_active, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
        """, (org_id, name, slug, description, plan, max_users, max_devices,
              max_scans_per_day, json.dumps({}), now, now))
        
        conn.commit()
        return True
        
    except Exception as e:
        conn.rollback()
        logger.error(f"Error creating organization: {e}")
        return False
    finally:
        conn.close()


def get_organization(org_id: str) -> Optional[Dict[str, Any]]:
    """Get organization by ID"""
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM organizations WHERE id = ?", (org_id,))
    row = cursor.fetchone()
    conn.close()
    
    if row:
        org = dict(row)
        if org.get('settings'):
            org['settings'] = json.loads(org['settings'])
        return org
    return None


def get_user_organizations(user_id: str) -> List[Dict[str, Any]]:
    """Get all organizations for a user"""
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT o.*, r.name as role_name, r.display_name as role_display_name
        FROM organizations o
        JOIN user_roles ur ON o.id = ur.organization_id
        JOIN roles r ON ur.role_id = r.id
        WHERE ur.user_id = ?
        ORDER BY o.name
    """, (user_id,))
    
    rows = cursor.fetchall()
    conn.close()
    
    orgs = []
    for row in rows:
        org = dict(row)
        if org.get('settings'):
            org['settings'] = json.loads(org['settings'])
        orgs.append(org)
    
    return orgs


# ============================================
# ROLES FUNCTIONS
# ============================================

def get_all_roles() -> List[Dict[str, Any]]:
    """Get all roles"""
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM roles ORDER BY name")
    rows = cursor.fetchall()
    conn.close()
    
    roles = []
    for row in rows:
        role = dict(row)
        if role.get('permissions'):
            role['permissions'] = json.loads(role['permissions'])
        roles.append(role)
    
    return roles


def get_role_by_name(name: str) -> Optional[Dict[str, Any]]:
    """Get role by name"""
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM roles WHERE name = ?", (name,))
    row = cursor.fetchone()
    conn.close()
    
    if row:
        role = dict(row)
        if role.get('permissions'):
            role['permissions'] = json.loads(role['permissions'])
        return role
    return None


# ============================================
# USER ROLES FUNCTIONS
# ============================================

def assign_user_role(
    user_id: str,
    organization_id: str,
    role_name: str,
    assigned_by: Optional[str] = None
) -> bool:
    """Assign role to user in organization"""
    conn = get_connection()
    cursor = conn.cursor()
    
    try:
        # Get role ID
        cursor.execute("SELECT id FROM roles WHERE name = ?", (role_name,))
        role_row = cursor.fetchone()
        
        if not role_row:
            logger.error(f"Role not found: {role_name}")
            return False
        
        role_id = role_row[0]
        now = datetime.now().isoformat()
        
        # Insert or update user role
        cursor.execute("""
            INSERT INTO user_roles (user_id, organization_id, role_id, assigned_by, assigned_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(user_id, organization_id) 
            DO UPDATE SET role_id = ?, assigned_by = ?, assigned_at = ?
        """, (user_id, organization_id, role_id, assigned_by, now,
              role_id, assigned_by, now))
        
        conn.commit()
        return True
        
    except Exception as e:
        conn.rollback()
        logger.error(f"Error assigning role: {e}")
        return False
    finally:
        conn.close()


def get_user_role(user_id: str, organization_id: str) -> Optional[Dict[str, Any]]:
    """Get user's role in organization"""
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT r.*, ur.assigned_at, ur.assigned_by
        FROM roles r
        JOIN user_roles ur ON r.id = ur.role_id
        WHERE ur.user_id = ? AND ur.organization_id = ?
    """, (user_id, organization_id))
    
    row = cursor.fetchone()
    conn.close()
    
    if row:
        role = dict(row)
        if role.get('permissions'):
            role['permissions'] = json.loads(role['permissions'])
        return role
    return None


def user_has_permission(
    user_id: str,
    organization_id: str,
    resource: str,
    action: str
) -> bool:
    """Check if user has specific permission"""
    role = get_user_role(user_id, organization_id)
    
    if not role:
        return False
    
    permissions = role.get('permissions', {})
    
    # Check if user has 'all' permission (admin)
    if permissions.get('all'):
        return True
    
    # Check specific resource permission
    resource_perms = permissions.get(resource, [])
    return action in resource_perms


# Auto-initialize on import
if __name__ != "__main__":
    try:
        init_enterprise_tables()
    except Exception as e:
        logger.error(f"Failed to initialize enterprise tables: {e}")