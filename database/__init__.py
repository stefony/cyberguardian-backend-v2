"""
CyberGuardian AI - Database Module
Exports main database functions for easy importing
"""

from .db import (
    get_connection,
    init_database,
    add_threat,
    get_threats,
    get_threat_by_id,
    update_threat_status,
    get_threat_stats,
    delete_old_threats,
    get_scans,
    get_scan_by_id,
    add_scan,
    get_detection_stats,
    get_honeypots,
    get_honeypot_by_id,
    add_honeypot,
    update_honeypot_status,
    get_honeypot_logs,
    add_honeypot_log,
    get_deception_stats,
    DB_PATH
)

# ✨ Enterprise features (Phase 7)
from .schema_enterprise import (
    create_organization,
    get_organization,
    get_user_organizations,
    assign_user_role,
    get_user_role,
    get_all_roles,
    get_role_by_name,
    user_has_permission
)


__all__ = [
    "get_connection",
    "init_database",
    "add_threat",
    "get_threats",
    "get_threat_by_id",
    "update_threat_status",
    "get_threat_stats",
    "delete_old_threats",
    "get_scans",
    "get_scan_by_id",
    "add_scan",
    "get_detection_stats",
    "get_honeypots",
    "get_honeypot_by_id",
    "add_honeypot",
    "update_honeypot_status",
    "get_honeypot_logs",
    "add_honeypot_log",
    "get_deception_stats",
    "DB_PATH",
    # ✨ Enterprise exports
    "create_organization",
    "get_organization",
    "get_user_organizations",
    "assign_user_role",
    "get_user_role",
    "get_all_roles",
    "get_role_by_name",
    "user_has_permission"
]