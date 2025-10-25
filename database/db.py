"""
CyberGuardian AI - Database Module
SQLite database management for threats and system data
"""

import sqlite3
from datetime import datetime
from typing import List, Optional, Dict, Any
from pathlib import Path
import json

# Database file path
DB_PATH = Path(__file__).parent / "cyberguardian.db"


def get_connection():
    """Get database connection"""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row  # Return rows as dictionaries
    return conn


def init_database():
    """
    Initialize database - create tables if they don't exist
    """
    conn = get_connection()
    cursor = conn.cursor()
    
    # Threats table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS threats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            threat_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            description TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'active',
            details TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)
    
    # Threat actions history table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS threat_actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            threat_id INTEGER NOT NULL,
            action TEXT NOT NULL,
            reason TEXT,
            performed_at TEXT NOT NULL,
            FOREIGN KEY (threat_id) REFERENCES threats (id)
        )
    """)
    
    # Scans table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_type TEXT NOT NULL,
            status TEXT NOT NULL,
            started_at TEXT NOT NULL,
            completed_at TEXT,
            duration_seconds REAL,
            items_scanned INTEGER NOT NULL DEFAULT 0,
            threats_found INTEGER NOT NULL DEFAULT 0,
            results TEXT
        )
    """)
    
    # Honeypots table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS honeypots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            type TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'inactive',
            ip_address TEXT NOT NULL,
            port INTEGER NOT NULL,
            description TEXT NOT NULL,
            interactions INTEGER NOT NULL DEFAULT 0,
            last_interaction TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)
    
    # Honeypot logs table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS honeypot_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            honeypot_id INTEGER NOT NULL,
            timestamp TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            action TEXT NOT NULL,
            details TEXT,
            FOREIGN KEY (honeypot_id) REFERENCES honeypots (id)
        )
    """)
    
    # Users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            username TEXT UNIQUE NOT NULL,
            hashed_password TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1,
            is_verified INTEGER NOT NULL DEFAULT 0,
            is_admin INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT,
            last_login TEXT,
            full_name TEXT,
            company TEXT
        )
    """)

    # Licenses table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS licenses (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            license_key TEXT UNIQUE NOT NULL,
            license_type TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'active',
            expires_at TEXT,
            max_devices INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            activated_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)

    # Device activations table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS device_activations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_id TEXT NOT NULL,
            device_id TEXT NOT NULL,
            device_name TEXT,
            activated_at TEXT NOT NULL,
            last_seen TEXT,
            is_active INTEGER NOT NULL DEFAULT 1,
            FOREIGN KEY (license_id) REFERENCES licenses (id)
        )
    """)
    
    conn.commit()
    conn.close()
    
    print(f"✅ Database initialized at {DB_PATH}")


# ========== THREATS FUNCTIONS ==========

def add_threat(
    source_ip: str,
    threat_type: str,
    severity: str,
    description: str,
    details: Optional[Dict[str, Any]] = None,
    timestamp: Optional[str] = None
) -> int:
    """
    Add a new threat to the database
    
    Returns: threat_id
    """
    conn = get_connection()
    cursor = conn.cursor()
    
    now = datetime.now().isoformat()
    threat_timestamp = timestamp or now
    details_json = json.dumps(details) if details else None
    
    cursor.execute("""
        INSERT INTO threats 
        (timestamp, source_ip, threat_type, severity, description, status, details, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?)
    """, (threat_timestamp, source_ip, threat_type, severity, description, details_json, now, now))
    
    threat_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    return threat_id


def get_threats(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 100,
    offset: int = 0
) -> List[Dict[str, Any]]:
    """
    Get threats with optional filters
    """
    conn = get_connection()
    cursor = conn.cursor()
    
    query = "SELECT * FROM threats WHERE 1=1"
    params = []
    
    if severity:
        query += " AND severity = ?"
        params.append(severity.lower())
    
    if status:
        query += " AND status = ?"
        params.append(status.lower())
    
    query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    
    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()
    
    # Convert to list of dicts and parse JSON details
    threats = []
    for row in rows:
        threat = dict(row)
        if threat["details"]:
            threat["details"] = json.loads(threat["details"])
        threats.append(threat)
    
    return threats


def get_threat_by_id(threat_id: int) -> Optional[Dict[str, Any]]:
    """
    Get a specific threat by ID
    """
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM threats WHERE id = ?", (threat_id,))
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        return None
    
    threat = dict(row)
    if threat["details"]:
        threat["details"] = json.loads(threat["details"])
    
    return threat


def update_threat_status(threat_id: int, status: str, action: str, reason: Optional[str] = None) -> bool:
    """
    Update threat status (block, dismiss, etc.)
    """
    conn = get_connection()
    cursor = conn.cursor()
    
    now = datetime.now().isoformat()
    
    # Update threat status
    cursor.execute("""
        UPDATE threats 
        SET status = ?, updated_at = ?
        WHERE id = ?
    """, (status, now, threat_id))
    
    if cursor.rowcount == 0:
        conn.close()
        return False
    
    # Log action
    cursor.execute("""
        INSERT INTO threat_actions (threat_id, action, reason, performed_at)
        VALUES (?, ?, ?, ?)
    """, (threat_id, action, reason, now))
    
    conn.commit()
    conn.close()
    
    return True


def get_threat_stats() -> Dict[str, Any]:
    """
    Get threat statistics
    """
    conn = get_connection()
    cursor = conn.cursor()
    
    # Total threats
    cursor.execute("SELECT COUNT(*) as total FROM threats")
    total = cursor.fetchone()["total"]
    
    # Count by severity
    cursor.execute("""
        SELECT severity, COUNT(*) as count 
        FROM threats 
        GROUP BY severity
    """)
    severity_rows = cursor.fetchall()
    severity_counts = {row["severity"]: row["count"] for row in severity_rows}
    
    # Count by status
    cursor.execute("""
        SELECT status, COUNT(*) as count 
        FROM threats 
        GROUP BY status
    """)
    status_rows = cursor.fetchall()
    status_counts = {row["status"]: row["count"] for row in status_rows}
    
    conn.close()
    
    return {
        "total_threats": total,
        "severity_breakdown": severity_counts,
        "status_breakdown": status_counts,
        "last_updated": datetime.now().isoformat()
    }


def delete_old_threats(days: int = 30) -> int:
    """
    Delete threats older than specified days
    Returns: number of deleted threats
    """
    conn = get_connection()
    cursor = conn.cursor()
    
    cutoff_date = datetime.now().timestamp() - (days * 24 * 60 * 60)
    cutoff_iso = datetime.fromtimestamp(cutoff_date).isoformat()
    
    cursor.execute("DELETE FROM threats WHERE created_at < ?", (cutoff_iso,))
    deleted_count = cursor.rowcount
    
    conn.commit()
    conn.close()
    
    return deleted_count


# ========== SCANS FUNCTIONS ==========

def get_scans(
    status: Optional[str] = None,
    scan_type: Optional[str] = None,
    limit: int = 50
) -> List[Dict[str, Any]]:
    """
    Get scans with optional filters
    """
    conn = get_connection()
    cursor = conn.cursor()
    
    query = "SELECT * FROM scans WHERE 1=1"
    params = []
    
    if status:
        query += " AND status = ?"
        params.append(status.lower())
    
    if scan_type:
        query += " AND scan_type = ?"
        params.append(scan_type.lower())
    
    query += " ORDER BY started_at DESC LIMIT ?"
    params.append(limit)
    
    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()
    
    # Convert to list of dicts and parse JSON results
    scans = []
    for row in rows:
        scan = dict(row)
        if scan.get("results"):
            scan["results"] = json.loads(scan["results"])
        scans.append(scan)
    
    return scans


def get_scan_by_id(scan_id: int) -> Optional[Dict[str, Any]]:
    """
    Get a specific scan by ID
    """
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        return None
    
    scan = dict(row)
    if scan.get("results"):
        scan["results"] = json.loads(scan["results"])
    
    return scan


def add_scan(
    scan_type: str,
    status: str,
    started_at: str,
    completed_at: Optional[str] = None,
    duration_seconds: Optional[float] = None,
    items_scanned: int = 0,
    threats_found: int = 0,
    results: Optional[Dict[str, Any]] = None
) -> int:
    """
    Add a new scan to the database
    
    Returns: scan_id
    """
    conn = get_connection()
    cursor = conn.cursor()
    
    results_json = json.dumps(results) if results else None
    
    cursor.execute("""
        INSERT INTO scans 
        (scan_type, status, started_at, completed_at, duration_seconds, items_scanned, threats_found, results)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (scan_type, status, started_at, completed_at, duration_seconds, items_scanned, threats_found, results_json))
    
    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    return scan_id


def get_detection_stats() -> Dict[str, Any]:
    """
    Get detection statistics
    """
    conn = get_connection()
    cursor = conn.cursor()
    
    # Total scans
    cursor.execute("SELECT COUNT(*) as total FROM scans")
    total = cursor.fetchone()["total"]
    
    # Count by status
    cursor.execute("""
        SELECT status, COUNT(*) as count 
        FROM scans 
        GROUP BY status
    """)
    status_rows = cursor.fetchall()
    status_counts = {row["status"]: row["count"] for row in status_rows}
    
    # Count by scan type
    cursor.execute("""
        SELECT scan_type, COUNT(*) as count 
        FROM scans 
        GROUP BY scan_type
    """)
    type_rows = cursor.fetchall()
    type_counts = {row["scan_type"]: row["count"] for row in type_rows}
    
    # Total threats found
    cursor.execute("SELECT SUM(threats_found) as total_threats FROM scans")
    total_threats = cursor.fetchone()["total_threats"] or 0
    
    # Average scan duration
    cursor.execute("SELECT AVG(duration_seconds) as avg_duration FROM scans WHERE duration_seconds IS NOT NULL")
    avg_duration = cursor.fetchone()["avg_duration"] or 0
    
    conn.close()
    
    return {
        "total_scans": total,
        "status_breakdown": status_counts,
        "scan_type_breakdown": type_counts,
        "total_threats_found": total_threats,
        "average_duration_seconds": round(avg_duration, 2),
        "last_updated": datetime.now().isoformat()
    }


# ========== HONEYPOTS FUNCTIONS ==========

def get_honeypots(
    status: Optional[str] = None,
    type: Optional[str] = None,
    limit: int = 50
) -> List[Dict[str, Any]]:
    """
    Get honeypots with optional filters
    """
    conn = get_connection()
    cursor = conn.cursor()
    
    query = "SELECT * FROM honeypots WHERE 1=1"
    params = []
    
    if status:
        query += " AND status = ?"
        params.append(status.lower())
    
    if type:
        query += " AND type = ?"
        params.append(type.lower())
    
    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)
    
    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()
    
    honeypots = [dict(row) for row in rows]
    return honeypots


def get_honeypot_by_id(honeypot_id: int) -> Optional[Dict[str, Any]]:
    """
    Get a specific honeypot by ID
    """
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM honeypots WHERE id = ?", (honeypot_id,))
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        return None
    
    return dict(row)


def add_honeypot(
    name: str,
    type: str,
    status: str,
    ip_address: str,
    port: int,
    description: str,
    interactions: int = 0
) -> int:
    """
    Add a new honeypot to the database
    
    Returns: honeypot_id
    """
    conn = get_connection()
    cursor = conn.cursor()
    
    now = datetime.now().isoformat()
    
    cursor.execute("""
        INSERT INTO honeypots 
        (name, type, status, ip_address, port, description, interactions, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (name, type, status, ip_address, port, description, interactions, now, now))
    
    honeypot_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    return honeypot_id


def update_honeypot_status(honeypot_id: int, status: str) -> bool:
    """
    Update honeypot status
    """
    conn = get_connection()
    cursor = conn.cursor()
    
    now = datetime.now().isoformat()
    
    cursor.execute("""
        UPDATE honeypots 
        SET status = ?, updated_at = ?
        WHERE id = ?
    """, (status, now, honeypot_id))
    
    success = cursor.rowcount > 0
    conn.commit()
    conn.close()
    
    return success


def get_honeypot_logs(
    honeypot_id: Optional[int] = None,
    limit: int = 100
) -> List[Dict[str, Any]]:
    """
    Get honeypot interaction logs
    """
    conn = get_connection()
    cursor = conn.cursor()
    
    query = "SELECT * FROM honeypot_logs WHERE 1=1"
    params = []
    
    if honeypot_id:
        query += " AND honeypot_id = ?"
        params.append(honeypot_id)
    
    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)
    
    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()
    
    logs = []
    for row in rows:
        log = dict(row)
        if log.get("details"):
            log["details"] = json.loads(log["details"])
        logs.append(log)
    
    return logs


def add_honeypot_log(
    honeypot_id: int,
    source_ip: str,
    action: str,
    details: Optional[Dict[str, Any]] = None
) -> int:
    """
    Add a honeypot interaction log
    
    Returns: log_id
    """
    conn = get_connection()
    cursor = conn.cursor()
    
    now = datetime.now().isoformat()
    details_json = json.dumps(details) if details else None
    
    cursor.execute("""
        INSERT INTO honeypot_logs 
        (honeypot_id, timestamp, source_ip, action, details)
        VALUES (?, ?, ?, ?, ?)
    """, (honeypot_id, now, source_ip, action, details_json))
    
    log_id = cursor.lastrowid
    
    # Update honeypot interactions count and last_interaction
    cursor.execute("""
        UPDATE honeypots 
        SET interactions = interactions + 1, 
            last_interaction = ?,
            updated_at = ?
        WHERE id = ?
    """, (now, now, honeypot_id))
    
    conn.commit()
    conn.close()
    
    return log_id


def get_deception_stats() -> Dict[str, Any]:
    """
    Get deception layer statistics
    """
    conn = get_connection()
    cursor = conn.cursor()
    
    # Total honeypots
    cursor.execute("SELECT COUNT(*) as total FROM honeypots")
    total = cursor.fetchone()["total"]
    
    # Active honeypots
    cursor.execute("SELECT COUNT(*) as active FROM honeypots WHERE status = 'active'")
    active = cursor.fetchone()["active"]
    
    # Compromised honeypots
    cursor.execute("SELECT COUNT(*) as compromised FROM honeypots WHERE status = 'compromised'")
    compromised = cursor.fetchone()["compromised"]
    
    # Total interactions
    cursor.execute("SELECT SUM(interactions) as total_interactions FROM honeypots")
    total_interactions = cursor.fetchone()["total_interactions"] or 0
    
    # Interactions today
    today = datetime.now().date().isoformat()
    cursor.execute("""
        SELECT COUNT(*) as today_interactions 
        FROM honeypot_logs 
        WHERE DATE(timestamp) = ?
    """, (today,))
    interactions_today = cursor.fetchone()["today_interactions"]
    
    conn.close()
    
    return {
        "total_honeypots": total,
        "active_honeypots": active,
        "compromised_honeypots": compromised,
        "total_interactions": total_interactions,
        "interactions_today": interactions_today,
        "last_updated": datetime.now().isoformat()
    }


# ========== USERS FUNCTIONS ==========

import uuid
# import hashlib  # No longer needed
from typing import Optional

def create_user(
    email: str,
    username: str,
    password: str,
    full_name: Optional[str] = None,
    company: Optional[str] = None,
    is_admin: bool = False
) -> str:
    """
    Create a new user
    
    Returns: user_id
    """
    conn = get_connection()
    cursor = conn.cursor()
    
    user_id = str(uuid.uuid4())
    now = datetime.now().isoformat()
    
    # Hash password (simple SHA256 for now, will upgrade to bcrypt later)
    hashed_password = password
    
    cursor.execute("""
        INSERT INTO users 
        (id, email, username, hashed_password, is_active, is_verified, is_admin, 
         created_at, full_name, company)
        VALUES (?, ?, ?, ?, 1, 0, ?, ?, ?, ?)
    """, (user_id, email, username, hashed_password, int(is_admin), now, full_name, company))
    
    conn.commit()
    conn.close()
    
    return user_id


def get_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    """Get user by email"""
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    row = cursor.fetchone()
    conn.close()
    
    return dict(row) if row else None


def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    """Get user by username"""
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()
    
    return dict(row) if row else None


def get_user_by_id(user_id: str) -> Optional[Dict[str, Any]]:
    """Get user by ID"""
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    
    return dict(row) if row else None


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against hash"""
    return hashlib.sha256(plain_password.encode()).hexdigest() == hashed_password


def update_last_login(user_id: str):
    """Update user's last login timestamp"""
    conn = get_connection()
    cursor = conn.cursor()
    
    now = datetime.now().isoformat()
    
    cursor.execute("""
        UPDATE users 
        SET last_login = ?, updated_at = ?
        WHERE id = ?
    """, (now, now, user_id))
    
    conn.commit()
    conn.close()


# Initialize database on module import
init_database()