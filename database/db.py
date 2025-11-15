"""
CyberGuardian AI - Database Module
SQLite database management for threats and system data
"""

import sqlite3
from datetime import datetime
from typing import List, Optional, Dict, Any
from pathlib import Path
import json
import logging
import hashlib

logger = logging.getLogger(__name__)


# Database file path
DB_PATH = Path(__file__).parent / "cyberguardian.db"

import requests

def get_ip_geolocation(ip: str) -> Dict[str, Any]:
    """
    Get geolocation data for an IP address using ip-api.com
    Returns: dict with country, city, lat, lon
    """
    try:
        # Skip private/local IPs
        if ip.startswith(('127.', '192.168.', '10.', '172.')):
            return {
                "country": "Local",
                "city": "Local",
                "latitude": 0.0,
                "longitude": 0.0
            }
        
        # Call ip-api.com (free, no API key needed)
        response = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,country,city,lat,lon",
            timeout=3
        )
        
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success":
                return {
                    "country": data.get("country", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "latitude": data.get("lat", 0.0),
                    "longitude": data.get("lon", 0.0)
                }
    except Exception as e:
        print(f"⚠️ Geolocation lookup failed for {ip}: {e}")
    
    # Fallback
    return {
        "country": "Unknown",
        "city": "Unknown",
        "latitude": 0.0,
        "longitude": 0.0
    }


def get_connection():
    """Get database connection (PostgreSQL in production, SQLite local)"""
    from database.postgres import get_connection as pg_get_connection
    return pg_get_connection()


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
            confidence_score REAL DEFAULT 0.0,
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
    country TEXT,
    city TEXT,
    latitude REAL,
    longitude REAL,
    FOREIGN KEY (honeypot_id) REFERENCES honeypots (id)
)
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS fs_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        event_type TEXT NOT NULL,
        file_path TEXT NOT NULL,
        file_size INTEGER,
        file_hash TEXT,
        threat_score REAL,
        threat_level TEXT,
        ml_details TEXT,
        quarantined INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL
    )
""")
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS protection_settings (
        id INTEGER PRIMARY KEY DEFAULT 1,
        enabled INTEGER NOT NULL DEFAULT 0,
        watch_paths TEXT NOT NULL,
        auto_quarantine INTEGER NOT NULL DEFAULT 0,
        threat_threshold INTEGER NOT NULL DEFAULT 80,
        updated_at TEXT NOT NULL,
        CHECK (id = 1)
    )  
        
    """) 
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS exclusions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        type TEXT NOT NULL,
        value TEXT NOT NULL,
        reason TEXT,
        created_at TEXT NOT NULL,
        created_by TEXT,
        UNIQUE(type, value)
    )
""")

    # IOC (Indicators of Compromise) tables
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS iocs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ioc_type TEXT NOT NULL,
            ioc_value TEXT NOT NULL UNIQUE,
            threat_type TEXT,
            threat_name TEXT,
            severity TEXT DEFAULT 'medium',
            confidence REAL DEFAULT 50.0,
            source TEXT,
            source_url TEXT,
            mitre_tactics TEXT,
            mitre_techniques TEXT,
            description TEXT,
            tags TEXT,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            times_seen INTEGER DEFAULT 1,
            is_active INTEGER DEFAULT 1,
            is_whitelisted INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)
    # ============================================
    # MITRE ATT&CK TABLES
    # ============================================
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS mitre_tactics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tactic_id TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL,
            description TEXT,
            url TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS mitre_techniques (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            technique_id TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL,
            description TEXT,
            url TEXT,
            tactic_id INTEGER NOT NULL,
            parent_technique_id INTEGER,
            is_sub_technique INTEGER DEFAULT 0,
            platforms TEXT,
            data_sources TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (tactic_id) REFERENCES mitre_tactics(id),
            FOREIGN KEY (parent_technique_id) REFERENCES mitre_techniques(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS threat_mitre_mappings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            threat_id INTEGER NOT NULL,
            threat_type TEXT,
            threat_name TEXT,
            technique_id INTEGER NOT NULL,
            tactic_id INTEGER NOT NULL,
            confidence INTEGER DEFAULT 50,
            mapping_source TEXT,
            description TEXT,
            evidence TEXT,
            detected_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (technique_id) REFERENCES mitre_techniques(id),
            FOREIGN KEY (tactic_id) REFERENCES mitre_tactics(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS mitre_detection_coverage (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            technique_id INTEGER NOT NULL UNIQUE,
            can_detect INTEGER DEFAULT 0,
            detection_methods TEXT,
            coverage_level TEXT DEFAULT 'none',
            times_detected INTEGER DEFAULT 0,
            last_detected TEXT,
            notes TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (technique_id) REFERENCES mitre_techniques(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS threat_feeds (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            feed_type TEXT NOT NULL,
            url TEXT,
            api_key TEXT,
            enabled INTEGER DEFAULT 1,
            refresh_interval INTEGER DEFAULT 3600,
            last_refresh TEXT,
            total_iocs INTEGER DEFAULT 0,
            successful_updates INTEGER DEFAULT 0,
            failed_updates INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS threat_matches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ioc_id INTEGER NOT NULL,
            matched_value TEXT NOT NULL,
            match_type TEXT,
            detection_source TEXT,
            file_path TEXT,
            process_name TEXT,
            threat_level TEXT,
            confidence_score REAL,
            action_taken TEXT,
            matched_at TEXT NOT NULL,
            FOREIGN KEY (ioc_id) REFERENCES iocs(id)
        )
    """)
          
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scan_schedules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        scan_type TEXT NOT NULL,
        target_path TEXT NOT NULL,
        schedule_type TEXT NOT NULL,
        cron_expression TEXT,
        interval_days INTEGER,
        enabled INTEGER NOT NULL DEFAULT 1,
        last_run TEXT,
        next_run TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
""")
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scan_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        schedule_id INTEGER,
        scan_type TEXT NOT NULL,
        target_path TEXT NOT NULL,
        started_at TEXT NOT NULL,
        completed_at TEXT,
        status TEXT NOT NULL,
        files_scanned INTEGER NOT NULL DEFAULT 0,
        threats_found INTEGER NOT NULL DEFAULT 0,
        duration_seconds INTEGER,
        error_message TEXT,
        FOREIGN KEY (schedule_id) REFERENCES scan_schedules(id)
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
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_email_accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            email_address TEXT NOT NULL,
            provider TEXT NOT NULL,
            auth_method TEXT NOT NULL,
            
            access_token TEXT,
            refresh_token TEXT,
            token_expiry TEXT,
            
            imap_host TEXT,
            imap_port INTEGER,
            encrypted_password TEXT,
            
            auto_scan_enabled INTEGER NOT NULL DEFAULT 1,
            scan_interval_hours INTEGER NOT NULL DEFAULT 24,
            folders_to_scan TEXT DEFAULT 'INBOX',
            
            total_scanned INTEGER NOT NULL DEFAULT 0,
            phishing_detected INTEGER NOT NULL DEFAULT 0,
            last_scan_date TEXT,
            
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            
            FOREIGN KEY (user_id) REFERENCES users(id),
            UNIQUE(user_id, email_address)
        )
    """)

    # Email Scan History table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS email_scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email_account_id INTEGER NOT NULL,
            scan_started_at TEXT NOT NULL,
            scan_completed_at TEXT,
            emails_scanned INTEGER NOT NULL DEFAULT 0,
            phishing_detected INTEGER NOT NULL DEFAULT 0,
            safe_emails INTEGER NOT NULL DEFAULT 0,
            suspicious_emails INTEGER NOT NULL DEFAULT 0,
            dangerous_emails INTEGER NOT NULL DEFAULT 0,
            scan_status TEXT NOT NULL,
            error_message TEXT,
            
            FOREIGN KEY (email_account_id) REFERENCES user_email_accounts(id)
        )
    """)

    # Scanned Emails table (detailed results)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scanned_emails (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_history_id INTEGER NOT NULL,
            email_account_id INTEGER NOT NULL,
            email_id TEXT NOT NULL,
            subject TEXT,
            sender TEXT,
            recipient TEXT,
            date TEXT,
            is_phishing INTEGER NOT NULL DEFAULT 0,
            phishing_score REAL NOT NULL DEFAULT 0.0,
            threat_level TEXT NOT NULL,
            indicators TEXT,
            urls TEXT,
            attachments TEXT,
            recommendations TEXT,
            scanned_at TEXT NOT NULL,
            
            FOREIGN KEY (scan_history_id) REFERENCES email_scan_history(id),
            FOREIGN KEY (email_account_id) REFERENCES user_email_accounts(id),
            UNIQUE(email_account_id, email_id)
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
    
    # ============================================
    # INTEGRITY MONITORING TABLES
    # ============================================
    
    # Integrity logs table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS integrity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_path TEXT NOT NULL,
            expected_checksum TEXT NOT NULL,
            actual_checksum TEXT,
            status TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            details TEXT
        )
    """)
    
    # File manifests table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS file_manifests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            version TEXT NOT NULL,
            manifest_data TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Integrity alerts table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS integrity_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            file_path TEXT,
            message TEXT NOT NULL,
            resolved INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            resolved_at DATETIME
        )
    """)
    # ============================================
    # UPDATE HISTORY TABLE
    # ============================================
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS update_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            from_version TEXT NOT NULL,
            to_version TEXT NOT NULL,
            update_type TEXT,
            status TEXT NOT NULL,
            started_at TEXT NOT NULL DEFAULT (datetime('now')),
            completed_at TEXT,
            duration_seconds INTEGER,
            error_message TEXT,
            rollback_performed INTEGER DEFAULT 0,
            backup_path TEXT,
            download_size_bytes INTEGER,
            release_notes TEXT
        )
    """)
    
    # Indexes for update history
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_update_history_status 
        ON update_history(status)
    """)
    
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_update_history_versions 
        ON update_history(to_version, from_version)
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
    timestamp: Optional[str] = None,
    confidence_score: float = 0.0,
    organization_id: Optional[str] = None  # ✨ ДОБАВЕНО
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
        (timestamp, source_ip, threat_type, severity, description, status, details, confidence_score, organization_id, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?, ?, ?)
    """, (threat_timestamp, source_ip, threat_type, severity, description, details_json, confidence_score, organization_id, now, now))
    
    threat_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    return threat_id


def get_threats(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    organization_id: Optional[str] = None  # ✨ ДОБАВЕНО
) -> List[Dict[str, Any]]:
    """
    Get threats with optional filters
    """
    conn = get_connection()
    cursor = conn.cursor()
    
    query = """
        SELECT id, timestamp, source_ip, threat_type, severity, 
               description, status, details, confidence_score, 
               organization_id, created_at, updated_at
        FROM threats 
        WHERE 1=1
    """
    params = []
    
    # ✨ ДОБАВЕНО: Organization filter
    if organization_id:
        query += " AND organization_id = ?"
        params.append(organization_id)
    
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
    
    # Convert to list of dicts with explicit column mapping
    threats = []
    for row in rows:
        threat = {
            "id": row["id"],
            "timestamp": row["timestamp"],
            "source_ip": row["source_ip"],
            "threat_type": row["threat_type"],
            "severity": row["severity"],
            "description": row["description"],
            "status": row["status"],
            "details": json.loads(row["details"]) if row["details"] else None,
            "confidence_score": row["confidence_score"],
            "organization_id": row["organization_id"],  # ✨ ДОБАВЕНО
            "created_at": row["created_at"],
            "updated_at": row["updated_at"]
        }
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
    details: Optional[Dict[str, Any]] = None,
    country: Optional[str] = None,
    city: Optional[str] = None,
    latitude: Optional[float] = None,
    longitude: Optional[float] = None
) -> int:
    """
    Add a honeypot interaction log
    
    Returns: log_id
    """
    conn = get_connection()
    cursor = conn.cursor()
    
    now = datetime.now().isoformat()
    details_json = json.dumps(details) if details else None
    
    # Auto-fetch geolocation if not provided
    if country is None or latitude is None:
        geo_data = get_ip_geolocation(source_ip)
        country = geo_data["country"]
        city = geo_data["city"]
        latitude = geo_data["latitude"]
        longitude = geo_data["longitude"]
    
    cursor.execute("""
        INSERT INTO honeypot_logs 
        (honeypot_id, timestamp, source_ip, action, details, country, city, latitude, longitude)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (honeypot_id, now, source_ip, action, details_json, country, city, latitude, longitude))
    
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
# ========== FS EVENTS FUNCTIONS ==========

def add_fs_event(
    event_type: str,
    file_path: str,
    threat_score: float = 0.0,
    threat_level: str = "low",
    ml_details: Optional[Dict[str, Any]] = None,
    file_size: Optional[int] = None,
    file_hash: Optional[str] = None,
    quarantined: bool = False
) -> int:
    """Add file system event"""
    conn = get_connection()
    cursor = conn.cursor()
    
    now = datetime.now().isoformat()
    ml_json = json.dumps(ml_details) if ml_details else None
    
    cursor.execute("""
        INSERT INTO fs_events 
        (timestamp, event_type, file_path, file_size, file_hash, 
         threat_score, threat_level, ml_details, quarantined, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (now, event_type, file_path, file_size, file_hash,
          threat_score, threat_level, ml_json, int(quarantined), now))
    
    event_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    return event_id


def get_fs_events(limit: int = 100) -> List[Dict[str, Any]]:
    """Get recent file system events"""
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT * FROM fs_events 
        ORDER BY timestamp DESC 
        LIMIT ?
    """, (limit,))
    
    rows = cursor.fetchall()
    conn.close()
    
    events = []
    for row in rows:
        event = dict(row)
        if event.get("ml_details"):
            event["ml_details"] = json.loads(event["ml_details"])
        events.append(event)
    
    return events


def get_protection_settings() -> Dict[str, Any]:
    """Get protection settings"""
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM protection_settings WHERE id = 1")
    row = cursor.fetchone()
    
    if not row:
        # Create default settings
        now = datetime.now().isoformat()
        cursor.execute("""
            INSERT INTO protection_settings 
            (id, enabled, watch_paths, auto_quarantine, threat_threshold, updated_at)
            VALUES (1, 0, '[]', 0, 80, ?)
        """, (now,))
        conn.commit()
        cursor.execute("SELECT * FROM protection_settings WHERE id = 1")
        row = cursor.fetchone()
    
    conn.close()
    
    settings = dict(row)
    settings["watch_paths"] = json.loads(settings["watch_paths"])
    return settings


def update_protection_settings(
    enabled: bool,
    watch_paths: List[str],
    auto_quarantine: Optional[bool] = None,
    threat_threshold: Optional[int] = None
) -> bool:
    """Update protection settings"""
    conn = get_connection()
    cursor = conn.cursor()
    
    now = datetime.now().isoformat()
    paths_json = json.dumps(watch_paths)
    
    updates = ["enabled = ?", "watch_paths = ?", "updated_at = ?"]
    params = [int(enabled), paths_json, now]
    
    if auto_quarantine is not None:
        updates.append("auto_quarantine = ?")
        params.append(int(auto_quarantine))
    
    if threat_threshold is not None:
        updates.append("threat_threshold = ?")
        params.append(threat_threshold)
    
    params.append(1)  # WHERE id = 1
    
    cursor.execute(f"""
        UPDATE protection_settings 
        SET {', '.join(updates)}
        WHERE id = ?
    """, params)
    
    success = cursor.rowcount > 0
    conn.commit()
    conn.close()
    
    return success

# ========== SCAN SCHEDULES FUNCTIONS ==========

def add_scan_schedule(
    name: str,
    scan_type: str,
    target_path: str,
    schedule_type: str,
    cron_expression: Optional[str] = None,
    interval_days: Optional[int] = None,
    enabled: bool = True
) -> int:
    """Add new scan schedule"""
    conn = get_connection()
    cursor = conn.cursor()
    
    now = datetime.now().isoformat()
    
    cursor.execute("""
        INSERT INTO scan_schedules 
        (name, scan_type, target_path, schedule_type, cron_expression, 
         interval_days, enabled, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (name, scan_type, target_path, schedule_type, cron_expression,
          interval_days, int(enabled), now, now))
    
    schedule_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    return schedule_id


def get_scan_schedules(enabled_only: bool = False) -> List[Dict[str, Any]]:
    """Get all scan schedules"""
    conn = get_connection()
    cursor = conn.cursor()
    
    query = "SELECT * FROM scan_schedules"
    if enabled_only:
        query += " WHERE enabled = 1"
    query += " ORDER BY created_at DESC"
    
    cursor.execute(query)
    rows = cursor.fetchall()
    conn.close()
    
    return [dict(row) for row in rows]


def get_scan_schedule(schedule_id: int) -> Optional[Dict[str, Any]]:
    """Get single scan schedule"""
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM scan_schedules WHERE id = ?", (schedule_id,))
    row = cursor.fetchone()
    conn.close()
    
    return dict(row) if row else None


def update_scan_schedule(
    schedule_id: int,
    name: Optional[str] = None,
    enabled: Optional[bool] = None,
    last_run: Optional[str] = None,
    next_run: Optional[str] = None
) -> bool:
    """Update scan schedule"""
    conn = get_connection()
    cursor = conn.cursor()
    
    updates = ["updated_at = ?"]
    params = [datetime.now().isoformat()]
    
    if name is not None:
        updates.append("name = ?")
        params.append(name)
    
    if enabled is not None:
        updates.append("enabled = ?")
        params.append(int(enabled))
    
    if last_run is not None:
        updates.append("last_run = ?")
        params.append(last_run)
    
    if next_run is not None:
        updates.append("next_run = ?")
        params.append(next_run)
    
    params.append(schedule_id)
    
    cursor.execute(f"""
        UPDATE scan_schedules 
        SET {', '.join(updates)}
        WHERE id = ?
    """, params)
    
    success = cursor.rowcount > 0
    conn.commit()
    conn.close()
    
    return success


def delete_scan_schedule(schedule_id: int) -> bool:
    """Delete scan schedule"""
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("DELETE FROM scan_schedules WHERE id = ?", (schedule_id,))
    
    success = cursor.rowcount > 0
    conn.commit()
    conn.close()
    
    return success


# ========== SCAN HISTORY FUNCTIONS ==========

def add_scan_history(
    schedule_id: Optional[int],
    scan_type: str,
    target_path: str,
    started_at: str,
    status: str = "running"
) -> int:
    """Add scan history entry"""
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        INSERT INTO scan_history 
        (schedule_id, scan_type, target_path, started_at, status)
        VALUES (?, ?, ?, ?, ?)
    """, (schedule_id, scan_type, target_path, started_at, status))
    
    history_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    return history_id


def update_scan_history(
    history_id: int,
    completed_at: Optional[str] = None,
    status: Optional[str] = None,
    files_scanned: Optional[int] = None,
    threats_found: Optional[int] = None,
    duration_seconds: Optional[int] = None,
    error_message: Optional[str] = None
) -> bool:
    """Update scan history entry"""
    conn = get_connection()
    cursor = conn.cursor()
    
    updates = []
    params = []
    
    if completed_at is not None:
        updates.append("completed_at = ?")
        params.append(completed_at)
    
    if status is not None:
        updates.append("status = ?")
        params.append(status)
    
    if files_scanned is not None:
        updates.append("files_scanned = ?")
        params.append(files_scanned)
    
    if threats_found is not None:
        updates.append("threats_found = ?")
        params.append(threats_found)
    
    if duration_seconds is not None:
        updates.append("duration_seconds = ?")
        params.append(duration_seconds)
    
    if error_message is not None:
        updates.append("error_message = ?")
        params.append(error_message)
    
    if not updates:
        conn.close()
        return False
    
    params.append(history_id)
    
    cursor.execute(f"""
        UPDATE scan_history 
        SET {', '.join(updates)}
        WHERE id = ?
    """, params)
    
    success = cursor.rowcount > 0
    conn.commit()
    conn.close()
    
    return success


def get_scan_history(limit: int = 50) -> List[Dict[str, Any]]:
    """Get scan history"""
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT * FROM scan_history 
        ORDER BY started_at DESC 
        LIMIT ?
    """, (limit,))
    
    rows = cursor.fetchall()
    conn.close()
    
    return [dict(row) for row in rows]

# ADD THESE FUNCTIONS AT THE END OF database/db.py (before init_database() call)

# ========== USER EMAIL ACCOUNTS FUNCTIONS ==========

def add_email_account(
    user_id: str,
    email_address: str,
    provider: str,
    auth_method: str,
    imap_host: Optional[str] = None,
    imap_port: Optional[int] = None,
    encrypted_password: Optional[str] = None,
    access_token: Optional[str] = None,
    refresh_token: Optional[str] = None,
    token_expiry: Optional[str] = None
) -> int:
    """Add email account for user"""
    conn = get_connection()
    cursor = conn.cursor()
    
    now = datetime.now().isoformat()
    
    cursor.execute("""
        INSERT INTO user_email_accounts 
        (user_id, email_address, provider, auth_method, imap_host, imap_port,
         encrypted_password, access_token, refresh_token, token_expiry,
         created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (user_id, email_address, provider, auth_method, imap_host, imap_port,
          encrypted_password, access_token, refresh_token, token_expiry, now, now))
    
    account_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    return account_id


def get_user_email_accounts(user_id: str) -> List[Dict[str, Any]]:
    """Get all email accounts for a user"""
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT * FROM user_email_accounts 
        WHERE user_id = ?
        ORDER BY created_at DESC
    """, (user_id,))
    
    rows = cursor.fetchall()
    conn.close()
    
    return [dict(row) for row in rows]


def get_email_account(account_id: int) -> Optional[Dict[str, Any]]:
    """Get single email account"""
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM user_email_accounts WHERE id = ?", (account_id,))
    row = cursor.fetchone()
    conn.close()
    
    return dict(row) if row else None


def get_email_account_by_email(user_id: str, email_address: str) -> Optional[Dict[str, Any]]:
    """Get email account by email address"""
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT * FROM user_email_accounts 
        WHERE user_id = ? AND email_address = ?
    """, (user_id, email_address))
    
    row = cursor.fetchone()
    conn.close()
    
    return dict(row) if row else None


def update_email_account(
    account_id: int,
    auto_scan_enabled: Optional[bool] = None,
    scan_interval_hours: Optional[int] = None,
    folders_to_scan: Optional[str] = None,
    access_token: Optional[str] = None,
    refresh_token: Optional[str] = None,
    token_expiry: Optional[str] = None
) -> bool:
    """Update email account settings"""
    conn = get_connection()
    cursor = conn.cursor()
    
    updates = ["updated_at = ?"]
    params = [datetime.now().isoformat()]
    
    if auto_scan_enabled is not None:
        updates.append("auto_scan_enabled = ?")
        params.append(int(auto_scan_enabled))
    
    if scan_interval_hours is not None:
        updates.append("scan_interval_hours = ?")
        params.append(scan_interval_hours)
    
    if folders_to_scan is not None:
        updates.append("folders_to_scan = ?")
        params.append(folders_to_scan)
    
    if access_token is not None:
        updates.append("access_token = ?")
        params.append(access_token)
    
    if refresh_token is not None:
        updates.append("refresh_token = ?")
        params.append(refresh_token)
    
    if token_expiry is not None:
        updates.append("token_expiry = ?")
        params.append(token_expiry)
    
    params.append(account_id)
    
    cursor.execute(f"""
        UPDATE user_email_accounts 
        SET {', '.join(updates)}
        WHERE id = ?
    """, params)
    
    success = cursor.rowcount > 0
    conn.commit()
    conn.close()
    
    return success


def delete_email_account(account_id: int) -> bool:
    """Delete email account"""
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("DELETE FROM user_email_accounts WHERE id = ?", (account_id,))
    
    success = cursor.rowcount > 0
    conn.commit()
    conn.close()
    
    return success


def update_email_scan_stats(
    account_id: int,
    emails_scanned: int,
    phishing_detected: int
) -> bool:
    """Update email account scan statistics"""
    conn = get_connection()
    cursor = conn.cursor()
    
    now = datetime.now().isoformat()
    
    cursor.execute("""
        UPDATE user_email_accounts 
        SET total_scanned = total_scanned + ?,
            phishing_detected = phishing_detected + ?,
            last_scan_date = ?,
            updated_at = ?
        WHERE id = ?
    """, (emails_scanned, phishing_detected, now, now, account_id))
    
    success = cursor.rowcount > 0
    conn.commit()
    conn.close()
    
    return success


# ========== EMAIL SCAN HISTORY FUNCTIONS ==========

def add_email_scan_history(
    email_account_id: int,
    scan_started_at: str,
    scan_status: str = "running"
) -> int:
    """Add email scan history entry"""
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        INSERT INTO email_scan_history 
        (email_account_id, scan_started_at, scan_status)
        VALUES (?, ?, ?)
    """, (email_account_id, scan_started_at, scan_status))
    
    history_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    return history_id


def update_email_scan_history(
    history_id: int,
    scan_completed_at: Optional[str] = None,
    emails_scanned: Optional[int] = None,
    phishing_detected: Optional[int] = None,
    safe_emails: Optional[int] = None,
    suspicious_emails: Optional[int] = None,
    dangerous_emails: Optional[int] = None,
    scan_status: Optional[str] = None,
    error_message: Optional[str] = None
) -> bool:
    """Update email scan history"""
    conn = get_connection()
    cursor = conn.cursor()
    
    updates = []
    params = []
    
    if scan_completed_at is not None:
        updates.append("scan_completed_at = ?")
        params.append(scan_completed_at)
    
    if emails_scanned is not None:
        updates.append("emails_scanned = ?")
        params.append(emails_scanned)
    
    if phishing_detected is not None:
        updates.append("phishing_detected = ?")
        params.append(phishing_detected)
    
    if safe_emails is not None:
        updates.append("safe_emails = ?")
        params.append(safe_emails)
    
    if suspicious_emails is not None:
        updates.append("suspicious_emails = ?")
        params.append(suspicious_emails)
    
    if dangerous_emails is not None:
        updates.append("dangerous_emails = ?")
        params.append(dangerous_emails)
    
    if scan_status is not None:
        updates.append("scan_status = ?")
        params.append(scan_status)
    
    if error_message is not None:
        updates.append("error_message = ?")
        params.append(error_message)
    
    if not updates:
        conn.close()
        return False
    
    params.append(history_id)
    
    cursor.execute(f"""
        UPDATE email_scan_history 
        SET {', '.join(updates)}
        WHERE id = ?
    """, params)
    
    success = cursor.rowcount > 0
    conn.commit()
    conn.close()
    
    return success


def get_email_scan_history(email_account_id: int, limit: int = 50) -> List[Dict[str, Any]]:
    """Get email scan history for account"""
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT * FROM email_scan_history 
        WHERE email_account_id = ?
        ORDER BY scan_started_at DESC 
        LIMIT ?
    """, (email_account_id, limit))
    
    rows = cursor.fetchall()
    conn.close()
    
    return [dict(row) for row in rows]


# ========== SCANNED EMAILS FUNCTIONS ==========

def add_scanned_email(
    scan_history_id: int,
    email_account_id: int,
    email_id: str,
    subject: str,
    sender: str,
    date: str,
    is_phishing: bool,
    phishing_score: float,
    threat_level: str,
    indicators: List[str],
    urls: List[str],
    attachments: List[str],
    recommendations: List[str],
    recipient: Optional[str] = None
) -> int:
    """Add scanned email result"""
    conn = get_connection()
    cursor = conn.cursor()
    
    now = datetime.now().isoformat()
    indicators_json = json.dumps(indicators)
    urls_json = json.dumps(urls)
    attachments_json = json.dumps(attachments)
    recommendations_json = json.dumps(recommendations)
    
    try:
        cursor.execute("""
            INSERT INTO scanned_emails 
            (scan_history_id, email_account_id, email_id, subject, sender, recipient,
             date, is_phishing, phishing_score, threat_level, indicators, urls,
             attachments, recommendations, scanned_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (scan_history_id, email_account_id, email_id, subject, sender, recipient,
              date, int(is_phishing), phishing_score, threat_level, indicators_json,
              urls_json, attachments_json, recommendations_json, now))
        
        email_result_id = cursor.lastrowid
        conn.commit()
    except sqlite3.IntegrityError:
        # Email already exists (UNIQUE constraint)
        conn.close()
        return -1
    
    conn.close()
    return email_result_id


def get_scanned_emails(email_account_id: int, limit: int = 100) -> List[Dict[str, Any]]:
    """Get scanned emails for account"""
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT * FROM scanned_emails 
        WHERE email_account_id = ?
        ORDER BY scanned_at DESC 
        LIMIT ?
    """, (email_account_id, limit))
    
    rows = cursor.fetchall()
    conn.close()
    
    emails = []
    for row in rows:
        email = dict(row)
        email["indicators"] = json.loads(email["indicators"])
        email["urls"] = json.loads(email["urls"])
        email["attachments"] = json.loads(email["attachments"])
        email["recommendations"] = json.loads(email["recommendations"])
        emails.append(email)
    
    return emails

# ========== EXCLUSIONS FUNCTIONS ==========

def add_exclusion(
    exclusion_type: str,
    value: str,
    reason: Optional[str] = None,
    created_by: Optional[str] = None
) -> int:
    """Add new exclusion"""
    conn = get_connection()
    cursor = conn.cursor()
    
    now = datetime.now().isoformat()
    
    try:
        cursor.execute("""
            INSERT INTO exclusions (type, value, reason, created_at, created_by)
            VALUES (?, ?, ?, ?, ?)
        """, (exclusion_type, value, reason, now, created_by))
        
        exclusion_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return exclusion_id
    except sqlite3.IntegrityError:
        conn.close()
        return -1  # Already exists


def get_exclusions(exclusion_type: Optional[str] = None) -> List[Dict[str, Any]]:
    """Get all exclusions or filter by type"""
    conn = get_connection()
    cursor = conn.cursor()
    
    if exclusion_type:
        cursor.execute("SELECT * FROM exclusions WHERE type = ? ORDER BY created_at DESC", (exclusion_type,))
    else:
        cursor.execute("SELECT * FROM exclusions ORDER BY created_at DESC")
    
    rows = cursor.fetchall()
    conn.close()
    
    return [dict(row) for row in rows]


def delete_exclusion(exclusion_id: int) -> bool:
    """Delete exclusion by ID"""
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("DELETE FROM exclusions WHERE id = ?", (exclusion_id,))
    success = cursor.rowcount > 0
    
    conn.commit()
    conn.close()
    
    return success


def is_excluded(exclusion_type: str, value: str) -> bool:
    """Check if a value is excluded"""
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT COUNT(*) as count FROM exclusions 
        WHERE type = ? AND value = ?
    """, (exclusion_type, value))
    
    result = cursor.fetchone()
    conn.close()
    
    return result["count"] > 0

# ========== IOC FUNCTIONS ==========

def add_ioc(
    ioc_value: str,
    ioc_type: str,
    threat_type: Optional[str] = None,
    threat_name: Optional[str] = None,
    severity: str = "medium",
    confidence: float = 50.0,
    source: str = "manual",
    description: Optional[str] = None,
    mitre_tactics: Optional[List[str]] = None,
    mitre_techniques: Optional[List[str]] = None,
    tags: Optional[List[str]] = None
) -> int:
    """Add or update IOC"""
    conn = get_connection()
    cursor = conn.cursor()
    
    now = datetime.now().isoformat()
    
    # Check if exists
    cursor.execute("SELECT id, times_seen FROM iocs WHERE ioc_value = ?", (ioc_value,))
    existing = cursor.fetchone()
    
    if existing:
        # Update existing
        cursor.execute("""
            UPDATE iocs 
            SET times_seen = times_seen + 1, 
                last_seen = ?,
                confidence = MAX(confidence, ?),
                updated_at = ?
            WHERE id = ?
        """, (now, confidence, now, existing["id"]))
        
        ioc_id = existing["id"]
    else:
        # Create new
        mitre_tactics_json = json.dumps(mitre_tactics) if mitre_tactics else None
        mitre_techniques_json = json.dumps(mitre_techniques) if mitre_techniques else None
        tags_json = json.dumps(tags) if tags else None
        
        cursor.execute("""
            INSERT INTO iocs 
            (ioc_type, ioc_value, threat_type, threat_name, severity, confidence,
             source, description, mitre_tactics, mitre_techniques, tags,
             first_seen, last_seen, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (ioc_type, ioc_value, threat_type, threat_name, severity, confidence,
              source, description, mitre_tactics_json, mitre_techniques_json, tags_json,
              now, now, now, now))
        
        ioc_id = cursor.lastrowid
    
    conn.commit()
    conn.close()
    
    return ioc_id


def get_ioc(ioc_value: str) -> Optional[Dict[str, Any]]:
    """Get IOC by value"""
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT * FROM iocs 
        WHERE ioc_value = ? AND is_active = 1 AND is_whitelisted = 0
    """, (ioc_value,))
    
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        return None
    
    ioc = dict(row)
    if ioc.get("mitre_tactics"):
        ioc["mitre_tactics"] = json.loads(ioc["mitre_tactics"])
    if ioc.get("mitre_techniques"):
        ioc["mitre_techniques"] = json.loads(ioc["mitre_techniques"])
    if ioc.get("tags"):
        ioc["tags"] = json.loads(ioc["tags"])
    
    return ioc


def get_iocs(
    ioc_type: Optional[str] = None,
    severity: Optional[str] = None,
    source: Optional[str] = None,
    limit: int = 100
) -> List[Dict[str, Any]]:
    """Get IOCs with filters"""
    conn = get_connection()
    cursor = conn.cursor()
    
    query = "SELECT * FROM iocs WHERE is_active = 1"
    params = []
    
    if ioc_type:
        query += " AND ioc_type = ?"
        params.append(ioc_type)
    
    if severity:
        query += " AND severity = ?"
        params.append(severity)
    
    if source:
        query += " AND source = ?"
        params.append(source)
    
    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)
    
    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()
    
    iocs = []
    for row in rows:
        ioc = dict(row)
        if ioc.get("mitre_tactics"):
            ioc["mitre_tactics"] = json.loads(ioc["mitre_tactics"])
        if ioc.get("mitre_techniques"):
            ioc["mitre_techniques"] = json.loads(ioc["mitre_techniques"])
        if ioc.get("tags"):
            ioc["tags"] = json.loads(ioc["tags"])
        iocs.append(ioc)
    
    return iocs


def check_ioc(value: str) -> Dict[str, Any]:
    """Check if value matches any IOC"""
    ioc = get_ioc(value)
    
    if ioc:
        return {
            "is_threat": True,
            "ioc_id": ioc["id"],
            "ioc_type": ioc["ioc_type"],
            "threat_type": ioc["threat_type"],
            "threat_name": ioc["threat_name"],
            "severity": ioc["severity"],
            "confidence": ioc["confidence"],
            "source": ioc["source"],
            "description": ioc["description"],
            "first_seen": ioc["first_seen"],
            "times_seen": ioc["times_seen"]
        }
    
    return {
        "is_threat": False,
        "message": "No threat intelligence match"
    }


def record_threat_match(
    ioc_id: int,
    matched_value: str,
    detection_source: str,
    file_path: Optional[str] = None,
    threat_level: str = "medium",
    confidence_score: float = 50.0,
    action_taken: str = "alerted"
) -> int:
    """Record IOC match"""
    conn = get_connection()
    cursor = conn.cursor()
    
    now = datetime.now().isoformat()
    
    cursor.execute("""
        INSERT INTO threat_matches 
        (ioc_id, matched_value, match_type, detection_source, file_path,
         threat_level, confidence_score, action_taken, matched_at)
        VALUES (?, ?, 'exact', ?, ?, ?, ?, ?, ?)
    """, (ioc_id, matched_value, detection_source, file_path,
          threat_level, confidence_score, action_taken, now))
    
    match_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    return match_id


def get_ioc_statistics() -> Dict[str, Any]:
    """Get IOC statistics"""
    conn = get_connection()
    cursor = conn.cursor()
    
    # Total IOCs
    cursor.execute("SELECT COUNT(*) as total FROM iocs WHERE is_active = 1")
    total = cursor.fetchone()["total"]
    
    # By type
    cursor.execute("""
        SELECT ioc_type, COUNT(*) as count 
        FROM iocs 
        WHERE is_active = 1
        GROUP BY ioc_type
    """)
    type_rows = cursor.fetchall()
    by_type = {row["ioc_type"]: row["count"] for row in type_rows}
    
    # By severity
    cursor.execute("""
        SELECT severity, COUNT(*) as count 
        FROM iocs 
        WHERE is_active = 1
        GROUP BY severity
    """)
    severity_rows = cursor.fetchall()
    by_severity = {row["severity"]: row["count"] for row in severity_rows}
    
    # Total matches
    cursor.execute("SELECT COUNT(*) as total FROM threat_matches")
    total_matches = cursor.fetchone()["total"]
    
    # Recent threats
    cursor.execute("""
        SELECT COUNT(*) as count 
        FROM iocs 
        WHERE is_active = 1 AND severity IN ('high', 'critical')
        AND date(created_at) >= date('now', '-7 days')
    """)
    recent_high = cursor.fetchone()["count"]
    
    conn.close()
    
    return {
        "total_iocs": total,
        "iocs_by_type": by_type,
        "iocs_by_severity": by_severity,
        "total_matches": total_matches,
        "recent_high_severity": recent_high,
        "last_updated": datetime.now().isoformat()
    }

# ============================================
# MITRE ATT&CK FUNCTIONS
# ============================================

def add_mitre_tactic(
    tactic_id: str,
    name: str,
    description: Optional[str] = None,
    url: Optional[str] = None
) -> int:
    """Add MITRE tactic"""
    conn = get_connection()
    cursor = conn.cursor()
    
    now = datetime.now().isoformat()
    
    try:
        cursor.execute("""
            INSERT INTO mitre_tactics (tactic_id, name, description, url, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (tactic_id, name, description, url, now, now))
        
        tactic_db_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return tactic_db_id
    
    except sqlite3.IntegrityError:
        conn.close()
        return -1


def get_mitre_tactics() -> List[Dict[str, Any]]:
    """Get all MITRE tactics"""
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM mitre_tactics ORDER BY tactic_id")
    rows = cursor.fetchall()
    conn.close()
    
    return [dict(row) for row in rows]


def add_mitre_technique(
    technique_id: str,
    name: str,
    tactic_id: str,
    description: Optional[str] = None,
    url: Optional[str] = None,
    platforms: Optional[List[str]] = None
) -> int:
    """Add MITRE technique"""
    conn = get_connection()
    cursor = conn.cursor()
    
    now = datetime.now().isoformat()
    
    # Get tactic DB ID
    cursor.execute("SELECT id FROM mitre_tactics WHERE tactic_id = ?", (tactic_id,))
    tactic_row = cursor.fetchone()
    
    if not tactic_row:
        conn.close()
        raise ValueError(f"Tactic {tactic_id} not found")
    
    tactic_db_id = tactic_row["id"]
    platforms_json = json.dumps(platforms) if platforms else None
    
    try:
        cursor.execute("""
            INSERT INTO mitre_techniques 
            (technique_id, name, description, url, tactic_id, platforms, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (technique_id, name, description, url, tactic_db_id, platforms_json, now, now))
        
        technique_db_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return technique_db_id
    
    except sqlite3.IntegrityError:
        conn.close()
        return -1


def get_mitre_techniques(tactic_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Get MITRE techniques, optionally filtered by tactic"""
    conn = get_connection()
    cursor = conn.cursor()
    
    if tactic_id:
        cursor.execute("""
            SELECT t.* FROM mitre_techniques t
            JOIN mitre_tactics tac ON t.tactic_id = tac.id
            WHERE tac.tactic_id = ?
            ORDER BY t.technique_id
        """, (tactic_id,))
    else:
        cursor.execute("SELECT * FROM mitre_techniques ORDER BY technique_id")
    
    rows = cursor.fetchall()
    conn.close()
    
    techniques = []
    for row in rows:
        tech = dict(row)
        if tech.get("platforms"):
            tech["platforms"] = json.loads(tech["platforms"])
        techniques.append(tech)
    
    return techniques


def add_threat_mitre_mapping(
    threat_id: int,
    threat_type: str,
    threat_name: str,
    technique_id: str,
    tactic_id: str,
    confidence: int = 50,
    mapping_source: str = "automatic",
    description: Optional[str] = None,
    evidence: Optional[Dict[str, Any]] = None
) -> int:
    """Add threat to MITRE technique mapping"""
    conn = get_connection()
    cursor = conn.cursor()
    
    now = datetime.now().isoformat()
    
    # Get technique and tactic DB IDs
    cursor.execute("SELECT id FROM mitre_techniques WHERE technique_id = ?", (technique_id,))
    tech_row = cursor.fetchone()
    
    cursor.execute("SELECT id FROM mitre_tactics WHERE tactic_id = ?", (tactic_id,))
    tac_row = cursor.fetchone()
    
    if not tech_row or not tac_row:
        conn.close()
        raise ValueError(f"Technique {technique_id} or Tactic {tactic_id} not found")
    
    tech_db_id = tech_row["id"]
    tac_db_id = tac_row["id"]
    evidence_json = json.dumps(evidence) if evidence else None
    
    cursor.execute("""
        INSERT INTO threat_mitre_mappings 
        (threat_id, threat_type, threat_name, technique_id, tactic_id,
         confidence, mapping_source, description, evidence, detected_at, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (threat_id, threat_type, threat_name, tech_db_id, tac_db_id,
          confidence, mapping_source, description, evidence_json, now, now))
    
    mapping_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    return mapping_id


def get_threat_mitre_mappings(threat_id: Optional[int] = None, limit: int = 100) -> List[Dict[str, Any]]:
    """Get threat-to-MITRE mappings"""
    conn = get_connection()
    cursor = conn.cursor()
    
    if threat_id:
        cursor.execute("""
            SELECT 
                tm.*,
                tac.tactic_id as tactic_mitre_id,
                tac.name as tactic_name,
                tech.technique_id as technique_mitre_id,
                tech.name as technique_name
            FROM threat_mitre_mappings tm
            JOIN mitre_tactics tac ON tm.tactic_id = tac.id
            JOIN mitre_techniques tech ON tm.technique_id = tech.id
            WHERE tm.threat_id = ?
            ORDER BY tm.detected_at DESC
        """, (threat_id,))
    else:
        cursor.execute("""
            SELECT 
                tm.*,
                tac.tactic_id as tactic_mitre_id,
                tac.name as tactic_name,
                tech.technique_id as technique_mitre_id,
                tech.name as technique_name
            FROM threat_mitre_mappings tm
            JOIN mitre_tactics tac ON tm.tactic_id = tac.id
            JOIN mitre_techniques tech ON tm.technique_id = tech.id
            ORDER BY tm.detected_at DESC
            LIMIT ?
        """, (limit,))
    
    rows = cursor.fetchall()
    conn.close()
    
    mappings = []
    for row in rows:
        mapping = dict(row)
        if mapping.get("evidence"):
            mapping["evidence"] = json.loads(mapping["evidence"])
        mappings.append(mapping)
    
    return mappings


def get_mitre_statistics() -> Dict[str, Any]:
    """Get MITRE ATT&CK statistics"""
    conn = get_connection()
    cursor = conn.cursor()
    
    # Total tactics and techniques
    cursor.execute("SELECT COUNT(*) as count FROM mitre_tactics")
    total_tactics = cursor.fetchone()["count"]
    
    cursor.execute("SELECT COUNT(*) as count FROM mitre_techniques")
    total_techniques = cursor.fetchone()["count"]
    
    # Total mappings
    cursor.execute("SELECT COUNT(*) as count FROM threat_mitre_mappings")
    total_mappings = cursor.fetchone()["count"]
    
    # Most mapped techniques
    cursor.execute("""
        SELECT 
            tech.technique_id,
            tech.name,
            COUNT(tm.id) as mapping_count
        FROM mitre_techniques tech
        LEFT JOIN threat_mitre_mappings tm ON tm.technique_id = tech.id
        GROUP BY tech.id
        HAVING mapping_count > 0
        ORDER BY mapping_count DESC
        LIMIT 10
    """)
    top_techniques_rows = cursor.fetchall()
    
    top_techniques = [
        {"technique_id": row["technique_id"], "name": row["name"], "count": row["mapping_count"]}
        for row in top_techniques_rows
    ]
    
    conn.close()
    
    return {
        "total_tactics": total_tactics,
        "total_techniques": total_techniques,
        "total_mappings": total_mappings,
        "top_mapped_techniques": top_techniques,
        "last_updated": datetime.now().isoformat()
        
    }
def correlate_threat_with_iocs(threat_id: int):
        """
        Correlate a threat with matching IOCs
        Returns list of matched IOCs
        """
        try:
            conn = sqlite3.connect(str(DB_PATH))
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Get threat details
            cursor.execute("""
                SELECT file_hash, file_path, detection_type, threat_name
                FROM threats
                WHERE id = ?
            """, (threat_id,))
            
            threat = cursor.fetchone()
            if not threat:
                return []
            
            matched_iocs = []
            
            # Check file hash match
            if threat['file_hash']:
                cursor.execute("""
                    SELECT id, ioc_value, ioc_type, threat_name, severity, confidence
                    FROM iocs
                    WHERE ioc_type = 'hash' AND ioc_value = ?
                """, (threat['file_hash'],))
                
                hash_matches = cursor.fetchall()
                for match in hash_matches:
                    matched_iocs.append(dict(match))
            
            # Check if file path contains malicious domains/IPs
            if threat['file_path']:
                cursor.execute("""
                    SELECT id, ioc_value, ioc_type, threat_name, severity, confidence
                    FROM iocs
                    WHERE ioc_type IN ('domain', 'ip', 'url')
                """)
                
                path_iocs = cursor.fetchall()
                for ioc in path_iocs:
                    if ioc['ioc_value'].lower() in threat['file_path'].lower():
                        matched_iocs.append(dict(ioc))
            
            conn.close()
            return matched_iocs
            
        except Exception as e:
            logger.error(f"Error correlating threat with IOCs: {e}")
            return []
    
def get_threat_correlations(threat_id: int):
        """
        Get all IOC correlations for a threat
        """
        try:
            correlations = correlate_threat_with_iocs(threat_id)
            
            return {
                "threat_id": threat_id,
                "matched_iocs": correlations,
                "match_count": len(correlations),
                "correlation_score": _calculate_correlation_score(correlations)
            }
            
        except Exception as e:
            logger.error(f"Error getting threat correlations: {e}")
            return {
                "threat_id": threat_id,
                "matched_iocs": [],
                "match_count": 0,
                "correlation_score": 0
            }
    
def _calculate_correlation_score(matched_iocs: list) -> float:
        """
        Calculate correlation confidence score (0-100)
        """
        if not matched_iocs:
            return 0.0
        
        total_confidence = sum(ioc.get('confidence', 50) for ioc in matched_iocs)
        avg_confidence = total_confidence / len(matched_iocs)
        
        match_bonus = min(len(matched_iocs) * 10, 30)
        
        score = min(avg_confidence + match_bonus, 100)
        return round(score, 1)   
    
    # ============================================================================
# INTEGRITY MONITORING FUNCTIONS
# ============================================================================

def log_integrity_check(file_path: str, expected_checksum: str, actual_checksum: str, 
                        status: str, details: str = None):
    """
    Log an integrity check result
    
    Args:
        file_path: Path to checked file
        expected_checksum: Expected SHA256 checksum
        actual_checksum: Actual SHA256 checksum (None if missing)
        status: Check status (OK, MODIFIED, MISSING, ERROR)
        details: Additional details
    """
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        INSERT INTO integrity_logs (file_path, expected_checksum, actual_checksum, status, details)
        VALUES (?, ?, ?, ?, ?)
    """, (file_path, expected_checksum, actual_checksum, status, details))
    
    conn.commit()
    conn.close()


def get_integrity_logs(limit: int = 100, status_filter: str = None):
    """
    Get integrity check logs
    
    Args:
        limit: Maximum number of logs to return
        status_filter: Filter by status (OK, MODIFIED, MISSING, ERROR)
        
    Returns:
        List of integrity logs
    """
    conn = get_connection()
    cursor = conn.cursor()
    
    if status_filter:
        cursor.execute("""
            SELECT * FROM integrity_logs 
            WHERE status = ?
            ORDER BY timestamp DESC 
            LIMIT ?
        """, (status_filter, limit))
    else:
        cursor.execute("""
            SELECT * FROM integrity_logs 
            ORDER BY timestamp DESC 
            LIMIT ?
        """, (limit,))
    
    logs = []
    for row in cursor.fetchall():
        logs.append({
            'id': row[0],
            'file_path': row[1],
            'expected_checksum': row[2],
            'actual_checksum': row[3],
            'status': row[4],
            'timestamp': row[5],
            'details': row[6]
        })
    
    conn.close()
    return logs


def save_manifest_to_db(version: str, manifest_data: dict):
    """
    Save manifest to database
    
    Args:
        version: Manifest version
        manifest_data: Manifest dictionary
    """
    import json
    
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        INSERT INTO file_manifests (version, manifest_data)
        VALUES (?, ?)
    """, (version, json.dumps(manifest_data)))
    
    conn.commit()
    conn.close()


def get_latest_manifest():
    """
    Get latest manifest from database
    
    Returns:
        Manifest dictionary or None
    """
    import json
    
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT * FROM file_manifests 
        ORDER BY created_at DESC 
        LIMIT 1
    """)
    
    row = cursor.fetchone()
    conn.close()
    
    if row:
        return {
            "id": row[0],
            "version": row[1],
            "manifest_data": json.loads(row[2]),
            "created_at": row[3]
        }
    
    return None


def get_all_manifests(limit: int = 10):
    """
    Get all manifests (for history)
    
    Args:
        limit: Maximum number of manifests to return
        
    Returns:
        List of manifest records
    """
    import json
    
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT id, version, created_at FROM file_manifests 
        ORDER BY created_at DESC 
        LIMIT ?
    """, (limit,))
    
    manifests = []
    for row in cursor.fetchall():
        manifests.append({
            'id': row[0],
            'version': row[1],
            'created_at': row[2]
        })
    
    conn.close()
    return manifests


def create_integrity_alert(alert_type: str, severity: str, message: str, 
                          file_path: str = None):
    """
    Create an integrity alert
    
    Args:
        alert_type: Type of alert (FILE_MODIFIED, FILE_MISSING, TAMPER_DETECTED)
        severity: Alert severity (LOW, MEDIUM, HIGH, CRITICAL)
        message: Alert message
        file_path: Path to affected file
    """
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        INSERT INTO integrity_alerts (alert_type, severity, file_path, message)
        VALUES (?, ?, ?, ?)
    """, (alert_type, severity, file_path, message))
    
    conn.commit()
    conn.close()


def get_integrity_alerts(resolved: bool = None, limit: int = 50):
    """
    Get integrity alerts
    
    Args:
        resolved: Filter by resolved status (True/False/None for all)
        limit: Maximum number of alerts
        
    Returns:
        List of alerts
    """
    conn = get_connection()
    cursor = conn.cursor()
    
    if resolved is not None:
        cursor.execute("""
            SELECT * FROM integrity_alerts 
            WHERE resolved = ?
            ORDER BY created_at DESC 
            LIMIT ?
        """, (1 if resolved else 0, limit))
    else:
        cursor.execute("""
            SELECT * FROM integrity_alerts 
            ORDER BY created_at DESC 
            LIMIT ?
        """, (limit,))
    
    alerts = []
    for row in cursor.fetchall():
        alerts.append({
            'id': row[0],
            'alert_type': row[1],
            'severity': row[2],
            'file_path': row[3],
            'message': row[4],
            'resolved': bool(row[5]),
            'created_at': row[6],
            'resolved_at': row[7]
        })
    
    conn.close()
    return alerts


def resolve_integrity_alert(alert_id: int):
    """
    Mark an integrity alert as resolved
    
    Args:
        alert_id: Alert ID
    """
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        UPDATE integrity_alerts 
        SET resolved = 1, resolved_at = CURRENT_TIMESTAMP
        WHERE id = ?
    """, (alert_id,))
    
    conn.commit()
    conn.close()


def get_integrity_statistics():
    """
    Get integrity monitoring statistics
    
    Returns:
        Dictionary with statistics
    """
    conn = get_connection()
    cursor = conn.cursor()
    
    # Total checks
    cursor.execute("SELECT COUNT(*) FROM integrity_logs")
    total_checks = cursor.fetchone()[0]
    
    # Checks by status
    cursor.execute("""
        SELECT status, COUNT(*) as count 
        FROM integrity_logs 
        GROUP BY status
    """)
    status_counts = {row[0]: row[1] for row in cursor.fetchall()}
    
    # Active alerts
    cursor.execute("SELECT COUNT(*) FROM integrity_alerts WHERE resolved = 0")
    active_alerts = cursor.fetchone()[0]
    
    # Recent compromised files (last 24 hours)
    cursor.execute("""
        SELECT COUNT(DISTINCT file_path) 
        FROM integrity_logs 
        WHERE status IN ('MODIFIED', 'MISSING') 
        AND timestamp > datetime('now', '-1 day')
    """)
    recent_compromised = cursor.fetchone()[0]
    
    # Total manifests
    cursor.execute("SELECT COUNT(*) FROM file_manifests")
    total_manifests = cursor.fetchone()[0]
    
    conn.close()
    
    return {
        "total_checks": total_checks,
        "status_counts": status_counts,
        "active_alerts": active_alerts,
        "recent_compromised": recent_compromised,
        "total_manifests": total_manifests
    }


def delete_old_integrity_logs(days: int = 30):
    """
    Delete integrity logs older than specified days
    
    Args:
        days: Number of days to keep logs
        
    Returns:
        Number of deleted logs
    """
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        DELETE FROM integrity_logs 
        WHERE timestamp < datetime('now', '-' || ? || ' days')
    """, (days,))
    
    deleted_count = cursor.rowcount
    conn.commit()
    conn.close()
    
    return deleted_count
    
# ============================================================================
# UPDATE HISTORY
# ============================================================================

def create_update_history_table():
    """Create update history table"""
    query = """
    CREATE TABLE IF NOT EXISTS update_history (
        id SERIAL PRIMARY KEY,
        from_version VARCHAR(50) NOT NULL,
        to_version VARCHAR(50) NOT NULL,
        update_type VARCHAR(20),
        status VARCHAR(50) NOT NULL,
        started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        completed_at TIMESTAMP,
        duration_seconds INTEGER,
        error_message TEXT,
        rollback_performed BOOLEAN DEFAULT FALSE,
        backup_path TEXT,
        download_size_bytes BIGINT,
        release_notes TEXT
    );
    
    CREATE INDEX IF NOT EXISTS idx_update_history_status 
    ON update_history(status);
    
    CREATE INDEX IF NOT EXISTS idx_update_history_versions 
    ON update_history(to_version, from_version);
    """
    execute_query(query)
    logger.info("✅ Update history table created")


def log_update_attempt(
    from_version: str,
    to_version: str,
    update_type: str,
    download_size: Optional[int] = None,
    release_notes: Optional[str] = None
) -> int:
    """
    Log update attempt
    
    Args:
        from_version: Current version
        to_version: Target version
        update_type: Type of update (major/minor/patch)
        download_size: Download size in bytes
        release_notes: Release notes
        
    Returns:
        Update history ID
    """
    query = """
    INSERT INTO update_history (
        from_version, to_version, update_type, status,
        download_size_bytes, release_notes
    )
    VALUES (%s, %s, %s, 'in_progress', %s, %s)
    RETURNING id;
    """
    
    result = execute_query(
        query,
        (from_version, to_version, update_type, download_size, release_notes),
        fetch=True
    )
    
    if result:
        update_id = result[0][0]
        logger.info(f"✅ Update attempt logged: ID {update_id}")
        return update_id
    
    return 0


def update_history_status(
    update_id: int,
    status: str,
    error_message: Optional[str] = None,
    rollback_performed: bool = False,
    backup_path: Optional[str] = None
):
    """
    Update history entry status
    
    Args:
        update_id: Update history ID
        status: New status (completed/failed/rolled_back)
        error_message: Error message if failed
        rollback_performed: Whether rollback was performed
        backup_path: Path to backup
    """
    query = """
    UPDATE update_history
    SET status = %s,
        completed_at = CURRENT_TIMESTAMP,
        duration_seconds = EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - started_at))::INTEGER,
        error_message = %s,
        rollback_performed = %s,
        backup_path = %s
    WHERE id = %s;
    """
    
    execute_query(query, (status, error_message, rollback_performed, backup_path, update_id))
    logger.info(f"✅ Update history updated: ID {update_id} - {status}")


def get_update_history(limit: int = 50) -> List[Dict[str, Any]]:
    """
    Get update history
    
    Args:
        limit: Maximum number of records
        
    Returns:
        List of update history records
    """
    query = """
    SELECT 
        id,
        from_version,
        to_version,
        update_type,
        status,
        started_at,
        completed_at,
        duration_seconds,
        error_message,
        rollback_performed,
        backup_path,
        download_size_bytes,
        release_notes
    FROM update_history
    ORDER BY started_at DESC
    LIMIT %s;
    """
    
    results = execute_query(query, (limit,), fetch=True)
    
    if not results:
        return []
    
    updates = []
    for row in results:
        updates.append({
            "id": row[0],
            "from_version": row[1],
            "to_version": row[2],
            "update_type": row[3],
            "status": row[4],
            "started_at": row[5].isoformat() if row[5] else None,
            "completed_at": row[6].isoformat() if row[6] else None,
            "duration_seconds": row[7],
            "error_message": row[8],
            "rollback_performed": row[9],
            "backup_path": row[10],
            "download_size_bytes": row[11],
            "release_notes": row[12]
        })
    
    return updates


def get_last_successful_update() -> Optional[Dict[str, Any]]:
    """
    Get last successful update
    
    Returns:
        Last successful update record
    """
    query = """
    SELECT 
        id, from_version, to_version, update_type,
        completed_at, duration_seconds
    FROM update_history
    WHERE status = 'completed'
    ORDER BY completed_at DESC
    LIMIT 1;
    """
    
    results = execute_query(query, fetch=True)
    
    if not results or not results[0]:
        return None
    
    row = results[0]
    return {
        "id": row[0],
        "from_version": row[1],
        "to_version": row[2],
        "update_type": row[3],
        "completed_at": row[4].isoformat() if row[4] else None,
        "duration_seconds": row[5]
    }
    
    # ============================================================================
# UPDATE HISTORY FUNCTIONS
# ============================================================================

def log_update_attempt(
    from_version: str,
    to_version: str,
    update_type: str,
    download_size: Optional[int] = None,
    release_notes: Optional[str] = None
) -> int:
    """
    Log update attempt
    
    Args:
        from_version: Current version
        to_version: Target version
        update_type: Type of update (major/minor/patch)
        download_size: Download size in bytes
        release_notes: Release notes
        
    Returns:
        Update history ID
    """
    conn = get_connection()
    cursor = conn.cursor()
    
    now = datetime.now().isoformat()
    
    cursor.execute("""
        INSERT INTO update_history (
            from_version, to_version, update_type, status,
            started_at, download_size_bytes, release_notes
        )
        VALUES (?, ?, ?, 'in_progress', ?, ?, ?)
    """, (from_version, to_version, update_type, now, download_size, release_notes))
    
    update_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    logger.info(f"✅ Update attempt logged: ID {update_id}")
    return update_id


def update_history_status(
    update_id: int,
    status: str,
    error_message: Optional[str] = None,
    rollback_performed: bool = False,
    backup_path: Optional[str] = None
):
    """
    Update history entry status
    
    Args:
        update_id: Update history ID
        status: New status (completed/failed/rolled_back)
        error_message: Error message if failed
        rollback_performed: Whether rollback was performed
        backup_path: Path to backup
    """
    conn = get_connection()
    cursor = conn.cursor()
    
    now = datetime.now().isoformat()
    
    # Calculate duration
    cursor.execute("SELECT started_at FROM update_history WHERE id = ?", (update_id,))
    row = cursor.fetchone()
    
    duration_seconds = None
    if row:
        started_at = datetime.fromisoformat(row[0])
        duration_seconds = int((datetime.now() - started_at).total_seconds())
    
    cursor.execute("""
        UPDATE update_history
        SET status = ?,
            completed_at = ?,
            duration_seconds = ?,
            error_message = ?,
            rollback_performed = ?,
            backup_path = ?
        WHERE id = ?
    """, (status, now, duration_seconds, error_message, int(rollback_performed), backup_path, update_id))
    
    conn.commit()
    conn.close()
    
    logger.info(f"✅ Update history updated: ID {update_id} - {status}")


def get_update_history(limit: int = 50) -> List[Dict[str, Any]]:
    """
    Get update history
    
    Args:
        limit: Maximum number of records
        
    Returns:
        List of update history records
    """
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT 
            id, from_version, to_version, update_type, status,
            started_at, completed_at, duration_seconds,
            error_message, rollback_performed, backup_path,
            download_size_bytes, release_notes
        FROM update_history
        ORDER BY started_at DESC
        LIMIT ?
    """, (limit,))
    
    rows = cursor.fetchall()
    conn.close()
    
    updates = []
    for row in rows:
        updates.append({
            "id": row[0],
            "from_version": row[1],
            "to_version": row[2],
            "update_type": row[3],
            "status": row[4],
            "started_at": row[5],
            "completed_at": row[6],
            "duration_seconds": row[7],
            "error_message": row[8],
            "rollback_performed": bool(row[9]),
            "backup_path": row[10],
            "download_size_bytes": row[11],
            "release_notes": row[12]
        })
    
    return updates


def get_last_successful_update() -> Optional[Dict[str, Any]]:
    """
    Get last successful update
    
    Returns:
        Last successful update record
    """
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT 
            id, from_version, to_version, update_type,
            completed_at, duration_seconds
        FROM update_history
        WHERE status = 'completed'
        ORDER BY completed_at DESC
        LIMIT 1
    """)
    
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        return None
    
    return {
        "id": row[0],
        "from_version": row[1],
        "to_version": row[2],
        "update_type": row[3],
        "completed_at": row[4],
        "duration_seconds": row[5]
    }


def get_update_statistics() -> Dict[str, Any]:
    """
    Get update statistics
    
    Returns:
        Statistics dictionary
    """
    conn = get_connection()
    cursor = conn.cursor()
    
    # Total updates
    cursor.execute("SELECT COUNT(*) FROM update_history")
    total = cursor.fetchone()[0]
    
    # Successful updates
    cursor.execute("SELECT COUNT(*) FROM update_history WHERE status = 'completed'")
    successful = cursor.fetchone()[0]
    
    # Failed updates
    cursor.execute("SELECT COUNT(*) FROM update_history WHERE status = 'failed'")
    failed = cursor.fetchone()[0]
    
    # Rollbacks
    cursor.execute("SELECT COUNT(*) FROM update_history WHERE rollback_performed = 1")
    rollbacks = cursor.fetchone()[0]
    
    # Last update
    cursor.execute("""
        SELECT to_version, completed_at 
        FROM update_history 
        WHERE status = 'completed' 
        ORDER BY completed_at DESC 
        LIMIT 1
    """)
    last_update_row = cursor.fetchone()
    
    last_update = None
    if last_update_row:
        last_update = {
            "version": last_update_row[0],
            "date": last_update_row[1]
        }
    
    conn.close()
    
    return {
        "total_updates": total,
        "successful_updates": successful,
        "failed_updates": failed,
        "rollbacks": rollbacks,
        "last_update": last_update
    }
# Initialize database on module import
init_database()