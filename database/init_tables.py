"""
Database initialization with PostgreSQL/SQLite compatibility
"""

import os

def get_auto_id_syntax():
    """Returns correct auto-increment syntax based on database type"""
    is_postgres = bool(os.getenv("DATABASE_URL"))
    return "SERIAL PRIMARY KEY" if is_postgres else "INTEGER PRIMARY KEY AUTOINCREMENT"

def get_datetime_type():
    """Returns correct datetime type based on database"""
    is_postgres = bool(os.getenv("DATABASE_URL"))
    return "TIMESTAMP" if is_postgres else "DATETIME"

def init_database(conn):
    """
    Initialize all database tables
    PostgreSQL and SQLite compatible
    """
    cursor = conn.cursor()
    auto_id = get_auto_id_syntax()
    dt_type = get_datetime_type()
    
    tables = [
        # Threats
        f"""CREATE TABLE IF NOT EXISTS threats (
            id {auto_id},
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
        )""",
        
        # Threat actions
        f"""CREATE TABLE IF NOT EXISTS threat_actions (
            id {auto_id},
            threat_id INTEGER NOT NULL,
            action TEXT NOT NULL,
            reason TEXT,
            performed_at TEXT NOT NULL,
            FOREIGN KEY (threat_id) REFERENCES threats (id)
        )""",
        
        # Scans
        f"""CREATE TABLE IF NOT EXISTS scans (
            id {auto_id},
            scan_type TEXT NOT NULL,
            status TEXT NOT NULL,
            started_at TEXT NOT NULL,
            completed_at TEXT,
            duration_seconds REAL,
            items_scanned INTEGER NOT NULL DEFAULT 0,
            threats_found INTEGER NOT NULL DEFAULT 0,
            results TEXT
        )""",
        
        # Honeypots
        f"""CREATE TABLE IF NOT EXISTS honeypots (
            id {auto_id},
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
        )""",
        
        # Honeypot logs
        f"""CREATE TABLE IF NOT EXISTS honeypot_logs (
            id {auto_id},
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
        )""",
        
        # Filesystem events
        f"""CREATE TABLE IF NOT EXISTS fs_events (
            id {auto_id},
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
        )""",
        
        # Protection settings
        f"""CREATE TABLE IF NOT EXISTS protection_settings (
            id INTEGER PRIMARY KEY DEFAULT 1,
            enabled INTEGER NOT NULL DEFAULT 0,
            watch_paths TEXT NOT NULL,
            auto_quarantine INTEGER NOT NULL DEFAULT 0,
            threat_threshold INTEGER NOT NULL DEFAULT 80,
            updated_at TEXT NOT NULL,
            CHECK (id = 1)
        )""",
        
        # Exclusions
        f"""CREATE TABLE IF NOT EXISTS exclusions (
            id {auto_id},
            type TEXT NOT NULL,
            value TEXT NOT NULL,
            reason TEXT,
            created_at TEXT NOT NULL,
            created_by TEXT,
            UNIQUE(type, value)
        )""",
        
        # IOCs
        f"""CREATE TABLE IF NOT EXISTS iocs (
            id {auto_id},
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
        )""",
        
        # MITRE tactics
        f"""CREATE TABLE IF NOT EXISTS mitre_tactics (
            id {auto_id},
            tactic_id TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL,
            description TEXT,
            url TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )""",
        
        # MITRE techniques
        f"""CREATE TABLE IF NOT EXISTS mitre_techniques (
            id {auto_id},
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
        )""",
        
        # Threat MITRE mappings
        f"""CREATE TABLE IF NOT EXISTS threat_mitre_mappings (
            id {auto_id},
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
        )""",
        
        # MITRE detection coverage
        f"""CREATE TABLE IF NOT EXISTS mitre_detection_coverage (
            id {auto_id},
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
        )""",
        
        # Threat feeds
        f"""CREATE TABLE IF NOT EXISTS threat_feeds (
            id {auto_id},
            name TEXT NOT NULL UNIQUE,
            feed_type TEXT NOT NULL,
            url TEXT,
            api_key TEXT,
            enabled INTEGER DEFAULT 1,
            refresh_interval INTEGER DEFAULT 3600,
            last_refresh TEXT,
            total_iocs INTEGER DEFAULT 0,
            successful_updates INTEGER NOT NULL DEFAULT 0,
            failed_updates INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )""",
        
        # Threat matches
        f"""CREATE TABLE IF NOT EXISTS threat_matches (
            id {auto_id},
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
        )""",
        
        # Scan schedules
        f"""CREATE TABLE IF NOT EXISTS scan_schedules (
            id {auto_id},
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
        )""",
        
        # Scan history
        f"""CREATE TABLE IF NOT EXISTS scan_history (
            id {auto_id},
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
        )""",
        
        # Users
        f"""CREATE TABLE IF NOT EXISTS users (
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
        )""",
        
        # User email accounts
        f"""CREATE TABLE IF NOT EXISTS user_email_accounts (
            id {auto_id},
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
        )""",
        
        # Email scan history
        f"""CREATE TABLE IF NOT EXISTS email_scan_history (
            id {auto_id},
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
        )""",
        
        # Scanned emails
        f"""CREATE TABLE IF NOT EXISTS scanned_emails (
            id {auto_id},
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
        )""",
        
        # Licenses
        f"""CREATE TABLE IF NOT EXISTS licenses (
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
        )""",
        
        # Device activations
        f"""CREATE TABLE IF NOT EXISTS device_activations (
            id {auto_id},
            license_id TEXT NOT NULL,
            device_id TEXT NOT NULL,
            device_name TEXT,
            activated_at TEXT NOT NULL,
            last_seen TEXT,
            is_active INTEGER NOT NULL DEFAULT 1,
            FOREIGN KEY (license_id) REFERENCES licenses (id)
        )""",
        
        # Integrity logs
        f"""CREATE TABLE IF NOT EXISTS integrity_logs (
            id {auto_id},
            file_path TEXT NOT NULL,
            expected_checksum TEXT NOT NULL,
            actual_checksum TEXT,
            status TEXT NOT NULL,
            timestamp {dt_type} DEFAULT CURRENT_TIMESTAMP,
            details TEXT
        )""",
        
        # File manifests
        f"""CREATE TABLE IF NOT EXISTS file_manifests (
            id {auto_id},
            version TEXT NOT NULL,
            manifest_data TEXT NOT NULL,
            created_at {dt_type} DEFAULT CURRENT_TIMESTAMP
        )""",
        
        # Integrity alerts
        f"""CREATE TABLE IF NOT EXISTS integrity_alerts (
            id {auto_id},
            alert_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            file_path TEXT,
            message TEXT NOT NULL,
            resolved INTEGER DEFAULT 0,
            created_at {dt_type} DEFAULT CURRENT_TIMESTAMP,
            resolved_at {dt_type}
        )""",
        
        # Update history
        f"""CREATE TABLE IF NOT EXISTS update_history (
            id {auto_id},
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
        )""",
    ]
    
    # Execute all CREATE TABLE statements
    for table_sql in tables:
        cursor.execute(table_sql)
    
    # Create indexes
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_update_history_status 
        ON update_history(status)
    """)
    
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_update_history_versions 
        ON update_history(to_version, from_version)
    """)
    
    conn.commit()
    print("✅ Database tables initialized")