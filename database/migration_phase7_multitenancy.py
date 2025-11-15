"""
CyberGuardian AI - PHASE 7 Database Migration
Multi-Tenancy & Data Isolation

Adds organization_id to all critical tables for tenant isolation.
"""

import sqlite3
from pathlib import Path
from datetime import datetime
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database path
DB_PATH = Path(__file__).parent / "cyberguardian.db"


def backup_database():
    """Create backup before migration"""
    import shutil
    
    backup_path = Path(__file__).parent / f"cyberguardian_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
    
    try:
        shutil.copy2(DB_PATH, backup_path)
        logger.info(f"✅ Database backed up to: {backup_path}")
        return str(backup_path)
    except Exception as e:
        logger.error(f"❌ Backup failed: {e}")
        return None


def run_migration():
    """
    Run Phase 7 migration - Add organization_id to tables
    """
    logger.info("=" * 60)
    logger.info("🚀 PHASE 7 MIGRATION: Multi-Tenancy")
    logger.info("=" * 60)
    
    # Backup first
    backup_path = backup_database()
    if not backup_path:
        logger.error("❌ Cannot proceed without backup!")
        return False
    
    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.cursor()
    
    try:
        # ============================================
        # 1. Add organization_id to threats table
        # ============================================
        logger.info("📝 Adding organization_id to threats table...")
        
        cursor.execute("PRAGMA table_info(threats)")
        columns = [col[1] for col in cursor.fetchall()]
        
        if 'organization_id' not in columns:
            cursor.execute("""
                ALTER TABLE threats 
                ADD COLUMN organization_id TEXT
            """)
            logger.info("   ✅ Added organization_id to threats")
        else:
            logger.info("   ⏭️  organization_id already exists in threats")
        
        # ============================================
        # 2. Add organization_id to scans table
        # ============================================
        logger.info("📝 Adding organization_id to scans table...")
        
        cursor.execute("PRAGMA table_info(scans)")
        columns = [col[1] for col in cursor.fetchall()]
        
        if 'organization_id' not in columns:
            cursor.execute("""
                ALTER TABLE scans 
                ADD COLUMN organization_id TEXT
            """)
            logger.info("   ✅ Added organization_id to scans")
        else:
            logger.info("   ⏭️  organization_id already exists in scans")
        
        # ============================================
        # 3. Add organization_id to fs_events table
        # ============================================
        logger.info("📝 Adding organization_id to fs_events table...")
        
        cursor.execute("PRAGMA table_info(fs_events)")
        columns = [col[1] for col in cursor.fetchall()]
        
        if 'organization_id' not in columns:
            cursor.execute("""
                ALTER TABLE fs_events 
                ADD COLUMN organization_id TEXT
            """)
            logger.info("   ✅ Added organization_id to fs_events")
        else:
            logger.info("   ⏭️  organization_id already exists in fs_events")
        
        # ============================================
        # 4. Add organization_id to honeypots table
        # ============================================
        logger.info("📝 Adding organization_id to honeypots table...")
        
        cursor.execute("PRAGMA table_info(honeypots)")
        columns = [col[1] for col in cursor.fetchall()]
        
        if 'organization_id' not in columns:
            cursor.execute("""
                ALTER TABLE honeypots 
                ADD COLUMN organization_id TEXT
            """)
            logger.info("   ✅ Added organization_id to honeypots")
        else:
            logger.info("   ⏭️  organization_id already exists in honeypots")
        
        # ============================================
        # 5. Add organization_id to honeypot_logs table
        # ============================================
        logger.info("📝 Adding organization_id to honeypot_logs table...")
        
        cursor.execute("PRAGMA table_info(honeypot_logs)")
        columns = [col[1] for col in cursor.fetchall()]
        
        if 'organization_id' not in columns:
            cursor.execute("""
                ALTER TABLE honeypot_logs 
                ADD COLUMN organization_id TEXT
            """)
            logger.info("   ✅ Added organization_id to honeypot_logs")
        else:
            logger.info("   ⏭️  organization_id already exists in honeypot_logs")
        
        # ============================================
        # 6. Add organization_id to iocs table
        # ============================================
        logger.info("📝 Adding organization_id to iocs table...")
        
        cursor.execute("PRAGMA table_info(iocs)")
        columns = [col[1] for col in cursor.fetchall()]
        
        if 'organization_id' not in columns:
            cursor.execute("""
                ALTER TABLE iocs 
                ADD COLUMN organization_id TEXT
            """)
            logger.info("   ✅ Added organization_id to iocs")
        else:
            logger.info("   ⏭️  organization_id already exists in iocs")
        
        # ============================================
        # 7. Add organization_id to scan_schedules table
        # ============================================
        logger.info("📝 Adding organization_id to scan_schedules table...")
        
        cursor.execute("PRAGMA table_info(scan_schedules)")
        columns = [col[1] for col in cursor.fetchall()]
        
        if 'organization_id' not in columns:
            cursor.execute("""
                ALTER TABLE scan_schedules 
                ADD COLUMN organization_id TEXT
            """)
            logger.info("   ✅ Added organization_id to scan_schedules")
        else:
            logger.info("   ⏭️  organization_id already exists in scan_schedules")
        
        # ============================================
        # 8. Create indexes for performance
        # ============================================
        logger.info("📝 Creating indexes for organization_id...")
        
        indexes = [
            ("idx_threats_org", "threats", "organization_id"),
            ("idx_scans_org", "scans", "organization_id"),
            ("idx_fs_events_org", "fs_events", "organization_id"),
            ("idx_honeypots_org", "honeypots", "organization_id"),
            ("idx_honeypot_logs_org", "honeypot_logs", "organization_id"),
            ("idx_iocs_org", "iocs", "organization_id"),
            ("idx_scan_schedules_org", "scan_schedules", "organization_id"),
        ]
        
        for idx_name, table_name, column_name in indexes:
            try:
                cursor.execute(f"""
                    CREATE INDEX IF NOT EXISTS {idx_name} 
                    ON {table_name}({column_name})
                """)
                logger.info(f"   ✅ Created index: {idx_name}")
            except Exception as e:
                logger.warning(f"   ⚠️  Index {idx_name} creation skipped: {e}")
        
        # ============================================
        # 9. Create audit_logs table
        # ============================================
        logger.info("📝 Creating audit_logs table...")
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                organization_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                action TEXT NOT NULL,
                resource_type TEXT NOT NULL,
                resource_id TEXT,
                ip_address TEXT,
                user_agent TEXT,
                details TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (organization_id) REFERENCES organizations(id),
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        logger.info("   ✅ Created audit_logs table")
        
        # Create audit logs index
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_audit_logs_org 
            ON audit_logs(organization_id)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_audit_logs_user 
            ON audit_logs(user_id)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_audit_logs_created 
            ON audit_logs(created_at)
        """)
        logger.info("   ✅ Created audit_logs indexes")
        
        # ============================================
        # Commit changes
        # ============================================
        conn.commit()
        
        logger.info("=" * 60)
        logger.info("✅ PHASE 7 MIGRATION COMPLETED SUCCESSFULLY!")
        logger.info("=" * 60)
        logger.info(f"📦 Backup saved: {backup_path}")
        logger.info("🔒 Multi-tenancy columns added")
        logger.info("📊 Indexes created for performance")
        logger.info("📝 Audit logs table created")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Migration failed: {e}")
        conn.rollback()
        logger.error(f"💡 Restore from backup: {backup_path}")
        return False
        
    finally:
        conn.close()


def verify_migration():
    """Verify migration was successful"""
    logger.info("\n" + "=" * 60)
    logger.info("🔍 VERIFYING MIGRATION")
    logger.info("=" * 60)
    
    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.cursor()
    
    tables_to_check = [
        "threats", "scans", "fs_events", "honeypots", 
        "honeypot_logs", "iocs", "scan_schedules", "audit_logs"
    ]
    
    all_good = True
    
    for table in tables_to_check:
        try:
            cursor.execute(f"PRAGMA table_info({table})")
            columns = [col[1] for col in cursor.fetchall()]
            
            if table == "audit_logs":
                # Just check if table exists
                logger.info(f"✅ {table}: EXISTS")
            elif 'organization_id' in columns:
                logger.info(f"✅ {table}: organization_id column present")
            else:
                logger.error(f"❌ {table}: organization_id column MISSING")
                all_good = False
                
        except Exception as e:
            logger.error(f"❌ {table}: Error checking - {e}")
            all_good = False
    
    conn.close()
    
    if all_good:
        logger.info("=" * 60)
        logger.info("✅ ALL CHECKS PASSED!")
        logger.info("=" * 60)
    else:
        logger.error("=" * 60)
        logger.error("❌ SOME CHECKS FAILED!")
        logger.error("=" * 60)
    
    return all_good


if __name__ == "__main__":
    print("\n")
    print("🛡️  CyberGuardian AI - PHASE 7 Migration")
    print("   Multi-Tenancy & Data Isolation")
    print("=" * 60)
    print()
    
    response = input("⚠️  This will modify the database. Continue? (yes/no): ")
    
    if response.lower() == "yes":
        success = run_migration()
        
        if success:
            verify_migration()
        else:
            print("\n❌ Migration failed! Check logs above.")
    else:
        print("\n🚫 Migration cancelled.")