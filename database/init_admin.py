"""
Initialize default admin user if not exists
"""
import sqlite3
from pathlib import Path
import sys
import os

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.auth import hash_password


def init_admin_user():
    """Create default admin user if not exists"""
    
    db_path = Path(__file__).parent / "cyberguardian.db"
    
    if not db_path.exists():
        print("⚠️  Database not found, skipping admin init")
        return
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Check if admin exists
    cursor.execute("SELECT id FROM users WHERE email = 'admin@cyberguardian.ai'")
    admin_exists = cursor.fetchone()
    
    if admin_exists:
        # Update existing admin to ensure correct password and admin status
        hashed_pwd = hash_password("Admin123!")
        cursor.execute("""
            UPDATE users 
            SET hashed_password = ?, is_admin = 1, is_active = 1
            WHERE email = 'admin@cyberguardian.ai'
        """, (hashed_pwd,))
        conn.commit()
        print("✅ Admin user updated successfully")
    else:
        # Create new admin
        import uuid
        from datetime import datetime
        
        user_id = str(uuid.uuid4())
        hashed_pwd = hash_password("Admin123!")
        now = datetime.utcnow().isoformat()
        
        cursor.execute("""
            INSERT INTO users (
                id, email, username, hashed_password, 
                full_name, company, is_active, is_verified, 
                is_admin, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            user_id, 
            "admin@cyberguardian.ai",
            "admin",
            hashed_pwd,
            "System Administrator",
            "CyberGuardian AI",
            1, 1, 1,
            now, now
        ))
        conn.commit()
        print("✅ Admin user created successfully")
    
    conn.close()


if __name__ == "__main__":
    init_admin_user()