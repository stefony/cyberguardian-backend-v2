"""
Initialize default admin user if not exists
"""
import sys
import os
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.auth import hash_password
from database.db import get_connection
from database.postgres import convert_query_placeholders


def init_admin_user():
    """Create default admin user if not exists"""
    
    try:
        conn = get_connection()
        cursor = conn.cursor()
        
        # Check if admin exists
        query = "SELECT id FROM users WHERE email = ?"
        params = ['admin@cyberguardian.ai']
        query, params = convert_query_placeholders(query, params)
        
        cursor.execute(query, params)
        admin_exists = cursor.fetchone()
        
        if admin_exists:
            # Update existing admin to ensure correct password and admin status
            hashed_pwd = hash_password("Admin123!")
            
            update_query = """
                UPDATE users 
                SET hashed_password = ?, is_admin = 1, is_active = 1
                WHERE email = ?
            """
            update_params = [hashed_pwd, 'admin@cyberguardian.ai']
            update_query, update_params = convert_query_placeholders(update_query, update_params)
            
            cursor.execute(update_query, update_params)
            conn.commit()
            print("✅ Admin user updated successfully")
        else:
            # Create new admin
            import uuid
            from datetime import datetime
            
            user_id = str(uuid.uuid4())
            hashed_pwd = hash_password("Admin123!")
            now = datetime.utcnow().isoformat()
            
            insert_query = """
                INSERT INTO users (
                    id, email, username, hashed_password, 
                    full_name, company, is_active, is_verified, 
                    is_admin, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """
            insert_params = [
                user_id, 
                "admin@cyberguardian.ai",
                "admin",
                hashed_pwd,
                "System Administrator",
                "CyberGuardian AI",
                1, 1, 1,
                now, now
            ]
            insert_query, insert_params = convert_query_placeholders(insert_query, insert_params)
            
            cursor.execute(insert_query, insert_params)
            conn.commit()
            print("✅ Admin user created successfully")
        
        conn.close()
        
    except Exception as e:
        print(f"⚠️  Admin user initialization skipped: {e}")


if __name__ == "__main__":
    init_admin_user()