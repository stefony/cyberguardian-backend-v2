import sqlite3
from pathlib import Path

# Connect to database
db_path = Path("database/cyberguardian.db")

if not db_path.exists():
    print("❌ Database file NOT found!")
    print(f"Expected path: {db_path.absolute()}")
else:
    print("✅ Database file found!")
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Check if users table exists
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users';")
    table_exists = cursor.fetchone()
    
    if not table_exists:
        print("❌ 'users' table does NOT exist!")
    else:
        print("✅ 'users' table exists!")
        
        # Get all users
        cursor.execute("SELECT id, email, username, is_admin, is_active FROM users;")
        users = cursor.fetchall()
        
        if len(users) == 0:
            print("\n⚠️ NO USERS in database!")
        else:
            print(f"\n📊 Found {len(users)} user(s):")
            print("-" * 80)
            for user in users:
                print(f"ID: {user[0]}")
                print(f"Email: {user[1]}")
                print(f"Username: {user[2]}")
                print(f"Is Admin: {user[3]}")
                print(f"Is Active: {user[4]}")
                print("-" * 80)
    
    conn.close()
    