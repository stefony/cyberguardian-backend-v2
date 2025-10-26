import sqlite3
from pathlib import Path
from dotenv import load_dotenv

# Load .env FIRST
load_dotenv()

# NOW import after .env is loaded
from core.auth import hash_password

# New admin password
new_password = "Admin123!"
hashed = hash_password(new_password)

# Connect to database
db_path = Path("database/cyberguardian.db")
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# Update admin user
cursor.execute("""
    UPDATE users 
    SET hashed_password = ?, is_admin = 1 
    WHERE email = 'admin@cyberguardian.ai'
""", (hashed,))

conn.commit()

# Verify
cursor.execute("SELECT email, username, is_admin FROM users WHERE email = 'admin@cyberguardian.ai'")
admin = cursor.fetchone()

print("✅ Admin updated successfully!")
print(f"Email: {admin[0]}")
print(f"Username: {admin[1]}")
print(f"Is Admin: {admin[2]}")
print(f"New Password: {new_password}")

conn.close()