import sqlite3
import os

db_path = os.path.join(os.path.dirname(__file__), 'instance', 'sdms.db')

if os.path.exists(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # 1. Update Document table
    cursor.execute("PRAGMA table_info(document)")
    doc_cols = [info[1] for info in cursor.fetchall()]
    
    if 'is_signed' not in doc_cols:
        print("Adding is_signed to document table...")
        cursor.execute("ALTER TABLE document ADD COLUMN is_signed BOOLEAN DEFAULT 0;")
        
    if 'signed_by_id' not in doc_cols:
        print("Adding signed_by_id to document table...")
        cursor.execute("ALTER TABLE document ADD COLUMN signed_by_id INTEGER REFERENCES user(id);")
        
    if 'signed_at' not in doc_cols:
        print("Adding signed_at to document table...")
        cursor.execute("ALTER TABLE document ADD COLUMN signed_at DATETIME;")
        
    if 'signature_hash' not in doc_cols:
        print("Adding signature_hash to document table...")
        cursor.execute("ALTER TABLE document ADD COLUMN signature_hash VARCHAR(100);")

    # 2. Update User table
    cursor.execute("PRAGMA table_info(user)")
    user_cols = [info[1] for info in cursor.fetchall()]
    
    if 'totp_secret' not in user_cols:
        print("Adding totp_secret to user table...")
        cursor.execute("ALTER TABLE user ADD COLUMN totp_secret VARCHAR(100);")
        
    if 'is_2fa_enabled' not in user_cols:
        print("Adding is_2fa_enabled to user table...")
        cursor.execute("ALTER TABLE user ADD COLUMN is_2fa_enabled BOOLEAN DEFAULT 0;")

    # 3. Create SecuritySetting table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS security_setting (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_whitelist_enabled BOOLEAN DEFAULT 0,
        allowed_ips TEXT DEFAULT '127.0.0.1, ::1'
    )
    ''')
    
    # Seed default security setting if empty
    cursor.execute("SELECT COUNT(*) FROM security_setting")
    if cursor.fetchone()[0] == 0:
        cursor.execute("INSERT INTO security_setting (ip_whitelist_enabled, allowed_ips) VALUES (0, '127.0.0.1, ::1')")

    conn.commit()
    conn.close()
    print("Database migration for Enterprise Security Suite complete.")
else:
    print("Database file not found yet. Models will create it.")
