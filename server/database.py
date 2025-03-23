import sqlite3
import hashlib
import os
import pyotp
from datetime import datetime

DB_FILE = 'server/storage.db'

def create_tables():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0,
            otp_secret TEXT
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            encrypted_data BLOB NOT NULL,
            FOREIGN KEY (owner_id) REFERENCES users(id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS shared_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id INTEGER NOT NULL,
            shared_user_id INTEGER NOT NULL,
            FOREIGN KEY (file_id) REFERENCES files(id),
            FOREIGN KEY (shared_user_id) REFERENCES users(id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            detail TEXT,
            timestamp TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')

    conn.commit()
    conn.close()

def create_user(username, password, is_admin=False):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    salt = os.urandom(16).hex()
    password_hash = hashlib.pbkdf2_hmac(
        'sha256', password.encode(), salt.encode(), 100000
    ).hex()

    admin_val = 1 if is_admin else 0
    otp_secret = pyotp.random_base32()
    try:
        cursor.execute(
            "INSERT INTO users (username, password_hash, salt, is_admin, otp_secret) VALUES (?, ?, ?, ?, ?)", 
            (username, password_hash, salt, admin_val, otp_secret)
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return (False, None)
    conn.close()
    return (True, otp_secret)

def verify_user(username, password):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    # 參數化查詢
    cursor.execute("SELECT password_hash, salt FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()
    if row:
        stored_hash, salt = row
        input_hash = hashlib.pbkdf2_hmac(
            'sha256', password.encode(), salt.encode(), 100000
        ).hex()
        return stored_hash == input_hash
    return False

def update_password(username, new_password):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return False

    salt = os.urandom(16).hex()
    new_hash = hashlib.pbkdf2_hmac(
        'sha256', new_password.encode(), salt.encode(), 100000
    ).hex()
    cursor.execute(
        "UPDATE users SET password_hash = ?, salt = ? WHERE username = ?", 
        (new_hash, salt, username)
    )
    conn.commit()
    conn.close()
    return True

def is_admin_user(username):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT is_admin FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return (row[0] == 1)
    return False

def get_user_id(username):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else None

def get_username_by_id(user_id):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else None

def upload_file_db(owner_id, filename, encrypted_data):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO files (owner_id, filename, encrypted_data) VALUES (?, ?, ?)",
        (owner_id, filename, encrypted_data)
    )
    conn.commit()
    conn.close()

def get_user_files(owner_id):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT id, filename FROM files WHERE owner_id = ?", (owner_id,))
    files = cursor.fetchall()
    conn.close()
    return files

def get_file_by_id(file_id):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT owner_id, filename, encrypted_data FROM files WHERE id = ?", (file_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return {
            "owner_id": row[0],
            "filename": row[1],
            "encrypted_data": row[2]
        }
    return None

def delete_file_db(file_id, owner_id):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM files WHERE id = ? AND owner_id = ?", (file_id, owner_id))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return False

    cursor.execute("DELETE FROM shared_files WHERE file_id = ?", (file_id,))
    cursor.execute("DELETE FROM files WHERE id = ?", (file_id,))
    conn.commit()
    conn.close()
    return True

def share_file_db(file_id, shared_user_id):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id FROM shared_files 
        WHERE file_id = ? AND shared_user_id = ?
    """, (file_id, shared_user_id))
    row = cursor.fetchone()
    if row:
        conn.close()
        return False

    cursor.execute("""
        INSERT INTO shared_files (file_id, shared_user_id) 
        VALUES (?, ?)
    """, (file_id, shared_user_id))
    conn.commit()
    conn.close()
    return True

def unshare_file_db(file_id, shared_user_id):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        DELETE FROM shared_files
        WHERE file_id = ? AND shared_user_id = ?
    """, (file_id, shared_user_id))
    affected = cursor.rowcount
    conn.commit()
    conn.close()
    return (affected > 0)

def has_access(user_id, file_id):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT owner_id FROM files WHERE id = ?", (file_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return False
    owner_id = row[0]
    if owner_id == user_id:
        conn.close()
        return True

    cursor.execute("""
        SELECT id FROM shared_files 
        WHERE file_id = ? AND shared_user_id = ?
    """, (file_id, user_id))
    row2 = cursor.fetchone()
    conn.close()
    return (row2 is not None)

def get_shared_users(file_id):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT shared_user_id FROM shared_files
        WHERE file_id = ?
    """, (file_id,))
    rows = cursor.fetchall()
    conn.close()
    return [r[0] for r in rows]

def get_accessible_files(user_id):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    sql = """
    SELECT f.id, f.filename, u.username AS owner_name, 'owner' AS relation
    FROM files f
    JOIN users u ON u.id = f.owner_id
    WHERE f.owner_id = ?

    UNION

    SELECT f2.id, f2.filename, u2.username AS owner_name, 'shared' AS relation
    FROM files f2
    JOIN users u2 ON u2.id = f2.owner_id
    JOIN shared_files s ON s.file_id = f2.id
    WHERE s.shared_user_id = ?
    """
    cursor.execute(sql, (user_id, user_id))
    rows = cursor.fetchall()
    conn.close()
    results = []
    for row in rows:
        results.append({
            "id": row[0],
            "filename": row[1],
            "owner_name": row[2],
            "relation": row[3]
        })
    return results

def log_event(user_id, action, detail=""):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    timestamp = datetime.utcnow().isoformat()
    cursor.execute('''
        INSERT INTO audit_logs (user_id, action, detail, timestamp)
        VALUES (?, ?, ?, ?)
    ''', (user_id, action, detail, timestamp))
    conn.commit()
    conn.close()

def read_all_logs():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT audit_logs.id, audit_logs.user_id, users.username,
               audit_logs.action, audit_logs.detail, audit_logs.timestamp
        FROM audit_logs
        LEFT JOIN users ON users.id = audit_logs.user_id
        ORDER BY audit_logs.id ASC
    """)
    rows = cursor.fetchall()
    conn.close()
    results = []
    for r in rows:
        results.append({
            "log_id": r[0],
            "user_id": r[1],
            "username": r[2] if r[2] else "Unknown",
            "action": r[3],
            "detail": r[4],
            "timestamp": r[5]
        })
    return results

def get_otp_secret(username):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT otp_secret FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return row[0]  
    return None

if __name__ == '__main__':
    create_tables()
    print("[INFO] Database initialized.")
