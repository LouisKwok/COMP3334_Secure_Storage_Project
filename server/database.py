import sqlite3
import hashlib
import os
import pyotp
from datetime import datetime

# Path to the SQLite database file (adjust as necessary).
DB_FILE = 'server/storage.db'

def create_tables():
    """
    Create all necessary tables if they do not already exist:
      1) users           - Holds user credentials, admin status, and OTP secret
      2) files           - Basic file records (owner + filename + optional data)
      3) shared_files    - Tracks which user can access which file
      4) audit_logs      - Records security-relevant actions (logins, uploads, etc.)
      5) chunks          - Stores encrypted file chunks (for partial updates)
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # Users table for account/credentials info
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

    # Files table for basic file metadata
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            encrypted_data BLOB,
            FOREIGN KEY (owner_id) REFERENCES users(id)
        )
    ''')

    # shared_files table: which user is granted access to which file
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS shared_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id INTEGER NOT NULL,
            shared_user_id INTEGER NOT NULL,
            FOREIGN KEY (file_id) REFERENCES files(id),
            FOREIGN KEY (shared_user_id) REFERENCES users(id)
        )
    ''')

    # audit_logs table: record critical operations for non-repudiation
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

    # chunks table: stores chunked file data for partial updates
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS chunks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id INTEGER NOT NULL,
            chunk_index INTEGER NOT NULL,
            encrypted_data BLOB NOT NULL,
            FOREIGN KEY (file_id) REFERENCES files(id),
            UNIQUE (file_id, chunk_index)
        )
    ''')

    conn.commit()
    conn.close()

def create_user(username, password, is_admin=False):
    """
    Insert a new user into 'users' table with salted, hashed password, plus an OTP secret.
    Returns (success, otp_secret) where 'success' is True/False, 'otp_secret' is the
    user's newly generated TOTP secret if success.
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    salt = os.urandom(16).hex()
    password_hash = hashlib.pbkdf2_hmac(
        'sha256', password.encode(), salt.encode(), 100000
    ).hex()

    admin_val = 1 if is_admin else 0
    otp_secret = pyotp.random_base32()  # Generate a TOTP secret

    try:
        cursor.execute(
            "INSERT INTO users (username, password_hash, salt, is_admin, otp_secret) VALUES (?, ?, ?, ?, ?)", 
            (username, password_hash, salt, admin_val, otp_secret)
        )
        conn.commit()
    except sqlite3.IntegrityError:
        # Typically triggered if 'username' is duplicated (unique constraint).
        conn.close()
        return (False, None)

    conn.close()
    return (True, otp_secret)

def verify_user(username, password):
    """
    Check if the provided 'username' and 'password' match the stored hash in DB.
    Returns True if password is correct, False otherwise.
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
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
    """
    Replace the specified user's old password with a newly hashed one.
    Returns True on success, False if user not found.
    """
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
    """
    Check if the user is marked as admin (is_admin=1).
    Returns True if admin, False otherwise.
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT is_admin FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()

    if row:
        return (row[0] == 1)
    return False

def get_user_id(username):
    """
    Given a username, return its user_id or None if not found.
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else None

def get_username_by_id(user_id):
    """
    Reverse lookup: from user_id to username (for logs/sharing info).
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else None

def upload_file_db(owner_id, filename, encrypted_data):
    """
    Insert a new record in 'files' table for a single-block upload scenario.
    The entire encrypted data is stored in 'encrypted_data'.
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO files (owner_id, filename, encrypted_data) VALUES (?, ?, ?)",
        (owner_id, filename, encrypted_data)
    )
    conn.commit()
    conn.close()

def get_user_files(owner_id):
    """
    Return a list of (file_id, filename) for files owned by a given user_id.
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT id, filename FROM files WHERE owner_id = ?", (owner_id,))
    files = cursor.fetchall()
    conn.close()
    return files

def get_file_by_id(file_id):
    """
    Retrieve basic file info from 'files' by its file_id.
    Returns a dict with {owner_id, filename, encrypted_data} or None if not found.
    Note that 'encrypted_data' is used only in single-block approach, not chunk-based.
    """
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
    """
    Delete a file record if the user_id is the owner.
    Also remove any shared_files references to that file.
    Returns True on success, False if file not found or not owned by user.
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # Ensure the file is owned by 'owner_id'
    cursor.execute("SELECT id FROM files WHERE id = ? AND owner_id = ?", (file_id, owner_id))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return False

    # If found, delete references in shared_files and the file entry
    cursor.execute("DELETE FROM shared_files WHERE file_id = ?", (file_id,))
    cursor.execute("DELETE FROM files WHERE id = ?", (file_id,))
    conn.commit()
    conn.close()
    return True

def share_file_db(file_id, shared_user_id):
    """
    Share the specified file with 'shared_user_id'.
    If already shared, return False; otherwise True if share is created.
    """
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
    """
    Remove sharing of file_id from 'shared_user_id'.
    Returns True if a share record was deleted, False otherwise.
    """
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
    """
    Check if the specified user_id can access file_id (either owner or shared).
    Returns True if access is granted, otherwise False.
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # First check if the user is the owner
    cursor.execute("SELECT owner_id FROM files WHERE id = ?", (file_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return False

    owner_id = row[0]
    if owner_id == user_id:
        conn.close()
        return True

    # If not the owner, check 'shared_files'
    cursor.execute("""
        SELECT id FROM shared_files 
        WHERE file_id = ? AND shared_user_id = ?
    """, (file_id, user_id))
    row2 = cursor.fetchone()
    conn.close()
    return (row2 is not None)

def get_shared_users(file_id):
    """
    Return a list of user_ids to whom the given file_id is shared.
    Useful for showing 'shared_with' info in file_info.
    """
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
    """
    Return all files the user_id can access (either as owner or in shared_files).
    This query does a UNION to combine 'owner' vs. 'shared' relationships,
    also returning the 'relation' for clarity.
    """
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
    """
    Insert an audit log entry describing an important action,
    such as login, upload, chunk update, file deletion, etc.
    """
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
    """
    Return all records in audit_logs, joined with user's username if available.
    Sorted in ascending order by log entry ID.
    """
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
    """
    Return the TOTP secret for the given username, if any.
    This might be used server-side to verify OTP codes.
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT otp_secret FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return row[0]
    return None

def upsert_chunk(file_id, chunk_index, encrypted_data):
    """
    Insert or update a single chunk for a chunk-based file upload.
    If (file_id, chunk_index) exists, we overwrite encrypted_data.
    Otherwise, we create a new row. This uses SQLite's ON CONFLICT upsert.
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO chunks (file_id, chunk_index, encrypted_data)
        VALUES (?, ?, ?)
        ON CONFLICT(file_id, chunk_index) DO UPDATE SET encrypted_data=excluded.encrypted_data
    """, (file_id, chunk_index, encrypted_data))
    conn.commit()
    conn.close()

def get_chunks(file_id):
    """
    Retrieve all chunks for a given file_id, returning (chunk_index, encrypted_data) list,
    sorted by chunk_index ASC in the calling code if desired.
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT chunk_index, encrypted_data FROM chunks WHERE file_id = ? ORDER BY chunk_index ASC", (file_id,))
    rows = cursor.fetchall()
    conn.close()
    return rows

def remove_chunk(file_id, chunk_index):
    """
    Delete a specific chunk from 'chunks' table, used when file is shortened
    or we want to remove an unneeded chunk.
    Returns how many rows were deleted (rowcount).
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        DELETE FROM chunks
        WHERE file_id = ? AND chunk_index = ?
    """, (file_id, chunk_index))
    rowcount = cursor.rowcount
    conn.commit()
    conn.close()
    return rowcount

def create_file_in_db(owner_id, filename):
    """
    Used in single-route chunk approach:
    Insert a new row in 'files', returning its auto-incremented file_id.
    This file has no 'encrypted_data' because we store chunk data in 'chunks'.
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO files (owner_id, filename) VALUES (?, ?)", (owner_id, filename))
    new_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return new_id

if __name__ == '__main__':
    # If run directly, just create tables and confirm success.
    create_tables()
    print("[INFO] Database initialized.")
