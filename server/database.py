import sqlite3
import hashlib
import os

DB_FILE = 'server/storage.db'

def create_tables():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL
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

    conn.commit()
    conn.close()

def create_user(username, password):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    salt = os.urandom(16).hex()
    password_hash = hashlib.pbkdf2_hmac(
        'sha256', password.encode(), salt.encode(), 100000
    ).hex()
    try:
        cursor.execute(
            "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)", 
            (username, password_hash, salt)
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return False
    conn.close()
    return True

def verify_user(username, password):
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
    """
    先檢查檔案是否屬於 owner_id，
    若是，再把 shared_files 裡對應的紀錄刪除，
    最後刪除 files 中的紀錄。
    回傳 True/False 表示是否成功刪除。
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # 確認該檔案的 owner_id 是否是傳入的使用者
    cursor.execute("SELECT id FROM files WHERE id = ? AND owner_id = ?", (file_id, owner_id))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return False

    # 先刪除 shared_files 中對應的 file_id
    cursor.execute("DELETE FROM shared_files WHERE file_id = ?", (file_id,))
    # 再刪除 files 裏的紀錄
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
        return False  # already shared

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
    # check if user is the owner
    cursor.execute("SELECT owner_id FROM files WHERE id = ?", (file_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return False
    owner_id = row[0]
    if owner_id == user_id:
        conn.close()
        return True

    # otherwise check shared_files
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

if __name__ == '__main__':
    create_tables()
    print("[INFO] Database initialized.")
