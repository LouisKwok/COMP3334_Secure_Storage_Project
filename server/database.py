import sqlite3
import hashlib
import os

DB_FILE = 'server/storage.db'

# 初始化資料庫
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

    conn.commit()
    conn.close()

# 創建使用者
def create_user(username, password):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # 產生 salt 並加鹽儲存密碼
    salt = os.urandom(16).hex()
    password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000).hex()
    
    try:
        cursor.execute("INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)", 
                       (username, password_hash, salt))
        conn.commit()
    except sqlite3.IntegrityError:
        print("⚠ 用戶名已存在")
        return False
    finally:
        conn.close()
    
    return True

# 驗證使用者登入
def verify_user(username, password):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    cursor.execute("SELECT password_hash, salt FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    
    if row:
        stored_hash, salt = row
        input_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000).hex()
        return stored_hash == input_hash
    
    return False

# 上傳文件（加密後的文件）
def upload_file(owner_id, filename, encrypted_data):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    cursor.execute("INSERT INTO files (owner_id, filename, encrypted_data) VALUES (?, ?, ?)", 
                   (owner_id, filename, encrypted_data))
    conn.commit()
    conn.close()

# 取得使用者的所有文件
def get_user_files(owner_id):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    cursor.execute("SELECT id, filename FROM files WHERE owner_id = ?", (owner_id,))
    files = cursor.fetchall()
    conn.close()
    
    return files

# 刪除文件
def delete_file(file_id, owner_id):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    cursor.execute("DELETE FROM files WHERE id = ? AND owner_id = ?", (file_id, owner_id))
    conn.commit()
    conn.close()

if __name__ == '__main__':
    create_tables()
    print("資料庫初始化完成")
