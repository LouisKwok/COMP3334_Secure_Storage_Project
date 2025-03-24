from flask import Flask, request, jsonify
import os
import base64
import re

from server.database import (
    create_tables, create_user, verify_user, update_password, is_admin_user,
    get_user_id, get_username_by_id, upload_file_db, get_user_files, get_file_by_id,
    delete_file_db, share_file_db, unshare_file_db, has_access, get_shared_users,
    get_accessible_files, log_event, read_all_logs, get_otp_secret, upsert_chunk, get_chunks, remove_chunk, create_file_in_db
)

app = Flask(__name__)
logged_in_users = {}

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    
    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400
    
    if not validate_username(username):
        return jsonify({"error": "Invalid username format"}), 400

    success, otp_secret = create_user(username, password, is_admin=False)
    if success:
        user_id = get_user_id(username)
        log_event(user_id, "REGISTER", detail=f"username={username}")
        print(f"[INFO] A new user '{username}' has been registered.")
        print(f"[INFO] New user {username} OTP secret = {otp_secret}")
        return jsonify({"message": f"User '{username}' registered successfully!"})
    else:
        print(f"[WARN] Registration failed. User '{username}' already exists.")
        return jsonify({"error": "Username already exists"}), 400


@app.route('/admin_register', methods=['POST'])
def admin_register():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    success, otp_secret = create_user(username, password, is_admin=True)
    if success:
        user_id = get_user_id(username)
        log_event(user_id, "REGISTER_ADMIN", detail=f"username={username}")
        print(f"[INFO] A new admin '{username}' has been created.")
        print(f"[INFO] New user {username} OTP secret = {otp_secret}")
        return jsonify({"message": f"Admin '{username}' registered successfully!"})
    else:
        return jsonify({"error": "Admin creation failed. Username might exist."}), 400

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    otp_code = data.get("otp_code")

    if verify_user(username, password):
        # 檢查 OTP
        secret = get_otp_secret(username)
        if secret is None:
            return jsonify({"error": "User has no OTP secret"}), 400

        import pyotp
        totp = pyotp.TOTP(secret)
        if not otp_code:
            return jsonify({"error": "OTP code is required"}), 400

        # 驗證 OTP 是否正確
        if not totp.verify(otp_code):
            print(f"[WARN] OTP verification failed for user '{username}'.")
            return jsonify({"error": "Invalid OTP code"}), 401

        # OTP ok 才算登入成功
        token = os.urandom(16).hex()
        logged_in_users[token] = username

        user_id = get_user_id(username)
        log_event(user_id, "LOGIN", detail=f"token={token}")
        print(f"[INFO] User '{username}' logged in with OTP. Token: {token}")
        is_admin = is_admin_user(username)
        return jsonify({
            "message": "Login successful",
            "token": token,
            "is_admin": is_admin
        })
    else:
        print(f"[WARN] Login attempt failed for user '{username}'.")
        return jsonify({"error": "Invalid username or password"}), 401

@app.route('/logout', methods=['POST'])
def logout():
    data = request.json
    token = data.get("token")
    if token and token in logged_in_users:
        user = logged_in_users[token]
        user_id = get_user_id(user)
        log_event(user_id, "LOGOUT", detail=f"token={token}")
        del logged_in_users[token]
        print(f"[INFO] User '{user}' logged out. Token invalidated.")
        return jsonify({"message": "Logout successful"})
    print(f"[WARN] Invalid logout attempt with token: {token}")
    return jsonify({"error": "Invalid token"}), 401

@app.route('/reset_password', methods=['POST'])
def reset_password():
    data = request.json
    token = data.get("token")
    old_password = data.get("old_password")
    new_password = data.get("new_password")
    if token not in logged_in_users:
        print("[WARN] Password reset attempt without valid token.")
        return jsonify({"error": "Not logged in"}), 401

    username = logged_in_users[token]
    if not verify_user(username, old_password):
        print(f"[WARN] Incorrect old password for user '{username}'.")
        return jsonify({"error": "Old password is incorrect"}), 400

    if update_password(username, new_password):
        user_id = get_user_id(username)
        log_event(user_id, "RESET_PASSWORD", detail="Password updated")
        print(f"[INFO] User '{username}' has reset their password.")
        return jsonify({"message": "Password reset successful"})
    else:
        print(f"[ERROR] Failed to reset password for user '{username}'.")
        return jsonify({"error": "Failed to reset password"}), 400

@app.route('/upload', methods=['POST'])
def upload():
    data = request.json
    token = data.get("token")
    filename = data.get("filename")
    file_data = data.get("file_data")

    if token not in logged_in_users:
        return jsonify({"error": "Not logged in"}), 401

    if not filename or not file_data:
        return jsonify({"error": "Filename and file_data are required"}), 400

    # 檔名驗證：防止 "../" 或不允許字元
    if not validate_filename(filename):
        return jsonify({"error": "Invalid filename"}), 400

    username = logged_in_users[token]
    user_id = get_user_id(username)

    import base64
    encrypted_bytes = base64.b64decode(file_data)
    upload_file_db(user_id, filename, encrypted_bytes)

    log_event(user_id, "UPLOAD", detail=f"filename={filename}")
    print(f"[INFO] User '{username}' uploaded file '{filename}'.")
    return jsonify({"message": f"File '{filename}' uploaded successfully"})

def validate_username(username):
    pattern = r'^[a-zA-Z0-9_-]{3,20}$'
    return bool(re.match(pattern, username))

@app.route('/list_files', methods=['GET'])
def list_files():
    token = request.args.get("token")
    if token not in logged_in_users:
        return jsonify({"error": "Not logged in"}), 401

    username = logged_in_users[token]
    user_id = get_user_id(username)
    files = get_user_files(user_id)
    file_list = [{"id": f[0], "filename": f[1]} for f in files]
    return jsonify({"files": file_list})

@app.route('/list_my_accessible_files', methods=['GET'])
def list_my_accessible_files():
    token = request.args.get("token")
    if token not in logged_in_users:
        return jsonify({"error": "Not logged in"}), 401

    username = logged_in_users[token]
    user_id = get_user_id(username)
    files = get_accessible_files(user_id)
    file_list = []
    for f in files:
        file_list.append({
            "id": f["id"], 
            "filename": f["filename"],
            "owner_name": f["owner_name"],
            "relation": f["relation"]
        })
    return jsonify({"files": file_list})

@app.route('/download', methods=['GET'])
def download():
    token = request.args.get("token")
    file_id = request.args.get("file_id")
    if token not in logged_in_users:
        return jsonify({"error": "Not logged in"}), 401
    if not file_id:
        return jsonify({"error": "file_id is required"}), 400

    username = logged_in_users[token]
    user_id = get_user_id(username)
    if not has_access(user_id, file_id):
        print(f"[WARN] User '{username}' tried to download file '{file_id}' without permission.")
        return jsonify({"error": "Access denied"}), 403

    file_record = get_file_by_id(file_id)
    if not file_record:
        return jsonify({"error": "File not found"}), 404

    import base64
    b64_data = base64.b64encode(file_record["encrypted_data"]).decode()
    log_event(user_id, "DOWNLOAD", detail=f"file_id={file_id}")
    print(f"[INFO] User '{username}' downloaded file ID '{file_id}'.")
    return jsonify({
        "file_data": b64_data,
        "filename": file_record["filename"]
    })

@app.route('/delete', methods=['DELETE'])
def delete_file():
    data = request.json
    token = data.get("token")
    file_id = data.get("file_id")
    if token not in logged_in_users:
        return jsonify({"error": "Not logged in"}), 401

    username = logged_in_users[token]
    user_id = get_user_id(username)
    deleted = delete_file_db(file_id, user_id)
    if deleted:
        log_event(user_id, "DELETE", detail=f"file_id={file_id}")
        print(f"[INFO] User '{username}' deleted file ID '{file_id}'. Shared records also removed.")
        return jsonify({"message": "File deleted successfully, along with any sharing records."})
    else:
        print(f"[WARN] Delete failed by user '{username}' for file ID '{file_id}'.")
        return jsonify({"error": "Delete failed. Either file not found or not owner."}), 400

@app.route('/share', methods=['POST'])
def share():
    data = request.json
    token = data.get("token")
    file_id = data.get("file_id")
    target_username = data.get("target_username")
    if token not in logged_in_users:
        return jsonify({"error": "Not logged in"}), 401

    username = logged_in_users[token]
    user_id = get_user_id(username)
    file_record = get_file_by_id(file_id)
    if not file_record:
        return jsonify({"error": "File not found"}), 404
    if file_record["owner_id"] != user_id:
        return jsonify({"error": "You are not the owner of this file"}), 403

    target_id = get_user_id(target_username)
    if not target_id:
        return jsonify({"error": f"Target user '{target_username}' not found"}), 404

    if share_file_db(file_id, target_id):
        log_event(user_id, "SHARE", detail=f"file_id={file_id}, shared_to={target_username}")
        print(f"[INFO] User '{username}' shared file ID '{file_id}' with '{target_username}'.")
        return jsonify({"message": f"File shared with {target_username}"})
    else:
        return jsonify({"error": f"Already shared with {target_username} or DB error"}), 400

@app.route('/unshare', methods=['POST'])
def unshare():
    data = request.json
    token = data.get("token")
    file_id = data.get("file_id")
    target_username = data.get("target_username")
    if token not in logged_in_users:
        return jsonify({"error": "Not logged in"}), 401

    username = logged_in_users[token]
    user_id = get_user_id(username)
    file_record = get_file_by_id(file_id)
    if not file_record:
        return jsonify({"error": "File not found"}), 404
    if file_record["owner_id"] != user_id:
        return jsonify({"error": "You are not the owner of this file"}), 403

    target_id = get_user_id(target_username)
    if not target_id:
        return jsonify({"error": f"Target user '{target_username}' not found"}), 404

    removed = unshare_file_db(file_id, target_id)
    if removed:
        log_event(user_id, "UNSHARE", detail=f"file_id={file_id}, unshare_from={target_username}")
        print(f"[INFO] User '{username}' unshared file ID '{file_id}' with '{target_username}'.")
        return jsonify({"message": f"File unshared from {target_username}"})
    else:
        return jsonify({"error": "Unshare failed or no such sharing existed"}), 400

@app.route('/file_info', methods=['GET'])
def file_info():
    token = request.args.get("token")
    file_id = request.args.get("file_id")
    if token not in logged_in_users:
        return jsonify({"error": "Not logged in"}), 401
    if not file_id:
        return jsonify({"error": "file_id is required"}), 400

    username = logged_in_users[token]
    user_id = get_user_id(username)
    if not has_access(user_id, file_id):
        return jsonify({"error": "Access denied"}), 403

    file_record = get_file_by_id(file_id)
    if not file_record:
        return jsonify({"error": "File not found"}), 404

    owner_name = get_username_by_id(file_record["owner_id"])
    shared_list = get_shared_users(file_id)
    shared_usernames = []
    for uid in shared_list:
        uname = get_username_by_id(uid)
        if uname:
            shared_usernames.append(uname)

    return jsonify({
        "owner": owner_name,
        "filename": file_record["filename"],
        "shared_with": shared_usernames
    })

@app.route('/read_logs', methods=['GET'])
def read_logs():
    token = request.args.get("token")
    if token not in logged_in_users:
        return jsonify({"error": "Not logged in"}), 401

    username = logged_in_users[token]
    if not is_admin_user(username):
        return jsonify({"error": "Only admin can read logs"}), 403

    logs = read_all_logs()
    return jsonify({"logs": logs})

def validate_filename(filename):
    if "../" in filename or "..\\" in filename:
        return False
    pattern = r'^[a-zA-Z0-9._-]+$'
    if not re.match(pattern, filename):
        return False
    if not filename.strip():
        return False
    return True

@app.route('/upload_chunk', methods=['POST'])
def upload_chunk():
    """
    單一路由: 若 file_id=-1/None 且 chunk_index=0 => 自動建立檔案並回傳 file_id。
    若 file_id>0 => 上傳更新既有檔案的 chunk。
    """
    data = request.json
    token = data.get("token")
    raw_file_id = data.get("file_id", None)
    chunk_index = data.get("chunk_index")
    chunk_data_b64 = data.get("chunk_data")
    filename = data.get("filename")  # 只有第一次 chunk 需要

    if token not in logged_in_users:
        return jsonify({"error": "Not logged in"}), 401

    if chunk_index is None or chunk_data_b64 is None:
        return jsonify({"error": "chunk_index, chunk_data are required"}), 400

    # chunk_index 檢查
    try:
        chunk_index = int(chunk_index)
        if chunk_index < 0:
            return jsonify({"error": "chunk_index cannot be negative"}), 400
    except ValueError:
        return jsonify({"error": "chunk_index must be integer"}), 400

    # base64 decode
    try:
        encrypted_data = base64.b64decode(chunk_data_b64)
    except Exception:
        return jsonify({"error": "Invalid base64 chunk_data"}), 400

    max_chunk_size = 10 * 1024 * 1024
    if len(encrypted_data) > max_chunk_size:
        return jsonify({"error": "Chunk too large"}), 413

    current_user = logged_in_users[token]
    user_id = get_user_id(current_user)
    if not user_id:
        return jsonify({"error": "User record not found"}), 404

    # file_id 檢查
    if raw_file_id is None or raw_file_id in [-1, 0]:
        # 表示要新建檔案 => 必須 chunk_index=0, 且要有filename
        if chunk_index != 0:
            return jsonify({"error": "To create a new file, chunk_index must be 0"}), 400
        if not filename:
            return jsonify({"error": "filename is required for the first chunk of a new file"}), 400

        # create file row
        new_file_id = create_file_in_db(user_id, filename)
        real_file_id = new_file_id
        print(f"[INFO] Created new file with id={real_file_id} for user_id={user_id}")
    else:
        # 使用現有檔案
        try:
            real_file_id = int(raw_file_id)
        except ValueError:
            return jsonify({"error": "file_id must be integer"}), 400

        frow = get_file_by_id(real_file_id)
        if not frow:
            return jsonify({"error": f"File with id={real_file_id} not found"}), 404
        if not has_access(user_id, real_file_id):
            return jsonify({"error": "Access denied"}), 403

    # upsert chunk
    upsert_chunk(real_file_id, chunk_index, encrypted_data)

    # log
    log_event(user_id, "UPLOAD_CHUNK", detail=f"file_id={real_file_id}, chunk_index={chunk_index}")

    return jsonify({
        "message": f"Chunk #{chunk_index} for file_id={real_file_id} uploaded",
        "file_id": real_file_id
    })

@app.route('/download_chunks', methods=['GET'])
def download_chunks():
    token = request.args.get("token")
    file_id = request.args.get("file_id")

    if token not in logged_in_users:
        return jsonify({"error": "Not logged in"}), 401
    if not file_id:
        return jsonify({"error": "file_id is required"}), 400

    try:
        file_id = int(file_id)
    except ValueError:
        return jsonify({"error": "file_id must be integer"}), 400

    frow = get_file_by_id(file_id)
    if not frow:
        return jsonify({"error": "File not found"}), 404

    current_user = logged_in_users[token]
    user_id = get_user_id(current_user)
    if not has_access(user_id, file_id):
        return jsonify({"error": "Access denied"}), 403

    chunk_rows = get_chunks(file_id)
    result = []
    for (cidx, enc) in chunk_rows:
        b64_enc = base64.b64encode(enc).decode()
        result.append({"chunk_index": cidx, "chunk_data": b64_enc})

    log_event(user_id, "DOWNLOAD_CHUNKS", detail=f"file_id={file_id}")

    return jsonify({"chunks": result})

@app.route('/delete_chunk', methods=['DELETE'])
def delete_chunk_endpoint():
    data = request.json
    token = data.get("token")
    file_id = data.get("file_id")
    chunk_index = data.get("chunk_index")

    if token not in logged_in_users:
        return jsonify({"error": "Not logged in"}), 401

    if file_id is None or chunk_index is None:
        return jsonify({"error": "file_id and chunk_index are required"}), 400

    # 檢查型別
    try:
        file_id = int(file_id)
        chunk_index = int(chunk_index)
    except ValueError:
        return jsonify({"error": "file_id and chunk_index must be integers"}), 400

    file_record = get_file_by_id(file_id)
    if not file_record:
        return jsonify({"error": "File not found"}), 404

    user = logged_in_users[token]
    user_id = get_user_id(user)
    if not has_access(user_id, file_id):
        return jsonify({"error": "Access denied"}), 403

    # 執行資料庫刪除
    rowcount = remove_chunk(file_id, chunk_index)
    if rowcount > 0:
        log_event(user_id, "DELETE_CHUNK", detail=f"file_id={file_id}, chunk_index={chunk_index}")
        return jsonify({"message": f"Chunk #{chunk_index} for file_id={file_id} removed"})
    else:
        return jsonify({"error": "No such chunk or already deleted"}), 404

if __name__ == '__main__':
    create_tables()
    print("[INFO] Database initialized.")
    app.run(host='0.0.0.0', port=5000, debug=True)