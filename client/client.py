import requests
import math
import os
import base64
from cryptography.fernet import Fernet

# The server's base URL (replace if running on a different host/port).
BASE_URL = "http://127.0.0.1:5000"

# Global variables to store session info and user details.
token = None            # Holds the current user's session token
is_admin = False        # Indicates if the current user is an admin
current_username = None # The username currently logged in

def print_response(res):
    """
    Safely parse a server response as JSON.
    Then read 'message' or 'error' fields (if present) and display them.
    """
    data = {}
    try:
        data = res.json()  # Attempt to parse JSON
    except:
        # If parsing fails, indicate an invalid server response
        print("[ERROR] : Invalid response from server.")
        return

    msg = data.get("message")
    err = data.get("error")

    if msg:
        print(f"[MESSAGE] : {msg}")
    elif err:
        print(f"[ERROR] : {err}")
    else:
        # If server didn't provide specific fields, print a generic info.
        print("[INFO] : No relevant message from server.")

def init_key():
    """
    Initialize the encryption key for client-side encryption.
    If 'secret.key' doesn't exist, generate a new Fernet key and save it locally.
    """
    if not os.path.exists("secret.key"):
        new_key = Fernet.generate_key()
        with open("secret.key", "wb") as f:
            f.write(new_key)

def load_key():
    """
    Load the previously generated Fernet key from 'secret.key'.
    This key is used for file encryption/decryption on the client side.
    """
    with open("secret.key", "rb") as f:
        return f.read()

def register(is_admin=False):
    """
    Register a new user (normal or admin).
    If is_admin=True, call '/admin_register'; otherwise '/register'.
    """
    username = input("Enter username: ")
    password = input("Enter password: ")
    if is_admin:
        endpoint = "/admin_register"
    else:
        endpoint = "/register"

    res = requests.post(f"{BASE_URL}{endpoint}", json={
        "username": username,
        "password": password
    })
    print_response(res)

def login():
    """
    Log in by sending username, password, and an OTP code.
    On success, store the returned token, is_admin flag, and current_username globally.
    """
    global token, is_admin, current_username
    username = input("Enter username: ")
    password = input("Enter password: ")
    otp_code = input("Enter OTP code: ")
    res = requests.post(f"{BASE_URL}/login", json={
        "username": username,
        "password": password,
        "otp_code": otp_code
    })

    # Parse the JSON response
    data = res.json()
    if 'token' in data:
        token = data['token']
        current_username = username
        is_admin = data.get("is_admin", False)

    print_response(res)

def logout():
    """
    Log out from the server by invalidating the current token.
    """
    global token, is_admin, current_username
    if not token:
        print("[ERROR] : You are not logged in.")
        return

    res = requests.post(f"{BASE_URL}/logout", json={"token": token})
    if res.status_code == 200:
        # Clear local session info
        token = None
        is_admin = False
        current_username = None

    print_response(res)

def reset_password():
    """
    Reset the current user's password.
    This requires providing the old password, then the new one.
    """
    global token
    if not token:
        print("[ERROR] : You are not logged in.")
        return

    old_password = input("Enter your old password: ")
    new_password = input("Enter your new password: ")

    res = requests.post(f"{BASE_URL}/reset_password", json={
        "token": token,
        "old_password": old_password,
        "new_password": new_password
    })
    print_response(res)

def list_owned_files():
    """
    Fetch a list of files owned by the current user (simple listing).
    Returns an empty list on error or if none found.
    """
    if not token:
        print("[ERROR] : You are not logged in.")
        return []

    res = requests.get(f"{BASE_URL}/list_files", params={"token": token})
    if res.status_code == 200:
        data = res.json()
        return data.get("files", [])
    else:
        print_response(res)
        return []

def list_accessible_files():
    """
    Fetch files that the current user can access (owned or shared).
    This includes details like owner and relation.
    """
    if not token:
        print("[ERROR] : You are not logged in.")
        return []

    res = requests.get(f"{BASE_URL}/list_my_accessible_files", params={"token": token})
    if res.status_code == 200:
        data = res.json()
        files = data.get("files", [])
        if files:
            print("\n[INFO] You can access these files:")
            for f in files:
                print(f"  file_id={f['id']} | filename={f['filename']} | owner={f['owner_name']} | relation={f['relation']}")
        else:
            print("[INFO] No accessible files found.")
        return files
    else:
        print_response(res)
        return []

def upload_file():
    """
    Upload a file in one piece (non-chunk).
    This is the simpler approach where the entire file is encrypted at once.
    """
    file_path = input("Enter the file path to upload: ")
    if not os.path.exists(file_path):
        print("[ERROR] : File not found.")
        return

    confirm = input(f"Are you sure to upload '{file_path}'? (y/n): ").lower()
    if confirm != 'y':
        print("[MESSAGE] : Upload canceled.")
        return

    key = load_key()
    cipher = Fernet(key)

    # Read file data then encrypt
    with open(file_path, "rb") as f:
        file_data = f.read()
    encrypted_data = cipher.encrypt(file_data)
    encoded_data = base64.b64encode(encrypted_data).decode()

    # Use the file's local name as 'filename'
    filename = os.path.basename(file_path)

    res = requests.post(f"{BASE_URL}/upload", json={
        "token": token,
        "filename": filename,
        "file_data": encoded_data
    })
    print_response(res)

def download_file():
    """
    Download an entire file (non-chunk) after listing accessible files.
    The user selects a file_id, confirms, then the file is retrieved and decrypted.
    """
    files = list_accessible_files()
    if not files:
        print("[MESSAGE] : You have no accessible files.")
        return

    print("\n[Your Accessible Files]")
    for f in files:
        print(f"  ID: {f['id']} | NAME: {f['filename']} | OWNER: {f['owner_name']} | RELATION: {f['relation']}")

    file_id = input("Enter the file ID to download: ")
    confirm = input(f"Are you sure to download file ID '{file_id}'? (y/n): ").lower()
    if confirm != 'y':
        print("[MESSAGE] : Download canceled.")
        return

    params = {"token": token, "file_id": file_id}
    res = requests.get(f"{BASE_URL}/download", params=params)
    if res.status_code != 200:
        print_response(res)
        return

    data = res.json()
    encrypted_b64 = data.get("file_data")
    fname = data.get("filename")
    if not encrypted_b64 or not fname:
        print("[ERROR] : Missing file data or filename.")
        return

    key = load_key()
    cipher = Fernet(key)
    encrypted_bytes = base64.b64decode(encrypted_b64)

    try:
        decrypted_data = cipher.decrypt(encrypted_bytes)
    except Exception:
        print("[ERROR] : Decryption failed.")
        return

    save_path = input(f"Enter the local path to save the file (default: {fname}): ")
    if not save_path.strip():
        save_path = fname

    with open(save_path, "wb") as f:
        f.write(decrypted_data)

    print(f"[MESSAGE] : File saved to {save_path}")

def share_file():
    """
    Share an owned file with another user. The target username can then access that file.
    """
    owned = list_owned_files()
    if not owned:
        print("[MESSAGE] : You have no owned files.")
        return

    print("\n[Your Owned Files]")
    for f in owned:
        print(f"  ID: {f['id']} | NAME: {f['filename']}")

    file_id = input("Enter the file ID to share: ")
    target_username = input("Enter target username to share with: ")
    confirm = input(f"Are you sure to share file ID '{file_id}' with '{target_username}'? (y/n): ").lower()
    if confirm != 'y':
        print("[MESSAGE] : Sharing canceled.")
        return

    res = requests.post(f"{BASE_URL}/share", json={
        "token": token,
        "file_id": file_id,
        "target_username": target_username
    })
    print_response(res)

def unshare_file():
    """
    Cancel sharing a previously shared file with a particular user.
    Only the file owner can unshare.
    """
    owned = list_owned_files()
    if not owned:
        print("[MESSAGE] : You have no owned files.")
        return

    print("\n[Your Owned Files]")
    for f in owned:
        print(f"  ID: {f['id']} | NAME: {f['filename']}")

    file_id = input("Enter the file ID to unshare: ")
    target_username = input("Enter target username to unshare: ")
    confirm = input(f"Are you sure to unshare file ID '{file_id}' from '{target_username}'? (y/n): ").lower()
    if confirm != 'y':
        print("[MESSAGE] : Unsharing canceled.")
        return

    res = requests.post(f"{BASE_URL}/unshare", json={
        "token": token,
        "file_id": file_id,
        "target_username": target_username
    })
    print_response(res)

def delete_file():
    """
    Delete an owned file entirely. Only the file owner can do this.
    """
    owned = list_owned_files()
    if not owned:
        print("[MESSAGE] : You have no owned files.")
        return

    print("\n[Your Owned Files]")
    for f in owned:
        print(f"  ID: {f['id']} | NAME: {f['filename']}")

    file_id = input("Enter the file ID to delete: ")
    confirm = input(f"Are you sure to delete file ID '{file_id}'? (y/n): ").lower()
    if confirm != 'y':
        print("[MESSAGE] : Deletion canceled.")
        return

    res = requests.delete(f"{BASE_URL}/delete", json={
        "token": token,
        "file_id": file_id
    })
    print_response(res)

def show_file_info():
    """
    Display detailed file info: owner name, who it is shared with, etc.
    """
    files = list_accessible_files()
    if not files:
        print("[MESSAGE] : You have no accessible files.")
        return

    print("\n[Your Accessible Files]")
    for f in files:
        print(f"  ID: {f['id']} | NAME: {f['filename']} | OWNER: {f['owner_name']} | RELATION: {f['relation']}")

    file_id = input("Enter the file ID to check info: ")
    params = {"token": token, "file_id": file_id}
    res = requests.get(f"{BASE_URL}/file_info", params=params)

    if res.status_code == 200:
        data = res.json()
        owner = data.get("owner")
        fname = data.get("filename")
        shared_list = data.get("shared_with", [])

        print(f"\n[MESSAGE] : File Info")
        print(f"  Filename : {fname}")
        print(f"  Owner    : {owner}")
        print(f"  Shared with:")
        if shared_list:
            for uname in shared_list:
                print(f"    - {uname}")
        else:
            print("    (No shared users)")
    else:
        print_response(res)

def view_logs():
    """
    View system logs (audit records), only accessible if the user is admin.
    """
    global token, is_admin
    if not token:
        print("[ERROR] : Not logged in.")
        return
    if not is_admin:
        print("[ERROR] : You are not admin. Access denied.")
        return

    res = requests.get(f"{BASE_URL}/read_logs", params={"token": token})
    if res.status_code == 200:
        data = res.json()
        logs = data.get("logs", [])
        if not logs:
            print("[MESSAGE] : No logs found.")
        else:
            print("[MESSAGE] : System Logs")
            for log in logs:
                print(f" LogID={log['log_id']} | user={log['username']} | action={log['action']} | detail={log['detail']} | time={log['timestamp']}")
    else:
        print_response(res)

def upload_file_in_chunks_single_route():
    """
    Single-route chunk-based file upload:
      - If file_id=-1 => server will auto-create a new file (first chunk).
      - If file_id>=0 => server updates the existing file chunk by chunk.
    """
    if not token:
        print("[ERROR] You are not logged in.")
        return

    file_path = input("Enter the file path to upload: ")
    if not os.path.exists(file_path):
        print("[ERROR] : File not found.")
        return

    confirm = input(f"Are you sure to upload '{file_path}' in chunk mode? (y/n): ").lower()
    if confirm != 'y':
        print("[MESSAGE] : Upload canceled.")
        return

    raw_file_id = input("Enter file_id (or -1 for new): ")
    try:
        raw_file_id = int(raw_file_id)
    except ValueError:
        print("[ERROR] : file_id must be an integer or -1")
        return

    filename = None
    if raw_file_id < 0:
        filename = input("Enter filename for the new file: ")

    chunk_size = 8192
    key = load_key()
    cipher = Fernet(key)

    chunk_idx = 0
    with open(file_path, "rb") as f:
        while True:
            chunk_data = f.read(chunk_size)
            if not chunk_data:
                break
            enc_data = cipher.encrypt(chunk_data)
            b64_data = base64.b64encode(enc_data).decode()

            post_data = {
                "token": token,
                "file_id": raw_file_id,
                "chunk_index": chunk_idx,
                "chunk_data": b64_data
            }
            # For the very first chunk of a new file, send the filename
            if chunk_idx == 0 and raw_file_id < 0:
                post_data["filename"] = filename

            r = requests.post(f"{BASE_URL}/upload_chunk", json=post_data)
            if r.status_code != 200:
                print_response(r)
                return
            else:
                j = r.json()
                print("[MESSAGE]", j.get("message", ""))

                # If server created a new file_id on chunk 0, update local raw_file_id
                if chunk_idx == 0 and raw_file_id < 0:
                    new_fid = j.get("file_id")
                    if new_fid is not None:
                        raw_file_id = new_fid
                        print(f"[INFO] Server assigned file_id={raw_file_id} for subsequent chunks.")

            chunk_idx += 1

    print("[MESSAGE] All chunks uploaded via single-route approach.")

def download_file_in_chunks():
    """
    Download a file in chunk-based mode, merge all chunks locally.
    """
    if not token:
        print("[ERROR] You are not logged in.")
        return

    # List accessible files to help user pick file_id
    all_files = list_accessible_files()
    if not all_files:
        print("[MESSAGE] : No files to download.")
        return

    file_id = input("Enter the file_id to download: ")

    # Attempt to guess a default local filename
    default_name = "output.txt"
    for f in all_files:
        if str(f["id"]) == file_id:
            default_name = f["filename"]
            break

    out_path = input(f"Enter local path to save (default: {default_name}): ").strip()
    if not out_path:
        out_path = default_name

    confirm = input(f"Are you sure to download file_id={file_id} => {out_path}? (y/n) : ").lower()
    if confirm != 'y':
        print("[MESSAGE] : Download canceled.")
        return

    # Get all chunks
    res = requests.get(f"{BASE_URL}/download_chunks", params={
        "token": token,
        "file_id": file_id
    })
    if res.status_code != 200:
        print_response(res)
        return

    data = res.json()
    chunks = data.get("chunks", [])

    key = load_key()
    cipher = Fernet(key)

    # Sort by chunk_index and decrypt
    sorted_chunks = sorted(chunks, key=lambda x: x["chunk_index"])
    with open(out_path,"wb") as out:
        for c in sorted_chunks:
            enc = base64.b64decode(c["chunk_data"])
            dec = cipher.decrypt(enc)
            out.write(dec)

    print("[MESSAGE] Downloaded and merged all chunks into", out_path)

def auto_update_file_in_chunks():
    """
    Automatically compare the old file (downloaded from server in chunks) 
    with a new local file, then only update the changed chunks.
    Also remove extra chunks if the new file is shorter.
    """
    global token
    if not token:
        print("[ERROR] You are not logged in.")
        return

    all_files = list_accessible_files()
    if not all_files:
        print("[MESSAGE] : You have no accessible files to update.")
        return

    file_id = input("Enter file_id to update: ")
    new_file_path = input("Enter local path of the NEW file: ")
    if not os.path.exists(new_file_path):
        print("[ERROR] New file not found.")
        return

    confirm = input(f"Are you sure to update file_id={file_id} with new file '{new_file_path}'? (y/n): ").lower()
    if confirm != 'y':
        print("[MESSAGE] : Update canceled.")
        return

    # 1) Download old file's chunks -> decrypt and merge
    res = requests.get(f"{BASE_URL}/download_chunks", params={
        "token": token,
        "file_id": file_id
    })
    if res.status_code != 200:
        print_response(res)
        return

    data = res.json()
    chunk_list = data.get("chunks", [])

    key = load_key()
    cipher = Fernet(key)

    # Merge old plaintext
    sorted_chunks = sorted(chunk_list, key=lambda c: c["chunk_index"])
    old_plain_bytes = b""
    for c in sorted_chunks:
        enc_bytes = base64.b64decode(c["chunk_data"])
        dec_bytes = cipher.decrypt(enc_bytes)
        old_plain_bytes += dec_bytes

    # 2) Read new local file
    with open(new_file_path, "rb") as nf:
        new_plain_bytes = nf.read()

    chunk_size = 8192
    old_length = len(old_plain_bytes)
    new_length = len(new_plain_bytes)
    max_length = max(old_length, new_length)

    offset = 0
    chunk_index = 0

    # Compare each chunk and only upload differences
    while offset < max_length:
        old_chunk = old_plain_bytes[offset:offset+chunk_size]
        new_chunk = new_plain_bytes[offset:offset+chunk_size]

        if old_chunk != new_chunk:
            enc = cipher.encrypt(new_chunk)
            b64_data = base64.b64encode(enc).decode()
            rr = requests.post(f"{BASE_URL}/upload_chunk", json={
                "token": token,
                "file_id": file_id,
                "chunk_index": chunk_index,
                "chunk_data": b64_data
            })
            if rr.status_code != 200:
                print_response(rr)
                return
            else:
                print(f"[MESSAGE] Updated chunk #{chunk_index}")

        chunk_index += 1
        offset += chunk_size

    # Remove extra chunk(s) if old was longer
    old_total_chunks = math.ceil(old_length / chunk_size)
    new_total_chunks = math.ceil(new_length / chunk_size)

    if old_total_chunks > new_total_chunks:
        print(f"[INFO] old_total_chunks={old_total_chunks} > new_total_chunks={new_total_chunks}")
        # Delete from new_total_chunks up to old_total_chunks-1
        for cindex in range(new_total_chunks, old_total_chunks):
            delr = requests.delete(f"{BASE_URL}/delete_chunk", json={
                "token": token,
                "file_id": file_id,
                "chunk_index": cindex
            })
            if delr.status_code == 200:
                print(f"[MESSAGE] Chunk #{cindex} removed.")
            else:
                print_response(delr)
                return
    else:
        print(f"[INFO] No extra chunk to remove. (old={old_total_chunks}, new={new_total_chunks})")

    print("[MESSAGE] auto_update_file_in_chunks completed. Only changed chunks re-uploaded. Extra chunks removed if needed.")

def file_menu():
    """
    Sub-menu for file operations. 
    Provides both single-block (upload/download) and extended chunk-based approaches.
    """
    while True:
        print("\n[File Menu]")
        print("1. Upload File (Single)")
        print("2. Download File (Single)")
        print("3. Share File")
        print("4. Unshare File")
        print("5. Delete File")
        print("6. List My Owned Files")
        print("7. List All Accessible Files")
        print("8. Show File Info")
        print("9. Upload File (Single-Route Chunks) (Extended)")
        print("10. Download File in Chunks (Extended)")
        print("11. Auto Update Partial File (diff-based) (Extended)")
        print("12. Back to Main Menu")

        choice = input("Choose an option: ")

        if choice == "1":
            upload_file()
        elif choice == "2":
            download_file()
        elif choice == "3":
            share_file()
        elif choice == "4":
            unshare_file()
        elif choice == "5":
            delete_file()
        elif choice == "6":
            owned = list_owned_files()
            if not owned:
                print("[MESSAGE] : No owned files.")
            else:
                print("\n[Your Owned Files]")
                for f in owned:
                    print(f"  ID: {f['id']} | NAME: {f['filename']}")
        elif choice == "7":
            accessible = list_accessible_files()
            if not accessible:
                print("[MESSAGE] : No accessible files.")
            else:
                print("\n[All Accessible Files]")
                for f in accessible:
                    print(f"  ID: {f['id']} | NAME: {f['filename']} | OWNER: {f['owner_name']} | RELATION: {f['relation']}")
        elif choice == "8":
            show_file_info()
        elif choice == "9":
            upload_file_in_chunks_single_route()
        elif choice == "10":
            download_file_in_chunks()
        elif choice == "11":
            auto_update_file_in_chunks()
        elif choice == "12":
            break
        else:
            print("[ERROR] : Invalid selection.")

def main():
    """
    The main entry point of the client.
    Provides a top-level menu for Register/Login/Exit or for file operations if logged in.
    """
    print("[MESSAGE] : Welcome to the Secure Storage System with Log Auditing!")
    init_key()

    global token, is_admin, current_username
    while True:
        # If user has a token, we consider them logged in, show the "logged in" menu
        if token:
            print("\n[Main Menu - Logged In]")
            print("1. Access Files")
            print("2. Reset Password")
            if is_admin:
                print("3. View Logs")
                print("4. Logout")
                print("5. Exit")
                choice = input("Choose an option: ")
                if choice == "1":
                    file_menu()
                elif choice == "2":
                    reset_password()
                elif choice == "3":
                    view_logs()
                elif choice == "4":
                    logout()
                elif choice == "5":
                    break
                else:
                    print("[ERROR] : Invalid selection.")
            else:
                # Non-admin user
                print("3. Logout")
                print("4. Exit")
                choice = input("Choose an option: ")
                if choice == "1":
                    file_menu()
                elif choice == "2":
                    reset_password()
                elif choice == "3":
                    logout()
                elif choice == "4":
                    break
                else:
                    print("[ERROR] : Invalid selection.")
        else:
            # Not logged in
            print("\n[Main Menu - Not Logged In]")
            print("1. Register (normal user)")
            print("2. Register (admin) [Just a demonstration!]")
            print("3. Login")
            print("4. Exit")
            choice = input("Choose an option: ")
            if choice == "1":
                register(is_admin=False)
            elif choice == "2":
                register(is_admin=True)
            elif choice == "3":
                login()
            elif choice == "4":
                break
            else:
                print("[ERROR] : Invalid selection.")

if __name__ == "__main__":
    main()
