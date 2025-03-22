import requests
import os
import base64
from cryptography.fernet import Fernet

BASE_URL = "http://127.0.0.1:5000"
token = None

def print_response(res):
    data = {}
    try:
        data = res.json()
    except:
        print("[ERROR] : Invalid response from server.")
        return

    msg = data.get("message")
    err = data.get("error")
    if msg:
        print(f"[MESSAGE] : {msg}")
    elif err:
        print(f"[ERROR] : {err}")
    else:
        print("[INFO] : No relevant message from server.")

def init_key():
    if not os.path.exists("secret.key"):
        new_key = Fernet.generate_key()
        with open("secret.key", "wb") as f:
            f.write(new_key)

def load_key():
    with open("secret.key", "rb") as f:
        return f.read()

def register():
    username = input("Enter username: ")
    password = input("Enter password: ")
    res = requests.post(f"{BASE_URL}/register", json={
        "username": username,
        "password": password
    })
    print_response(res)

def login():
    global token
    username = input("Enter username: ")
    password = input("Enter password: ")
    res = requests.post(f"{BASE_URL}/login", json={
        "username": username,
        "password": password
    })
    data = res.json()
    if 'token' in data:
        token = data['token']
    print_response(res)

def logout():
    global token
    if not token:
        print("[ERROR] : You are not logged in.")
        return
    res = requests.post(f"{BASE_URL}/logout", json={"token": token})
    if res.status_code == 200:
        token = None
    print_response(res)

def reset_password():
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
    if not token:
        print("[ERROR] : You are not logged in.")
        return []
    res = requests.get(f"{BASE_URL}/list_my_accessible_files", params={"token": token})
    if res.status_code == 200:
        data = res.json()
        return data.get("files", [])
    else:
        print_response(res)
        return []

def upload_file():
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
    with open(file_path, "rb") as f:
        file_data = f.read()
    encrypted_data = cipher.encrypt(file_data)
    encoded_data = base64.b64encode(encrypted_data).decode()
    filename = os.path.basename(file_path)

    res = requests.post(f"{BASE_URL}/upload", json={
        "token": token,
        "filename": filename,
        "file_data": encoded_data
    })
    print_response(res)

def download_file():
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

def file_menu():
    while True:
        print("\n[File Menu]")
        print("1. Upload File")
        print("2. Download File")
        print("3. Share File")
        print("4. Unshare File")
        print("5. Delete File")
        print("6. List My Owned Files")
        print("7. List All Accessible Files")
        print("8. Show File Info")
        print("9. Back to Main Menu")
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
            break
        else:
            print("[ERROR] : Invalid selection.")

def main():
    print("[MESSAGE] : Welcome to the Secure Storage System with Enhanced Interface!")
    init_key()

    global token
    while True:
        if token:
            print("\n[Main Menu - Logged In]")
            print("1. Access Files")
            print("2. Reset Password")
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
            print("\n[Main Menu - Not Logged In]")
            print("1. Register")
            print("2. Login")
            print("3. Exit")
            choice = input("Choose an option: ")

            if choice == "1":
                register()
            elif choice == "2":
                login()
            elif choice == "3":
                break
            else:
                print("[ERROR] : Invalid selection.")

if __name__ == "__main__":
    main()
