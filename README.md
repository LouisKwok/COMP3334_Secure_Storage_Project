
---

# README: Secure Online Storage System

This project implements a **Secure Online Storage System** with core functionalities and extended features:

- **Core**:
  1. User Management (Register/Login with password hashing)
  2. Data Encryption (client-side encryption with Fernet/pyotp)
  3. Access Control (owner-only, share/unshare)
  4. Log Auditing (records critical operations for non-repudiation)
  5. General Security Protection (filename validation, SQL injection prevention)
- **Extended**:
  1. Multi-Factor Authentication (OTP-based, using pyotp)
  2. Partial (chunk-based) updates for large files (upload only changed parts)

This README will guide you through a **clean installation** on Windows 10 (or later), including creating a Python virtual environment, installing dependencies, initializing the SQLite database, and running the client/server programs.

---

## 1. Prerequisites

1. **Python 3.8+**  
   - Make sure you have Python installed.  
   - If not, download and install from [python.org](https://www.python.org/downloads/).

2. **Git (optional)**  
   - If you want to clone the repository directly. Otherwise, you can just copy the code folder.

3. **No assumptions on pre-installed software**  
   - This guide explains how to install any needed libraries from scratch using `pip`.

---

## 2. Creating and Activating a Python Virtual Environment

Open **Command Prompt** or **PowerShell** on Windows, then navigate to the folder where you have the project.

### 2.1 Create a Virtual Environment

```bash
python -m venv venv
```

This will create a folder named `venv` containing an isolated Python environment.

### 2.2 Activate the Virtual Environment

```bash
.\venv\Scripts\activate
```

You should now see `(venv)` at the beginning of your command prompt, indicating your virtual environment is active.

---

## 3. Install Required Python Libraries

Your project should include a `requirements.txt` file listing all necessary packages (like `Flask`, `pyotp`, `cryptography`, etc.). To install them:

```bash
pip install -r requirements.txt
```

If everything installs successfully, you should see messages indicating successful installation of packages.

---

## 4. Initialize the SQLite Database

1. **Server-Side Setup**  
   - Navigate to the `server` directory (if your folder structure places `server.py` in `server/`).
   - The server code will automatically create and initialize the SQLite database (usually `storage.db`) on first run, thanks to the `create_tables()` call.  
   - Alternatively, you can run `python server/database.py` (if it has a `create_tables()` call in the `if __name__ == '__main__':` block), or simply let the server do it on startup.

2. **Optional**: Confirm the DB file is created  
   - By default, it should appear in `server/storage.db`. If you want to customize the path, adjust `DB_FILE` in your code.

---

## 5. Running the Server

1. Make sure you are still in your Python virtual environment `(venv)`.  
2. Navigate to the location of `server.py`.  
3. Run the server:

```bash
python -m server.server
```

You should see output such as:

```
[INFO] Database initialized.
 * Serving Flask app 'server'
 * Running on http://0.0.0.0:5000 (Press CTRL+C to quit)
```

This indicates your Flask server is now listening on port 5000.

---

## 6. Running the Client

Open a **new terminal** (or the same one in a separate window) while the server is still running. Remember to ensure the **virtual environment** is active:

```bash
.\venv\Scripts\activate
```

Then run:

```bash
python client/client.py
```

You will see a menu-based interface with options like Register, Login, Access Files, etc.

**Workflow**:
1. **Register** a user (normal or admin).
2. **Login** (with your username/password + OTP code).
3. Access the file-related menu: 
   - Upload/Download (single-block),
   - Share/Unshare,
   - Chunk-based partial upload,
   - View logs (admin only),
   - etc.

### 6.1 The `secret.key` File

- The client-side encryption uses a Fernet key.  
- When you **first run** `client.py`, it will automatically generate a file called **`secret.key`** if it does not already exist.  
- This key is used to encrypt and decrypt files on the client side.  
- **Important**: If you lose or remove `secret.key`, you cannot decrypt previously encrypted files. In a real-world scenario, you would store this key securely or handle key rotation carefully.

---

## 7. Using the TOTP (OTP) Simulator

We have a `otp_sim.py` program that simulates the phone-based OTP generation:

```bash
python client/otp_sim.py
```

- It will ask for the TOTP secret (which you can see in the server logs or returned upon new user creation).
- It then prints the current 6-digit code and a countdown timer until the next refresh.

Use this code when the client asks for an OTP code during login. If correct, the server will permit login.

---

## 8. Partial/Chunk-Based Updates

1. Run the server as normal.  
2. In the client, choose the extended chunk-based upload (single-route). If you provide `file_id = -1`, it will create a new file automatically.  
3. Use “Download File in Chunks” to retrieve it.  
4. “Auto Update Partial File” only re-uploads changed chunks (and removes extra chunks if the new file is smaller).

---

## 9. Deactivating the Virtual Environment

When finished, you can deactivate your Python environment:

```bash
deactivate
```

---

## 10. Additional Notes

- **Logging**:  
  - Each critical operation (Register, Login, Upload, Share, etc.) is recorded in `audit_logs` (SQLite table).  
  - If you’re an admin user, you can see logs with the `View Logs` menu.

- **Security**:  
  - Passwords are salted + hashed with `hashlib.pbkdf2_hmac('sha256')`.  
  - OTP secrets are assigned on user creation, stored in the `users` table.  
  - Filenames are validated to block suspicious patterns (`../`, etc.).  
  - All SQL queries use parameterized statements to avoid injection.

- **Requirements File**:
  - The `requirements.txt` typically contains lines like:
    ```
    Flask==3.1.0
    pyotp==2.9.0
    cryptography==44.0.2
    ```
    Make sure these versions align with your local environment.

- **Code Documentation**:
  - The project is extensively commented (see docstrings and inline comments in `client.py`, `server.py`, and `database.py`).  
  - For a deeper explanation, refer to each file’s docstrings or your separate technical report.

---

## 11. Troubleshooting

1. **Port conflicts**: If port 5000 is in use, change the `app.run(...)` port in `server.py`.  
2. **Database location**: If you want a custom path, edit `DB_FILE` in `database.py`.  
3. **Dependency versions**: If installation fails, check your `requirements.txt` or update Python.  

---

## 12. Credits / References

- **Flask** for the web framework.  
- **pyotp** for TOTP-based MFA.  
- **cryptography** / **hashlib** for encryption and password hashing.  
- Various Python community resources for chunk-based file handling patterns.

---
