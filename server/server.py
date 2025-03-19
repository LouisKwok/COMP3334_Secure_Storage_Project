from flask import Flask, request, jsonify
from server.database import create_user, verify_user, reset_password

app = Flask(__name__)

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    
    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    if create_user(username, password):
        return jsonify({"message": f"User {username} registered successfully!"})
    else:
        return jsonify({"error": "Username already exists"}), 400

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if verify_user(username, password):
        return jsonify({"message": "Login successful"})
    else:
        return jsonify({"error": "Invalid username or password"}), 401

@app.route('/reset_password', methods=['POST'])
def reset():
    data = request.json
    username = data.get("username")
    new_password = data.get("new_password")
    
    if reset_password(username, new_password):
        return jsonify({"message": "Password reset successful"})
    else:
        return jsonify({"error": "Failed to reset password. User may not exist."}), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
