from flask import Flask, request, jsonify
from server.database import create_user, verify_user

app = Flask(__name__)

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    
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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
