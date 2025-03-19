import requests

def register():
    username = input("Enter username: ")
    password = input("Enter password: ")
    
    response = requests.post("http://127.0.0.1:5000/register", json={
        "username": username,
        "password": password
    })
    
    print(response.json())

def reset_password():
    username = input("Enter username to reset password: ")
    new_password = input("Enter new password: ")

    response = requests.post("http://127.0.0.1:5000/reset_password", json={
        "username": username,
        "new_password": new_password
    })
    
    print(response.json())

def login():
    username = input("Enter username: ")
    password = input("Enter password: ")

    response = requests.post("http://127.0.0.1:5000/login", json={
        "username": username,
        "password": password
    })
    
    print(response.json())

if __name__ == "__main__":
    while True:
        print("\n1. Register")
        print("2. Login")
        print("3. Reset Password")
        print("4. Exit")
        choice = input("Choose an option: ")
        
        if choice == "1":
            register()
        elif choice == "2":
            login()
        elif choice == "3":
            reset_password()
        elif choice == "4":
            break
