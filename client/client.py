import requests

def register():
    username = input("Enter username: ")
    password = input("Enter password: ")
    
    response = requests.post("http://127.0.0.1:5000/register", json={
        "username": username,
        "password": password
    })
    
    print(response.json())

if __name__ == "__main__":
    while True:
        print("\n1. 註冊")
        print("2. 退出")
        choice = input("請選擇: ")
        
        if choice == "1":
            register()
        elif choice == "2":
            break
