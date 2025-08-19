import json
import os
import hashlib
import re

USER_FILE = "users.json"

def init_user_file():
    if not os.path.exists(USER_FILE):
        with open(USER_FILE, "w") as f:
            json.dump({}, f)

def load_users():
    with open(USER_FILE, "r") as f:
        return json.load(f)

def save_users(users):
    with open(USER_FILE, "w") as f:
        json.dump(users, f, indent=4)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def is_strong_password(password):
    return (len(password) >= 8 and
            re.search(r"[A-Z]", password) and
            re.search(r"[a-z]", password) and
            re.search(r"[0-9]", password) and
            re.search(r"[!@#$%^&*(),.?\":{}|<>]", password))

def signup(username, password, role):
    users = load_users()
    if username in users:
        return False, "Username already exists."
    if not is_strong_password(password):
        return False, "Password must be at least 8 characters long, and include uppercase, lowercase, digit, and special character."

    users[username] = {
        "password": hash_password(password),
        "role": role
    }
    save_users(users)
    return True, "Signup successful."

def login(username, password):
    users = load_users()
    if username not in users:
        return False, "Username not found."
    if users[username]["password"] != hash_password(password):
        return False, "Incorrect password."
    return True, users[username]["role"]
