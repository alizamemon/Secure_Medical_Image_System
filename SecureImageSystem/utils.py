import json
import os
import base64
from Crypto.Random import get_random_bytes

def load_json(file_path):
    if not os.path.exists(file_path):
        return {}
    with open(file_path, "r") as f:
        return json.load(f)

def save_json(data, file_path):
    with open(file_path, "w") as f:
        json.dump(data, f, indent=4)

def generate_aes_key():
    return base64.b64encode(get_random_bytes(32)).decode()
