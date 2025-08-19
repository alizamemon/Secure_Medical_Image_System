import base64
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from utils import load_json

def get_physician_key(username):
    keys = load_json("physician_keys.json")
    if username not in keys:
        raise ValueError("Physician key not found.")
    return base64.b64decode(keys[username])

def encrypt_image(image_path, output_path, key):
    with open(image_path, "rb") as f:
        data = f.read()

    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    iv = cipher.iv

    with open(output_path, "wb") as f:
        f.write(iv + ct_bytes)

def decrypt_image(encrypted_path, output_path, key):
    with open(encrypted_path, "rb") as f:
        iv = f.read(16)
        ct = f.read()

    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)

    with open(output_path, "wb") as f:
        f.write(pt)
