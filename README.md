# 🛡️ Secure Medical Image System

A simple yet effective system to **securely store and transmit medical images** (e.g., X-rays, MRIs) using **AES symmetric encryption**.  
The system ensures that only **authenticated and authorized healthcare professionals** can decrypt and access the images.

---

## 📌 Features
- 🔒 **AES-256 Encryption**: Encrypts medical images into unreadable form.
- 👩‍⚕️ **Authentication**: Only authorized users can access images.
- 🔑 **Key Management**: Encryption key is securely stored for decryption.
- 📂 **Data Security**: Protects sensitive patient data during storage and transmission.
- 🖼️ **Medical Images**: Works with standard image formats (PNG, JPEG, DICOM).

---

##  How to Run

### 1. Clone the Repository
```bash
git clone ...
cd Secure_Medical_Image_System
```

### 2. Install Dependencies
```bash
pip install pycryptodome
```
### 3. Add a sample image
Place an image (e.g., xray.png) inside the assets/ folder.

### 4. Encrypt the Image
```bash
python encrypt_image.py
```

### 5. Decrypt the Image
```bash
python decrypt_image.py
```

🔐 Authentication
User credentials are stored in users.json.

Example users:
{
  "doctor1": "password123",
  "radiologist": "securepass"
}
Only authenticated users can encrypt/decrypt images.

📜 License

This project is licensed under the MIT License.

Developed by Aliza Memon
