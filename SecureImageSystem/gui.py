import tkinter as tk
from tkinter import messagebox, filedialog, simpledialog
import os
from auth import login, signup, init_user_file
from encryptor import encrypt_image, decrypt_image, get_physician_key
from utils import load_json, save_json, generate_aes_key

PRIMARY_COLOR = "#2C3E50"
ACCENT_COLOR = "#1ABC9C"
TEXT_COLOR = "white"
FONT = ("Helvetica", 12)
TITLE_FONT = ("Helvetica", 18, "bold")


def run_app():
    init_user_file()
    App()


class App:
    def __init__(self):   #constructor
        self.root = tk.Tk() #mainwindow
        self.root.title("Secure Medical Image System")
        self.root.geometry("600x400")
        self.root.configure(bg=PRIMARY_COLOR)
        self.username = None
        self.role = None
        self.login_screen()
        self.root.mainloop() #keep showing the main window until clicks or typing

    def login_screen(self):
        self.clear()
        tk.Label(self.root, text="Login", font=TITLE_FONT, bg=PRIMARY_COLOR, fg=TEXT_COLOR).pack(pady=20)
        tk.Label(self.root, text="Username", bg=PRIMARY_COLOR, fg=TEXT_COLOR).pack()
        user_entry = tk.Entry(self.root, font=FONT)
        user_entry.pack()
        tk.Label(self.root, text="Password", bg=PRIMARY_COLOR, fg=TEXT_COLOR).pack()
        pass_entry = tk.Entry(self.root, show="*", font=FONT)
        pass_entry.pack()

        def handle_login():
            u, p = user_entry.get(), pass_entry.get()
            success, msg = login(u, p)
            if success:
                self.username, self.role = u, msg
                self.dashboard()
            else:
                messagebox.showerror("Login Failed", msg)

        def go_to_signup():
            self.signup_screen()

        tk.Button(self.root, text="Login", command=handle_login, bg=ACCENT_COLOR, fg="black", font=FONT).pack(pady=10)
        tk.Button(self.root, text="Sign up", command=go_to_signup, bg="gray", fg="white", font=FONT).pack()

    def signup_screen(self):
        self.clear()
        tk.Label(self.root, text="Sign Up", font=TITLE_FONT, bg=PRIMARY_COLOR, fg=TEXT_COLOR).pack(pady=20)
        tk.Label(self.root, text="Username", bg=PRIMARY_COLOR, fg=TEXT_COLOR).pack()
        user_entry = tk.Entry(self.root, font=FONT)
        user_entry.pack()
        tk.Label(self.root, text="Password", bg=PRIMARY_COLOR, fg=TEXT_COLOR).pack()
        pass_entry = tk.Entry(self.root, show="*", font=FONT)
        pass_entry.pack()
        tk.Label(self.root, text="Role (lab/physician)", bg=PRIMARY_COLOR, fg=TEXT_COLOR).pack()
        role_entry = tk.Entry(self.root, font=FONT)
        role_entry.pack()

        def handle_signup():
            u, p, r = user_entry.get(), pass_entry.get(), role_entry.get().lower()
            if r not in ['lab', 'physician']:
                messagebox.showerror("Invalid Role", "Role must be 'lab' or 'physician'")
                return
            success, msg = signup(u, p, r)
            if success:
                if r == 'physician':
                    keys = load_json("physician_keys.json")
                    keys[u] = generate_aes_key()
                    save_json(keys, "physician_keys.json")
                messagebox.showinfo("Success", msg)
                self.login_screen()
            else:
                messagebox.showerror("Signup Failed", msg)

        tk.Button(self.root, text="Sign up", command=handle_signup, bg=ACCENT_COLOR, fg="black", font=FONT).pack(pady=10)
        tk.Button(self.root, text="Back to Login", command=self.login_screen, bg="gray", fg="white", font=FONT).pack()

    def dashboard(self):
        self.clear()
        tk.Label(self.root, text=f"{self.role.capitalize()} Dashboard", font=TITLE_FONT, bg=PRIMARY_COLOR, fg=TEXT_COLOR).pack(pady=20)
        if self.role == 'lab':
            tk.Button(self.root, text="Encrypt Medical Image", command=self.encrypt_ui, bg=ACCENT_COLOR, fg="black", font=FONT).pack(pady=15)
        elif self.role == 'physician':
            tk.Button(self.root, text="Decrypt Assigned Image", command=self.decrypt_ui, bg=ACCENT_COLOR, fg="black", font=FONT).pack(pady=15)
        tk.Button(self.root, text="Logout", command=self.login_screen, bg="red", fg="white", font=FONT).pack(pady=10)

    def encrypt_ui(self):
        image_path = filedialog.askopenfilename(initialdir="assets", title="Select Medical Image")
        if not image_path:
            return

        patient_id = simpledialog.askstring("Patient ID", "Enter Patient ID:")
        physician = simpledialog.askstring("Physician Username", "Enter Physician Username:")

        try:
            key = get_physician_key(physician)
        except ValueError as e:
            messagebox.showerror("Key Error", str(e))
            return

        os.makedirs("encrypted_images", exist_ok=True)
        output_path = os.path.join("encrypted_images", f"{patient_id}.enc")

        try:
            encrypt_image(image_path, output_path, key)
        except Exception as e:
            messagebox.showerror("Encryption Error", str(e))
            return

        mapping = load_json("patient_mapping.json")
        mapping[patient_id] = physician
        save_json(mapping, "patient_mapping.json")

        messagebox.showinfo("Success", f"Image encrypted and assigned to {physician}.")
        self.dashboard()

    def decrypt_ui(self):
        mapping = load_json("patient_mapping.json")
        assigned = [pid for pid, doc in mapping.items() if doc == self.username]
        if not assigned:
            messagebox.showinfo("No Data", "No assigned patient data found.")
            return

        pid = simpledialog.askstring("Patient ID", f"Enter Patient ID to decrypt (Options: {', '.join(assigned)}):")
        if pid not in assigned:
            messagebox.showerror("Access Denied", "You are not authorized to access this patient's data.")
            return

        os.makedirs("decrypted_images", exist_ok=True)
        encrypted_path = os.path.join("encrypted_images", f"{pid}.enc")
        output_path = os.path.join("decrypted_images", f"{pid}_decrypted.jpg")

        try:
            key = get_physician_key(self.username)
            decrypt_image(encrypted_path, output_path, key)
        except Exception as e:
            messagebox.showerror("Decryption Error", str(e))
            return

        messagebox.showinfo("Success", f"Image decrypted and saved as {output_path}")
        self.dashboard()

    def clear(self):
        for widget in self.root.winfo_children():
            widget.destroy()
