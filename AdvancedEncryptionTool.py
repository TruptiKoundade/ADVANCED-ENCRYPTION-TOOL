import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet
import base64
import hashlib
import os

# Generate a Fernet key from a password
def generate_key(password):
    return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())

# Encrypt the file
def encrypt_file():
    file_path = filedialog.askopenfilename()
    if not file_path:
        return

    password = password_entry.get()
    if not password:
        messagebox.showwarning("Missing Password", "Please enter a password.")
        return

    try:
        # Read file data
        with open(file_path, 'rb') as f:
            data = f.read()

        # Encrypt
        key = generate_key(password)
        fernet = Fernet(key)
        encrypted = fernet.encrypt(data)

        # Save encrypted file
        enc_path = file_path + ".enc"
        with open(enc_path, 'wb') as f:
            f.write(encrypted)

        # Also save original extension
        with open(enc_path + ".ext", 'w') as f:
            f.write(os.path.splitext(file_path)[1])  # Example: .txt

        messagebox.showinfo("Success", f"File encrypted as:\n{enc_path}")
    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed:\n{str(e)}")

# Decrypt the file
def decrypt_file():
    enc_file_path = filedialog.askopenfilename(filetypes=[("Encrypted Files", "*.enc")])
    if not enc_file_path:
        return

    password = password_entry.get()
    if not password:
        messagebox.showwarning("Missing Password", "Please enter a password.")
        return

    try:
        with open(enc_file_path, 'rb') as f:
            encrypted_data = f.read()

        # Read original extension if exists
        ext_path = enc_file_path + ".ext"
        file_ext = ".decrypted"
        if os.path.exists(ext_path):
            with open(ext_path, 'r') as f:
                file_ext = f.read().strip()

        # Decrypt
        key = generate_key(password)
        fernet = Fernet(key)
        decrypted_data = fernet.decrypt(encrypted_data)

        # Output path
        output_path = enc_file_path.replace(".enc", "_decrypted") + file_ext

        # If original was .txt, save as UTF-8
        if file_ext == ".txt":
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(decrypted_data.decode('utf-8'))
        else:
            with open(output_path, 'wb') as f:
                f.write(decrypted_data)

        messagebox.showinfo("Success", f"File decrypted and saved as:\n{output_path}")
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed:\n{str(e)}")

# ---------------- GUI Setup ----------------
root = tk.Tk()
root.title("Advanced File Encryption Tool")
root.geometry("450x260")
root.configure(bg="#2e2e2e")

tk.Label(root, text="🔐 Advanced File Encryption Tool", font=("Helvetica", 16, "bold"), bg="#2e2e2e", fg="white").pack(pady=10)
tk.Label(root, text="Enter Password:", bg="#2e2e2e", fg="white").pack(pady=5)

password_entry = tk.Entry(root, show="*", width=40)
password_entry.pack(pady=5)

tk.Button(root, text="Encrypt File", command=encrypt_file, width=25, bg="#4caf50", fg="white", font=("Arial", 10)).pack(pady=10)
tk.Button(root, text="Decrypt File", command=decrypt_file, width=25, bg="#f44336", fg="white", font=("Arial", 10)).pack()

tk.Label(root, text="Text files (.txt) will be readable after decryption", bg="#2e2e2e", fg="gray", font=("Arial", 9)).pack(pady=10)

root.mainloop()