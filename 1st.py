import os
import base64
from hashlib import sha256
from Crypto.Cipher import DES, AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
import customtkinter as ctk

# Constants for key file names
RSA_PRIVATE_KEY_FILE = "rsa_private.pem"
RSA_PUBLIC_KEY_FILE = "rsa_public.pem"
DES_KEY_FILE = "des.key"
AES_KEY_FILE = "aes.key"
USERS_FILE = "users.txt"

# Generate or load keys
def generate_or_load_keys():
    # RSA Keys
    if not os.path.exists(RSA_PRIVATE_KEY_FILE) or not os.path.exists(RSA_PUBLIC_KEY_FILE):
        rsa_key = RSA.generate(2048)
        with open(RSA_PRIVATE_KEY_FILE, "wb") as priv_file:
            priv_file.write(rsa_key.export_key())
        with open(RSA_PUBLIC_KEY_FILE, "wb") as pub_file:
            pub_file.write(rsa_key.publickey().export_key())

    # DES Key
    if not os.path.exists(DES_KEY_FILE):
        des_key = os.urandom(8)  # DES key must be 8 bytes
        with open(DES_KEY_FILE, "wb") as des_file:
            des_file.write(des_key)

    # AES Key
    if not os.path.exists(AES_KEY_FILE):
        aes_key = os.urandom(16)  # AES key must be 16 bytes
        with open(AES_KEY_FILE, "wb") as aes_file:
            aes_file.write(aes_key)

def load_keys():
    with open(RSA_PRIVATE_KEY_FILE, "rb") as priv_file:
        rsa_private_key = RSA.import_key(priv_file.read())
    with open(RSA_PUBLIC_KEY_FILE, "rb") as pub_file:
        rsa_public_key = RSA.import_key(pub_file.read())
    with open(DES_KEY_FILE, "rb") as des_file:
        des_key = des_file.read()
    with open(AES_KEY_FILE, "rb") as aes_file:
        aes_key = aes_file.read()
    return rsa_private_key, rsa_public_key, des_key, aes_key

# Encryption sequence
def onion_encrypt(password, des_key, aes_key, rsa_public_key):
    # Step A: Hash the password using SHA-256
    hashed_password = sha256(password.encode()).digest()

    # Step B: Encrypt the hash using DES
    des_cipher = DES.new(des_key, DES.MODE_CBC)
    des_encrypted = des_cipher.encrypt(pad(hashed_password, DES.block_size))

    # Step C: Encrypt the DES output using AES
    aes_cipher = AES.new(aes_key, AES.MODE_CBC)
    aes_encrypted = aes_cipher.encrypt(pad(des_encrypted, AES.block_size))

    # Step D: Encrypt the AES output using RSA
    rsa_cipher = PKCS1_OAEP.new(rsa_public_key)
    rsa_encrypted = rsa_cipher.encrypt(aes_encrypted)

    # Return all encrypted data along with IVs for DES and AES
    return base64.b64encode(des_cipher.iv + aes_cipher.iv + rsa_encrypted).decode()

# Decryption sequence (for verification)
def onion_decrypt(encrypted_data, des_key, aes_key, rsa_private_key):
    encrypted_data = base64.b64decode(encrypted_data)

    # Extract IVs and RSA encrypted data
    des_iv = encrypted_data[:8]
    aes_iv = encrypted_data[8:24]
    rsa_encrypted = encrypted_data[24:]

    # Step D: Decrypt RSA
    rsa_cipher = PKCS1_OAEP.new(rsa_private_key)
    aes_encrypted = rsa_cipher.decrypt(rsa_encrypted)

    # Step C: Decrypt AES
    aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv=aes_iv)
    des_encrypted = unpad(aes_cipher.decrypt(aes_encrypted), AES.block_size)

    # Step B: Decrypt DES
    des_cipher = DES.new(des_key, DES.MODE_CBC, iv=des_iv)
    hashed_password = unpad(des_cipher.decrypt(des_encrypted), DES.block_size)

    return hashed_password

# User management
def register(username, password):
    rsa_private_key, rsa_public_key, des_key, aes_key = load_keys()
    encrypted_password = onion_encrypt(password, des_key, aes_key, rsa_public_key)

    with open(USERS_FILE, "a") as users_file:
        users_file.write(f"{username}:{encrypted_password}\n")
    print("User registered successfully.")

def login(username, password):
    rsa_private_key, rsa_public_key, des_key, aes_key = load_keys()

    if not os.path.exists(USERS_FILE):
        print("No users registered.")
        return

    with open(USERS_FILE, "r") as users_file:
        for line in users_file:
            stored_username, stored_password = line.strip().split(":")
            if stored_username == username:
                # Decrypt the stored password
                try:
                    decrypted_hash = onion_decrypt(stored_password, des_key, aes_key, rsa_private_key)
                    input_hash = sha256(password.encode()).digest()

                    if decrypted_hash == input_hash:
                        print("Login successful.")
                        return
                except Exception as e:
                    print("Error during decryption:", e)
                    break
        else:
            print("Invalid username or password.")

    # Allow the program to continue after login attempt
    print("Returning to main menu...")

# Initialize customtkinter appearance and theme
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

# GUI Application Class
class SecureAuthApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Configure main window
        self.title("Secure Auth System")
        self.geometry("500x400")

        # Tab View
        self.tab_view = ctk.CTkTabview(self)
        self.tab_view.pack(expand=True, fill="both", padx=20, pady=20)

        # Login Tab
        self.login_tab = self.tab_view.add("Login")
        self.create_login_tab()

        # Register Tab
        self.register_tab = self.tab_view.add("Register")
        self.create_register_tab()

        # Status Label
        self.status_label = ctk.CTkLabel(self, text="", text_color="white")
        self.status_label.pack(pady=10)

        # Bottom Left Label
        self.bottom_left_label = ctk.CTkLabel(self, text="Supervised by:\nDr. Marwa\nDr. Heba Samy", anchor="w")
        self.bottom_left_label.place(relx=0.01, rely=0.95, anchor="sw")

        # Bottom Right Label
        self.bottom_right_label = ctk.CTkLabel(self, text="Project by:\nMazen Muhamed\nMareez Magdy\nMennatallah Sameh\nSaga Amr\nLara Nagy", anchor="e")
        self.bottom_right_label.place(relx=0.99, rely=0.95, anchor="se")

        # Load keys at startup
        generate_or_load_keys()

    def create_login_tab(self):
        # Username Entry
        self.login_username_entry = ctk.CTkEntry(self.login_tab, placeholder_text="Username")
        self.login_username_entry.pack(pady=10, padx=20)

        # Password Entry
        self.login_password_entry = ctk.CTkEntry(self.login_tab, placeholder_text="Password", show="*")
        self.login_password_entry.pack(pady=10, padx=20)

        # Login Button
        self.login_button = ctk.CTkButton(self.login_tab, text="Login", command=self.handle_login)
        self.login_button.pack(pady=20)

        # Result Label for displaying hashes below the password bar
        self.result_label = ctk.CTkLabel(self.login_tab, text="", text_color="white", justify="left")
        self.result_label.pack(pady=10, padx=20)

    def create_register_tab(self):
        # Username Entry
        self.register_username_entry = ctk.CTkEntry(self.register_tab, placeholder_text="Username")
        self.register_username_entry.pack(pady=10, padx=20)

        # Password Entry
        self.register_password_entry = ctk.CTkEntry(self.register_tab, placeholder_text="Password", show="*")
        self.register_password_entry.pack(pady=10, padx=20)

        # Register Button
        self.register_button = ctk.CTkButton(self.register_tab, text="Register", command=self.handle_register)
        self.register_button.pack(pady=20)

    def handle_login(self):
        username = self.login_username_entry.get()
        password = self.login_password_entry.get()

        if not username or not password:
            self.update_status("Please fill in all fields.")
            return

        rsa_private_key, rsa_public_key, des_key, aes_key = load_keys()

        if not os.path.exists(USERS_FILE):
            self.update_status("No users registered.")
            return

        with open(USERS_FILE, "r") as users_file:
            for line in users_file:
                stored_username, stored_password = line.strip().split(":")
                if stored_username == username:
                    try:
                        # Decrypt the stored password
                        decrypted_hash = onion_decrypt(stored_password, des_key, aes_key, rsa_private_key)
                        input_hash = sha256(password.encode()).digest()

                        if decrypted_hash == input_hash:
                            self.update_status("Login successful.")

                            # Display hashes and encryption steps in separate lines below the password bar
                            des_cipher = DES.new(des_key, DES.MODE_CBC)
                            aes_cipher = AES.new(aes_key, AES.MODE_CBC)
                            des_encrypted = des_cipher.encrypt(pad(input_hash, DES.block_size))
                            aes_encrypted = aes_cipher.encrypt(pad(des_encrypted, AES.block_size))

                            self.result_label.configure(
                                text=f"SHA-256 Hash:\n{input_hash.hex()}\n\n"
                                     f"DES Encrypted:\n{base64.b64encode(des_encrypted).decode()}\n\n"
                                     f"AES Encrypted:\n{base64.b64encode(aes_encrypted).decode()}\n\n"
                                     f"RSA Encrypted:\n{stored_password}",
                                justify="center")
                            return
                    except Exception as e:
                        self.update_status(f"Error during decryption: {e}")
                        return
        self.update_status("Invalid username or password.")

    def handle_register(self):
        username = self.register_username_entry.get()
        password = self.register_password_entry.get()

        if not username or not password:
            self.update_status("Please fill in all fields.")
            return

        rsa_private_key, rsa_public_key, des_key, aes_key = load_keys()
        encrypted_password = onion_encrypt(password, des_key, aes_key, rsa_public_key)

        with open(USERS_FILE, "a") as users_file:
            users_file.write(f"{username}:{encrypted_password}\n")
        self.update_status("Registration successful.")

    def update_status(self, message):
        self.status_label.configure(text=message)

if __name__ == "__main__":
    app = SecureAuthApp()
    app.mainloop()