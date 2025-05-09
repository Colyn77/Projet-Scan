# securite/chiffrement_module.py
import os
from cryptography.fernet import Fernet

KEY_FILE = "securite/secret.key"

def generate_key():
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(key)

def load_key():
    if not os.path.exists(KEY_FILE):
        generate_key()
    with open(KEY_FILE, "rb") as f:
        return f.read()

# Utilitaires chiffrer/déchiffrer
def encrypt(data: bytes) -> bytes:
    fernet = Fernet(load_key())
    return fernet.encrypt(data)

def decrypt(token: bytes) -> bytes:
    fernet = Fernet(load_key())
    return fernet.decrypt(token)

def encrypt_file(input_file: str, output_file: str):
    with open(input_file, "rb") as f:
        data = f.read()
    encrypted_data = encrypt(data)
    with open(output_file, "wb") as f:
        f.write(encrypted_data)

def decrypt_file(input_file: str, output_file: str):
    """Déchiffre un fichier crypté et enregistre le contenu déchiffré."""
    with open(input_file, "rb") as f:
        encrypted_data = f.read()
    decrypted_data = decrypt(encrypted_data)
    with open(output_file, "wb") as f:
        f.write(decrypted_data)
