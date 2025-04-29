# chiffrement_module.py
from cryptography.fernet import Fernet
from key_manager import load_key

key = load_key()
fernet = Fernet(key)

# Chiffrer des données binaires
def encrypt(data: bytes) -> bytes:
    return fernet.encrypt(data)

# Déchiffrer des données binaires
def decrypt(token: bytes) -> bytes:
    return fernet.decrypt(token)

# Chiffrer un fichier
def encrypt_file(input_file, output_file):
    with open(input_file, "rb") as f:
        data = f.read()
    encrypted_data = encrypt(data)
    with open(output_file, "wb") as f:
        f.write(encrypted_data)

# Déchiffrer un fichier
def decrypt_file(input_file, output_file):
    with open(input_file, "rb") as f:
        encrypted_data = f.read()
    decrypted_data = decrypt(encrypted_data)
    with open(output_file, "wb") as f:
        f.write(decrypted_data)

# === MODULE SCAN DE PORTS / VULNÉRABILITÉS ===
def proteger_resultats_scan():
    fichier_resultat = "resultats/scan_result.json"
    fichier_chiffre = "resultats/scan_result.encrypted"
    encrypt_file(fichier_resultat, fichier_chiffre)
    print("✅ Résultats de scan chiffrés")

# === MODULE ANALYSE FORENSIQUE ===
def proteger_donnees_forensiques():
    fichier_dump = "forensics/memory_dump.txt"
    fichier_chiffre = "forensics/memory_dump.encrypted"
    encrypt_file(fichier_dump, fichier_chiffre)
    print("✅ Données forensiques chiffrées")

# === MODULE AUTHENTIFICATION / POST-EXPLOIT ===
def proteger_identifiants():
    creds = b"admin:password123"
    enc = encrypt(creds)
    with open("auth/credentials.encrypted", "wb") as f:
        f.write(enc)
    print("✅ Identifiants chiffrés")

# === MODULE RAPPORTS ===
def proteger_rapport():
    fichier_rapport = "rapport/rapport_final.txt"
    fichier_chiffre = "rapport/rapport_final.encrypted"
    encrypt_file(fichier_rapport, fichier_chiffre)
    print("✅ Rapport chiffré")

# === MODULE TESTS / SAUVEGARDES ===
def proteger_sauvegarde():
    fichier_backup = "sauvegarde/backup_logs.txt"
    fichier_chiffre = "sauvegarde/backup_logs.encrypted"
    encrypt_file(fichier_backup, fichier_chiffre)
    print("✅ Sauvegarde chiffrée")

# === MAIN ===
def main():
    proteger_resultats_scan()
    proteger_donnees_forensiques()
    proteger_identifiants()
    proteger_rapport()
    proteger_sauvegarde()

if __name__ == "__main__":
    main()
