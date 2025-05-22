import os
import psutil
from datetime import datetime
from flask import session
from app.securite.chiffrement_module import encrypt_file
import zipfile

def analyser_processus_suspects():
    utilisateur = session.get("username", "inconnu")
    horodatage = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = f"{utilisateur}_{horodatage}"
    
    lignes = [
        f"🧠 Analyse mémoire lancée par : {utilisateur}",
        f"📅 Date : {datetime.now()}",
        ""
    ]

    # Analyse des processus avec connexions réseau
    for proc in psutil.process_iter(attrs=["pid", "name", "username"]):
        try:
            info = proc.info
            conns = proc.connections()
            if info["username"] != "root" and conns:
                lignes.append(
                    f"[⚠️] Process suspect : {info['name']} (PID {info['pid']}) avec connexions actives."
                )
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    # Analyse mémoire (RAM)
    mem = psutil.virtual_memory()
    swap = psutil.swap_memory()

    lignes.append("\n=== État mémoire (RAM) ===")
    lignes.append(f"Total       : {mem.total / (1024 ** 2):.2f} MB")
    lignes.append(f"Utilisé     : {mem.used / (1024 ** 2):.2f} MB")
    lignes.append(f"Disponible  : {mem.available / (1024 ** 2):.2f} MB")
    lignes.append(f"Pourcentage : {mem.percent}%")

    lignes.append("\n=== Mémoire SWAP ===")
    lignes.append(f"Total   : {swap.total / (1024 ** 2):.2f} MB")
    lignes.append(f"Utilisé : {swap.used / (1024 ** 2):.2f} MB")

    # Enregistrement et chiffrement
    os.makedirs("forensics", exist_ok=True)

    txt_path = f"forensics/{base_name}.txt"
    enc_path = f"forensics/{base_name}.encrypted"

    with open(txt_path, "w") as f:
        f.write("\n".join(lignes))

    encrypt_file(txt_path, enc_path)
    print(f"✅ Rapport généré : {enc_path}")

        # Archivage ZIP
    os.makedirs("forensics/archives", exist_ok=True)
    zip_path = f"forensics/archives/{base_name}.zip"
    
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.write(txt_path)
        archive.write(enc_path)
    
    print(f"📦 Rapport archivé : {zip_path}")

