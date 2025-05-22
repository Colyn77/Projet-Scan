import psutil
from datetime import datetime
import os
from chiffrement_module import encrypt_file

def analyser_processus_suspects():
    lignes = []
    lignes.append(f"🕵️ Analyse mémoire - {datetime.now()}\n")

    for proc in psutil.process_iter(attrs=['pid', 'name', 'username']):
        try:
            infos = proc.info
            connections = proc.connections()  # ✅ appel séparé

            if infos['username'] != 'root' and connections:
                lignes.append(f"[⚠️] Process suspect : {infos['name']} (PID {infos['pid']}) - Connexions actives")
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    # Création du dossier
    os.makedirs("forensics", exist_ok=True)

    # Sauvegarde brute
    with open("forensics/memory_dump.txt", "w") as f:
        f.write("\n".join(lignes))

    print("✅ Dump mémoire généré dans forensics/memory_dump.txt")

    # 🔐 Chiffrement
    encrypt_file("forensics/memory_dump.txt", "forensics/memory_dump.encrypted")
    print("🔒 Fichier mémoire chiffré : memory_dump.encrypted")
