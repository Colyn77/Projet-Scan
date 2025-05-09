import os
import zipfile
from datetime import datetime
from flask import session
from scapy.all import sniff, IP, TCP, UDP
from securite.chiffrement_module import encrypt_file

def analyser_trafic(interface="lo", count=50):
    utilisateur = session.get("username", "inconnu")
    horodatage = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = f"{utilisateur}_{horodatage}"

    lignes = [
        f"🧠 Analyse réseau déclenchée par : {utilisateur}",
        f"📅 Date : {datetime.now()}",
        f"🌐 Interface : {interface}",
        f"📦 Nombre de paquets : {count}",
        ""
    ]

    try:
        paquets = sniff(count=count, iface=interface, timeout=10)
    except Exception as e:
        return False, [f"❌ Erreur pendant le sniff : {str(e)}"]

    for pkt in paquets:
        if IP in pkt:
            proto = "TCP" if TCP in pkt else "UDP" if UDP in pkt else "?"
            lignes.append(f"[{proto}] {pkt[IP].src} → {pkt[IP].dst}")

    # Enregistrement + chiffrement
    os.makedirs("sniffer", exist_ok=True)
    os.makedirs("sniffer/archives", exist_ok=True)

    txt_path = f"sniffer/{base}.txt"
    enc_path = f"sniffer/{base}.encrypted"
    zip_path = f"sniffer/archives/{base}.zip"

    with open(txt_path, "w") as f:
        f.write("\n".join(lignes))

    encrypt_file(txt_path, enc_path)

    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.write(txt_path)
        zipf.write(enc_path)

    return True, lignes, zip_path
