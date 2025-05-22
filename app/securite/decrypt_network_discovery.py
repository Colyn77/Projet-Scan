from chiffrement_module import decrypt_file
import json

# Déchiffrement
encrypted_path = "results/network_discovery.encrypted"
decrypted_path = "results/network_discovery_decrypted.json"

decrypt_file(encrypted_path, decrypted_path)

# Affichage du contenu
with open(decrypted_path, "r") as f:
    data = json.load(f)

print("✅ Résultats déchiffrés :\n")
for host in data:
    print(f"- IP : {host['ip']} | État : {host['state']} | Nom : {host['hostname']}")

# Optionnel : supprimer le fichier déchiffré après affichage
# import os
# os.remove(decrypted_path)
