import hashlib
import os

def get_info():
    return {
        "name": "File Hasher",
        "description": "Calcule les empreintes MD5, SHA1 et SHA256 d’un fichier",
        "author": "bryan",
        "version": "1.0"
    }

def run(input_data):
    file_path = input_data.get("file_path")
    if not file_path or not os.path.isfile(file_path):
        return {"error": "Chemin de fichier invalide"}

    hashes = {"md5": hashlib.md5(), "sha1": hashlib.sha1(), "sha256": hashlib.sha256()}
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                for h in hashes.values():
                    h.update(chunk)
        return {k: v.hexdigest() for k, v in hashes.items()}
    except Exception as e:
        return {"error": str(e)}
