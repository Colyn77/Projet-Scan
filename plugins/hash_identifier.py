import re

def get_info():
    return {
        "name": "Hash Identifier",
        "description": "Tente d’identifier le type de hash fourni",
        "author": "bryan",
        "version": "1.0"
    }

def run(input_data):
    hash_value = input_data.get("hash", "")
    if not hash_value:
        return {"error": "Aucun hash fourni"}
    
    patterns = {
        "MD5": r"^[a-fA-F0-9]{32}$",
        "SHA1": r"^[a-fA-F0-9]{40}$",
        "SHA256": r"^[a-fA-F0-9]{64}$",
        "SHA512": r"^[a-fA-F0-9]{128}$",
        "NTLM": r"^[a-fA-F0-9]{32}$"
    }

    matches = [name for name, pattern in patterns.items() if re.fullmatch(pattern, hash_value)]
    return {"possible_types": matches or ["Inconnu"]}
