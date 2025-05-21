# plugins/password_generator.py
import random
import string

def get_info():
    return {
        "name": "Password Generator",
        "description": "Génère un mot de passe aléatoire fort",
        "author": "bryan",
        "version": "1.0"
    }

def run(input_data):
    # Convertir la valeur en entier, avec une valeur par défaut de 12
    try:
        length = int(input_data.get("length", 12))
    except (ValueError, TypeError):
        length = 12
    
    chars = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(chars) for _ in range(length))
    return {"password": password}
