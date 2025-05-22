# ids.py
import time

# Dictionnaire temporaire de tentatives : { ip : [timestamps] }
intrusion_log = {}

# Seuils de sécurité
MAX_FAILED_ATTEMPTS = 5
BLOCK_DURATION = 60  # en secondes

# IP bloquées temporairement
blocked_ips = {}

def log_failed_attempt(ip):
    now = time.time()

    # Réinitialisation auto
    if ip in blocked_ips and now > blocked_ips[ip]:
        del blocked_ips[ip]

    # Si déjà bloqué, ne rien faire
    if ip in blocked_ips:
        return False

    # Enregistre l’échec
    if ip not in intrusion_log:
        intrusion_log[ip] = []
    intrusion_log[ip].append(now)

    # Garde que les dernières 5 minutes
    intrusion_log[ip] = [t for t in intrusion_log[ip] if now - t <60]

    if len(intrusion_log[ip]) >= MAX_FAILED_ATTEMPTS:
        blocked_ips[ip] = now + BLOCK_DURATION
        print(f"🚨 IP bloquée temporairement : {ip}")
        return False

    return True

def is_blocked(ip):
    return ip in blocked_ips
