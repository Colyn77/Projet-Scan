import socket

def get_info():
    return {
        "name": "Reverse DNS",
        "description": "Résout une IP en nom de domaine",
        "author": "bryan",
        "version": "1.0"
    }

def run(input_data):
    ip = input_data.get("ip")
    if not ip:
        return {"error": "IP manquante"}
    try:
        host = socket.gethostbyaddr(ip)[0]
        return {"hostname": host}
    except Exception as e:
        return {"error": str(e)}
