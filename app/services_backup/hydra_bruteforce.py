import subprocess
import os
from datetime import datetime
from app.utils.logger import get_logger

# Configuration du logger
logger = get_logger('hydra_bruteforce')

# Répertoire pour stocker les fichiers temporaires de wordlists
WORDLISTS_DIR = "wordlists"

def get_available_wordlists():
    """
    Récupère les wordlists disponibles dans le système
    
    Returns:
        dict: Dictionnaires contenant les listes d'utilisateurs et de mots de passe
    """
    logger.info("Récupération des wordlists disponibles")
    
    # Créer le dossier s'il n'existe pas
    if not os.path.exists(WORDLISTS_DIR):
        os.makedirs(WORDLISTS_DIR)
        logger.debug(f"Création du dossier {WORDLISTS_DIR}")
    
    # Chemins par défaut pour Kali Linux
    common_paths = [
        "/usr/share/wordlists",
        "/usr/share/seclists",
        WORDLISTS_DIR
    ]
    
    user_lists = []
    pass_lists = []
    
    # Parcourir les chemins communs
    for path in common_paths:
        if os.path.exists(path):
            logger.debug(f"Exploration du chemin: {path}")
            for root, _, files in os.walk(path):
                for file in files:
                    full_path = os.path.join(root, file)
                    # Filtrer les fichiers selon certains critères
                    if os.path.getsize(full_path) < 20 * 1024 * 1024:  # Limiter à 20MB
                        # MODIFICATION: Si le fichier est dans notre WORDLISTS_DIR local, l'ajouter aux deux listes
                        if root == WORDLISTS_DIR:
                            # Ajouter le fichier aux listes d'utilisateurs
                            user_lists.append({"name": file, "path": full_path})
                            # Et aussi aux listes de mots de passe
                            pass_lists.append({"name": file, "path": full_path})
                            logger.debug(f"Ajout de {file} aux listes utilisateurs et mots de passe")
                        else:
                            # Pour les autres chemins, garder le comportement original
                            if "user" in file.lower() or "login" in file.lower():
                                user_lists.append({"name": file, "path": full_path})
                                logger.debug(f"Ajout de {file} à la liste des utilisateurs")
                            elif "pass" in file.lower() or "pwd" in file.lower() or "dict" in file.lower():
                                pass_lists.append({"name": file, "path": full_path})
                                logger.debug(f"Ajout de {file} à la liste des mots de passe")
    
    # Ajouter les wordlists communes si elles existent
    if os.path.exists("/usr/share/wordlists/rockyou.txt"):
        pass_lists.append({"name": "rockyou.txt", "path": "/usr/share/wordlists/rockyou.txt"})
        logger.debug("Ajout de rockyou.txt")
    
    if os.path.exists("/etc/passwd"):
        user_lists.append({"name": "system-users", "path": "/etc/passwd"})
        logger.debug("Ajout des utilisateurs système")
    
    logger.info(f"Trouvé {len(user_lists)} listes d'utilisateurs et {len(pass_lists)} listes de mots de passe")
    
    return {
        "user_lists": sorted(user_lists, key=lambda x: x["name"]),
        "pass_lists": sorted(pass_lists, key=lambda x: x["name"])
    }

def create_custom_wordlist(content, list_type="userlist"):
    """
    Crée une wordlist personnalisée à partir du contenu fourni
    
    Args:
        content (str): Contenu de la wordlist (une entrée par ligne)
        list_type (str): Type de liste ('userlist' ou 'passlist')
        
    Returns:
        str: Chemin vers le fichier de wordlist créé
    """
    logger.info(f"Création d'une wordlist personnalisée de type {list_type}")
    
    # Créer le dossier s'il n'existe pas
    if not os.path.exists(WORDLISTS_DIR):
        os.makedirs(WORDLISTS_DIR)
        logger.debug(f"Création du dossier {WORDLISTS_DIR}")
    
    # Générer un nom de fichier unique
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{WORDLISTS_DIR}/{list_type}_{timestamp}.txt"
    
    try:
        # Écrire le contenu dans le fichier
        with open(filename, "w") as f:
            f.write(content)
        
        logger.info(f"Wordlist personnalisée créée: {filename}")
        return filename
    except Exception as e:
        logger.error(f"Erreur lors de la création de la wordlist: {e}", exc_info=True)
        raise

def get_services():
    """
    Récupère la liste des services supportés par Hydra
    
    Returns:
        list: Liste des services supportés
    """
    logger.debug("Récupération de la liste des services Hydra")
    
    # Services couramment utilisés avec Hydra
    common_services = [
        {"name": "ssh", "port": 22, "description": "Secure Shell"},
        {"name": "ftp", "port": 21, "description": "File Transfer Protocol"},
        {"name": "telnet", "port": 23, "description": "Telnet Remote Login"},
        {"name": "http-get", "port": 80, "description": "HTTP GET Form"},
        {"name": "http-post-form", "port": 80, "description": "HTTP POST Form"},
        {"name": "https-get", "port": 443, "description": "HTTPS GET Form"},
        {"name": "https-post-form", "port": 443, "description": "HTTPS POST Form"},
        {"name": "smb", "port": 445, "description": "SMB/CIFS Protocol"},
        {"name": "mysql", "port": 3306, "description": "MySQL Database"},
        {"name": "postgres", "port": 5432, "description": "PostgreSQL Database"},
        {"name": "mssql", "port": 1433, "description": "Microsoft SQL Server"},
        {"name": "vnc", "port": 5900, "description": "VNC Remote Desktop"},
        {"name": "rdp", "port": 3389, "description": "Remote Desktop Protocol"},
        {"name": "smtp", "port": 25, "description": "Simple Mail Transfer Protocol"},
        {"name": "pop3", "port": 110, "description": "Post Office Protocol v3"},
        {"name": "imap", "port": 143, "description": "Internet Message Access Protocol"}
    ]
    
    return common_services

def run_hydra(target_ip, service, userlist, passlist, options=None):
    """
    Lance une attaque brute-force avec Hydra
    
    Args:
        target_ip (str): Adresse IP ou nom d'hôte de la cible
        service (str): Service à attaquer (ssh, ftp, etc.)
        userlist (str): Chemin vers la liste d'utilisateurs
        passlist (str): Chemin vers la liste de mots de passe
        options (dict, optional): Options supplémentaires pour Hydra
        
    Returns:
        dict: Résultats de l'attaque
    """
    logger.info(f"Lancement de l'attaque Hydra sur {target_ip} - Service: {service}")
    
    # Vérifier que les fichiers existent
    if not os.path.exists(userlist):
        logger.error(f"Liste d'utilisateurs introuvable: {userlist}")
        return {"error": f"Liste d'utilisateurs introuvable: {userlist}"}
    
    if not os.path.exists(passlist):
        logger.error(f"Liste de mots de passe introuvable: {passlist}")
        return {"error": f"Liste de mots de passe introuvable: {passlist}"}
    
    # Options par défaut
    if options is None:
        options = {}
    
    # Construction de la commande
    command = ["hydra"]
    
    # Ajouter les options
    if options.get("tasks"):
        command.extend(["-t", str(options["tasks"])])
    
    if options.get("verbose"):
        command.append("-v")
    
    # Paramètres principaux
    command.extend([
        "-L", userlist,
        "-P", passlist
    ])
    
    # Paramètres spécifiques aux formulaires HTTP
    if service.startswith("http") and "form" in service:
        form_path = options.get("form_path", "/")
        form_data = options.get("form_data", "username=^USER^&password=^PASS^")
        form_success = options.get("form_success", "F=incorrect")
        
        # Format pour http-post-form: "path:form_data:failure_message"
        http_form_param = f"{form_path}:{form_data}:{form_success}"
        command.extend([target_ip, service, http_form_param])
    else:
        # Pour les autres services
        command.append(f"{target_ip}")
        command.append(service)
    
    try:
        logger.info(f"Commande Hydra: {' '.join(command)}")
        
        # Exécuter la commande
        process = subprocess.run(command, capture_output=True, text=True, timeout=600)
        
        # Traiter la sortie
        if process.returncode == 0:
            # Analyser les résultats
            credentials = []
            for line in process.stdout.splitlines():
                if "host:" in line and "login:" in line and "password:" in line:
                    credentials.append(line.strip())
                    logger.info(f"Credentials trouvés: {line.strip()}")
            
            if credentials:
                logger.info(f"Attaque réussie: {len(credentials)} credential(s) trouvé(s)")
            else:
                logger.info("Attaque terminée sans trouver de credentials")
            
            return {
                "success": True,
                "credentials": credentials,
                "stdout": process.stdout,
                "stderr": process.stderr,
                "command": " ".join(command)
            }
        else:
            # Si Hydra renvoie un code d'erreur
            logger.error(f"Hydra a échoué avec le code {process.returncode}")
            return {
                "success": False,
                "error": f"Hydra a échoué avec le code {process.returncode}",
                "stdout": process.stdout,
                "stderr": process.stderr,
                "command": " ".join(command)
            }
    except subprocess.TimeoutExpired:
        logger.error("Délai d'exécution dépassé (10 minutes)")
        return {
            "success": False,
            "error": "Délai d'exécution dépassé (10 minutes)",
            "command": " ".join(command)
        }
    except Exception as e:
        logger.error(f"Erreur d'exécution : {str(e)}", exc_info=True)
        return {
            "success": False,
            "error": f"Erreur d'exécution : {str(e)}",
            "command": " ".join(command)
        }

# Test du module
if __name__ == "__main__":
    # Afficher les wordlists disponibles
    wordlists = get_available_wordlists()
    print(f"Listes d'utilisateurs disponibles: {len(wordlists['user_lists'])}")
    print(f"Listes de mots de passe disponibles: {len(wordlists['pass_lists'])}")
    
    # Créer une wordlist personnalisée
    user_file = create_custom_wordlist("root\nadmin\nuser", "userlist")
    pass_file = create_custom_wordlist("password\n123456\nadmin", "passlist")
    
    # Afficher les services disponibles
    services = get_services()
    print(f"Services disponibles: {len(services)}")
    
    # Exemple d'utilisation
    result = run_hydra("127.0.0.1", "ssh", user_file, pass_file)
    print(result)
