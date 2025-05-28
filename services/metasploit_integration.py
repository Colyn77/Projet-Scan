# services/metasploit_integration.py
# Créez ce nouveau fichier dans votre dossier services/

import subprocess
import shutil
import tempfile
import os
from utils.logger import get_logger

logger = get_logger('metasploit')

def check_metasploit_availability():
    """Vérifie si Metasploit Framework est disponible et configuré"""
    try:
        # 1. Vérifier msfconsole
        msfconsole_path = shutil.which("msfconsole")
        if not msfconsole_path:
            return False, "msfconsole non trouvé"
        
        # 2. Test rapide de msfconsole
        result = subprocess.run(
            ["msfconsole", "-q", "-x", "version; exit"], 
            capture_output=True, 
            text=True, 
            timeout=30
        )
        
        if result.returncode == 0:
            logger.info("Metasploit Framework disponible et fonctionnel")
            return True, "Metasploit OK"
        else:
            error_msg = result.stderr.strip() if result.stderr else "Erreur inconnue"
            logger.error(f"Erreur Metasploit: {error_msg}")
            return False, error_msg
            
    except subprocess.TimeoutExpired:
        logger.error("Timeout lors du test de msfconsole")
        return False, "Timeout msfconsole"
    except Exception as e:
        logger.error(f"Erreur lors de la vérification de Metasploit: {e}")
        return False, str(e)

def execute_metasploit_exploit(exploit_module, target_ip, target_port=None, options=None):
    """Exécuter un exploit Metasploit"""
    try:
        # Vérifier que Metasploit est disponible
        available, msg = check_metasploit_availability()
        if not available:
            return {
                "success": False,
                "error": f"Metasploit non disponible: {msg}",
                "available": False
            }
        
        logger.info(f"Lancement exploit {exploit_module} sur {target_ip}")
        
        # Créer le fichier de commandes Metasploit
        commands = [
            f"use {exploit_module}",
            f"set RHOSTS {target_ip}"
        ]
        
        if target_port:
            commands.append(f"set RPORT {target_port}")
        
        # Ajouter options personnalisées
        if options:
            for key, value in options.items():
                commands.append(f"set {key} {value}")
        
        # Commandes d'exécution
        commands.extend([
            "check",
            "exploit",
            "exit"
        ])
        
        # Créer fichier temporaire
        with tempfile.NamedTemporaryFile(mode='w', suffix='.rc', delete=False) as f:
            for cmd in commands:
                f.write(f"{cmd}\n")
            rc_file = f.name
        
        try:
            # Exécuter msfconsole avec le fichier de commandes
            result = subprocess.run(
                ["msfconsole", "-q", "-r", rc_file],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            success = result.returncode == 0
            output = result.stdout
            error = result.stderr
            
            logger.info(f"Exploit terminé - Succès: {success}")
            
            return {
                "success": success,
                "output": output,
                "error": error,
                "exploit_module": exploit_module,
                "target": f"{target_ip}:{target_port}" if target_port else target_ip,
                "available": True
            }
            
        finally:
            # Nettoyer le fichier temporaire
            try:
                os.unlink(rc_file)
            except:
                pass
                
    except subprocess.TimeoutExpired:
        logger.error("Timeout lors de l'exécution de l'exploit")
        return {
            "success": False,
            "error": "Timeout lors de l'exécution",
            "available": True
        }
    except Exception as e:
        logger.error(f"Erreur lors de l'exploitation: {e}")
        return {
            "success": False,
            "error": str(e),
            "available": True
        }

def get_metasploit_info():
    """Récupérer les informations sur Metasploit"""
    try:
        available, msg = check_metasploit_availability()
        
        info = {
            "available": available,
            "message": msg,
            "msfconsole_path": shutil.which("msfconsole"),
            "msfvenom_path": shutil.which("msfvenom"),
            "msfdb_path": shutil.which("msfdb")
        }
        
        if available:
            try:
                # Récupérer la version
                result = subprocess.run(
                    ["msfconsole", "-q", "-x", "version; exit"],
                    capture_output=True,
                    text=True,
                    timeout=15
                )
                if result.returncode == 0:
                    info["version"] = result.stdout.strip()
            except:
                info["version"] = "Version non disponible"
        
        return info
        
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des infos Metasploit: {e}")
        return {
            "available": False,
            "error": str(e)
        }
