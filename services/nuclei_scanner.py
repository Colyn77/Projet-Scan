import subprocess
import os
import json
from utils.logger import get_logger
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Union
import csv

# Configuration du logging
logger = get_logger("nuclei_scanner")
# Configuration simple - chemins possibles pour Nuclei
POSSIBLE_NUCLEI_PATHS = [
    "./bin/nuclei",
    "/usr/local/bin/nuclei", 
    "/usr/bin/nuclei",
    "nuclei"  # Dans le PATH
]

OUTPUT_FOLDER = "generated_reports/nuclei"
TEMPLATES_FOLDER = "./nuclei-templates"
NUCLEI_BINARY = None  # Sera défini par check_nuclei_available()

# Création des dossiers nécessaires
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

def get_nuclei_version() -> str:
    """Récupère la version de Nuclei"""
    try:
        if NUCLEI_BINARY:
            result = subprocess.run([NUCLEI_BINARY, "-version"], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                # Extraire la version du output
                output = result.stdout.strip()
                return output
    except Exception:
        pass
    return "unknown"

def get_json_flag() -> str:
    """Retourne le bon flag JSON selon la version de Nuclei"""
    version_output = get_nuclei_version()
    logger.info(f"Version Nuclei détectée: {version_output}")
    
    # Pour toutes les versions modernes, utiliser -jsonl
    # Nuclei utilise -jsonl comme format de sortie standard
    return "-jsonl"

def check_nuclei_available() -> bool:
    """Vérifie si Nuclei est disponible et définit le chemin"""
    global NUCLEI_BINARY
    
    for path in POSSIBLE_NUCLEI_PATHS:
        try:
            result = subprocess.run([path, "-version"], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                NUCLEI_BINARY = path
                logger.info(f"Nuclei trouvé et fonctionnel: {path}")
                return True
        except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError) as e:
            logger.debug(f"Nuclei non trouvé à {path}: {e}")
            continue
    
    logger.error("Nuclei non disponible dans aucun chemin testé")
    return False

def install_nuclei() -> Dict[str, Union[str, bool]]:
    """Tente d'installer Nuclei automatiquement"""
    try:
        logger.info("Tentative d'installation de Nuclei...")
        
        # Créer le dossier bin s'il n'existe pas
        os.makedirs("./bin", exist_ok=True)
        
        # Déterminer l'architecture
        import platform
        system = platform.system().lower()
        arch = platform.machine().lower()
        
        # Mapper l'architecture
        if arch in ['x86_64', 'amd64']:
            arch = 'amd64'
        elif arch in ['aarch64', 'arm64']:
            arch = 'arm64'
        else:
            return {"success": False, "error": f"Architecture non supportée: {arch}"}
        
        # URL de téléchargement
        filename = f"nuclei_3.2.9_{system}_{arch}.zip"
        url = f"https://github.com/projectdiscovery/nuclei/releases/download/v3.2.9/{filename}"
        
        # Télécharger avec curl ou wget
        download_commands = [
            ["curl", "-L", "-o", f"./bin/{filename}", url],
            ["wget", "-O", f"./bin/{filename}", url]
        ]
        
        download_success = False
        for cmd in download_commands:
            try:
                result = subprocess.run(cmd, capture_output=True, timeout=60)
                if result.returncode == 0:
                    download_success = True
                    logger.info(f"Téléchargement réussi avec {cmd[0]}")
                    break
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
        
        if not download_success:
            return {"success": False, "error": "Impossible de télécharger Nuclei (curl/wget non disponible)"}
        
        # Décompresser
        try:
            result = subprocess.run(["unzip", "-o", f"./bin/{filename}", "-d", "./bin/"], 
                                  capture_output=True, timeout=30)
            if result.returncode != 0:
                return {"success": False, "error": "Erreur lors de la décompression"}
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return {"success": False, "error": "unzip non disponible"}
        
        # Rendre exécutable
        nuclei_path = "./bin/nuclei"
        os.chmod(nuclei_path, 0o755)
        
        # Nettoyer
        try:
            os.remove(f"./bin/{filename}")
        except:
            pass
        
        # Vérifier l'installation
        if check_nuclei_available():
            return {"success": True, "message": "Nuclei installé avec succès"}
        else:
            return {"success": False, "error": "Installation échouée - binaire non fonctionnel"}
            
    except Exception as e:
        logger.error(f"Erreur lors de l'installation: {e}")
        return {"success": False, "error": str(e)}

def update_templates() -> Dict[str, Union[str, bool]]:
    """Met à jour les templates Nuclei"""
    if not NUCLEI_BINARY or not check_nuclei_available():
        return {"success": False, "error": "Nuclei non disponible"}
    
    try:
        command = [NUCLEI_BINARY, "-update-templates"]
        result = subprocess.run(command, capture_output=True, text=True, timeout=300)
        
        if result.returncode == 0:
            logger.info("Templates Nuclei mis à jour avec succès")
            return {"success": True, "message": "Templates mis à jour"}
        else:
            logger.error(f"Erreur mise à jour templates: {result.stderr}")
            return {"success": False, "error": result.stderr}
            
    except Exception as e:
        logger.error(f"Erreur lors de la mise à jour: {e}")
        return {"success": False, "error": str(e)}

def get_available_templates() -> List[str]:
    """Récupère la liste des catégories de templates disponibles"""
    categories = [
        "cve", "exposures", "technologies", "vulnerabilities", 
        "misconfiguration", "default-logins", "takeovers",
        "dns", "file", "network", "ssl", "headless"
    ]
    return categories

def scan_url(
    url: str, 
    severity: str = "medium,high,critical",
    templates: Optional[List[str]] = None,
    exclude_tags: Optional[List[str]] = None,
    timeout: int = 300,
    rate_limit: int = 150,
    custom_headers: Optional[Dict[str, str]] = None
) -> Dict:
    """Lance un scan Nuclei sur une URL - Compatible toutes versions"""
    
    if not NUCLEI_BINARY or not check_nuclei_available():
        return {"error": "Nuclei n'est pas disponible sur ce système"}
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = os.path.join(OUTPUT_FOLDER, f"nuclei_{timestamp}.json")
    
    # Détecter le bon flag JSON
    json_flag = get_json_flag()
    logger.info(f"Utilisation du flag JSON: {json_flag}")
    
    # Construction de la commande de base
    command = [
        NUCLEI_BINARY,
        "-u", url,
        json_flag,  # -json ou -jsonl selon la version
        "-o", output_path,
        "-rate-limit", str(rate_limit),
        "-timeout", str(timeout)
    ]
    
    # Ajouter des tags par défaut si aucun spécifié
    if templates and len(templates) > 0:
        for template in templates:
            command.extend(["-tags", template])
    else:
        # Tags par défaut qui fonctionnent bien
        command.extend(["-tags", "cve,exposure,misconfiguration"])
    
    # Ajouter severity
    if severity:
        command.extend(["-severity", severity])
    
    try:
        logger.info(f"Démarrage du scan Nuclei pour {url}")
        logger.info(f"Commande: {' '.join(command)}")
        
        # Exécution du scan
        process = subprocess.run(
            command, 
            capture_output=True, 
            text=True, 
            timeout=timeout + 60
        )
        
        logger.info(f"Code de retour: {process.returncode}")
        if process.stderr:
            logger.info(f"Stderr: {process.stderr}")
        
        # Vérifier la création du fichier
        if not os.path.exists(output_path) or os.path.getsize(output_path) == 0:
            return {
                "error": f"Aucun résultat généré. Code: {process.returncode}",
                "details": {
                    "stderr": process.stderr,
                    "command": " ".join(command),
                    "json_flag_used": json_flag
                }
            }
        
        # Parse des résultats
        results = parse_results(output_path)
        
        # Ajout des métadonnées
        results["scan_info"] = {
            "target": url,
            "timestamp": timestamp,
            "severity": severity,
            "templates_used": templates or ["cve", "exposure", "misconfiguration"],
            "nuclei_version": get_nuclei_version(),
            "json_flag_used": json_flag
        }
        
        logger.info(f"Scan terminé. {len(results.get('findings', []))} vulnérabilités trouvées")
        return results
        
    except subprocess.TimeoutExpired:
        logger.error(f"Timeout du scan pour {url}")
        return {"error": f"Timeout du scan après {timeout} secondes"}
    except Exception as e:
        logger.error(f"Erreur inattendue: {e}")
        return {"error": f"Erreur inattendue: {str(e)}"}

def scan_multiple_urls(
    urls: List[str], 
    severity: str = "medium,high,critical",
    templates: Optional[List[str]] = None,
    batch_size: int = 10,
    timeout: int = 300
) -> Dict:
    """Lance un scan Nuclei sur plusieurs URLs avec traitement par batch"""
    
    if not NUCLEI_BINARY or not check_nuclei_available():
        return {"error": "Nuclei n'est pas disponible sur ce système"}
    
    if not urls:
        return {"error": "Aucune URL fournie"}
    
    if len(urls) > 100:
        return {"error": "Trop d'URLs (maximum 100)"}
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = os.path.join(OUTPUT_FOLDER, f"nuclei_batch_{timestamp}.json")
    
    # Créer un fichier temporaire avec les URLs
    urls_file = os.path.join(OUTPUT_FOLDER, f"temp_urls_{timestamp}.txt")
    
    try:
        # Écrire les URLs dans un fichier temporaire
        with open(urls_file, 'w', encoding='utf-8') as f:
            for url in urls:
                f.write(f"{url}\n")
        
        # Construction de la commande
        command = [
            NUCLEI_BINARY,
            "-list", urls_file,
            "-severity", severity,
            "-json",
            "-o", output_path,
            "-rate-limit", "100",
            "-timeout", str(timeout),
            "-silent",
            "-bulk-size", str(batch_size)
        ]
        
        # Ajout des templates spécifiques
        if templates:
            for template in templates:
                command.extend(["-tags", template])
        
        logger.info(f"Démarrage du scan Nuclei pour {len(urls)} URLs")
        
        # Exécution du scan
        process = subprocess.run(
            command, 
            capture_output=True, 
            text=True, 
            timeout=timeout * 2
        )
        
        # Parse des résultats
        results = parse_results(output_path)
        
        # Ajout des métadonnées
        results["scan_info"] = {
            "targets": urls,
            "targets_count": len(urls),
            "timestamp": timestamp,
            "severity": severity,
            "templates_used": templates or "default",
            "batch_size": batch_size
        }
        
        logger.info(f"Scan batch terminé. {len(results.get('findings', []))} vulnérabilités trouvées sur {len(urls)} URLs")
        return results
        
    except subprocess.TimeoutExpired:
        logger.error(f"Timeout du scan batch après {timeout * 2} secondes")
        return {"error": f"Timeout du scan après {timeout * 2} secondes"}
    except Exception as e:
        logger.error(f"Erreur inattendue lors du scan batch: {e}")
        return {"error": f"Erreur inattendue: {str(e)}"}
    finally:
        # Nettoyage du fichier temporaire
        try:
            if os.path.exists(urls_file):
                os.remove(urls_file)
        except Exception as e:
            logger.warning(f"Impossible de supprimer le fichier temporaire: {e}")

def parse_results(filepath: str) -> Dict:
    """Parse les résultats JSON de Nuclei"""
    findings = []
    stats = {"total": 0, "by_severity": {}}
    
    if not os.path.exists(filepath):
        logger.warning(f"Fichier de résultat non trouvé: {filepath}")
        return {"findings": [], "stats": stats, "source": filepath, "success": True}
    
    try:
        with open(filepath, "r", encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                    
                try:
                    finding = json.loads(line)
                    findings.append(finding)
                    
                    # Statistiques
                    severity = finding.get("info", {}).get("severity", "unknown")
                    stats["by_severity"][severity] = stats["by_severity"].get(severity, 0) + 1
                    stats["total"] += 1
                    
                except json.JSONDecodeError:
                    continue
        
        return {
            "findings": findings, 
            "stats": stats,
            "source": filepath,
            "success": True
        }
        
    except Exception as e:
        logger.error(f"Erreur lors du parsing: {e}")
        return {"error": f"Erreur lors du parsing: {str(e)}", "findings": [], "stats": stats}

def get_scan_history() -> List[Dict]:
    """Récupère l'historique des scans"""
    history = []
    
    try:
        if not os.path.exists(OUTPUT_FOLDER):
            return history
            
        for filename in os.listdir(OUTPUT_FOLDER):
            if filename.endswith('.json') and filename.startswith('nuclei_'):
                filepath = os.path.join(OUTPUT_FOLDER, filename)
                stat = os.stat(filepath)
                
                # Extraction des infos du nom de fichier
                timestamp_str = filename.replace('nuclei_', '').replace('.json', '')
                
                try:
                    scan_time = datetime.strptime(timestamp_str, "%Y%m%d_%H%M%S")
                except ValueError:
                    scan_time = datetime.fromtimestamp(stat.st_mtime)
                
                # Compter les findings
                results = parse_results(filepath)
                finding_count = len(results.get('findings', []))
                
                history.append({
                    "filename": filename,
                    "timestamp": scan_time.isoformat(),
                    "size": stat.st_size,
                    "findings_count": finding_count,
                    "stats": results.get('stats', {})
                })
        
        # Tri par date décroissante
        history.sort(key=lambda x: x['timestamp'], reverse=True)
        
    except Exception as e:
        logger.error(f"Erreur récupération historique: {e}")
    
    return history

def get_scan_report(filename: str) -> Dict:
    """Récupère un rapport de scan spécifique"""
    filepath = os.path.join(OUTPUT_FOLDER, filename)
    
    if not os.path.exists(filepath):
        return {"error": "Rapport introuvable"}
    
    return parse_results(filepath)

def export_report(filename: str, format_type: str = "json") -> Dict:
    """Exporte un rapport dans différents formats"""
    filepath = os.path.join(OUTPUT_FOLDER, filename)
    
    if not os.path.exists(filepath):
        return {"error": "Rapport introuvable"}
    
    try:
        results = parse_results(filepath)
        
        if format_type == "json":
            return results
        elif format_type == "csv":
            csv_filename = filename.replace('.json', '.csv')
            csv_filepath = os.path.join(OUTPUT_FOLDER, csv_filename)
            
            with open(csv_filepath, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = ['host', 'template_id', 'name', 'severity', 'description', 'matched_at']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                
                writer.writeheader()
                for finding in results.get('findings', []):
                    info = finding.get('info', {})
                    writer.writerow({
                        'host': finding.get('host', ''),
                        'template_id': finding.get('template-id', ''),
                        'name': info.get('name', ''),
                        'severity': info.get('severity', ''),
                        'description': info.get('description', ''),
                        'matched_at': finding.get('matched_at', '')
                    })
            
            return {"success": True, "file": csv_filename}
        else:
            return {"error": "Format non supporté"}
            
    except Exception as e:
        logger.error(f"Erreur lors de l'export: {e}")
        return {"error": str(e)}

def clean_old_reports(days: int = 30) -> Dict:
    """Nettoie les anciens rapports"""
    try:
        if not os.path.exists(OUTPUT_FOLDER):
            return {"success": True, "deleted": 0}
        
        cutoff_date = datetime.now() - timedelta(days=days)
        deleted_count = 0
        
        for filename in os.listdir(OUTPUT_FOLDER):
            if filename.endswith('.json') and filename.startswith('nuclei_'):
                filepath = os.path.join(OUTPUT_FOLDER, filename)
                file_time = datetime.fromtimestamp(os.path.getmtime(filepath))
                
                if file_time < cutoff_date:
                    os.remove(filepath)
                    deleted_count += 1
                    logger.info(f"Rapport supprimé: {filename}")
        
        return {"success": True, "deleted": deleted_count}
        
    except Exception as e:
        logger.error(f"Erreur lors du nettoyage: {e}")
        return {"success": False, "error": str(e)}

# Initialisation au chargement du module
logger.info("Vérification de la disponibilité de Nuclei...")
check_nuclei_available()
