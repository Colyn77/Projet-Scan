import os
import datetime
import json
from jinja2 import Environment, FileSystemLoader
from utils.logger import get_logger

# Configuration du logger
logger = get_logger('reporting_generator')

# Configuration des chemins
TEMPLATES_DIR = "templates"
REPORTS_DIR = "generated_reports"

# Préparer le dossier si pas existant
os.makedirs(REPORTS_DIR, exist_ok=True)

def generate_report(module_name, scan_results, template_name="report_template.html", for_download=True):
    """
    Génère un rapport HTML basé sur un template Jinja2.
    
    Args:
        module_name (str): Nom du module (ex: "vuln_scan", "network_discovery")
        scan_results (dict or list): Résultats du scan
        template_name (str): Nom du template à utiliser
        for_download (bool): Si True, génère une version téléchargeable, sinon une version web
    
    Returns:
        str: Chemin vers le rapport généré
    """
    logger.info(f"Génération d'un rapport pour le module {module_name}")
    
    try:
        env = Environment(loader=FileSystemLoader(TEMPLATES_DIR))
        
        # Choisir le bon template en fonction du module
        if module_name == "vuln_scan":
            if for_download:
                template_name = "vuln_report_template.html"
            else:
                template_name = "vuln_results.html"
        elif module_name == "sniffer":
            template_name = "sniffer_report_template.html"
        
        template = env.get_template(template_name)
        
        now = datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        
        # Préparation des données pour le template
        data = {
            "module_name": module_name,
            "generated_on": now,
            "results": scan_results,  # Pour compatibilité avec anciens templates
            "module_title": get_module_title(module_name),
            "stats": get_scan_stats(scan_results)
        }
        
        # Ajouter toutes les clés du scan_results au contexte
        if isinstance(scan_results, dict):
            for key, value in scan_results.items():
                data[key] = value
        
        rendered = template.render(**data)
        
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"report_{module_name}_{timestamp}.html"
        filepath = os.path.join(REPORTS_DIR, filename)
        
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(rendered)
        
        logger.info(f"Rapport généré avec succès: {filepath}")
        return filepath
        
    except Exception as e:
        logger.error(f"Erreur lors de la génération du rapport: {e}", exc_info=True)
        raise

def get_module_title(module_name):
    """Retourne un titre lisible pour chaque module"""
    titles = {
        "vuln_scan": "Scan de Vulnérabilités Nmap",
        "network_discovery": "Découverte Réseau",
        "port_scan": "Scan de Ports",
        "service_enumeration": "Énumération des Services",
        "sniffer": "Capture Réseau"
    }
    return titles.get(module_name, module_name)

def get_scan_stats(scan_results):
    """Génère des statistiques à partir des résultats du scan"""
    stats = {}
    
    if isinstance(scan_results, dict):
        if "vulnerabilities" in scan_results:
            stats["total_vulnerabilities"] = len(scan_results["vulnerabilities"])
            stats["by_severity"] = count_vulnerabilities_by_severity(scan_results["vulnerabilities"])
        
        if "scan_time" in scan_results:
            stats["scan_time"] = scan_results["scan_time"]
        
        if "target" in scan_results:
            stats["target"] = scan_results["target"]
            
        # Pour les captures réseau
        if "total_packets" in scan_results:
            stats["total_packets"] = scan_results["total_packets"]
            stats["protocols"] = scan_results.get("protocols", {})
            stats["conversations"] = scan_results.get("conversations", [])
    
    return stats

def count_vulnerabilities_by_severity(vulnerabilities):
    """Compte les vulnérabilités par niveau de sévérité"""
    severity_count = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0
    }
    
    for vuln in vulnerabilities:
        if "severity" in vuln:
            severity = vuln["severity"].lower()
            if severity in severity_count:
                severity_count[severity] += 1
        else:
            # Si pas de sévérité spécifiée, considérer comme info
            severity_count["info"] += 1
    
    return severity_count
    
def generate_vuln_report(scan_results, for_download=True):
    """Fonction spécifique pour générer un rapport de vulnérabilités"""
    # Assurez-vous que le dossier existe
    os.makedirs(REPORTS_DIR, exist_ok=True)
    
    # Déterminer la sévérité de chaque vulnérabilité
    if "vulnerabilities" in scan_results:
        for vuln in scan_results["vulnerabilities"]:
            if "severity" not in vuln:
                vuln["severity"] = determine_vulnerability_severity(vuln)
    
    # Générer le rapport
    return generate_report("vuln_scan", scan_results, for_download=for_download)

def generate_sniffer_report(scan_results):
    """Fonction spécifique pour générer un rapport de capture réseau"""
    # Assurez-vous que le dossier existe
    os.makedirs(REPORTS_DIR, exist_ok=True)
    
    # Générer le rapport
    return generate_report("sniffer", scan_results)

def determine_vulnerability_severity(vuln):
    """Détermine la sévérité d'une vulnérabilité en fonction de son nom et de ses détails"""
    vuln_name = vuln.get("vulnerability", "").lower()
    vuln_details = str(vuln.get("details", "")).lower()
    
    # Vulnérabilités critiques
    critical_keywords = ["critical", "remote code execution", "rce", "command injection", "sql injection", "authentication bypass"]
    
    # Vulnérabilités élevées
    high_keywords = ["high", "xss", "cross site scripting", "arbitrary file", "directory traversal", "buffer overflow", "overflow"]
    
    # Vulnérabilités moyennes
    medium_keywords = ["medium", "information disclosure", "sensitive data", "csrf", "cross site request forgery"]
    
    # Vulnérabilités faibles
    low_keywords = ["low", "insecure", "deprecated"]
    
    # Vérifier les mots-clés pour déterminer la sévérité
    if any(keyword in vuln_name or keyword in vuln_details for keyword in critical_keywords):
        return "critical"
    elif any(keyword in vuln_name or keyword in vuln_details for keyword in high_keywords):
        return "high"
    elif any(keyword in vuln_name or keyword in vuln_details for keyword in medium_keywords):
        return "medium"
    elif any(keyword in vuln_name or keyword in vuln_details for keyword in low_keywords):
        return "low"
    else:
        return "info"
