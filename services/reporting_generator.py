import os
import datetime
import json
from jinja2 import Environment, FileSystemLoader
from utils.logger import get_logger
from weasyprint import HTML  # Ajout de l'import pour WeasyPrint

# Configuration du logger
logger = get_logger('reporting_generator')

# Configuration des chemins
TEMPLATES_DIR = "templates"
REPORTS_DIR = "generated_reports"

# Préparer le dossier si pas existant
os.makedirs(REPORTS_DIR, exist_ok=True)

def generate_report(module_name, scan_results, template_name="report_template.html", for_download=True, format="html"):
    """
    Génère un rapport basé sur un template Jinja2.
    
    Args:
        module_name (str): Nom du module (ex: "vuln_scan", "network_discovery")
        scan_results (dict or list): Résultats du scan
        template_name (str): Nom du template à utiliser
        for_download (bool): Si True, génère une version téléchargeable, sinon une version web
        format (str): Format du rapport ("html" ou "pdf")
    
    Returns:
        str: Chemin vers le rapport généré
    """
    logger.info(f"Génération d'un rapport {format.upper()} pour le module {module_name}")
    
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
        
        if format.lower() == "pdf":
            filename = f"report_{module_name}_{timestamp}.pdf"
            filepath = os.path.join(REPORTS_DIR, filename)
            
            # Conversion HTML vers PDF
            HTML(string=rendered).write_pdf(filepath)
            logger.info(f"Rapport PDF généré avec succès: {filepath}")
        else:  # format HTML par défaut
            filename = f"report_{module_name}_{timestamp}.html"
            filepath = os.path.join(REPORTS_DIR, filename)
            
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(rendered)
            logger.info(f"Rapport HTML généré avec succès: {filepath}")
        
        return filepath
        
    except Exception as e:
        logger.error(f"Erreur lors de la génération du rapport {format}: {e}", exc_info=True)
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
            
        # Ajouter la taille du fichier aux statistiques si disponible
        if "file_size" in scan_results:
            stats["file_size"] = scan_results["file_size"]
            
        # Ajouter les statistiques IP si disponibles
        if "src_ips" in scan_results or "dst_ips" in scan_results:
            stats["ip_stats"] = {
                "src_ips": scan_results.get("src_ips", {}),
                "dst_ips": scan_results.get("dst_ips", {}),
                "conversations": scan_results.get("conversations", {})
            }
            
        # Ajouter les statistiques de ports si disponibles
        if "src_ports" in scan_results or "dst_ports" in scan_results:
            stats["port_stats"] = {
                "src_ports": scan_results.get("src_ports", {}),
                "dst_ports": scan_results.get("dst_ports", {})
            }
            
        # Ajouter les requêtes DNS et paquets ARP si disponibles
        if "dns_queries" in scan_results:
            stats["dns_queries"] = scan_results["dns_queries"]
            
        if "arp_packets" in scan_results:
            stats["arp_packets"] = scan_results["arp_packets"]
    
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
    
def generate_vuln_report(scan_results, for_download=True, format="html"):
    """
    Fonction spécifique pour générer un rapport de vulnérabilités
    
    Args:
        scan_results (dict): Résultats du scan de vulnérabilités
        for_download (bool): Si True, génère une version téléchargeable, sinon une version web
        format (str): Format du rapport ("html" ou "pdf")
    
    Returns:
        str: Chemin vers le rapport généré
    """
    # Assurez-vous que le dossier existe
    os.makedirs(REPORTS_DIR, exist_ok=True)
    
    # Déterminer la sévérité de chaque vulnérabilité
    if "vulnerabilities" in scan_results:
        for vuln in scan_results["vulnerabilities"]:
            if "severity" not in vuln:
                vuln["severity"] = determine_vulnerability_severity(vuln)
    
    # Générer le rapport
    return generate_report("vuln_scan", scan_results, for_download=for_download, format=format)

def prepare_sniffer_report_data(scan_results, pcap_file=None):
    """
    Prépare les données pour les rapports de capture réseau en s'assurant que toutes les clés nécessaires sont présentes
    
    Args:
        scan_results (dict): Résultats d'analyse de capture
        pcap_file (str, optional): Chemin vers le fichier PCAP
        
    Returns:
        dict: Données formatées pour le rapport
    """
    # Créer une structure cohérente pour le rapport
    report_data = {
        'module_name': 'sniffer',
        'capture_file': os.path.basename(pcap_file) if pcap_file else scan_results.get('capture_file', 'unknown.pcap'),
        'generated_on': datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
        'stats': {
            'total_packets': scan_results.get('packet_count', scan_results.get('total_packets', 0)),
            'capture_time': scan_results.get('capture_time', datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")),
            'file_size': scan_results.get('file_size', 0),
            'protocols': scan_results.get('protocols', {}),
            'ip_stats': {
                'src_ips': scan_results.get('src_ips', {}),
                'dst_ips': scan_results.get('dst_ips', {}),
                'conversations': scan_results.get('conversations', {})
            },
            'port_stats': {
                'src_ports': scan_results.get('src_ports', {}),
                'dst_ports': scan_results.get('dst_ports', {})
            },
            'dns_queries': scan_results.get('dns_queries', []),
            'arp_packets': scan_results.get('arp_packets', [])
        }
    }
    
    # Si le fichier pcap est fourni, récupérer sa taille
    if pcap_file and os.path.exists(pcap_file):
        report_data['stats']['file_size'] = os.stat(pcap_file).st_size
        
    return report_data

def generate_sniffer_report(scan_results, format="html"):
    """
    Fonction spécifique pour générer un rapport de capture réseau
    
    Args:
        scan_results (dict): Résultats de la capture réseau
        format (str): Format du rapport ("html" ou "pdf")
    
    Returns:
        str: Chemin vers le rapport généré
    """
    # Assurez-vous que le dossier existe
    os.makedirs(REPORTS_DIR, exist_ok=True)
    
    # Préparation des données spécifiques pour le rapport de capture
    if isinstance(scan_results, dict):
        # Déterminer si scan_results contient déjà la structure attendue
        if 'stats' in scan_results and 'file_size' in scan_results['stats']:
            # Les données sont déjà bien formatées
            prepared_data = scan_results
        else:
            # Reformater les données
            prepared_data = prepare_sniffer_report_data(scan_results)
            
        logger.info(f"Génération d'un rapport {format} pour capture réseau avec données préparées")
    else:
        logger.warning("Les résultats de capture ne sont pas au format dictionnaire")
        prepared_data = {'stats': {}}
    
    # Générer le rapport avec les données préparées
    return generate_report("sniffer", prepared_data, format=format)

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

def generate_pdf_report(module_name, scan_results):
    """
    Génère directement un rapport PDF pour n'importe quel module
    
    Args:
        module_name (str): Nom du module
        scan_results (dict): Résultats du scan
    
    Returns:
        str: Chemin vers le rapport PDF généré
    """
    logger.info(f"Génération d'un rapport PDF pour le module {module_name}")
    
    if module_name == "vuln_scan":
        return generate_vuln_report(scan_results, for_download=True, format="pdf")
    elif module_name == "sniffer":
        return generate_sniffer_report(scan_results, format="pdf")
    else:
        return generate_report(module_name, scan_results, format="pdf")

def convert_html_to_pdf(html_path):
    """
    Convertit un rapport HTML existant en PDF
    
    Args:
        html_path (str): Chemin vers le fichier HTML
    
    Returns:
        str: Chemin vers le fichier PDF généré
    """
    logger.info(f"Conversion du rapport HTML en PDF: {html_path}")
    
    try:
        # Vérifier que le fichier existe
        if not os.path.exists(html_path):
            logger.error(f"Le fichier HTML n'existe pas: {html_path}")
            raise FileNotFoundError(f"Le fichier HTML n'existe pas: {html_path}")
        
        # Lire le contenu du fichier HTML
        with open(html_path, "r", encoding="utf-8") as f:
            html_content = f.read()
        
        # Générer le nom du fichier PDF
        pdf_filename = os.path.splitext(os.path.basename(html_path))[0] + ".pdf"
        pdf_path = os.path.join(REPORTS_DIR, pdf_filename)
        
        # Convertir HTML en PDF
        HTML(string=html_content).write_pdf(pdf_path)
        
        logger.info(f"Conversion réussie. PDF généré: {pdf_path}")
        return pdf_path
        
    except Exception as e:
        logger.error(f"Erreur lors de la conversion HTML vers PDF: {e}", exc_info=True)
        raise