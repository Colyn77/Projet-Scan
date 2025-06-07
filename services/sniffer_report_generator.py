# services/sniffer_report_generator.py
import os
import datetime
import json
import logging
from jinja2 import Environment, FileSystemLoader
from services.packet_sniffer import analyze_pcap
from utils.logger import get_logger
# Configuration des chemins
TEMPLATES_DIR = "templates"
REPORTS_DIR = "generated_reports"

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = get_logger("sniffer_report_generator")

class SnifferReportGenerator:
    def __init__(self):
        os.makedirs(REPORTS_DIR, exist_ok=True)
        self.env = Environment(loader=FileSystemLoader(TEMPLATES_DIR))
    
    def generate_report(self, pcap_file):
        """Génère un rapport HTML à partir d'un fichier PCAP"""
        try:
            # Analyser le fichier PCAP avec votre fonction existante
            analysis_results = analyze_pcap(pcap_file)
            
            if 'error' in analysis_results:
                logger.error(f"Erreur dans l'analyse: {analysis_results['error']}")
            
            # Transformer les données pour le template
            stats = self._transform_analysis_for_template(analysis_results)
            
            # Charger le template
            template = self.env.get_template("sniffer_report_template.html")
            
            # Préparer les données
            data = {
                "capture_file": os.path.basename(pcap_file),
                "generated_on": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "stats": stats
            }
            
            # Générer le HTML
            html_content = template.render(**data)
            
            # Sauvegarder le rapport
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            report_filename = f"sniffer_report_{timestamp}.html"
            report_path = os.path.join(REPORTS_DIR, report_filename)
            
            with open(report_path, "w", encoding="utf-8") as f:
                f.write(html_content)
            
            logger.info(f"Rapport généré avec succès: {report_path}")
            return report_path
            
        except Exception as e:
            logger.error(f"Erreur lors de la génération du rapport: {str(e)}")
            return None
    
    def _transform_analysis_for_template(self, analysis_results):
        """Transforme les résultats de l'analyse pour le template"""
        stats = {
            "total_packets": analysis_results.get("packet_count", 0),
            "capture_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "file_size": 0,  # Sera calculé ci-dessous
            "protocols": {},
            "ip_stats": {
                "src_ips": {},
                "dst_ips": {},
                "conversations": {}
            },
            "port_stats": {
                "src_ports": {},
                "dst_ports": {}
            },
            "dns_queries": [],
            "arp_packets": []
        }
        
        # Calculer la taille du fichier
        if 'file' in analysis_results and os.path.exists(analysis_results['file']):
            stats["file_size"] = os.path.getsize(analysis_results['file'])
        
        # Protocoles (transformer les top_protocols en dict)
        if 'top_protocols' in analysis_results:
            for proto, count in analysis_results['top_protocols']:
                stats["protocols"][proto] = count
        
        # IPs - extraire des données des premiers paquets
        if 'first_packets' in analysis_results:
            for packet in analysis_results['first_packets']:
                src = packet.get('src')
                dst = packet.get('dst')
                if src:
                    stats["ip_stats"]["src_ips"][src] = stats["ip_stats"]["src_ips"].get(src, 0) + 1
                if dst:
                    stats["ip_stats"]["dst_ips"][dst] = stats["ip_stats"]["dst_ips"].get(dst, 0) + 1
                if src and dst:
                    conv = f"{src} <-> {dst}"
                    stats["ip_stats"]["conversations"][conv] = stats["ip_stats"]["conversations"].get(conv, 0) + 1
        
        # Ports
        if 'tcp_ports' in analysis_results:
            for port in analysis_results['tcp_ports'][:10]:  # Limiter aux 10 premiers
                stats["port_stats"]["src_ports"][port] = 1  # Valeur arbitraire car on n'a pas le compte exact
        
        if 'udp_ports' in analysis_results:
            for port in analysis_results['udp_ports'][:10]:  # Limiter aux 10 premiers
                stats["port_stats"]["dst_ports"][port] = 1  # Valeur arbitraire car on n'a pas le compte exact
        
        # Trier et limiter les statistiques
        stats["ip_stats"]["src_ips"] = dict(sorted(stats["ip_stats"]["src_ips"].items(), key=lambda x: x[1], reverse=True)[:10])
        stats["ip_stats"]["dst_ips"] = dict(sorted(stats["ip_stats"]["dst_ips"].items(), key=lambda x: x[1], reverse=True)[:10])
        stats["ip_stats"]["conversations"] = dict(sorted(stats["ip_stats"]["conversations"].items(), key=lambda x: x[1], reverse=True)[:10])
        
        return stats

# Fonction utilitaire pour une utilisation simple
def generate_sniffer_report(pcap_file):
    """Fonction wrapper simple pour générer un rapport"""
    generator = SnifferReportGenerator()
    return generator.generate_report(pcap_file)
