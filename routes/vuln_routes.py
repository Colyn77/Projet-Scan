from flask import Blueprint, request, jsonify, render_template, send_file
from markupsafe import Markup
from services.nmap_vulnscan import vuln_scan, get_common_ports_by_category
from services.reporting_generator import generate_vuln_report
import os
import json
import logging

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("vuln_routes")

vuln_bp = Blueprint("vuln", __name__)

@vuln_bp.route("/nmap", methods=["POST"])
def launch_vuln_scan():
    """Lance un scan de vulnérabilités Nmap"""
    logger.info("Démarrage d'un scan de vulnérabilités Nmap")
    
    try:
        if request.is_json:
            data = request.get_json()
            target = data.get("target")
            ports = data.get("ports", "21,22,23,25,80,110,139,143,443,445,3389")
        else:
            target = request.form.get("target")
            ports = request.form.get("ports", "21,22,23,25,80,110,139,143,443,445,3389")

        if not target:
            logger.warning("Le paramètre 'target' est manquant")
            return jsonify({"error": "Le paramètre 'target' est requis."}), 400
        
        # Lancer le scan
        logger.info(f"Exécution du scan sur {target} (ports: {ports})")
        results = vuln_scan(target, ports)
        
        # Variables pour stocker les chemins des rapports
        html_report = None
        pdf_report = None
        
        # Générer les rapports si le scan a réussi
        if "error" not in results:
            try:
                # Générer un rapport HTML téléchargeable
                html_report = generate_vuln_report(results, for_download=True, format="html")
                logger.info(f"Rapport HTML généré: {html_report}")
                results["html_report"] = html_report
                
                # Générer un rapport PDF téléchargeable
                pdf_report = generate_vuln_report(results, for_download=True, format="pdf")
                logger.info(f"Rapport PDF généré: {pdf_report}")
                results["pdf_report"] = pdf_report
                
            except Exception as e:
                logger.error(f"Erreur lors de la génération des rapports: {str(e)}", exc_info=True)
                # Continuer même si la génération des rapports échoue
        
        # Si c'est une requête API JSON
        if request.headers.get('Accept') == 'application/json' or request.is_json:
            return jsonify(results)
        else:
            # Pour l'interface web, afficher la page de résultats
            if "error" in results:
                logger.warning(f"Erreur lors du scan: {results['error']}")
                return render_template("results.html", 
                                    title="Erreur de scan", 
                                    result=[f"Erreur: {results['error']}"],
                                    module="vuln")
            
            # Utiliser le template dédié aux résultats de vulnérabilités
            html_report_path = os.path.basename(html_report) if html_report else None
            pdf_report_path = os.path.basename(pdf_report) if pdf_report else None
            
            return render_template(
                "vuln_results.html", 
                target=results["target"],
                scan_time=results["scan_time"],
                host_status=results["host_status"],
                vulnerabilities=results["vulnerabilities"],
                command_line=results["command_line"],
                report_path=html_report,
                html_report_path=html_report_path,
                pdf_report_path=pdf_report_path
            )
            
    except Exception as e:
        logger.error(f"Erreur non gérée lors du scan: {str(e)}", exc_info=True)
        return jsonify({"error": f"Erreur: {str(e)}"}), 500

@vuln_bp.route("/download_report", methods=["GET"])
def download_vulnerability_report():
    """Télécharge un rapport de vulnérabilités dans le format spécifié"""
    
    filename = request.args.get("filename")
    format = request.args.get("format", "html").lower()
    
    if not filename:
        return jsonify({"error": "Le nom du fichier est requis"}), 400
    
    # Construire le chemin du fichier
    file_path = os.path.join("generated_reports", filename)
    
    # Vérifier si le fichier existe
    if not os.path.exists(file_path):
        logger.error(f"Fichier de rapport introuvable: {file_path}")
        return jsonify({"error": "Rapport introuvable"}), 404
    
    # Déterminer le type MIME en fonction du format
    mimetype = "application/pdf" if format == "pdf" else "text/html"
    
    # Retourner le fichier pour téléchargement
    return send_file(
        file_path,
        mimetype=mimetype,
        as_attachment=True,
        download_name=f"rapport_vulnerabilites.{format}"
    )

@vuln_bp.route("/ports", methods=["GET"])
def get_port_categories():
    """Retourne les catégories de ports disponibles"""
    return jsonify(get_common_ports_by_category())