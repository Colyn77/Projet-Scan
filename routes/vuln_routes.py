from flask import Blueprint, request, jsonify, render_template, send_file
from markupsafe import Markup
from services.nmap_vulnscan import vuln_scan, get_common_ports_by_category
from services.parallel_vuln_scanner import parallel_scanner, parse_targets, parse_port_ranges
from services.reporting_generator import generate_vuln_report
import os
import json
import logging
import time
from datetime import datetime

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("vuln_routes")

vuln_bp = Blueprint("vuln", __name__)

@vuln_bp.route("/", methods=["GET"])
def vuln_index():
    """Page principale des scans de vulnérabilités"""
    return render_template("vuln.html")

@vuln_bp.route("/nmap", methods=["POST"])
def launch_vuln_scan():
    """Lance un scan de vulnérabilités Nmap (simple ou parallèle)"""
    logger.info("Démarrage d'un scan de vulnérabilités")
    
    try:
        if request.is_json:
            data = request.get_json()
            targets_input = data.get("target", data.get("targets", ""))
            ports = data.get("ports", "21,22,23,25,80,110,139,143,443,445,3389")
            scan_mode = data.get("scan_mode", "single")
        else:
            targets_input = request.form.get("targets", request.form.get("target", ""))
            ports = request.form.get("ports", "21,22,23,25,80,110,139,143,443,445,3389")
            scan_mode = request.form.get("scan_mode", "single")

        if not targets_input:
            logger.warning("Le paramètre 'targets' est manquant")
            return jsonify({"error": "Le paramètre 'targets' est requis."}), 400
        
        # Parser les cibles
        targets = parse_targets(targets_input)
        
        if len(targets) == 0:
            return jsonify({"error": "Aucune cible valide trouvée"}), 400
        
        # Si mode parallèle ou plusieurs cibles
        if scan_mode == "parallel" or len(targets) > 1:
            return handle_parallel_scan(targets, ports, scan_mode)
        else:
            # Scan simple pour une seule cible
            return handle_single_scan(targets[0], ports)
            
    except Exception as e:
        logger.error(f"Erreur non gérée lors du scan: {str(e)}", exc_info=True)
        return jsonify({"error": f"Erreur: {str(e)}"}), 500

def handle_single_scan(target, ports):
    """Gère un scan simple sur une cible"""
    logger.info(f"Scan simple sur {target} (ports: {ports})")
    
    try:
        # Effectuer le scan
        results = vuln_scan(target, ports)
        
        # Variables pour stocker les chemins des rapports
        html_report = None
        pdf_report = None
        
        # Générer les rapports si le scan a réussi
        if "error" not in results:
            try:
                html_report = generate_vuln_report(results, for_download=True, format="html")
                logger.info(f"Rapport HTML généré: {html_report}")
                results["html_report"] = html_report
                
                pdf_report = generate_vuln_report(results, for_download=True, format="pdf")
                logger.info(f"Rapport PDF généré: {pdf_report}")
                results["pdf_report"] = pdf_report
                
            except Exception as e:
                logger.error(f"Erreur lors de la génération des rapports: {str(e)}", exc_info=True)
        
        # MODIFICATION PRINCIPALE : Toujours retourner du HTML pour les scans simples
        if "error" in results:
            return render_template("vuln_results.html",
                                 target=target,
                                 scan_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                                 host_status='error',
                                 vulnerabilities=[],
                                 command_line=f'nmap --script vuln -p {ports} {target}',
                                 error=results['error'])
        
        # Préparer les chemins des rapports pour les templates
        html_report_path = os.path.basename(html_report) if html_report else None
        pdf_report_path = os.path.basename(pdf_report) if pdf_report else None
        
        # Retourner directement le template HTML avec les résultats
        return render_template(
            "vuln_results.html", 
            target=results.get("target", target),
            scan_time=results.get("scan_time", datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
            host_status=results.get("host_status", "up"),
            vulnerabilities=results.get("vulnerabilities", []),
            command_line=results.get("command_line", f'nmap --script vuln -p {ports} {target}'),
            report_path=html_report,
            html_report_path=html_report_path,
            pdf_report_path=pdf_report_path,
            is_single_scan=True
        )
        
    except Exception as e:
        logger.error(f"Erreur lors du scan simple: {e}")
        return render_template("vuln_results.html",
                             target=target,
                             scan_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                             host_status='error',
                             vulnerabilities=[],
                             command_line=f'nmap --script vuln -p {ports} {target}',
                             error=f"Erreur lors du scan: {str(e)}")

def handle_parallel_scan(targets, ports, scan_mode):
    """Gère un scan parallèle sur plusieurs cibles"""
    logger.info(f"Scan parallèle sur {len(targets)} cibles (mode: {scan_mode})")
    
    try:
        if scan_mode == "port_ranges":
            # Scanner la même cible avec différentes plages de ports
            port_ranges = parse_port_ranges(ports)
            if len(port_ranges) > 1:
                job_ids = parallel_scanner.create_port_range_jobs(targets[0], port_ranges)
            else:
                job_ids = parallel_scanner.create_scan_job(targets, ports)
        else:
            # Scanner plusieurs cibles
            job_ids = parallel_scanner.create_scan_job(targets, ports)
        
        # Lancer les scans
        batch_id = parallel_scanner.start_parallel_scan(job_ids)
        
        # Pour les scans parallèles, retourner du JSON (pour le JavaScript)
        return jsonify({
            "batch_id": batch_id,
            "job_ids": job_ids,
            "targets": targets,
            "message": f"Scan parallèle démarré pour {len(targets)} cibles"
        })
        
    except Exception as e:
        logger.error(f"Erreur lors du scan parallèle: {e}")
        return jsonify({"error": str(e)}), 500

@vuln_bp.route("/status/<job_id>", methods=["GET"])
def get_job_status(job_id):
    """Récupère le statut d'un job de scan"""
    status = parallel_scanner.get_job_status(job_id)
    if status is None:
        return jsonify({"error": "Job introuvable"}), 404
    return jsonify(status)

@vuln_bp.route("/batch_status", methods=["GET"])
def get_batch_status():
    """Récupère le statut d'un batch de jobs"""
    job_ids = request.args.getlist('job_ids')
    if not job_ids:
        return jsonify({"error": "job_ids requis"}), 400
    
    batch_status = parallel_scanner.get_batch_status(job_ids)
    return jsonify(batch_status)

@vuln_bp.route("/cancel/<job_id>", methods=["POST"])
def cancel_job(job_id):
    """Annule un job de scan"""
    success = parallel_scanner.cancel_job(job_id)
    if success:
        return jsonify({"message": f"Job {job_id} annulé"})
    else:
        return jsonify({"error": "Impossible d'annuler le job"}), 400

@vuln_bp.route("/results/<job_id>", methods=["GET"])
def get_job_results(job_id):
    """Récupère les résultats détaillés d'un job et les affiche dans vuln_results.html"""
    logger.info(f"Accès aux résultats du job: {job_id}")
    
    # Récupérer le statut et les résultats du job
    status = parallel_scanner.get_job_status(job_id)
    if status is None:
        logger.warning(f"Job {job_id} introuvable")
        return render_template('vuln_results.html', 
                             error="Job introuvable ou expiré",
                             target="Inconnu")
    
    if status["status"] != "completed":
        logger.warning(f"Job {job_id} pas encore terminé (statut: {status['status']})")
        return render_template('vuln_results.html',
                             error=f"Scan pas encore terminé (statut: {status['status']})",
                             target=status.get('target', 'Inconnu'))
    
    # Récupérer les résultats depuis le stockage si nécessaire
    results = status.get("results")
    if not results:
        results = parallel_scanner.load_job_results(job_id)
        if not results:
            logger.error(f"Impossible de charger les résultats pour job {job_id}")
            return render_template('vuln_results.html',
                                 error="Résultats non disponibles",
                                 target=status.get('target', 'Inconnu'))
    
    # Préparer les chemins des rapports
    html_report_path = None
    pdf_report_path = None
    
    if status.get("html_report"):
        html_report_path = os.path.basename(status["html_report"])
    if status.get("pdf_report"):
        pdf_report_path = os.path.basename(status["pdf_report"])
    
    # Afficher les résultats dans le template vuln_results.html
    return render_template('vuln_results.html',
                         target=results.get('target'),
                         vulnerabilities=results.get('vulnerabilities', []),
                         scan_time=results.get('scan_time'),
                         host_status=results.get('host_status'),
                         command_line=results.get('command_line'),
                         report_path=status.get("html_report"),
                         html_report_path=html_report_path,
                         pdf_report_path=pdf_report_path,
                         job_id=job_id,
                         is_parallel_job=True)

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

@vuln_bp.route("/cleanup", methods=["POST"])
def cleanup_old_jobs():
    """Nettoie les anciens jobs"""
    max_age_hours = request.json.get("max_age_hours", 24) if request.is_json else 24
    parallel_scanner.cleanup_old_jobs(max_age_hours)
    return jsonify({"message": f"Jobs de plus de {max_age_hours}h nettoyés"})

# ROUTE SUPPRIMÉE : render_results plus nécessaire car on retourne directement du HTML
# La logique a été intégrée dans handle_single_scan()

# Routes supplémentaires pour la compatibilité avec l'ancien système
@vuln_bp.route("/test_scan", methods=["POST"])
def test_scan():
    """Route de test pour vérifier le fonctionnement"""
    return jsonify({
        "message": "Scanner de vulnérabilités fonctionnel",
        "timestamp": datetime.now().isoformat()
    })

@vuln_bp.route("/health", methods=["GET"])
def health_check():
    """Check de santé du service"""
    return jsonify({
        "status": "healthy",
        "service": "vulnerability_scanner",
        "timestamp": datetime.now().isoformat()
    })
