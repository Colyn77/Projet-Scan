# app.py - Version sécurisée avec auth + ids + chiffrement
from flask import Flask, render_template, redirect, send_file, request, session, abort
import os
import datetime
import json
import logging
import bcrypt
from dotenv import load_dotenv
from config import Config
from utils.logger import get_logger

# Forensics
from routes.forensics_routes import forensics_bp
from routes.timeline_routes import timeline_bp

# 🔐 Sécurité
from securite.auth import auth_bp, login_required
from securite.ids import log_failed_attempt, is_blocked
from securite.chiffrement_module import encrypt, decrypt
from routes.malware_routes import malware_bp

# 🔧 Routes fonctionnelles
from routes.scan_routes import scan_bp
from routes.discovery_routes import discovery_bp
from routes.enumeration_routes import enumeration_bp
from routes.sniffer_routes import sniffer_bp
from routes.hydra_routes import hydra_bp
from routes.vuln_routes import vuln_bp
from routes.exploit_routes import exploit_bp
from routes.post_exploit_routes import post_exploit_bp
from routes.plugin_routes import plugin_bp
from routes.nuclei_routes import nuclei_bp
from services.plugin_manager import init_plugin_environment

# 🌍 Initialisation
load_dotenv()
log_level = os.getenv("LOG_LEVEL", "INFO")
logging.basicConfig(
    level=getattr(logging, log_level.upper(), logging.INFO),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
init_plugin_environment()
# Configuration du logger
logger = get_logger('app')


def create_app():
    logger.info("Création de l'application Flask")
    app = Flask(__name__)
    app.config.from_object(Config)
    app.secret_key = os.getenv("SECRET_KEY", "changeme123")
    app.register_blueprint(forensics_bp, url_prefix="/api/forensics")
    app.register_blueprint(malware_bp)
    app.register_blueprint(timeline_bp)

    # 🔐 IP autorisées (pare-feu applicatif)
    ALLOWED_IPS = os.getenv("ALLOWED_IPS", "127.0.0.1,192.168.44.128,192.168.217.1,192.168.36.1").split(",")

    @app.before_request
    def check_ip():
        ip = request.remote_addr
        if ip not in ALLOWED_IPS:
            logger.warning(f"⛔ Accès bloqué : {ip}")
            abort(403)

    # 🔧 Filtres template
    @app.template_filter('basename')
    def basename_filter(path):
        return os.path.basename(path)

    # 🔌 Enregistrement des routes
    app.register_blueprint(scan_bp, url_prefix="/api/scan")
    app.register_blueprint(discovery_bp, url_prefix="/api/discover")
    app.register_blueprint(enumeration_bp, url_prefix="/api/enumerate")
    app.register_blueprint(sniffer_bp, url_prefix="/api/sniffer")
    app.register_blueprint(hydra_bp, url_prefix="/api/hydra")
    app.register_blueprint(vuln_bp, url_prefix="/api/vuln")
    app.register_blueprint(auth_bp)
    app.register_blueprint(exploit_bp, url_prefix='/api/exploit')
    app.register_blueprint(post_exploit_bp, url_prefix="/api/post_exploit")
    app.register_blueprint(nuclei_bp, url_prefix='/nuclei')
    app.register_blueprint(plugin_bp)
    
    logger.debug("Blueprints enregistrés")

    # === Authentification manuelle (en option si tu n'utilises pas `auth_bp`)
    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            ip = request.remote_addr
            if is_blocked(ip):
                return "⛔ IP temporairement bloquée", 403

            username = request.form["username"]
            password = request.form["password"]

            with open("securite/users.json") as f:
                users = json.load(f)

            if username in users:
                hashed_pw = users[username]["password"].encode()
                if bcrypt.checkpw(password.encode(), hashed_pw):
                    session["username"] = username
                    session["role"] = users[username]["role"]
                    return redirect("/")
            log_failed_attempt(ip)
            return render_template("login.html", error="Identifiants invalides")

        return render_template("login.html")

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect("/login")

    # === Pages Web sécurisées
    @app.route("/")
    @login_required
    def home():
        return render_template("index.html")

    @app.route("/network")
    @login_required
    def network_page():
        return render_template("network.html")

    @app.route("/portscan")
    @login_required
    def portscan_page():
        return render_template("portscan.html")

    @app.route("/enumerate")
    @login_required
    def enumerate_page():
        return render_template("enumerate.html")

    @app.route("/sniffer")
    @login_required
    def sniffer_page():
        return render_template("sniffer.html")

    @app.route("/hydra")
    @login_required
    def hydra_page():
        return render_template("hydra.html")

    @app.route("/vuln")
    @login_required
    def vuln_page():
        logger.debug("Accès à la page de scan de vulnérabilités")
        return render_template("vuln.html")

    # 🆕 NOUVELLES ROUTES POUR LES RÉSULTATS DE VULNÉRABILITÉS
    @app.route("/vuln/results")
    @app.route("/vuln/results/<job_id>")
    @login_required
    def vuln_results_page(job_id=None):
        """Affiche les résultats d'un scan de vulnérabilités"""
        logger.debug(f"Accès à la page de résultats de vulnérabilités - job_id: {job_id}")
        
        if job_id:
            # Rediriger vers l'API qui gère l'affichage des résultats de job
            from routes.vuln_routes import parallel_scanner
            
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
        else:
            # Si pas de job_id, utiliser le template qui récupère depuis sessionStorage
            return render_template('vuln_results_from_session.html')

    @app.route("/vuln/batch_results/<batch_id>")
    @login_required
    def vuln_batch_results_page(batch_id):
        """Affiche les résultats d'un scan parallèle"""
        logger.debug(f"Accès aux résultats de batch: {batch_id}")
        
        try:
            # Récupérer les résultats du batch depuis votre système
            # Adapter selon votre implémentation
            batch_file = f"batch_results/{batch_id}.json"
            if os.path.exists(batch_file):
                with open(batch_file, 'r') as f:
                    batch_data = json.load(f)
                    
                return render_template('vuln_batch_results.html', 
                                     batch_data=batch_data,
                                     batch_id=batch_id)
            else:
                logger.warning(f"Résultats de batch non trouvés: {batch_id}")
                return redirect('/vuln')
                
        except Exception as e:
            logger.error(f"Erreur lors de l'affichage des résultats de batch: {e}")
            return redirect('/vuln')

    @app.route("/exploit")
    def exploit_page():
        """Affiche la page d'exploitation avec les paramètres fournis"""
        logger.info("Accès à la page d'exploitation")
        
        # Récupérer les paramètres de la requête
        vuln_id = request.args.get("vuln_id")
        ip = request.args.get("ip")
        port = request.args.get("port")
        
        # Vérifier si les paramètres sont présents
        if not vuln_id or not ip or not port:
            logger.warning("Paramètres manquants pour la page d'exploitation")
            return redirect("/")
        
        # Trouver le module Metasploit correspondant
        from services.metasploit_auto import EXPLOIT_MAP
        module = "Unknown"
        for key, value in EXPLOIT_MAP.items():
            if key.lower() in vuln_id.lower() or vuln_id.lower() in key.lower():
                module = value
                break
        
        logger.info(f"Préparation de l'exploitation de {vuln_id} sur {ip}:{port}")
        
        # Rendre le template avec les informations
        return render_template(
            "exploit_form.html", 
            vuln={
                "id": vuln_id,
                "target": ip,
                "port": port
            },
            module=module
        )
    
    @app.route("/exploits")
    def exploits_list_page():
        """Affiche la liste des rapports d'exploitation"""
        logger.debug("Accès à la page des rapports d'exploitation")
        
        # Rediriger vers la route API correspondante
        return redirect("/api/exploit/reports")

    @app.route("/post_exploit")
    @login_required
    def post_exploit_page():
        """Affiche la page de post-exploitation"""
        logger.debug("Accès à la page de post-exploitation")
        target_ip = request.args.get("target_ip")
        return render_template("post_exploit.html", target_ip=target_ip)

    @app.template_filter('dirname')
    def dirname_filter(path):
        """Retourne le répertoire parent d'un chemin"""
        # Si le chemin se termine par /, le supprimer d'abord
        if path.endswith('/') and len(path) > 1:
            path = path[:-1]
        parent = os.path.dirname(path)
        # S'assurer qu'on ne renvoie jamais une chaîne vide
        return parent if parent else '/'    

    @app.route("/results")
    def results_page():
        return redirect("/")

    @app.route("/reports")
    @login_required
    def reports_page():
        reports = []
        if os.path.exists("generated_reports"):
            for filename in os.listdir("generated_reports"):
                if filename.endswith(".html"):
                    path = os.path.join("generated_reports", filename)
                    stats = os.stat(path)
                    reports.append({
                        "name": filename,
                        "date": datetime.datetime.fromtimestamp(stats.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                        "size": f"{stats.st_size / 1024:.1f} KB"
                    })
        reports.sort(key=lambda x: x["date"], reverse=True)
        return render_template("reports.html", reports=reports)

    @app.route("/api/report/download/<path:filename>")
    @login_required
    def download_report(filename):
        path = os.path.join("generated_reports", filename)
        if not os.path.exists(path):
            return "Fichier non trouvé", 404
        return send_file(path, as_attachment=True)

    @app.route("/api/report/pdf/<path:filename>", methods=["GET"])
    @login_required
    def download_pdf_report(filename):
        """
        Route pour télécharger spécifiquement un rapport PDF
        """
        # Vérifier si le fichier a une extension PDF, sinon l'ajouter
        if not filename.lower().endswith('.pdf'):
            filename += '.pdf'
    
        path = os.path.join("generated_reports", filename)
    
        # Vérifier si le fichier existe
        if not os.path.exists(path):
            logger.error(f"Rapport PDF non trouvé: {path}")
            return "Fichier non trouvé", 404
    
        # Renvoyer le fichier PDF
        return send_file(
            path, 
            mimetype='application/pdf',
            as_attachment=True,
            download_name=filename
        )

    @app.route("/api/report/view/<path:filename>")
    @login_required
    def view_report(filename):
        path = os.path.join("generated_reports", filename)
        if not os.path.exists(path):
            return "Fichier non trouvé", 404
        return send_file(path)

    return app


if __name__ == "__main__":
    app = create_app()
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", 5000))
    debug = os.getenv("FLASK_ENV", "production") == "development"
    logger.info(f"🚀 Application démarrée sur http://{host}:{port}")
    app.run(host=host, port=port, debug=debug)
