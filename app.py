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

# 🌍 Initialisation
load_dotenv()
log_level = os.getenv("LOG_LEVEL", "INFO")
logging.basicConfig(
    level=getattr(logging, log_level.upper(), logging.INFO),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
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
    ALLOWED_IPS = os.getenv("ALLOWED_IPS", "127.0.0.1,192.168.44.128,192.168.217.1").split(",")

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
    
    logger.debug("Blueprints enregistrés")

    # === Authentification manuelle (en option si tu n’utilises pas `auth_bp`)
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
        return render_template("vuln.html")

        logger.debug("Accès à la page de scan de vulnérabilités")
        return render_template("vuln.html")

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
