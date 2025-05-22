from flask import Flask, render_template
import os

# Importation des blueprints
from app.routes.discovery_routes import discovery_bp
from app.routes.enumeration_routes import enumeration_bp
from app.routes.exploit import exploit_bp
from app.routes.forensics_routes import forensics_bp
from app.routes.hydra_routes import hydra_bp
from app.routes.malware_routes import malware_bp
from app.routes.nmap import nmap_bp
from app.routes.scan import scan_bp
from app.routes.sniffer import sniffer_bp
from app.routes.timeline_routes import timeline_bp
from app.routes.vuln_routes import vuln_bp

# Détection dynamique du chemin du dossier "templates"
template_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'templates'))
static_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'static'))

# Création de l'application Flask
app = Flask(__name__, template_folder=template_path, static_folder=static_path)

# Enregistrement des Blueprints
app.register_blueprint(discovery_bp, url_prefix="/discover")
app.register_blueprint(enumeration_bp, url_prefix="/enumerate")
app.register_blueprint(exploit_bp, url_prefix="/exploit")
app.register_blueprint(forensics_bp, url_prefix="/forensics")
app.register_blueprint(hydra_bp, url_prefix="/hydra")
app.register_blueprint(malware_bp, url_prefix="/malware")
app.register_blueprint(nmap_bp, url_prefix="/nmap")
app.register_blueprint(scan_bp, url_prefix="/scan")
app.register_blueprint(sniffer_bp, url_prefix="/sniffer")
app.register_blueprint(timeline_bp, url_prefix="/timeline")
app.register_blueprint(vuln_bp, url_prefix="/vuln")

@app.route("/")
def home():
    return render_template("index.html")

if __name__ == '__main__':
    app.run(debug=True)

