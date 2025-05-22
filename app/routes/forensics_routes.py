from flask import Blueprint, render_template
from app.securite.forensics import analyser_processus_suspects
from app.securite.auth import login_required
import shutil
import os

forensics_bp = Blueprint("forensics", __name__)

@forensics_bp.route("/", methods=["GET"])
@login_required
def analyser():
    analyser_processus_suspects()
    
    os.makedirs("static/forensics", exist_ok=True)
    shutil.copy("forensics/memory_dump.encrypted", "static/forensics/memory_dump.encrypted")

    return render_template("results.html",
        title="Analyse Forensique",
        result="✅ Analyse mémoire terminée et chiffrée.",
        file_link="/static/forensics/memory_dump.encrypted"
    )

@forensics_bp.route("/", methods=["GET"])
def forensics_bp_home():
    return render_template("reports.html")
