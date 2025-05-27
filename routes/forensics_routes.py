import os
import shutil
import glob
from flask import Blueprint, render_template, current_app, url_for, send_file, request
from securite.forensics import analyser_processus_suspects
from securite.auth import login_required

forensics_bp = Blueprint("forensics", __name__)

@forensics_bp.route("/", methods=["GET"])
@login_required
def analyser():
    """
    Lance l'analyse forensique, récupère le dernier dump (.encrypted ou .txt)
    et propose un téléchargement via /api/forensics/download.
    """
    # 1) Exécuter l'analyse
    try:
        analyser_processus_suspects()
    except Exception as e:
        return render_template(
            "results.html",
            title="Erreur Forensique",
            result=[f"❌ Échec de l'analyse forensique : {e}"]
        )

    # 2) Rechercher le dump le plus récent
    encs = glob.glob("forensics/*.encrypted")
    if encs:
        chosen = max(encs, key=os.path.getmtime)
    else:
        txts = glob.glob("forensics/*.txt")
        if not txts:
            return render_template(
                "results.html",
                title="Analyse Forensique",
                result=["⚠️ Aucun dump forensique généré."]
            )
        chosen = max(txts, key=os.path.getmtime)

    fname = os.path.basename(chosen)

    # 3) Copier vers static/forensics pour affichage si besoin
    static_dir = os.path.join(current_app.static_folder, "forensics")
    os.makedirs(static_dir, exist_ok=True)
    shutil.copy(chosen, os.path.join(static_dir, fname))

    # 4) Préparer le lien de téléchargement direct
    download_url = url_for("forensics.download_dump", file=fname)

    return render_template(
        "results.html",
        title="Analyse Forensique",
        result=[f"✅ Dump disponible : {fname}"],
        file_link=download_url
    )


@forensics_bp.route("/download", methods=["GET"])
@login_required
def download_dump():
    """
    Télécharge le fichier forensique sélectionné.
    ?file=<nom_du_fichier>
    """
    fname = request.args.get("file")
    if not fname:
        return "Paramètre 'file' manquant", 400

    # Chemin réel
    path = os.path.join("forensics", fname)
    if not os.path.exists(path):
        return "Fichier introuvable", 404

    # Envoi du fichier en as_attachment
    return send_file(path, as_attachment=True, download_name=fname)
