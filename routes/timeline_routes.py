import os
from flask import Blueprint, render_template, session
from datetime import datetime
from securite.chiffrement_module import encrypt_file
from zipfile import ZipFile
from securite.auth import login_required

timeline_bp = Blueprint("timeline", __name__)

@timeline_bp.route("/timeline")
@login_required
def timeline():
    username = session.get("username", "inconnu")
    horodatage = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = f"{username}_{horodatage}"

    os.makedirs("timeline", exist_ok=True)
    os.makedirs("timeline/archives", exist_ok=True)

    fichiers = collect_recent_files()

    txt_path = f"timeline/{base}.txt"
    with open(txt_path, "w") as f:
        for item in fichiers:
            f.write(item + "\n")

    enc_path = f"timeline/{base}.encrypted"
    encrypt_file(txt_path, enc_path)

    zip_path = f"timeline/archives/{base}.zip"
    with ZipFile(zip_path, "w") as zipf:
        zipf.write(txt_path)
        zipf.write(enc_path)

    return render_template("results.html",
        title="📅 Timeline des événements récents",
        result=fichiers,
        file_link="/" + zip_path
    )

def collect_recent_files():
    paths = ["/var/log", "/home"]  
    fichiers = []

    for path in paths:
        for root, dirs, files in os.walk(path):
            for file in files:
                try:
                    full_path = os.path.join(root, file)
                    mtime = os.path.getmtime(full_path)
                    date = datetime.fromtimestamp(mtime)
                    fichiers.append(f"{date} - {full_path}")
                except Exception:
                    continue

    fichiers.sort()
    return fichiers[-50:]  # Les 50 plus récents
