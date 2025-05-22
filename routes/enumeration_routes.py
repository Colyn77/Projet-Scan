from flask import Blueprint, request, render_template
from services.service_enum import enumerate_services

enumeration_bp = Blueprint("enumerate", __name__)

@enumeration_bp.route("/", methods=["GET", "POST"])
def enumerate_route():
    if request.method == "POST":
        target = request.form.get("target")
        ports = request.form.get("ports")

        print(f"📡 IP : {target}, Ports : {ports}")

        if not target or not ports:
            return "Erreur : Cible ou ports manquants", 400

        result = enumerate_services(target, ports)

        return render_template("results.html", title="Énumération des Services", result=result)

    return render_template("index.html")
