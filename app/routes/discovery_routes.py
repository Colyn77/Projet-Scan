from flask import Blueprint, request, jsonify, render_template
from app.services.network_discovery import discover_network

discovery_bp = Blueprint("discover", __name__)

@discovery_bp.route("/", methods=["GET", "POST"])
def discover():
    if request.method == "POST":
        network_range = request.form["network"]
        result = discover_network(network_range)
        return render_template("results.html", title="Découverte Réseau", result=result)
    return render_template("index.html")

@discovery_bp.route("/", methods=["GET"])
def discovery_bp_home():
    return render_template("network.html")
