from flask import Blueprint, request, jsonify, render_template
from app.services.port_scanner import scan_ports

scan_bp = Blueprint("scan", __name__)

@scan_bp.route("/", methods=["GET", "POST"])
def scan():
    if request.method == "POST":
        target = request.form["target"]
        ports = request.form["ports"]
        result = scan_ports(target, ports)
        return render_template("results.html", title="Scan de Ports", result=result)
    return render_template("index.html")


@scan_bp.route("/", methods=["GET"])
def scan_bp_home():
    return render_template("reports.html")
