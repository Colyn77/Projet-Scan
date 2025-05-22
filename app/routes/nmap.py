
from flask import render_template
from flask import Blueprint, jsonify, request
from app.services.nmap_vulnscan import vuln_scan

nmap_bp = Blueprint("nmap", __name__)

@nmap_bp.route("/scan", methods=["GET"])
def scan():
    target = request.args.get("target", "127.0.0.1")  # Par défaut localhost
    ports = request.args.get("ports", "21,22,80,443")  # Ports par défaut
    result = vuln_scan(target, ports)
    return jsonify(result)

@nmap_bp.route("/", methods=["GET"])
def nmap_bp_home():
    return render_template("portscan.html")
