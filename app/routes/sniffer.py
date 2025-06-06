from flask import Blueprint, jsonify, request, send_file, render_template
from markupsafe import Markup
from app.services.packet_sniffer import capture_packets, get_interfaces, analyze_pcap
from app.services.sniffer_report_generator import SnifferReportGenerator
from app.securite.chiffrement_module import encrypt_file
import os
from utils.logger import get_logger
import zipfile

logging.basicConfig(level=logging.INFO)
logger = get_logger("sniffer_routes")

sniffer_bp = Blueprint('sniffer', __name__)

@sniffer_bp.route('/start', methods=['POST'])
def start_sniffer():
    try:
        if request.is_json:
            data = request.get_json()
            interface = data.get("interface", "eth0")
            count = int(data.get("count", 100))
        else:
            interface = request.form.get("interface", "eth0")
            count = int(request.form.get("count", 100))

        pcap_file = capture_packets(interface, count)
        filename = os.path.basename(pcap_file)

        analysis_results = {}
        report_path = None
        report_filename = None

        try:
            analysis_results = analyze_pcap(pcap_file)

            generator = SnifferReportGenerator()
            report_path = generator.generate_report(pcap_file)
            if report_path:
                report_filename = os.path.basename(report_path)
                logger.info(f"Rapport généré: {report_path}")

            # 🔐 Chiffrement du PCAP
            encrypted_pcap = f"{pcap_file}.encrypted"
            encrypt_file(pcap_file, encrypted_pcap)

            # 📦 Archive ZIP
            archive_dir = os.path.join("captures", "archives")
            os.makedirs(archive_dir, exist_ok=True)
            archive_name = os.path.splitext(filename)[0] + ".zip"
            archive_path = os.path.join(archive_dir, archive_name)

            with zipfile.ZipFile(archive_path, "w") as zipf:
                zipf.write(pcap_file)
                zipf.write(encrypted_pcap)
                if report_path and os.path.exists(report_path):
                    zipf.write(report_path)

        except Exception as e:
            logger.error(f"Erreur analyse ou rapport: {str(e)}")
            analysis_results = {
                "error": str(e),
                "note": "L'analyse n'a pas pu être complétée. Le fichier reste téléchargeable."
            }

        # === JSON
        if request.is_json:
            data = {
                "message": "Capture réussie",
                "file": filename,
                "download_url": f"/api/sniffer/download?file={filename}",
                "analysis": analysis_results,
                "zip": f"/{archive_path}"
            }
            if report_filename:
                data["report_url"] = f"/api/report/download/{report_filename}"
            return jsonify(data), 200

        # === HTML
        html = [
            "<h2>Capture réseau terminée</h2>",
            f"<p><strong>Fichier :</strong> {filename}</p>",
            f"<p><strong>Interface :</strong> {interface}</p>",
            f"<p><strong>Nombre de paquets :</strong> {count}</p>",
            "<div class='mb-3'>"
        ]

        html.append(f'<a href="/api/sniffer/download?file={filename}" class="btn btn-primary me-2">Télécharger le PCAP</a>')
        html.append(f'<a href="/{archive_path}" class="btn btn-secondary me-2">📦 Télécharger l’archive</a>')
        if report_filename:
            html.append(f'<a href="/api/report/download/{report_filename}" class="btn btn-success me-2">Voir le rapport</a>')
        html.append("</div>")

        if 'error' in analysis_results:
            html.append(f"<div class='alert alert-warning'>Note : {analysis_results.get('note', '')}</div>")
        else:
            html.append("<h3>Résumé de l'analyse</h3>")
            html.append(f"<p><strong>Paquets capturés :</strong> {analysis_results.get('packet_count', 0)}</p>")

            if 'unique_ips' in analysis_results:
                html.append(f"<p><strong>IP uniques :</strong> {analysis_results['unique_ips']}</p>")

            if 'top_protocols' in analysis_results:
                html.append("<h4>Protocoles utilisés</h4><ul>")
                for proto, count in analysis_results['top_protocols']:
                    html.append(f"<li>{proto} : {count} paquets</li>")
                html.append("</ul>")

            if 'tcp_ports' in analysis_results:
                ports = ', '.join(map(str, analysis_results['tcp_ports'][:10]))
                html.append(f"<p><strong>Ports TCP :</strong> {ports}</p>")

            if 'udp_ports' in analysis_results:
                ports = ', '.join(map(str, analysis_results['udp_ports'][:10]))
                html.append(f"<p><strong>Ports UDP :</strong> {ports}</p>")

            if 'first_packets' in analysis_results:
                html.append("<h4>Premiers paquets</h4>")
                html.append('<table class="table table-striped"><thead><tr>')
                html.append('<th>#</th><th>Temps</th><th>Source</th><th>Destination</th><th>Protocole</th><th>Taille</th></tr></thead><tbody>')
                for pkt in analysis_results['first_packets']:
                    html.append('<tr>')
                    html.append(f"<td>{pkt.get('number')}</td>")
                    html.append(f"<td>{pkt.get('time')}</td>")
                    html.append(f"<td>{pkt.get('src')}</td>")
                    html.append(f"<td>{pkt.get('dst')}</td>")
                    html.append(f"<td>{pkt.get('protocol')}</td>")
                    html.append(f"<td>{pkt.get('length')} bytes</td>")
                    html.append('</tr>')
                html.append('</tbody></table>')

        return render_template("results.html", title="Capture réseau", result=html, module="sniffer")

    except Exception as e:
        return render_template("results.html", title="Erreur", result=[f"❌ Erreur : {str(e)}"], module="sniffer")


@sniffer_bp.route('/download', methods=['GET'])
def download_capture():
    filename = request.args.get('file')
    if not filename:
        return jsonify({"error": "Nom de fichier manquant"}), 400

    path = os.path.join("captures", filename)
    if not os.path.exists(path):
        return jsonify({"error": "Fichier introuvable"}), 404
    return send_file(path, as_attachment=True)


@sniffer_bp.route('/interfaces', methods=['GET'])
def list_interfaces():
    try:
        return jsonify({"interfaces": get_interfaces()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@sniffer_bp.route('/report/<filename>', methods=['POST'])
def generate_report(filename):
    pcap_path = os.path.join("captures", filename)
    if not os.path.exists(pcap_path):
        return jsonify({"error": "Fichier PCAP non trouvé"}), 404

    try:
        generator = SnifferReportGenerator()
        report_path = generator.generate_report(pcap_path)
        if report_path:
            report_filename = os.path.basename(report_path)
            return jsonify({
                "message": "Rapport généré avec succès",
                "report_file": report_filename,
                "download_url": f"/api/report/download/{report_filename}"
            })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@sniffer_bp.route("/", methods=["GET"])
def sniffer_home():
    return render_template("sniffer.html")
