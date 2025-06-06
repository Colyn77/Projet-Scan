from flask import Blueprint, jsonify, request, send_file, render_template
from markupsafe import Markup
from services.packet_sniffer import capture_packets, get_interfaces, analyze_pcap
from services.sniffer_report_generator import SnifferReportGenerator
from services.reporting_generator import generate_sniffer_report as gen_pdf_report
from securite.chiffrement_module import encrypt_file
import os
from utils.logger import get_logger
import zipfile
import datetime

logging.basicConfig(level=logging.INFO)
logger = get_logger("sniffer_routes")

sniffer_bp = Blueprint('sniffer', __name__)

def prepare_report_data(analysis_results, pcap_file):
    """
    Prépare les données pour les rapports en s'assurant que toutes les clés nécessaires sont présentes
    """
    # Créer une structure cohérente pour le rapport
    report_data = {
        'capture_file': os.path.basename(pcap_file),
        'generated_on': datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
        'stats': {
            'total_packets': analysis_results.get('packet_count', 0),
            'capture_time': analysis_results.get('capture_time', datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")),
            'file_size': os.stat(pcap_file).st_size if os.path.exists(pcap_file) else 0,
            'protocols': {},  # Assurez-vous que c'est un dictionnaire, pas une liste
            'ip_stats': {
                'src_ips': analysis_results.get('src_ips', {}),
                'dst_ips': analysis_results.get('dst_ips', {}),
                'conversations': analysis_results.get('conversations', {})
            },
            'port_stats': {
                'src_ports': analysis_results.get('src_ports', {}),
                'dst_ports': analysis_results.get('dst_ports', {})
            },
            'dns_queries': analysis_results.get('dns_queries', []),
            'arp_packets': analysis_results.get('arp_packets', [])
        }
    }
    
    # Convertir les données de protocol en dictionnaire si elles sont sous forme de liste
    if 'top_protocols' in analysis_results:
        protocols_dict = {}
        for proto, count in analysis_results.get('top_protocols', []):
            protocols_dict[proto] = count
        report_data['stats']['protocols'] = protocols_dict
    elif 'protocols' in analysis_results:
        # Si c'est déjà un dictionnaire, l'utiliser directement
        if isinstance(analysis_results['protocols'], dict):
            report_data['stats']['protocols'] = analysis_results['protocols']
        # Si c'est une liste de tuples (protocole, compte), la convertir en dictionnaire
        elif isinstance(analysis_results['protocols'], list):
            protocols_dict = {}
            for item in analysis_results['protocols']:
                if isinstance(item, tuple) and len(item) == 2:
                    protocols_dict[item[0]] = item[1]
            report_data['stats']['protocols'] = protocols_dict
    
    return report_data

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
        pdf_report_path = None
        pdf_report_filename = None

        try:
            analysis_results = analyze_pcap(pcap_file)
            
            # Préparer les données du rapport
            report_data = prepare_report_data(analysis_results, pcap_file)
            
            # Génération du rapport HTML
            generator = SnifferReportGenerator()
            report_path = generator.generate_report(pcap_file)
            if report_path:
                report_filename = os.path.basename(report_path)
                logger.info(f"Rapport HTML généré: {report_path}")

            # Génération du rapport PDF
            try:
                # Utiliser les données formatées pour le rapport PDF
                pdf_report_path = gen_pdf_report(report_data, format="pdf")
                if pdf_report_path:
                    pdf_report_filename = os.path.basename(pdf_report_path)
                    logger.info(f"Rapport PDF généré: {pdf_report_path}")
            except Exception as pdf_error:
                logger.error(f"Erreur génération PDF: {str(pdf_error)}", exc_info=True)
                # Continuer même si la génération du PDF échoue

            # 🔐 Chiffrement du PCAP
            encrypted_pcap = f"{pcap_file}.encrypted"
            encrypt_file(pcap_file, encrypted_pcap)

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
                "analysis": analysis_results
            }
            if report_filename:
                data["report_url"] = f"/api/report/download/{report_filename}"
            if pdf_report_filename:
                data["pdf_report_url"] = f"/api/report/download/{pdf_report_filename}"
            return jsonify(data), 200

        # === HTML
        html = [
            "<h2>Capture réseau terminée</h2>",
            f"<p><strong>Fichier :</strong> {filename}</p>",
            f"<p><strong>Interface :</strong> {interface}</p>",
            f"<p><strong>Nombre de paquets :</strong> {count}</p>",
            "<div class='mb-3'>"
        ]

        html.append(f'<a href="/api/sniffer/download?file={filename}" class="btn btn-primary me-2"><i class="bi bi-download"></i> Télécharger le PCAP</a>')
        
        if report_filename:
            html.append(f'<a href="/api/report/download/{report_filename}" class="btn btn-success me-2"><i class="bi bi-file-earmark-text"></i> Voir le rapport HTML</a>')
        if pdf_report_filename:
            html.append(f'<a href="/api/report/download/{pdf_report_filename}" class="btn btn-danger me-2"><i class="bi bi-file-earmark-pdf"></i> Télécharger le PDF</a>')
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


@sniffer_bp.route('/report/<filename>', methods=['POST', 'GET'])
def generate_report(filename):
    pcap_path = os.path.join("captures", filename)
    if not os.path.exists(pcap_path):
        return jsonify({"error": "Fichier PCAP non trouvé"}), 404

    # Récupérer le format demandé (html ou pdf)
    format = request.args.get('format', 'html').lower()

    try:
        # Analyser le PCAP d'abord pour obtenir les résultats
        analysis_results = analyze_pcap(pcap_path)
        
        # Préparer les données du rapport
        report_data = prepare_report_data(analysis_results, pcap_path)
        
        if format == 'pdf':
            # Générer un rapport PDF avec les données formattées
            report_path = gen_pdf_report(report_data, format="pdf")
        else:
            # Générer un rapport HTML (comportement par défaut)
            generator = SnifferReportGenerator()
            report_path = generator.generate_report(pcap_path)
            
        if report_path:
            report_filename = os.path.basename(report_path)
            
            # Si c'est une requête GET, télécharger directement le fichier
            if request.method == 'GET':
                mimetype = "application/pdf" if format == "pdf" else "text/html"
                return send_file(
                    report_path,
                    mimetype=mimetype,
                    as_attachment=True,
                    download_name=f"rapport_capture.{format}"
                )
            
            # Sinon, retourner les informations sur le rapport généré
            return jsonify({
                "message": "Rapport généré avec succès",
                "report_file": report_filename,
                "download_url": f"/api/report/download/{report_filename}"
            })
    except Exception as e:
        logger.error(f"Erreur lors de la génération du rapport: {str(e)}", exc_info=True)
        return jsonify({"error": str(e)}), 500