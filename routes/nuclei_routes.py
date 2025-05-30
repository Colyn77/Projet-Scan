from flask import Blueprint, request, jsonify, render_template, flash, redirect, url_for
from services import nuclei_scanner
import logging
import traceback

logger = logging.getLogger(__name__)
nuclei_bp = Blueprint("nuclei", __name__)

@nuclei_bp.route("/")
def index():
    """Page principale du scanner Nuclei"""
    try:
        # Vérification de la disponibilité de Nuclei
        nuclei_available = nuclei_scanner.check_nuclei_available()
        
        # Récupération de l'historique des scans
        history = nuclei_scanner.get_scan_history()
        
        # Catégories de templates disponibles
        templates = nuclei_scanner.get_available_templates()
        
        return render_template(
            'nuclei_simple.html',
            nuclei_available=nuclei_available,
            scan_history=history,
            templates=templates
        )
    except Exception as e:
        logger.error(f"Erreur page Nuclei: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        flash(f"Erreur lors du chargement: {str(e)}", "error")
        return render_template('nuclei_simple.html', nuclei_available=False, scan_history=[], templates=[])

@nuclei_bp.route("/scan", methods=["POST"])  # ✅ CORRIGÉ : /scan au lieu de /nuclei/scan
def scan():
    """Lance un scan Nuclei"""
    try:
        # Log de debug
        logger.info("=== DÉBUT SCAN NUCLEI ===")
        logger.info(f"Content-Type: {request.content_type}")
        logger.info(f"Method: {request.method}")
        
        # Récupération des données
        if request.is_json:
            data = request.get_json()
            logger.info("Données JSON reçues")
        else:
            data = request.form.to_dict()
            logger.info("Données form reçues")
        
        logger.info(f"Données reçues: {data}")
        
        url = data.get("url", "").strip()
        if not url:
            logger.warning("URL manquante")
            return jsonify({"error": "URL manquante"}), 400
        
        # Validation basique de l'URL
        if not (url.startswith('http://') or url.startswith('https://')):
            url = f"https://{url}"
        
        logger.info(f"URL à scanner: {url}")
        
        # Vérification de Nuclei
        if not nuclei_scanner.check_nuclei_available():
            logger.error("Nuclei non disponible")
            return jsonify({"error": "Nuclei n'est pas disponible"}), 500
        
        # Paramètres optionnels
        severity = data.get("severity", "medium,high,critical")
        templates = data.get("templates", [])
        exclude_tags = data.get("exclude_tags", [])
        
        # Conversion sécurisée des entiers
        try:
            timeout = int(data.get("timeout", 300))
        except (ValueError, TypeError):
            timeout = 300
            
        try:
            rate_limit = int(data.get("rate_limit", 150))
        except (ValueError, TypeError):
            rate_limit = 150
        
        # Headers personnalisés
        custom_headers = {}
        user_agent = data.get("user_agent")
        if user_agent:
            custom_headers["User-Agent"] = user_agent
        
        logger.info(f"Paramètres scan - Severity: {severity}, Timeout: {timeout}, Rate: {rate_limit}")
        
        # Lancement du scan
        logger.info("Lancement du scan...")
        result = nuclei_scanner.scan_url(
            url=url,
            severity=severity,
            templates=templates if templates else None,
            exclude_tags=exclude_tags if exclude_tags else None,
            timeout=timeout,
            rate_limit=rate_limit,
            custom_headers=custom_headers if custom_headers else None
        )
        
        logger.info(f"Résultat scan: {type(result)}")
        logger.info(f"Clés résultat: {list(result.keys()) if isinstance(result, dict) else 'Not a dict'}")
        
        if "error" in result:
            logger.warning(f"Erreur scan Nuclei: {result['error']}")
            return jsonify(result), 400
        
        logger.info(f"Scan Nuclei terminé pour {url}")
        logger.info("=== FIN SCAN NUCLEI ===")
        return jsonify(result)
        
    except ValueError as e:
        logger.error(f"Erreur de valeur: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({"error": f"Paramètre invalide: {str(e)}"}), 400
    except Exception as e:
        logger.error(f"Erreur inattendue scan Nuclei: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({"error": f"Erreur interne: {str(e)}"}), 500

@nuclei_bp.route("/scan-multiple", methods=["POST"])  # ✅ CORRIGÉ
def scan_multiple():
    """Lance un scan sur plusieurs URLs"""
    try:
        logger.info("=== DÉBUT SCAN MULTIPLE ===")
        
        data = request.get_json() if request.is_json else request.form.to_dict()
        logger.info(f"Données reçues: {data}")
        
        urls_input = data.get("urls", "")
        if not urls_input:
            return jsonify({"error": "Aucune URL fournie"}), 400
        
        # Parse des URLs (séparées par des retours à la ligne)
        urls = [url.strip() for url in urls_input.split('\n') if url.strip()]
        
        if not urls:
            return jsonify({"error": "Aucune URL valide fournie"}), 400
        
        if len(urls) > 100:
            return jsonify({"error": "Trop d'URLs (maximum 100)"}), 400
        
        # Normalisation des URLs
        normalized_urls = []
        for url in urls:
            if not (url.startswith('http://') or url.startswith('https://')):
                url = f"https://{url}"
            normalized_urls.append(url)
        
        severity = data.get("severity", "medium,high,critical")
        templates = data.get("templates", [])
        
        try:
            batch_size = int(data.get("batch_size", 10))
        except (ValueError, TypeError):
            batch_size = 10
        
        logger.info(f"Scan de {len(normalized_urls)} URLs")
        
        result = nuclei_scanner.scan_multiple_urls(
            urls=normalized_urls,
            severity=severity,
            templates=templates if templates else None,
            batch_size=batch_size
        )
        
        if "error" in result:
            return jsonify(result), 400
        
        logger.info("=== FIN SCAN MULTIPLE ===")
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Erreur scan multiple Nuclei: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@nuclei_bp.route("/update-templates", methods=["POST"])  # ✅ CORRIGÉ
def update_templates():
    """Met à jour les templates Nuclei"""
    try:
        logger.info("Mise à jour des templates...")
        result = nuclei_scanner.update_templates()
        
        if result.get("success"):
            return jsonify({"message": "Templates mis à jour avec succès"})
        else:
            return jsonify({"error": result.get("error", "Erreur inconnue")}), 400
            
    except Exception as e:
        logger.error(f"Erreur mise à jour templates: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@nuclei_bp.route("/install", methods=["POST"])  # ✅ CORRIGÉ
def install_nuclei():
    """Installe Nuclei automatiquement"""
    try:
        logger.info("Demande d'installation de Nuclei...")
        result = nuclei_scanner.install_nuclei()
        
        if result.get("success"):
            logger.info("Installation de Nuclei réussie")
            return jsonify({"message": "Nuclei installé avec succès"})
        else:
            logger.error(f"Échec installation: {result.get('error')}")
            return jsonify({"error": result.get("error", "Erreur inconnue")}), 400
            
    except Exception as e:
        logger.error(f"Erreur installation Nuclei: {e}")
        return jsonify({"error": str(e)}), 500

@nuclei_bp.route("/history")  # ✅ CORRIGÉ
def history():
    """Récupère l'historique des scans"""
    try:
        history = nuclei_scanner.get_scan_history()
        return jsonify({"history": history})
    except Exception as e:
        logger.error(f"Erreur récupération historique: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@nuclei_bp.route("/report/<filename>")  # ✅ CORRIGÉ
def get_report(filename):
    """Récupère un rapport spécifique"""
    try:
        # Validation du nom de fichier pour éviter les attaques de chemin
        if not filename.endswith('.json') or '/' in filename or '\\' in filename:
            return jsonify({"error": "Nom de fichier invalide"}), 400
        
        result = nuclei_scanner.get_scan_report(filename)
        
        if "error" in result:
            return jsonify(result), 404
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Erreur récupération rapport: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@nuclei_bp.route("/templates")  # ✅ CORRIGÉ
def get_templates():
    """Récupère la liste des templates disponibles"""
    try:
        templates = nuclei_scanner.get_available_templates()
        return jsonify({"templates": templates})
    except Exception as e:
        logger.error(f"Erreur récupération templates: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@nuclei_bp.route("/status")  # ✅ CORRIGÉ
def status():
    """Vérifie le statut de Nuclei"""
    try:
        available = nuclei_scanner.check_nuclei_available()
        return jsonify({
            "available": available,
            "binary_path": nuclei_scanner.NUCLEI_BINARY if available else None
        })
    except Exception as e:
        logger.error(f"Erreur vérification statut: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@nuclei_bp.route("/export/<filename>/<format_type>")  # ✅ CORRIGÉ
def export_report(filename, format_type):
    """Exporte un rapport dans un format spécifique"""
    try:
        # Validation du nom de fichier
        if not filename.endswith('.json') or '/' in filename or '\\' in filename:
            return jsonify({"error": "Nom de fichier invalide"}), 400
        
        # Validation du format
        if format_type not in ['json', 'csv']:
            return jsonify({"error": "Format non supporté"}), 400
        
        result = nuclei_scanner.export_report(filename, format_type)
        
        if "error" in result:
            return jsonify(result), 400
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Erreur export rapport: {e}")
        return jsonify({"error": str(e)}), 500

@nuclei_bp.route("/clean", methods=["POST"])  # ✅ CORRIGÉ
def clean_reports():
    """Nettoie les anciens rapports"""
    try:
        data = request.get_json() if request.is_json else request.form
        days = int(data.get("days", 30))
        
        if days < 1:
            return jsonify({"error": "Le nombre de jours doit être positif"}), 400
        
        result = nuclei_scanner.clean_old_reports(days)
        
        if result.get("success"):
            return jsonify({
                "message": f"Nettoyage terminé. {result['deleted']} fichiers supprimés."
            })
        else:
            return jsonify({"error": result.get("error", "Erreur inconnue")}), 400
            
    except ValueError:
        return jsonify({"error": "Nombre de jours invalide"}), 400
    except Exception as e:
        logger.error(f"Erreur nettoyage: {e}")
        return jsonify({"error": str(e)}), 500

@nuclei_bp.route("/stats")  # ✅ CORRIGÉ
def get_stats():
    """Récupère les statistiques globales"""
    try:
        history = nuclei_scanner.get_scan_history()
        
        # Calculer les statistiques globales
        total_scans = len(history)
        total_findings = sum(scan.get('findings_count', 0) for scan in history)
        
        # Statistiques par sévérité (approximatives basées sur l'historique)
        severity_stats = {}
        for scan in history:
            scan_stats = scan.get('stats', {}).get('by_severity', {})
            for severity, count in scan_stats.items():
                severity_stats[severity] = severity_stats.get(severity, 0) + count
        
        stats = {
            "total_scans": total_scans,
            "total_findings": total_findings,
            "severity_distribution": severity_stats,
            "recent_scans": history[:5]  # 5 derniers scans
        }
        
        return jsonify({"stats": stats})
        
    except Exception as e:
        logger.error(f"Erreur récupération stats: {e}")
        return jsonify({"error": str(e)}), 500
