from flask import Blueprint, request, jsonify, render_template, flash, redirect, url_for
from markupsafe import Markup
from services.hydra_bruteforce import run_hydra, get_available_wordlists, create_custom_wordlist, get_services
import os
from utils.logger import get_logger
from werkzeug.utils import secure_filename

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = get_logger("hydra_routes")

hydra_bp = Blueprint('hydra', __name__)

# Répertoire pour les wordlists
WORDLISTS_DIR = "wordlists"

# Extensions autorisées pour les uploads
ALLOWED_EXTENSIONS = {'txt', 'lst', 'dict', 'wordlist'}

def allowed_file(filename):
    """Vérifie si l'extension du fichier est autorisée"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@hydra_bp.route('/upload', methods=['POST'])
def upload_wordlist():
    """Upload d'une nouvelle wordlist"""
    try:
        list_type = request.form.get('list_type', 'userlist')
        
        # Vérifier qu'un fichier a été soumis
        if 'file' not in request.files:
            return jsonify({"error": "Aucun fichier fourni"}), 400
            
        file = request.files['file']
        
        # Vérifier que le fichier a un nom
        if file.filename == '':
            return jsonify({"error": "Aucun fichier sélectionné"}), 400
            
        # Vérifier que le fichier a une extension autorisée
        if file and allowed_file(file.filename):
            # Sécuriser le nom du fichier
            original_filename = secure_filename(file.filename)
            
            # Ajouter un préfixe selon le type de liste pour faciliter la catégorisation
            if list_type == "userlist":
                filename = f"userlist_{original_filename}"
            else:
                filename = f"passlist_{original_filename}"
            
            # Créer le répertoire des wordlists s'il n'existe pas
            if not os.path.exists(WORDLISTS_DIR):
                os.makedirs(WORDLISTS_DIR)
                
            # Sauvegarder le fichier
            file_path = os.path.join(WORDLISTS_DIR, filename)
            file.save(file_path)
            
            logger.info(f"Wordlist '{filename}' téléchargée avec succès dans {file_path}")
            
            # Retourner un succès
            return jsonify({
                "success": True,
                "message": f"Fichier {original_filename} téléchargé avec succès",
                "file_path": file_path,
                "file_name": filename  # Retourner le nouveau nom avec préfixe
            })
        else:
            return jsonify({"error": f"Type de fichier non autorisé. Utilisez: {', '.join(ALLOWED_EXTENSIONS)}"}), 400
    except Exception as e:
        logger.error(f"Erreur lors de l'upload de fichier: {e}")
        return jsonify({"error": str(e)}), 500
        
@hydra_bp.route('/wordlists', methods=['GET'])
def get_wordlists():
    """Récupère les listes d'utilisateurs et de mots de passe disponibles"""
    try:
        wordlists = get_available_wordlists()
        
        # Si demandé en JSON
        if request.headers.get('Accept') == 'application/json':
            return jsonify(wordlists)
        
        # Sinon, afficher en HTML
        return render_template(
            "results.html", 
            title="Wordlists disponibles", 
            result=[
                f"<h3>Listes d'utilisateurs ({len(wordlists['user_lists'])})</h3>",
                "<ul>" + "".join([f"<li>{wl['name']} - {wl['path']}</li>" for wl in wordlists['user_lists']]) + "</ul>",
                f"<h3>Listes de mots de passe ({len(wordlists['pass_lists'])})</h3>",
                "<ul>" + "".join([f"<li>{wl['name']} - {wl['path']}</li>" for wl in wordlists['pass_lists']]) + "</ul>"
            ]
        )
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des wordlists: {e}")
        return jsonify({"error": str(e)}), 500

@hydra_bp.route('/services', methods=['GET'])
def list_services():
    """Liste les services supportés par Hydra"""
    try:
        services = get_services()
        
        # Si demandé en JSON
        if request.headers.get('Accept') == 'application/json':
            return jsonify({"services": services})
            
        # Sinon, afficher en HTML
        return render_template(
            "results.html", 
            title="Services supportés par Hydra", 
            result=[
                "<h3>Services disponibles</h3>",
                "<table border='1' style='border-collapse: collapse; width: 100%;'>",
                "<tr><th>Service</th><th>Port</th><th>Description</th></tr>",
                "".join([f"<tr><td>{svc['name']}</td><td>{svc['port']}</td><td>{svc['description']}</td></tr>" for svc in services]),
                "</table>"
            ]
        )
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des services: {e}")
        return jsonify({"error": str(e)}), 500

@hydra_bp.route('/attack', methods=['POST'])
def launch_bruteforce():
    """Lance une attaque brute-force avec Hydra"""
    try:
        # Traiter les données selon le type de contenu
        if request.is_json:
            # Pour les requêtes API JSON
            data = request.get_json()
            target = data.get("target")
            service = data.get("service")
            userlist_path = data.get("userlist")
            passlist_path = data.get("passlist")
            custom_userlist = data.get("custom_userlist")
            custom_passlist = data.get("custom_passlist")
            options = data.get("options", {})
        else:
            # Pour les formulaires HTML
            target = request.form.get("target")
            service = request.form.get("service")
            userlist_path = request.form.get("userlist")
            passlist_path = request.form.get("passlist")
            custom_userlist = request.form.get("custom_userlist")
            custom_passlist = request.form.get("custom_passlist")
            
            # Récupérer les options du formulaire
            options = {}
            if request.form.get("tasks"):
                options["tasks"] = request.form.get("tasks")
            if request.form.get("verbose") == "on":
                options["verbose"] = True
            
            # Options pour les formulaires HTTP
            if service and service.startswith("http") and "form" in service:
                options["form_path"] = request.form.get("form_path", "/")
                options["form_data"] = request.form.get("form_data", "username=^USER^&password=^PASS^")
                options["form_success"] = request.form.get("form_success", "F=incorrect")

        # Validation des paramètres
        if not target:
            return jsonify({"error": "Cible manquante"}), 400
        if not service:
            return jsonify({"error": "Service manquant"}), 400
            
        # Gestion des wordlists personnalisées
        if custom_userlist:
            userlist_path = create_custom_wordlist(custom_userlist, "userlist")
        if custom_passlist:
            passlist_path = create_custom_wordlist(custom_passlist, "passlist")
            
        # Validation des wordlists
        if not userlist_path:
            return jsonify({"error": "Liste d'utilisateurs manquante"}), 400
        if not passlist_path:
            return jsonify({"error": "Liste de mots de passe manquante"}), 400
            
        # Exécuter Hydra
        result = run_hydra(target, service, userlist_path, passlist_path, options)
        
        # Format de réponse pour l'API JSON
        if request.is_json:
            return jsonify(result)
            
        # Formater les résultats pour l'affichage HTML
        html_result = []
        
        if result.get("success", False):
            html_result.append("<div style='color: green; font-weight: bold;'>Attaque terminée avec succès</div>")
            
            # Afficher les credentials trouvés
            if result.get("credentials"):
                html_result.append("<h3>Identifiants trouvés</h3>")
                html_result.append("<ul>")
                for cred in result["credentials"]:
                    html_result.append(f"<li>{cred}</li>")
                html_result.append("</ul>")
            else:
                html_result.append("<p>Aucun identifiant trouvé</p>")
                
            # Afficher les détails complets
            html_result.append("<h3>Détails de la commande</h3>")
            html_result.append(f"<pre>{result.get('command', '')}</pre>")
            
            html_result.append("<h3>Sortie complète</h3>")
            html_result.append(f"<pre>{result.get('stdout', '')}</pre>")
        else:
            html_result.append(f"<div style='color: red; font-weight: bold;'>Erreur: {result.get('error', 'Erreur inconnue')}</div>")
            
            if "command" in result:
                html_result.append("<h3>Commande tentée</h3>")
                html_result.append(f"<pre>{result.get('command', '')}</pre>")
                
            if "stderr" in result:
                html_result.append("<h3>Erreur détaillée</h3>")
                html_result.append(f"<pre>{result.get('stderr', '')}</pre>")
                
        # Rendre le template avec les résultats formatés
        return render_template(
            "results.html", 
            title=f"Résultats de l'attaque Hydra sur {target}", 
            result=[Markup(item) for item in html_result]
        )
            
    except Exception as e:
        logger.error(f"Erreur lors du lancement de l'attaque: {e}")
        if request.is_json:
            return jsonify({"error": str(e)}), 500
        else:
            return render_template("results.html", title="Erreur", result=[f"Erreur: {str(e)}"])
