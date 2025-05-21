# routes/plugin_routes.py (amélioré)
from flask import Blueprint, jsonify, render_template, request, redirect, url_for
from services.plugin_manager import (
    get_available_plugins, enable_plugin, disable_plugin, 
    get_enabled_plugins, run_plugin
)

plugin_bp = Blueprint('plugins', __name__)

@plugin_bp.route("/plugins", methods=["GET"])
def list_plugins():
    """Page principale des plugins qui affiche tous les plugins disponibles."""
    plugins = get_available_plugins()
    return render_template("plugins/index.html", plugins=plugins, active_page="plugins")

@plugin_bp.route("/plugins/enable/<plugin_name>", methods=["POST"])
def enable(plugin_name):
    """Active un plugin."""
    success, message = enable_plugin(plugin_name)
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({"success": success, "message": message})
    else:
        return redirect(url_for('plugins.list_plugins'))

@plugin_bp.route("/plugins/disable/<plugin_name>", methods=["POST"])
def disable(plugin_name):
    """Désactive un plugin."""
    success, message = disable_plugin(plugin_name)
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({"success": success, "message": message})
    else:
        return redirect(url_for('plugins.list_plugins'))

@plugin_bp.route("/plugins/run/<plugin_name>", methods=["GET", "POST"])
def run(plugin_name):
    """Interface pour exécuter un plugin spécifique."""
    if request.method == "GET":
        # Affiche le formulaire pour le plugin
        plugins = get_available_plugins()
        if plugin_name not in plugins:
            return redirect(url_for('plugins.list_plugins'))
        
        return render_template(
            "plugins/run.html", 
            plugin=plugins[plugin_name], 
            plugin_name=plugin_name
        )
    
    elif request.method == "POST":
        # Exécute le plugin avec les données du formulaire
        input_data = request.form.to_dict()
        
        # Gestion des fichiers si nécessaire
        if 'file' in request.files and plugin_name == 'file_hasher':
            from werkzeug.utils import secure_filename
            import os
            
            file = request.files['file']
            if file.filename != '':
                filename = secure_filename(file.filename)
                temp_path = os.path.join('temp', filename)
                os.makedirs('temp', exist_ok=True)
                file.save(temp_path)
                input_data['file_path'] = temp_path
        
        result = run_plugin(plugin_name, input_data)
        
        # Nettoie les fichiers temporaires si nécessaire
        if 'file_path' in input_data and input_data['file_path'].startswith('temp/'):
            try:
                os.remove(input_data['file_path'])
            except:
                pass
        
        return render_template(
            "plugins/result.html", 
            plugin_name=plugin_name, 
            result=result
        )

@plugin_bp.route("/api/plugins", methods=["GET"])
def api_list_plugins():
    """API pour récupérer la liste des plugins disponibles."""
    plugins = get_available_plugins()
    return jsonify(plugins)

@plugin_bp.route("/api/plugins/run/<plugin_name>", methods=["POST"])
def api_run_plugin(plugin_name):
    """API pour exécuter un plugin."""
    input_data = request.json
    result = run_plugin(plugin_name, input_data)
    return jsonify(result)
