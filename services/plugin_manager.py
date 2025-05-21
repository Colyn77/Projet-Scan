# services/plugin_manager.py (amélioré)
import os
import importlib.util
import json

PLUGIN_FOLDER = "plugins"
ENABLED_PLUGINS_FILE = "enabled_plugins.txt"

def get_available_plugins():
    """Récupère la liste de tous les plugins disponibles avec leurs informations."""
    plugins_info = {}
    
    # Vérifie si le dossier de plugins existe
    if not os.path.exists(PLUGIN_FOLDER):
        return plugins_info
    
    # Parcourt tous les fichiers .py dans le dossier des plugins
    for file in os.listdir(PLUGIN_FOLDER):
        if file.endswith(".py"):
            plugin_name = file[:-3]
            try:
                # Charge le module pour récupérer ses informations
                path = os.path.join(PLUGIN_FOLDER, file)
                spec = importlib.util.spec_from_file_location(plugin_name, path)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                
                # Vérifie si le module a une fonction get_info()
                if hasattr(module, 'get_info'):
                    info = module.get_info()
                    # Ajoute l'état d'activation du plugin
                    info['enabled'] = plugin_name in get_enabled_plugins()
                    plugins_info[plugin_name] = info
            except Exception as e:
                print(f"[!] Erreur lors du chargement des informations du plugin {plugin_name}: {e}")
    
    return plugins_info

def get_enabled_plugins():
    """Récupère la liste des plugins activés."""
    if not os.path.exists(ENABLED_PLUGINS_FILE):
        return []
    with open(ENABLED_PLUGINS_FILE, "r") as f:
        return [line.strip() for line in f if line.strip()]

def load_plugins():
    """Charge les plugins activés."""
    plugins = {}
    enabled = get_enabled_plugins()
    
    # Vérifie si le dossier de plugins existe
    if not os.path.exists(PLUGIN_FOLDER):
        return plugins
    
    for file in os.listdir(PLUGIN_FOLDER):
        if file.endswith(".py") and file[:-3] in enabled:
            path = os.path.join(PLUGIN_FOLDER, file)
            name = file[:-3]
            spec = importlib.util.spec_from_file_location(name, path)
            module = importlib.util.module_from_spec(spec)
            try:
                spec.loader.exec_module(module)
                plugins[name] = module
            except Exception as e:
                print(f"[!] Erreur dans le plugin {name} : {e}")
    return plugins

def enable_plugin(plugin_name):
    """Active un plugin."""
    # Vérifie si le plugin existe
    plugin_path = os.path.join(PLUGIN_FOLDER, f"{plugin_name}.py")
    if not os.path.exists(plugin_path):
        return False, f"Le plugin {plugin_name} n'existe pas"
    
    # Vérifie si le plugin n'est pas déjà activé
    enabled = get_enabled_plugins()
    if plugin_name in enabled:
        return False, f"Le plugin {plugin_name} est déjà activé"
    
    # Active le plugin
    with open(ENABLED_PLUGINS_FILE, "a") as f:
        f.write(f"{plugin_name}\n")
    
    return True, f"Plugin {plugin_name} activé avec succès"

def disable_plugin(plugin_name):
    """Désactive un plugin."""
    if not os.path.exists(ENABLED_PLUGINS_FILE):
        return False, f"Le fichier des plugins activés n'existe pas"
    
    # Vérifie si le plugin est activé
    enabled = get_enabled_plugins()
    if plugin_name not in enabled:
        return False, f"Le plugin {plugin_name} n'est pas activé"
    
    # Désactive le plugin
    with open(ENABLED_PLUGINS_FILE, "r") as f:
        lines = f.readlines()
    with open(ENABLED_PLUGINS_FILE, "w") as f:
        for line in lines:
            if line.strip() != plugin_name:
                f.write(line)
    
    return True, f"Plugin {plugin_name} désactivé avec succès"

def run_plugin(plugin_name, input_data):
    """Exécute un plugin spécifique avec les données d'entrée fournies."""
    # Vérifie si le plugin est activé
    enabled = get_enabled_plugins()
    if plugin_name not in enabled:
        return {"error": f"Le plugin {plugin_name} n'est pas activé"}
    
    # Charge le plugin
    plugin_path = os.path.join(PLUGIN_FOLDER, f"{plugin_name}.py")
    if not os.path.exists(plugin_path):
        return {"error": f"Le plugin {plugin_name} n'existe pas"}
    
    try:
        # Prétraitement des données d'entrée en fonction du plugin
        if plugin_name == "password_generator" and "length" in input_data:
            try:
                input_data["length"] = int(input_data["length"])
            except (ValueError, TypeError):
                input_data["length"] = 12
        
        # Chargement et exécution du plugin
        spec = importlib.util.spec_from_file_location(plugin_name, plugin_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        
        # Vérifie si le module a une fonction run()
        if hasattr(module, 'run'):
            return module.run(input_data)
        else:
            return {"error": f"Le plugin {plugin_name} n'a pas de fonction run()"}
    except Exception as e:
        return {"error": f"Erreur lors de l'exécution du plugin {plugin_name}: {str(e)}"}
        
def init_plugin_environment():
    """Initialise l'environnement pour les plugins."""
    # Crée le dossier des plugins s'il n'existe pas
    if not os.path.exists(PLUGIN_FOLDER):
        os.makedirs(PLUGIN_FOLDER)
    
    # Crée le fichier des plugins activés s'il n'existe pas
    if not os.path.exists(ENABLED_PLUGINS_FILE):
        with open(ENABLED_PLUGINS_FILE, "w") as f:
            # Par défaut, activons quelques plugins
            f.write("reverse_dns\n")
            f.write("password_generator\n")
            f.write("hash_identifier\n")
            f.write("file_hasher\n")
