# utils/logger.py

import logging
import os
from logging.handlers import RotatingFileHandler
from datetime import datetime

class ToolboxLogger:
    """Système de logging centralisé pour la toolbox de sécurité"""
    
    _instances = {}
    
    def __new__(cls, name='toolbox'):
        """Singleton pattern pour réutiliser les loggers existants"""
        if name not in cls._instances:
            cls._instances[name] = super(ToolboxLogger, cls).__new__(cls)
        return cls._instances[name]
    
    def __init__(self, name='toolbox', level=logging.INFO):
        """
        Initialise le logger
        
        Args:
            name (str): Nom du logger (par défaut: 'toolbox')
            level: Niveau de logging (par défaut: INFO)
        """
        # Éviter la réinitialisation si déjà configuré
        if hasattr(self, 'logger'):
            return
            
        # Création du dossier logs s'il n'existe pas
        log_dir = 'logs'
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
        
        # Configuration du logger
        self.logger = logging.getLogger(name)
        
        # Éviter d'ajouter plusieurs handlers
        if not self.logger.handlers:
            self.logger.setLevel(level)
            
            # Format des logs avec plus d'informations
            detailed_formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s'
            )
            simple_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            
            # Handler pour le fichier de log principal avec rotation
            file_handler = RotatingFileHandler(
                os.path.join(log_dir, f'{name}.log'),
                maxBytes=5*1024*1024,  # 5 MB
                backupCount=5
            )
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(detailed_formatter)
            
            # Handler pour le fichier d'erreurs
            error_handler = RotatingFileHandler(
                os.path.join(log_dir, f'{name}_errors.log'),
                maxBytes=1*1024*1024,  # 1 MB
                backupCount=3
            )
            error_handler.setLevel(logging.ERROR)
            error_handler.setFormatter(detailed_formatter)
            
            # Handler pour la console
            console_handler = logging.StreamHandler()
            console_handler.setLevel(logging.INFO)
            console_handler.setFormatter(simple_formatter)
            
            # Handler pour les modules spécifiques (optionnel)
            if name != 'toolbox':
                module_handler = RotatingFileHandler(
                    os.path.join(log_dir, f'{name}_module.log'),
                    maxBytes=2*1024*1024,  # 2 MB
                    backupCount=3
                )
                module_handler.setLevel(logging.DEBUG)
                module_handler.setFormatter(detailed_formatter)
                self.logger.addHandler(module_handler)
            
            # Ajout des handlers au logger
            self.logger.addHandler(file_handler)
            self.logger.addHandler(error_handler)
            self.logger.addHandler(console_handler)
    
    def get_logger(self):
        """Retourne l'instance du logger"""
        return self.logger
    
    @classmethod
    def setup_module_logger(cls, module_name, level=logging.INFO):
        """
        Configure un logger pour un module spécifique
        
        Args:
            module_name (str): Nom du module
            level: Niveau de logging pour ce module
        """
        instance = cls(module_name, level)
        return instance.get_logger()

# Logger global pour l'application
def get_logger(name='toolbox'):
    """Fonction utilitaire pour obtenir un logger"""
    logger_instance = ToolboxLogger(name)
    return logger_instance.get_logger()

# Fonction pour archiver les logs
def archive_logs():
    """Archive les logs anciens dans un fichier ZIP"""
    import zipfile
    from datetime import datetime
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    archive_name = f"logs/archive_{timestamp}.zip"
    
    with zipfile.ZipFile(archive_name, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk('logs'):
            for file in files:
                if file.endswith('.log') and not file.startswith('archive'):
                    file_path = os.path.join(root, file)
                    zipf.write(file_path, file)
                    # Optionnel: supprimer le fichier après archivage
                    # os.remove(file_path)
