# utils/logger.py

import logging
import os
from logging.handlers import RotatingFileHandler
from datetime import datetime

import psycopg2
from psycopg2.extras import Json

DB_CONFIG = {
    "dbname":   "scan_results",
    "user":     "scan_user",
    "password": "colyn123",   # votre mot de passe réel
    "host":     "localhost",
    "port":     "5432"
}

class PGHandler(logging.Handler):
    """
    Handler qui envoie chaque enregistrement dans la table scan_results.logs.
    """
    def __init__(self, db_config):
        super().__init__()
        self.db_config = db_config
        self.conn = None
        self._connect()

    def _connect(self):
        try:
            self.conn = psycopg2.connect(
                dbname   = self.db_config["dbname"],
                user     = self.db_config["user"],
                password = self.db_config["password"],
                host     = self.db_config["host"],
                port     = self.db_config["port"]
            )
            self.conn.autocommit = True
            self.cursor = self.conn.cursor()
        except Exception as e:
            print(f"[PGHandler] Impossible de se connecter à PostgreSQL : {e}")

    def emit(self, record):
        if self.conn is None:
            self._connect()
            if self.conn is None:
                return

        try:
            niveau   = record.levelname
            source   = record.name
            message  = record.getMessage()
            metadata = {
                "filename": record.filename,
                "lineno": record.lineno,
                "funcName": record.funcName
            }

            sql = """
            INSERT INTO logs (niveau, source, message, métadonnées)
            VALUES (%s, %s, %s, %s);
            """
            self.cursor.execute(sql, (niveau, source, message, Json(metadata)))
        except Exception:
            try:
                if self.cursor:
                    self.cursor.close()
                if self.conn:
                    self.conn.close()
            except:
                pass
            self.conn = None

class ToolboxLogger:
    """Système de logging centralisé pour la toolbox de sécurité"""
    
    _instances = {}
    
    def __new__(cls, name='toolbox'):
        if name not in cls._instances:
            cls._instances[name] = super(ToolboxLogger, cls).__new__(cls)
        return cls._instances[name]
    
    def __init__(self, name='toolbox', level=logging.INFO):
        if hasattr(self, 'logger'):
            return
            
        log_dir = 'logs'
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
        
        self.logger = logging.getLogger(name)
        
        if not self.logger.handlers:
            self.logger.setLevel(level)
            
            detailed_formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s'
            )
            simple_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            
            # 1) Handler fichier principal
            file_handler = RotatingFileHandler(
                os.path.join(log_dir, f'{name}.log'),
                maxBytes=5*1024*1024,
                backupCount=5
            )
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(detailed_formatter)
            
            # 2) Handler erreurs
            error_handler = RotatingFileHandler(
                os.path.join(log_dir, f'{name}_errors.log'),
                maxBytes=1*1024*1024,
                backupCount=3
            )
            error_handler.setLevel(logging.ERROR)
            error_handler.setFormatter(detailed_formatter)
            
            # 3) Handler console
            console_handler = logging.StreamHandler()
            console_handler.setLevel(logging.INFO)
            console_handler.setFormatter(simple_formatter)
            
            # 4) Handler PostgreSQL
            pg_handler = PGHandler(DB_CONFIG)
            pg_handler.setLevel(logging.DEBUG)
            pg_handler.setFormatter(detailed_formatter)
            
            # 5) Handler modules spécifiques (optionnel)
            if name != 'toolbox':
                module_handler = RotatingFileHandler(
                    os.path.join(log_dir, f'{name}_module.log'),
                    maxBytes=2*1024*1024,
                    backupCount=3
                )
                module_handler.setLevel(logging.DEBUG)
                module_handler.setFormatter(detailed_formatter)
                self.logger.addHandler(module_handler)
            
            # Ajout des handlers
            self.logger.addHandler(file_handler)
            self.logger.addHandler(error_handler)
            self.logger.addHandler(console_handler)
            self.logger.addHandler(pg_handler)

    def get_logger(self):
        return self.logger
    
    @classmethod
    def setup_module_logger(cls, module_name, level=logging.INFO):
        instance = cls(module_name, level)
        return instance.get_logger()

# Cette fonction ne doit pas importer utils.logger, elle est définie ici même
def get_logger(name='toolbox'):
    """
    Renvoie un logger configuré (fichiers + console + PostgreSQL) pour le nom donné.
    """
    logger_instance = ToolboxLogger(name)
    return logger_instance.get_logger()

def archive_logs():
    """Archive les logs anciens dans un fichier ZIP"""
    import zipfile
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    archive_name = f"logs/archive_{timestamp}.zip"
    
    with zipfile.ZipFile(archive_name, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk('logs'):
            for file in files:
                if file.endswith('.log') and not file.startswith('archive'):
                    file_path = os.path.join(root, file)
                    zipf.write(file_path, file)
                    # os.remove(file_path)  # si vous souhaitez supprimer après archivage
