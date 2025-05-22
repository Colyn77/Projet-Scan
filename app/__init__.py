from flask import Flask
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

def create_app():
    app = Flask(__name__)
    app.config.from_object('app.core.config.Config')

    db.init_app(app)

    with app.app_context():
        # Enregistrement de l'API existante
        from app.api.routes import api_bp
        app.register_blueprint(api_bp)

        # Enregistrement des Blueprints de toutes les routes
        from app.routes import blueprints
        for bp in blueprints:
            app.register_blueprint(bp)

        # Création des tables si nécessaire
        # from app.models.schemas import ScanResult
        # db.create_all()

    return app

