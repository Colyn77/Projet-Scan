from flask import Blueprint, jsonify

api_bp = Blueprint('api', __name__)

@api_bp.route('/')
def home():
    return jsonify({"message": "Bienvenue dans votre environnement de scan"})

