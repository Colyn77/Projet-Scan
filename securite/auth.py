# securite/auth.py

from flask import Blueprint, render_template, request, redirect, session
import json
import os
import bcrypt  
from functools import wraps

auth_bp = Blueprint("auth", __name__)

def load_users():
    """Charge les utilisateurs depuis le fichier JSON sécurisé."""
    users_path = os.path.join(os.path.dirname(__file__), "users.json")
    with open(users_path) as f:
        return json.load(f)

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    from securite.ids import is_blocked, log_failed_attempt  

    if request.method == "POST":
        ip = request.remote_addr

        if is_blocked(ip):
            return "⛔ IP temporairement bloquée", 403

        username = request.form["username"]
        password = request.form["password"]
        users = load_users()

        if username in users:
            stored_hash = users[username]["password"].encode()
            if bcrypt.checkpw(password.encode(), stored_hash):
                session["username"] = username
                session["role"] = users[username]["role"]
                return redirect("/")
        
        log_failed_attempt(ip)
        return render_template("login.html", error="Identifiants invalides")

    return render_template("login.html")

@auth_bp.route("/logout")
def logout():
    from securite.forensics import analyser_processus_suspects

    if "username" in session:
        print(f"🔐 Fin de session de : {session['username']}")
        analyser_processus_suspects()

    session.clear()
    return redirect("/login")


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "username" not in session:
            return redirect("/login")
        return f(*args, **kwargs)
    return wrapper
