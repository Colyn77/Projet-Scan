from flask import Blueprint, render_template, request, redirect, session,  request
import json
import hashlib

auth_bp = Blueprint("auth", __name__)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def load_users():
    with open("users.json") as f:
        return json.load(f)

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        users = load_users()
        hashed = hash_password(password)

        if username in users and users[username]["password"] == hashed:
            session["username"] = username
            session["role"] = users[username]["role"]
            return redirect("/")
        else:
            return render_template("login.html", error="Identifiants invalides")
    return render_template("login.html")

@auth_bp.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

def login_required(f):
    from functools import wraps
    def wrapper(*args, **kwargs):
        if "username" not in session:
            return redirect("/login")
        return f(*args, **kwargs)
    return wraps(f)(wrapper)
