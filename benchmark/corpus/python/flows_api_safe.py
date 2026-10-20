"""Benchmark : mêmes fonctionnalités que flows_api.py, écrites de façon sûre (aucune alerte attendue)."""
import os
import secrets
import sqlite3
import subprocess
import tempfile

import jwt
import requests
from flask import Flask, make_response, request
from lxml import etree

app = Flask(__name__)
app.secret_key = os.environ["FLASK_SECRET_KEY"]
PUBLIC_KEY = os.environ["JWT_PUBLIC_KEY"]
EXPORT_DIR = os.environ["EXPORT_DIR"]  # dossier réservé à l'application, pas /tmp partagé


def check_credentials(email: str, password: str) -> bool:
    """Vérification du mot de passe haché (bcrypt, argon2…) : hors du périmètre du benchmark."""
    raise NotImplementedError


@app.route("/preview")
def preview():
    book_id = request.args.get("id", "0")
    page = requests.get(f"https://api.example.com/books/{int(book_id)}", timeout=5)
    return page.text


@app.route("/search")
def search():
    term = request.args["q"]
    rows = sqlite3.connect("books.db").execute(
        "SELECT id, title FROM books WHERE title LIKE ?", (f"%{term}%",)
    ).fetchall()
    return {"rows": rows}


@app.route("/archive", methods=["POST"])
def archive():
    folder = request.form.get("folder", "")
    subprocess.run(["tar", "czf", os.path.join(EXPORT_DIR, "out.tgz"), "--", folder], check=False)
    return "ok"


@app.route("/import", methods=["POST"])
def import_feed():
    parser = etree.XMLParser(resolve_entities=False, no_network=True)
    tree = etree.fromstring(request.get_data(), parser=parser)
    return {"items": len(tree)}


@app.route("/me")
def me():
    token = request.headers.get("Authorization", "").removeprefix("Bearer ")
    claims = jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"])
    return claims


@app.route("/login", methods=["POST"])
def login():
    if not check_credentials(request.form["email"], request.form["password"]):
        return "identifiants invalides", 401
    resp = make_response("ok")
    # Identifiant de session créé par le serveur, jamais repris de la requête (fixation de session)
    resp.set_cookie("session", secrets.token_urlsafe(32), secure=True, httponly=True, samesite="Lax")
    return resp


def export_path():
    with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as handle:
        return handle.name
