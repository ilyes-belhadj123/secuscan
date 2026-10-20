"""Benchmark : entrée utilisateur transmise à des fonctions d'un autre fichier (vulnérable)."""
from flask import Flask, request
from storage import load_attachment, preview_link

app = Flask(__name__)


@app.route("/attachment")
def attachment():
    name = request.args.get("name", "")
    return load_attachment(name)


@app.route("/preview")
def preview():
    return preview_link(request.args["url"])
