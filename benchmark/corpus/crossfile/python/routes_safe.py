"""Benchmark : mêmes appels entre fichiers, avec des valeurs converties en entiers (aucune alerte attendue)."""
from flask import Flask, request
from storage_safe import load_report, preview_catalog

app = Flask(__name__)


@app.route("/report")
def report():
    return load_report(int(request.args.get("id", "0")))


@app.route("/catalog")
def catalog():
    product_id = int(request.args["id"])
    return preview_catalog(product_id)
