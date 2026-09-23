"""Acme Shop — API commandes (projet de démonstration volontairement vulnérable)."""
import hashlib
import os
import pickle
import sqlite3
import subprocess

import requests
import yaml
from flask import Flask, abort, jsonify, render_template_string, request, send_file, session

app = Flask(__name__)

# Secrets factices, codés en dur (mauvaise pratique volontaire)
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
DB_PASSWORD = "Demo-P@ssw0rd-2026"

INVOICES_DIR = "/srv/acme/invoices"


def get_db():
    return sqlite3.connect("acme.db")


@app.route("/api/orders")
def search_orders():
    customer = request.args.get("customer", "")
    db = get_db()
    cursor = db.cursor()
    cursor.execute(f"SELECT id, total, status FROM orders WHERE customer_name = '{customer}'")
    rows = cursor.fetchall()
    return jsonify([{"id": r[0], "total": r[1], "status": r[2]} for r in rows])


@app.route("/api/orders/count")
def count_orders():
    # Requête construite par concaténation mais uniquement avec une constante :
    # aucune donnée utilisateur, donc pas d'injection possible (faux positif attendu).
    table = "orders"
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT COUNT(*) FROM " + table)
    return jsonify({"count": cursor.fetchone()[0]})


@app.route("/api/invoices/download")
def download_invoice():
    filename = request.args.get("file")
    return send_file(open(os.path.join(INVOICES_DIR, filename), "rb"), download_name=filename)


@app.route("/api/tools/ping")
def ping_host():
    host = request.args.get("host", "localhost")
    output = subprocess.check_output("ping -c 1 " + host, shell=True)
    return output


@app.route("/api/cart/restore", methods=["POST"])
def restore_cart():
    cart = pickle.loads(request.get_data())
    return jsonify({"items": len(cart)})


@app.route("/api/import/catalog", methods=["POST"])
def import_catalog():
    catalog = yaml.load(request.get_data())
    return jsonify({"products": len(catalog)})


@app.route("/hello")
def hello():
    name = request.args.get("name", "client")
    return render_template_string("<h1>Bonjour " + name + "</h1>")


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


def fetch_exchange_rates():
    return requests.get("https://rates.example.com/eur", verify=False).json()


def login_required(view):
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            abort(401)
        return view(*args, **kwargs)

    wrapper.__name__ = view.__name__
    return wrapper


@app.route("/api/invoices/<int:invoice_id>")
@login_required
def get_invoice(invoice_id):
    db = get_db()
    row = db.execute(
        "SELECT id, customer_id, amount, billing_address FROM invoices WHERE id = ?", (invoice_id,)
    ).fetchone()
    if row is None:
        abort(404)
    return jsonify({"id": row[0], "customer_id": row[1], "amount": row[2], "billing_address": row[3]})


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
