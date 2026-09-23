"""Corpus de benchmark SecuScan — code sûr (aucune alerte attendue)."""
import ast
import hashlib
import json
import os
import sqlite3
import subprocess

import requests
import yaml
from flask import Flask, render_template, request

app = Flask(__name__)

TABLE_NAME = "users"
SMTP_PASSWORD = os.environ["SMTP_PASSWORD"]


@app.route("/users")
def users():
    name = request.args.get("name")
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = ?", (name,))
    return str(cur.fetchall())


@app.route("/users/count")
def users_count():
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM " + TABLE_NAME)
    return str(cur.fetchone()[0])


@app.route("/files/list")
def list_files():
    folder = request.args.get("folder", ".")
    result = subprocess.run(["ls", "-la", "--", folder], capture_output=True, text=True, check=True)
    return result.stdout


@app.route("/calc", methods=["POST"])
def calc():
    return str(ast.literal_eval(request.form["literal"]))


@app.route("/session/restore", methods=["POST"])
def restore_session():
    return str(json.loads(request.get_data()))


@app.route("/config/import", methods=["POST"])
def import_config():
    return str(yaml.safe_load(request.get_data()))


@app.route("/greet")
def greet():
    return render_template("greet.html", name=request.args.get("name", ""))


def file_checksum(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def fetch_partner_prices():
    return requests.get("https://partner.example.com/prices", timeout=5).json()


if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
