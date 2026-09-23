"""Corpus de benchmark SecuScan — code volontairement vulnérable (ne pas déployer)."""
import hashlib
import os
import pickle
import sqlite3
import subprocess

import requests
import yaml
from flask import Flask, redirect, render_template_string, request

app = Flask(__name__)

SMTP_PASSWORD = "Bench-Mark-Pass-42!"


@app.route("/users")
def users():
    name = request.args.get("name")
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = '%s'" % name)
    return str(cur.fetchall())


@app.route("/users/by-email")
def users_by_email():
    email = request.args.get("email")
    conn = sqlite3.connect("app.db")
    query = "SELECT * FROM users WHERE email = '" + email + "'"
    return str(conn.execute(query).fetchall())


@app.route("/files/list")
def list_files():
    folder = request.args.get("folder", ".")
    return os.popen("ls -la " + folder).read()


@app.route("/files/archive", methods=["POST"])
def archive():
    name = request.form["name"]
    subprocess.run(f"tar -czf /tmp/{name}.tgz /srv/data", shell=True, check=True)
    return "ok"


@app.route("/calc", methods=["POST"])
def calc():
    return str(eval(request.form["expression"]))


@app.route("/session/restore", methods=["POST"])
def restore_session():
    state = pickle.loads(request.get_data())
    return str(state)


@app.route("/config/import", methods=["POST"])
def import_config():
    config = yaml.load(request.get_data(), Loader=yaml.Loader)
    return str(config)


@app.route("/greet")
def greet():
    name = request.args.get("name", "")
    return render_template_string(f"<p>Bonjour {name}</p>")


@app.route("/login/done")
def after_login():
    return redirect(request.args.get("next", "/"))


@app.route("/reports/raw")
def raw_report():
    return open("/srv/reports/" + request.args["file"]).read()


def store_password(password):
    return hashlib.md5(password.encode()).hexdigest()


def fetch_partner_prices():
    return requests.get("https://partner.example.com/prices", verify=False).json()
