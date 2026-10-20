"""Benchmark : flux de données sur plusieurs lignes et familles de failles récentes (vulnérable)."""
import sqlite3
import subprocess
import tempfile

import jwt
import requests
from flask import Flask, make_response, request
from lxml import etree

app = Flask(__name__)
app.secret_key = "dev-secret"


@app.route("/preview")
def preview():
    target = request.args.get("url")
    page = requests.get(target, timeout=5)
    return page.text


@app.route("/search")
def search():
    term = request.args["q"]
    query = "SELECT id, title FROM books WHERE title LIKE '%" + term + "%'"
    rows = sqlite3.connect("books.db").execute(query).fetchall()
    return {"rows": rows}


@app.route("/archive", methods=["POST"])
def archive():
    folder = request.form.get("folder", "")
    command = "tar czf /tmp/out.tgz " + folder
    subprocess.run(command, shell=True, check=False)
    return "ok"


@app.route("/import", methods=["POST"])
def import_feed():
    tree = etree.fromstring(request.get_data())
    return {"items": len(tree)}


@app.route("/me")
def me():
    token = request.headers.get("Authorization", "").removeprefix("Bearer ")
    claims = jwt.decode(token, options={"verify_signature": False})
    return claims


@app.route("/login", methods=["POST"])
def login():
    resp = make_response("ok")
    resp.set_cookie("session", request.form["sid"])
    return resp


def export_path():
    return tempfile.mktemp(suffix=".csv")
