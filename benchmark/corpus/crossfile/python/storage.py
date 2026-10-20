"""Benchmark : fonctions appelées avec une entrée utilisateur depuis routes.py (vulnérable)."""
import requests

ATTACHMENTS = "/srv/attachments/"


def load_attachment(filename):
    with open(ATTACHMENTS + filename, "rb") as handle:
        return handle.read()


def preview_link(target):
    page = requests.get(target, timeout=5)
    return page.text[:500]
