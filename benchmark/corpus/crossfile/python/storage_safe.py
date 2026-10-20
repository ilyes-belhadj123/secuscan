"""Benchmark : fonctions appelées uniquement avec des entiers depuis routes_safe.py (aucune alerte attendue)."""
import requests


def load_report(report_id):
    with open(f"/srv/reports/{report_id}.pdf", "rb") as handle:
        return handle.read()


def preview_catalog(product_id):
    page = requests.get(f"https://catalog.example.com/items/{product_id}", timeout=5)
    return page.text[:500]
