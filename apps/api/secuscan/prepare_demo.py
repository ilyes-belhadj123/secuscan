"""Préparation de la démo : vérifie l'IA, remplit le cache (IA + OSV) et affiche un bilan.

Usage (dans apps/api) :  uv run python -m secuscan.prepare_demo
À lancer la veille de la démo, avec la clé OpenRouter et le réseau.
"""
import sys
from collections import Counter

from .ai.enricher import AIUnavailable, Enricher
from .config import DEMO_PROJECT_DIR, get_settings
from .models import Scan
from .pipeline import ScanService, new_id
from .storage import Storage


def main() -> int:
    settings = get_settings()
    storage = Storage(settings.data_dir / "secuscan.db")
    print(f"Modèle : {settings.openrouter_model}")
    print(f"Base   : {settings.data_dir / 'secuscan.db'}")

    if not settings.ai_enabled:
        print("\n[!] OPENROUTER_API_KEY absente : seules les réponses déjà en cache seront utilisées.")
    else:
        print("\nTest de connexion à l'IA...", end=" ", flush=True)
        try:
            Enricher(settings, storage)._complete(
                'Test de connexion SecuScan. Réponds exactement : {"ok": true}'
            )
            print("OK")
        except AIUnavailable as exc:
            print(f"ÉCHEC\n    {exc}\n    Vérifiez la clé et l'identifiant du modèle (OPENROUTER_MODEL).")
            return 1

    print("Analyse du projet de démonstration (remplissage du cache)...", flush=True)
    service = ScanService(settings, storage)
    scan = Scan(id=new_id(), project_name="Acme Shop (démo)", source="demo")
    storage.save_scan(scan)
    findings = service.run(scan, DEMO_PROJECT_DIR)
    s = scan.summary

    kinds = Counter(f.kind for f in findings if f.status == "open")
    print(f"\nTerminé en {s.duration_seconds} s — score {scan.score}/100")
    print(f"  Alertes ouvertes        : {s.total}  ({dict(kinds)})")
    print(f"  Faux positifs écartés   : {s.false_positives}")
    print(f"  Failles logiques (IA)   : {kinds.get('ai', 0)}")
    print(f"  Appels IA / cache / err : {s.ai_calls} / {s.ai_cache_hits} / {s.ai_errors}")
    print(f"  Jetons consommés        : {s.ai_tokens}")

    enriched = sum(1 for f in findings if f.ai)
    ready = s.ai_errors == 0 and enriched > 0
    if ready:
        print("\n[OK] Démo prête : la prochaine analyse d'Acme Shop sera servie depuis le cache.")
    else:
        print(f"\n[!] {s.ai_errors} alerte(s) sans réponse IA. Relancez la commande pour compléter le cache.")
    return 0 if ready else 1


if __name__ == "__main__":
    sys.exit(main())
