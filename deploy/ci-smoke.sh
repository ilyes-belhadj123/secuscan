#!/usr/bin/env sh
# Test de fumée de la mise en ligne (job « docker » de la CI) : la pile docker-compose démarre, l'API
# répond, et le conteneur d'analyse est réellement isolé (sans réseau, lecture seule, sans root).
set -eu

export SECUSCAN_DOMAIN=ci.example.com
compose() { docker compose -f docker-compose.yml "$@"; }

# Variables obligatoires en production (valeurs factices de CI)
printf 'SECUSCAN_OPERATOR_EMAILS=["ops@example.com"]\n' > secuscan.env

compose up -d --build secuscan sandbox
trap 'compose logs --no-color secuscan sandbox | tail -n 80; compose down -v' EXIT

echo "== Santé de l'API"
ok=""
for _ in $(seq 1 40); do
  if compose exec -T secuscan python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=3)"; then
    ok=1; break
  fi
  sleep 3
done
[ -n "$ok" ] || { echo "L'API ne répond pas"; exit 1; }

echo "== Isolation du conteneur d'analyse"
compose exec -T sandbox python - <<'EOF'
import os
import socket

assert os.getuid() != 0, "le conteneur tourne en root"
try:
    socket.create_connection(("1.1.1.1", 53), timeout=3)
    raise SystemExit("le conteneur d'analyse a accès au réseau")
except OSError:
    pass
for path in ("/app/x", "/etc/x", "/x"):
    try:
        open(path, "w").close()
        raise SystemExit(f"écriture possible hors des dossiers prévus : {path}")
    except OSError:
        pass
print("isolation OK : pas de réseau, système de fichiers en lecture seule, utilisateur", os.getuid())
EOF

echo "== Analyse de la démo dans le conteneur isolé"
compose exec -T sandbox python -m secuscan.sandbox run --allow /app/demo --request \
  '{"root": "/app/demo/acme-shop", "scan_id": "ci", "exclude": [], "history": null, "settings": {}}' \
  | python3 -c "import json, sys; n = len(json.load(sys.stdin)['findings']); print(n, 'alertes'); sys.exit(0 if n > 10 else 1)"
