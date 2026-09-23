# SecuScan — analyse de sécurité du code assistée par IA (version démo)

Détecte les failles (Python, JavaScript/TypeScript, PHP, Java), les secrets commités et les
dépendances vulnérables, puis l'IA (Claude via OpenRouter) écarte les faux positifs, explique
chaque faille en français et propose un correctif sous forme de diff.

📊 **Suivi des tickets : [docs/AVANCEMENT.md](docs/AVANCEMENT.md)**

## Lancer la démo

Prérequis : Python 3.12 + [uv](https://docs.astral.sh/uv/), Node.js 20+. Pas besoin de Docker.

```powershell
copy .env.example .env      # puis renseigner OPENROUTER_API_KEY dans .env
powershell -ExecutionPolicy Bypass -File start-demo.ps1
```

L'interface s'ouvre sur http://127.0.0.1:5173 (API sur le port 8000).

Lancement manuel :

```powershell
cd apps/api; uv sync; uv run python -m uvicorn secuscan.main:app --port 8000
cd apps/web; npm install; npm run dev
```

## Mode « live + cache » : préparer la démo

Chaque réponse de l'IA et de la base de vulnérabilités OSV est mise en cache dans
`apps/api/data/secuscan.db`. **La veille de la démo**, avec la clé et le réseau :

```powershell
cd apps/api; uv run python -m secuscan.prepare_demo
```

La commande teste la connexion à l'IA (clé + identifiant du modèle), analyse Acme Shop pour
remplir le cache et affiche un bilan (`[OK] Démo prête`). Le jour J, la même analyse est
instantanée et fonctionne même si le réseau ou l'API tombe. Le code collé ou le dépôt Git
analysé en direct passent, eux, par l'IA en temps réel.

Sans clé et sans cache, l'outil reste utilisable : les alertes s'affichent avec l'explication
et le correctif génériques de la règle.

## Déroulé de démo conseillé (≈ 10 min)

1. **Accueil** : « Analyser Acme Shop » (boutique fictive, 4 langages). La progression
   s'affiche étape par étape.
2. **Tableau de bord** : score, répartition par sévérité (cliquer une barre filtre la liste),
   catégories OWASP Top 10 2025, secrets, dépendances vulnérables (dont Log4Shell).
3. **Faux positif écarté** : filtre « Écartées par l'IA ». La requête `SELECT COUNT(*)`
   construite avec une constante (`app.py:42`) est signalée par les règles, mais l'IA
   explique pourquoi elle n'est pas exploitable.
4. **Injection SQL** (`app.py:30`) : onglets Comprendre → Corriger (diff, « Copier le code
   corrigé »). Flèches ← → pour passer d'une faille à l'autre.
5. **Faille logique trouvée par l'IA seule** : filtre « Logique (IA) ». Accès à la facture
   d'un autre client (IDOR, `app.py` → `get_invoice`) et prix fourni par le client au
   paiement (`server.js` → `/api/checkout`) : aucune règle par motif ne peut les voir.
6. **Secret exposé** : la valeur n'est jamais affichée, stockée ni envoyée à l'IA.
7. **Ignorer une alerte** avec justification : elle reste masquée aux analyses suivantes.
8. **Analyse en direct** : coller du code du client, ou l'URL d'un dépôt Git public
   (ex. `https://github.com/OWASP/NodeGoat`).
9. **Rapport PDF** à transmettre, et export JSON (schéma : `/api/schemas/report-v1.json`).

## Architecture

| Élément | Emplacement |
|---|---|
| API FastAPI, pipeline d'analyse | `apps/api/secuscan/` |
| Règles statiques (couche 1) | `apps/api/secuscan/analyzers/rules.py` |
| Secrets (couche 2) | `apps/api/secuscan/analyzers/secrets.py` |
| Dépendances / OSV.dev (couche 3) | `apps/api/secuscan/analyzers/sca.py` |
| IA : prompts, filtre de sortie, cache | `apps/api/secuscan/ai/` |
| Score et sévérité (règles documentées) | `apps/api/secuscan/scoring.py` |
| Interface React + Vite | `apps/web/src/` |
| Projet vulnérable de démonstration | `demo/acme-shop/` |

Documents de cadrage (cahier des charges, backlog, tickets) : `docs/`.

Simplifications propres à la démo, à reprendre ensuite (voir `docs/03_tickets_securite_code.md`) :
SQLite au lieu de MongoDB, tâches en thread au lieu d'ARQ/Redis, pas de sandbox Docker
(SS-4 ; le code analysé n'est jamais exécuté), pas d'authentification ni de multi-tenant
(SS-2), dépôts Git publics uniquement, sans OAuth GitHub (SS-17), moteur de règles maison au lieu d'un moteur SAST open
source (SS-5 : l'adaptateur est prévu dans `analyzers/sast.py`).

## Tests

```powershell
cd apps/api; uv run python -m pytest -q; uv run ruff check .
cd apps/web; npm run build
```
