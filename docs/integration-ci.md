# Intégrer SecuScan dans la CI (SS-23)

La commande `secuscan` analyse un dossier et **fait échouer le pipeline** dès qu'une alerte atteint
le seuil de sévérité choisi.

```bash
cd apps/api
uv run python -m secuscan.cli scan CHEMIN [--fail-on high] [--format text|json|sarif] [--output FICHIER]
```

| Option | Rôle |
|---|---|
| `--fail-on critical\|high\|medium\|low\|none` | Sévérité minimale qui fait échouer la commande (défaut : `high`) |
| `--format text\|json\|sarif` | `text` pour les journaux, `json` (schéma du rapport SecuScan), `sarif` (standard) |
| `--output FICHIER` | Écrit le rapport dans un fichier au lieu de la sortie standard |
| `--exclude MOTIF` | Exclut des fichiers (répétable), ex. `--exclude tests/ --exclude "*.min.js"` |
| `--ai` | Active l'IA (validation des faux positifs, explications, correctifs) : nécessite `OPENROUTER_API_KEY` et consomme des crédits |
| `--offline` | Aucun appel réseau : les dépendances ne sont vérifiées que si elles sont déjà en cache |

## Codes retour

| Code | Signification |
|---|---|
| `0` | Aucune alerte au niveau du seuil ou au-dessus |
| `1` | Seuil dépassé : au moins une alerte au niveau du seuil ou au-dessus |
| `2` | Erreur d'utilisation ou de configuration (dossier absent, `.secuscan.yml` invalide) |
| `3` | Erreur pendant l'analyse |

## Fichier `.secuscan.yml`

Placé à la racine du dossier analysé (ou désigné avec `--config`). Les options de la ligne de
commande priment sur le fichier ; une clé inconnue est une erreur (code 2).

```yaml
fail_on: high            # critical | high | medium | low | none
exclude:                 # motifs de chemins à ne pas analyser
  - tests/
  - "*.min.js"
ignore_rules:            # règles désactivées pour ce projet (à justifier en revue de code)
  - JS-RANDOM
ai: false                # true : enrichissement IA (clé OpenRouter requise, coût par analyse)
offline: false
```

## Ignorer une alerte dans le code

Pour une alerte examinée et jugée sans risque, ajoutez un commentaire **sur la ligne signalée ou
celle du dessus**, avec la règle et la justification :

```python
# secuscan: ignore[PY-SQLI] nom de table issu d'une constante, jamais d'une saisie utilisateur
cursor.execute(f"SELECT COUNT(*) FROM {TABLE}")
```

L'alerte n'est pas supprimée : elle passe au statut « ignorée » avec sa justification, visible dans
les rapports JSON et PDF. Sans `[REGLE]`, toutes les alertes de la ligne sont concernées : préférez
toujours nommer la règle.

## GitHub Actions

```yaml
security:
  runs-on: ubuntu-latest
  permissions:
    contents: read
    security-events: write   # uniquement pour l'envoi SARIF vers l'onglet « Security »
  steps:
    - uses: actions/checkout@v4
    - uses: astral-sh/setup-uv@v6
    - run: uv sync
      working-directory: apps/api
    - name: Analyse SecuScan
      working-directory: apps/api
      run: uv run python -m secuscan.cli scan ../.. --format sarif --output ../../secuscan.sarif
    - name: Alertes dans l'onglet Security de GitHub
      if: always()
      uses: github/codeql-action/upload-sarif@v3
      with:
        sarif_file: secuscan.sarif
```

L'envoi SARIF vers l'onglet « Security » est gratuit pour les dépôts publics ; pour un dépôt privé,
il nécessite GitHub Advanced Security. À défaut, conservez le rapport comme artefact
(`actions/upload-artifact`), comme le fait le job `self-scan` de ce dépôt.

Pour activer l'IA en CI, déclarez la clé comme secret du dépôt (jamais en clair dans le fichier) :

```yaml
      env:
        OPENROUTER_API_KEY: ${{ secrets.OPENROUTER_API_KEY }}
      run: uv run python -m secuscan.cli scan ../.. --ai
```

## GitLab CI

```yaml
secuscan:
  image: ghcr.io/astral-sh/uv:python3.12-bookworm
  script:
    - cd apps/api && uv sync
    - uv run python -m secuscan.cli scan ../.. --format sarif --output ../../secuscan.sarif
  artifacts:
    when: always
    paths: [secuscan.sarif]
```
