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
| `--pr-comment` | Commente la pull request (GitHub) ou la merge request (GitLab) : voir plus bas |
| `--no-history` | Ne pas chercher de secrets dans l'historique Git (activé par défaut si le dossier est un dépôt Git) |

## Secrets dans l'historique Git

Un secret supprimé du code reste lisible dans les anciens commits. Quand le dossier analysé est un
dépôt Git, SecuScan relit les lignes ajoutées par les 200 derniers commits (`SECUSCAN_HISTORY_COMMITS`)
et signale les secrets qui n'apparaissent plus dans la version actuelle. Seuls l'identifiant court du
commit et sa date sont conservés (ni auteur, ni message).

En CI, le dépôt est souvent récupéré sans historique : demandez-le explicitement.

```yaml
    - uses: actions/checkout@v4
      with:
        fetch-depth: 200   # 0 = tout l'historique
```

Clé `.secuscan.yml` équivalente à `--no-history` : `history: false`.

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

## Commentaires sur les pull requests et merge requests (SS-22)

Avec `--pr-comment`, SecuScan commente directement la revue de code :

- **un commentaire en ligne par alerte située sur une ligne ajoutée ou modifiée par la PR** (au
  plus 25), avec l'explication et le correctif proposé quand l'IA est activée (`--ai`) ;
- **un commentaire de synthèse** (score, alertes par sévérité, seuil de blocage), mis à jour à
  chaque exécution au lieu d'être dupliqué ;
- une alerte déjà commentée n'est pas commentée une seconde fois après un nouveau push.

Les alertes des lignes que la PR ne touche pas ne sont pas commentées en ligne : elles figurent dans
la synthèse. Un échec de publication (jeton manquant, droits insuffisants) est affiché mais ne
change pas le code retour de l'analyse. Analysez la racine du dépôt : les chemins des alertes
doivent correspondre à ceux de la PR.

### GitHub Actions

Le jeton fourni par GitHub suffit ; il faut seulement l'autoriser à écrire sur les pull requests.

```yaml
on: pull_request

jobs:
  secuscan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v6
      - run: uv sync
        working-directory: apps/api
      - name: Analyse SecuScan et commentaires de PR
        working-directory: apps/api
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          OPENROUTER_API_KEY: ${{ secrets.OPENROUTER_API_KEY }}   # facultatif, avec --ai
        run: uv run python -m secuscan.cli scan ../.. --pr-comment --ai
```

Pour une PR ouverte depuis un fork, GitHub ne donne qu'un jeton en lecture : les commentaires ne
sont alors pas publiés (l'analyse et son code retour restent valables).

### GitLab CI

Le jeton automatique du job (`CI_JOB_TOKEN`) ne peut pas commenter : créez un **jeton d'accès au
projet** (Paramètres → Jetons d'accès, rôle Developer, portée `api`) et déclarez-le comme variable
CI/CD masquée `SECUSCAN_GITLAB_TOKEN`.

```yaml
secuscan:
  image: ghcr.io/astral-sh/uv:python3.12-bookworm
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  script:
    - cd apps/api && uv sync
    - uv run python -m secuscan.cli scan ../.. --pr-comment
```
