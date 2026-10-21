# Mettre SecuScan en ligne

SecuScan s'héberge comme **un seul service** : l'API sert aussi l'interface compilée. Le plus
simple est un petit serveur Linux (VPS, 2 vCPU / 4 Go de RAM suffisent pour la bêta) avec Docker,
et [Caddy](https://caddyserver.com) devant pour le HTTPS automatique.

```
Internet ──HTTPS──▶ Caddy ──▶ API SecuScan ──(file d'analyses en base)──▶ worker(s)
                                                                           │ dépose le code à lire
                                                                           ▼
                                                 conteneur « sandbox » : sans réseau, sans secret
```

| Service | Rôle | Accès |
|---|---|---|
| `secuscan` | API et interface | base, réseau (via Caddy) |
| `worker` | Exécute les analyses en file (clonage, dépendances OSV, IA) ; `--scale worker=3` pour en paralléliser | base, réseau, secrets |
| `sandbox` | Lit le code importé (secrets, règles, Bandit, manifestes) | **aucun réseau, aucun secret**, dossier des analyses uniquement, lecture seule, sans privilèges |
| `caddy` | HTTPS automatique | ports 80 / 443 |

## 1. Prérequis

- Un nom de domaine (ex. `secuscan.example.com`) dont l'enregistrement DNS `A` pointe vers le serveur.
- Ports 80 et 443 ouverts ; Docker et Docker Compose (v2.24 ou plus) installés sur le serveur.

## 2. Secrets

Sur le serveur, à côté de `docker-compose.yml`, créez `secuscan.env` (exclu de Git et de l'image
Docker) avec au minimum :

| Variable | Rôle |
|---|---|
| `SECUSCAN_TOKEN_KEY` | Clé AES-256 en base64 qui chiffre les jetons GitHub / GitLab (`python -c "import base64, os; print(base64.b64encode(os.urandom(32)).decode())"`) |
| `SECUSCAN_SMTP_HOST`, `SECUSCAN_SMTP_PORT`, `SECUSCAN_SMTP_USER`, `SECUSCAN_SMTP_PASSWORD`, `SECUSCAN_SMTP_FROM` | Envoi des invitations et des liens de mot de passe oublié |
| `SECUSCAN_OPERATOR_EMAILS` | **Obligatoire.** Opérateurs de la plateforme, seuls autorisés à régler la clé IA (écran « Paramètres ») et à voir le tableau de bord bêta ; format JSON : `["jane.doe@example.com"]`. Le premier inscrit ne devient pas administrateur de l'installation |
| `SECUSCAN_AI_MONTHLY_TOKENS_TOTAL` | Recommandé : plafond mensuel de jetons IA pour toute l'installation (ex. `100000000`), qui protège le crédit OpenRouter. Chaque organisation a en plus son plafond mensuel selon son offre (Free 0,6 M, Pro 15 M, Business 60 M) |
| `SECUSCAN_BILLING_DEMO` | `true` seulement pour une démonstration : changement d'offre sans paiement. Sinon, sans Stripe configuré, seul un opérateur peut changer l'offre d'une organisation |
| `SECUSCAN_GITHUB_CLIENT_ID`, `SECUSCAN_GITHUB_CLIENT_SECRET` | Facultatif : dépôts privés GitHub ([guide](connexion-github.md)), adresse de retour `https://DOMAINE/api/git/github/callback` |

**Clé OpenRouter et modèle** : renseignez-les depuis l'écran **Paramètres** une fois connecté. Ils
sont enregistrés sur le volume de données (`/data/secuscan.env`) et survivent aux redémarrages.
Si vous les mettez plutôt dans `secuscan.env` (`OPENROUTER_API_KEY`, `OPENROUTER_MODEL`), ces
valeurs reprennent le dessus à chaque redémarrage : choisissez l'un ou l'autre.

Sont déjà réglés par l'image : `SECUSCAN_PRODUCTION=true`, `SECUSCAN_COOKIE_SECURE=true`,
`SECUSCAN_DATA_DIR=/data`. `SECUSCAN_PUBLIC_URL` est déduite de `SECUSCAN_DOMAIN`.

## 3. Lancement

```bash
git clone https://github.com/ilyes-belhadj123/secuscan.git && cd secuscan
SECUSCAN_DOMAIN=secuscan.example.com docker compose up -d --build
docker compose logs -f secuscan
```

Au démarrage, SecuScan **refuse de démarrer** si la configuration n'est pas sûre (adresse publique
en `http://`, cookie de session non sécurisé, jetons Git sans clé de chiffrement, interface non
compilée) et affiche la liste des problèmes dans les journaux.

**Premier compte** : la première organisation créée est celle du propriétaire de l'installation
(offre Business, accès à l'écran « Paramètres »). Créez-la vous-même avant d'ouvrir l'accès.

### Option : un conteneur jetable par analyse

Par défaut, un seul conteneur `sandbox` lit le code de toutes les analyses. Pour une isolation
maximale, chaque analyse peut avoir **son propre conteneur**, créé par le worker puis détruit :
sans réseau, en lecture seule, sans privilèges, et qui ne voit **que le dossier de cette analyse**
(une analyse ne peut ni lire ni modifier le code d'une autre).

```bash
DOCKER_GID=$(stat -c %g /var/run/docker.sock) SECUSCAN_DOMAIN=secuscan.example.com   docker compose -f docker-compose.yml -f docker-compose.ephemeral.yml up -d --build
```

Prérequis : Docker Engine 26 ou plus. Contrepartie : le worker accède au moteur Docker (socket
`/var/run/docker.sock`), ce qui revient à des droits élevés sur le serveur s'il était compromis. Le
worker détient déjà les secrets et le réseau ; préférez [Docker sans root](https://docs.docker.com/engine/security/rootless/)
sur le serveur pour limiter ce risque. Worker lancé directement sur le serveur (hors conteneur) :
`SECUSCAN_SANDBOX=ephemeral` suffit, le dossier de l'analyse est monté directement.

## 4. Ce que la mise en ligne protège

- HTTPS de bout en bout côté navigateur, certificat renouvelé automatiquement par Caddy ;
- en-têtes `Strict-Transport-Security`, `Content-Security-Policy` (scripts du site uniquement),
  `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff` ;
- cookie de session `HttpOnly`, `Secure`, `SameSite=Lax`, et contrôle de l'origine des requêtes
  qui modifient des données (CSRF) ;
- adresse IP réelle des clients transmise par Caddy (limitation des tentatives de connexion) ;
- application exécutée par un utilisateur sans privilèges ; le code analysé n'est jamais exécuté,
  et il est supprimé après chaque analyse.

## 5. Sauvegardes et mises à jour

Tout l'état (comptes, analyses, file d'attente, cache IA, logos, réglages) est dans le volume `secuscan-data` ; `secuscan-work` ne contient que le code en cours d'analyse.

```bash
# Sauvegarde à chaud de la base SQLite (cohérente même pendant une analyse)
docker compose exec secuscan python -c "import sqlite3; s=sqlite3.connect('/data/secuscan.db'); d=sqlite3.connect('/data/backup.db'); s.backup(d)"
docker compose cp secuscan:/data/backup.db ./secuscan-$(date +%F).db

# Mise à jour
git pull && docker compose up -d --build
```

## 6. Limites connues

- La file d'analyses est stockée dans la base SQLite (pas de Redis à héberger) : adaptée à quelques
  workers sur un même serveur. Pour plusieurs serveurs, passer à une base serveur et à une file
  dédiée (ARQ + Redis), sans changer l'interface `ScanService.submit`.
- Le conteneur `sandbox` lit le code importé, mais le **clonage Git** se fait dans le worker (il a
  besoin du réseau). Git y est lancé sans hooks, sous-modules, LFS ni invite d'identifiants.
- La CI (job « docker », script `deploy/ci-smoke.sh`) construit l'image à chaque push, démarre l'API et
  le conteneur d'analyse, puis vérifie son isolation réelle (aucun réseau, système de fichiers en lecture
  seule, utilisateur non root) et analyse la démo. Le HTTPS (Caddy) et le mode « un conteneur par
  analyse » restent à valider sur le serveur, lors de la première mise en ligne.
