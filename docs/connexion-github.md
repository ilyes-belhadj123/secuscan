# Connecter GitHub (dépôts privés) — SS-17

## 1. Créer l'application OAuth sur GitHub (5 minutes)

1. GitHub → photo de profil → **Settings** → **Developer settings** → **OAuth Apps** → **New OAuth App**.
2. Renseigner :
   - **Application name** : `SecuScan`
   - **Homepage URL** : `http://127.0.0.1:5173`
   - **Authorization callback URL** : `http://127.0.0.1:5173/api/git/github/callback`
3. **Register application**, puis **Generate a new client secret**.
4. Garder la page ouverte : il faut le **Client ID** et le **Client secret**.

> Une fois SecuScan hébergé, remplacez `http://127.0.0.1:5173` par l'adresse publique (HTTPS) dans
> l'application GitHub et dans `SECUSCAN_PUBLIC_URL`.

## 2. Renseigner les identifiants dans SecuScan

Double-cliquer sur `configure-secrets.ps1` (clic droit → Exécuter avec PowerShell), choisir **2**,
coller le Client ID puis le Client secret (saisie masquée). Le script génère aussi la clé qui chiffre
les jetons d'accès (`SECUSCAN_TOKEN_KEY`). **Ne collez jamais ces valeurs dans une conversation.**

Redémarrer ensuite l'API.

## 3. Utiliser

Accueil → carte « Analyser un dépôt Git » → **Connecter GitHub** → autoriser SecuScan sur GitHub →
choisir le dépôt (🔒 = privé) et la branche → **Analyser**.

## Sécurité

- Le jeton d'accès est chiffré (AES-256-GCM) et lié à l'organisation et à l'utilisateur ; il n'est
  jamais renvoyé au navigateur ni écrit dans les journaux. Il est transmis à `git clone` par variables
  d'environnement, jamais dans la ligne de commande.
- Chaque utilisateur connecte son propre compte : il ne voit que les dépôts auxquels il a accès.
- **Limite des applications OAuth GitHub** : l'accès aux dépôts privés passe par le scope `repo`, qui
  autorise aussi l'écriture. SecuScan ne fait que lire, mais pour une garantie « lecture seule » stricte,
  l'étape suivante est une **GitHub App** (permission `Contents: read`).
- Révocation : bouton « Déconnecter » dans SecuScan, ou GitHub → Settings → Applications.

GitLab : même principe (Applications → nouvelle application, scopes `read_repository read_api
read_user`, callback `http://127.0.0.1:5173/api/git/gitlab/callback`), choix **3** du script.
