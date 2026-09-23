"""SS-17 — connexion GitHub / GitLab (OAuth) : dépôts privés, choix du dépôt et de la branche.

- Le jeton d'accès est chiffré (AES-256-GCM, clé SECUSCAN_TOKEN_KEY) et lié à l'organisation, à
  l'utilisateur et au fournisseur ; il n'est jamais renvoyé au navigateur.
- Le paramètre `state` du parcours OAuth est aléatoire, à usage unique, valable 10 minutes et lié
  à la session : il empêche qu'un tiers rattache son propre compte Git à la session d'une victime.
- Scopes : GitHub n'offre pas de lecture seule des dépôts privés aux applications OAuth (`repo`
  donne aussi l'écriture) ; SecuScan n'utilise que la lecture. GitLab : scopes en lecture seule.
"""
import base64
import json
import secrets
import time
from dataclasses import dataclass
from urllib.parse import quote, urlencode

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse

from .auth import token_hash
from .config import Settings
from .deps import Context, current_context, get_service
from .pipeline import ScanService
from .tokenbox import TokenKeyMissing, decrypt, encrypt

router = APIRouter(prefix="/api/git")
STATE_TTL_SECONDS = 600


@dataclass(frozen=True)
class Provider:
    id: str
    name: str
    scopes: str


PROVIDERS = {
    "github": Provider("github", "GitHub", "repo read:user"),
    "gitlab": Provider("gitlab", "GitLab", "read_repository read_api read_user"),
}


def _http() -> httpx.Client:
    """Client HTTP des appels aux fournisseurs (remplaçable dans les tests)."""
    return httpx.Client(timeout=20, headers={"User-Agent": "SecuScan"})


def _credentials(settings: Settings, provider: str) -> tuple[str, str]:
    if provider == "github":
        return settings.secuscan_github_client_id, settings.secuscan_github_client_secret
    return settings.secuscan_gitlab_client_id, settings.secuscan_gitlab_client_secret


def configured(settings: Settings, provider: str) -> bool:
    client_id, secret = _credentials(settings, provider)
    return bool(client_id and secret and settings.secuscan_token_key)


def _redirect_uri(settings: Settings, provider: str) -> str:
    return f"{settings.secuscan_public_url.rstrip('/')}/api/git/{provider}/callback"


def _gitlab(settings: Settings) -> str:
    return settings.secuscan_gitlab_url.rstrip("/")


def _aad(ctx_org: str, user: str, provider: str) -> str:
    return f"{ctx_org}:{user}:{provider}"


def provider_or_404(settings: Settings, provider: str) -> Provider:
    if provider not in PROVIDERS:
        raise HTTPException(404, "Fournisseur inconnu")
    if not configured(settings, provider):
        raise HTTPException(503, f"Connexion {PROVIDERS[provider].name} non configurée sur ce serveur.")
    return PROVIDERS[provider]


# ---------------------------------------------------------------------- jetons
def _store_tokens(service: ScanService, ctx: Context, provider: str, tokens: dict, login: str, scopes: str) -> None:
    settings = service.settings
    sealed = encrypt(json.dumps(tokens), settings.secuscan_token_key, _aad(ctx.org_id, ctx.user_id, provider))
    service.storage.save_git_connection(ctx.org_id, ctx.user_id, provider, login, sealed, scopes)


def _load_tokens(service: ScanService, ctx: Context, provider: str) -> dict:
    conn = service.storage.get_git_connection(ctx.org_id, ctx.user_id, provider)
    if not conn:
        raise HTTPException(409, f"Aucun compte {PROVIDERS[provider].name} connecté.")
    try:
        return json.loads(decrypt(conn["token_encrypted"], service.settings.secuscan_token_key,
                                  _aad(ctx.org_id, ctx.user_id, provider)))
    except (TokenKeyMissing, ValueError) as exc:
        raise HTTPException(409, f"Connexion {PROVIDERS[provider].name} à renouveler.") from exc


def _exchange_code(settings: Settings, provider: str, code: str) -> dict:
    client_id, secret = _credentials(settings, provider)
    with _http() as http:
        if provider == "github":
            resp = http.post("https://github.com/login/oauth/access_token", headers={"Accept": "application/json"},
                             data={"client_id": client_id, "client_secret": secret, "code": code,
                                   "redirect_uri": _redirect_uri(settings, provider)})
        else:
            resp = http.post(f"{_gitlab(settings)}/oauth/token", data={
                "client_id": client_id, "client_secret": secret, "code": code, "grant_type": "authorization_code",
                "redirect_uri": _redirect_uri(settings, provider)})
    data = resp.json() if resp.content else {}
    if resp.status_code >= 400 or "access_token" not in data:
        raise HTTPException(400, f"Autorisation refusée par {PROVIDERS[provider].name}.")
    return {k: data[k] for k in ("access_token", "refresh_token", "scope") if k in data}


def _refresh_gitlab(service: ScanService, ctx: Context, tokens: dict) -> dict:
    client_id, secret = _credentials(service.settings, "gitlab")
    with _http() as http:
        resp = http.post(f"{_gitlab(service.settings)}/oauth/token", data={
            "client_id": client_id, "client_secret": secret, "grant_type": "refresh_token",
            "refresh_token": tokens.get("refresh_token", ""), "redirect_uri": _redirect_uri(service.settings, "gitlab")})
    if resp.status_code >= 400:
        raise HTTPException(409, "Connexion GitLab expirée : reconnectez votre compte.")
    new_tokens = {**tokens, **{k: v for k, v in resp.json().items() if k in ("access_token", "refresh_token")}}
    conn = service.storage.get_git_connection(ctx.org_id, ctx.user_id, "gitlab")
    _store_tokens(service, ctx, "gitlab", new_tokens, conn["login"], conn["scopes"])
    return new_tokens


def _api_get(service: ScanService, ctx: Context, provider: str, path: str, params: dict | None = None):
    tokens = _load_tokens(service, ctx, provider)
    for attempt in range(2):
        if provider == "github":
            url, headers = f"https://api.github.com{path}", {
                "Authorization": f"Bearer {tokens['access_token']}", "Accept": "application/vnd.github+json"}
        else:
            url, headers = f"{_gitlab(service.settings)}/api/v4{path}", {
                "Authorization": f"Bearer {tokens['access_token']}"}
        with _http() as http:
            resp = http.get(url, headers=headers, params=params)
        if resp.status_code == 401 and provider == "gitlab" and attempt == 0 and tokens.get("refresh_token"):
            tokens = _refresh_gitlab(service, ctx, tokens)  # jetons GitLab à durée de vie courte
            continue
        if resp.status_code == 401:
            raise HTTPException(409, f"Connexion {PROVIDERS[provider].name} expirée ou révoquée : reconnectez votre compte.")
        if resp.status_code == 404:
            raise HTTPException(404, "Dépôt introuvable ou inaccessible avec ce compte.")
        if resp.status_code >= 400:
            raise HTTPException(502, f"{PROVIDERS[provider].name} a répondu {resp.status_code}.")
        return resp.json()
    raise HTTPException(409, "Connexion expirée : reconnectez votre compte.")


def clone_auth(service: ScanService, ctx: Context, provider: str, repo: str) -> tuple[str, str, str, str]:
    """Pour un dépôt du compte connecté : (URL de clonage, en-tête d'authentification, branche par défaut, nom)."""
    tokens = _load_tokens(service, ctx, provider)
    if provider == "github":
        info = _api_get(service, ctx, provider, f"/repos/{quote(repo, safe='/')}")
        clone_url = info["clone_url"]
        if not clone_url.startswith("https://github.com/"):
            raise HTTPException(400, "URL de clonage inattendue")
        user = "x-access-token"
    else:
        info = _api_get(service, ctx, provider, f"/projects/{quote(repo, safe='')}")
        clone_url = info["http_url_to_repo"]
        if not clone_url.startswith(_gitlab(service.settings) + "/"):
            raise HTTPException(400, "URL de clonage inattendue")
        tokens = _load_tokens(service, ctx, provider)  # éventuellement rafraîchi par l'appel précédent
        user = "oauth2"
    header = "Basic " + base64.b64encode(f"{user}:{tokens['access_token']}".encode()).decode()
    name = info.get("name") or repo.rsplit("/", 1)[-1]
    return clone_url, header, info.get("default_branch") or "", name


# ---------------------------------------------------------------------- routes
@router.get("/providers")
def providers(ctx: Context = Depends(current_context), service: ScanService = Depends(get_service)):
    out = []
    for p in PROVIDERS.values():
        conn = service.storage.get_git_connection(ctx.org_id, ctx.user_id, p.id)
        out.append({"id": p.id, "name": p.name, "configured": configured(service.settings, p.id),
                    "connected": bool(conn), "login": conn["login"] if conn else None})
    return out


@router.get("/{provider}/connect")
def connect(provider: str, ctx: Context = Depends(current_context), service: ScanService = Depends(get_service)):
    p = provider_or_404(service.settings, provider)
    state = secrets.token_urlsafe(24)
    service.storage.save_oauth_state(token_hash(state), ctx.org_id, ctx.user_id, provider, time.time() + STATE_TTL_SECONDS)
    client_id, _ = _credentials(service.settings, provider)
    params = {"client_id": client_id, "redirect_uri": _redirect_uri(service.settings, provider),
              "scope": p.scopes, "state": state}
    if provider == "github":
        url = "https://github.com/login/oauth/authorize?" + urlencode(params)
    else:
        url = f"{_gitlab(service.settings)}/oauth/authorize?" + urlencode({**params, "response_type": "code"})
    return {"authorize_url": url}


@router.get("/{provider}/callback")
def callback(provider: str, request: Request, ctx: Context = Depends(current_context),
             service: ScanService = Depends(get_service)):
    home = service.settings.secuscan_public_url.rstrip("/")
    p = provider_or_404(service.settings, provider)
    state = request.query_params.get("state", "")
    saved = service.storage.pop_oauth_state(token_hash(state)) if state else None
    if not saved or (saved["org_id"], saved["user_id"], saved["provider"]) != (ctx.org_id, ctx.user_id, provider):
        return RedirectResponse(f"{home}/?git=error&provider={provider}", status_code=303)
    if request.query_params.get("error") or not request.query_params.get("code"):
        return RedirectResponse(f"{home}/?git=denied&provider={provider}", status_code=303)
    tokens = _exchange_code(service.settings, provider, request.query_params["code"])
    _store_tokens(service, ctx, provider, tokens, "", tokens.get("scope", p.scopes))
    user = _api_get(service, ctx, provider, "/user")
    login = user.get("login") or user.get("username") or ""
    _store_tokens(service, ctx, provider, tokens, login, tokens.get("scope", p.scopes))
    service.storage.audit("git.connected", provider, {"provider": p.name, "login": login},
                          org_id=ctx.org_id, actor=ctx.email)
    return RedirectResponse(f"{home}/?git=connected&provider={provider}", status_code=303)


@router.delete("/{provider}")
def disconnect(provider: str, ctx: Context = Depends(current_context), service: ScanService = Depends(get_service)):
    if provider not in PROVIDERS:
        raise HTTPException(404, "Fournisseur inconnu")
    service.storage.delete_git_connection(ctx.org_id, ctx.user_id, provider)
    service.storage.audit("git.disconnected", provider, {"provider": PROVIDERS[provider].name},
                          org_id=ctx.org_id, actor=ctx.email)
    return {"ok": True}


@router.get("/{provider}/repos")
def repos(provider: str, ctx: Context = Depends(current_context), service: ScanService = Depends(get_service)):
    provider_or_404(service.settings, provider)
    if provider == "github":
        items = _api_get(service, ctx, provider, "/user/repos", {"per_page": 100, "sort": "updated"})
        return [{"id": r["full_name"], "name": r["full_name"], "private": r["private"],
                 "default_branch": r.get("default_branch")} for r in items]
    items = _api_get(service, ctx, provider, "/projects",
                     {"membership": "true", "simple": "true", "per_page": 100, "order_by": "last_activity_at"})
    return [{"id": str(r["id"]), "name": r["path_with_namespace"], "private": r.get("visibility") != "public",
             "default_branch": r.get("default_branch")} for r in items]


@router.get("/{provider}/branches")
def branches(provider: str, repo: str, ctx: Context = Depends(current_context), service: ScanService = Depends(get_service)):
    provider_or_404(service.settings, provider)
    if provider == "github":
        items = _api_get(service, ctx, provider, f"/repos/{quote(repo, safe='/')}/branches", {"per_page": 100})
    else:
        items = _api_get(service, ctx, provider, f"/projects/{quote(repo, safe='')}/repository/branches", {"per_page": 100})
    return [b["name"] for b in items]
