"""Dépendances FastAPI partagées : service, utilisateur connecté, organisation courante (SS-2)."""
from dataclasses import dataclass

from fastapi import Depends, HTTPException, Request

from .auth import token_hash
from .config import get_settings
from .pipeline import ScanService
from .storage import Storage

SESSION_COOKIE = "secuscan_session"
ROLES = ("owner", "admin", "member")
ROLE_LABELS = {"owner": "Propriétaire", "admin": "Administrateur", "member": "Membre"}

_service: ScanService | None = None


def get_service() -> ScanService:
    global _service
    if _service is None:
        settings = get_settings()
        _service = ScanService(settings, Storage(settings.data_dir / "secuscan.db"))
    return _service


def set_service(service: ScanService | None) -> None:
    """Remplace le service (tests)."""
    global _service
    _service = service


@dataclass
class Context:
    """Utilisateur connecté et organisation courante : toute requête métier est filtrée par `org_id`."""
    user_id: str
    email: str
    name: str
    org_id: str
    org_name: str
    role: str
    session: str  # empreinte du jeton de session

    @property
    def is_admin(self) -> bool:
        return self.role in ("owner", "admin")


def current_context(request: Request, service: ScanService = Depends(get_service)) -> Context:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        raise HTTPException(401, "Connexion requise")
    session_hash = token_hash(token)
    storage = service.storage
    session = storage.get_session(session_hash)
    if not session:
        raise HTTPException(401, "Session expirée, reconnectez-vous")
    role = storage.get_role(session["org_id"], session["user_id"])
    user = storage.get_user(session["user_id"])
    org = storage.get_org(session["org_id"])
    if not (role and user and org):
        # Membre retiré de l'organisation, ou organisation supprimée : la session n'est plus valable
        storage.delete_session(session_hash)
        raise HTTPException(401, "Accès à cette organisation révoqué")
    return Context(user["id"], user["email"], user["name"], org["id"], org["name"], role, session_hash)


def require_admin(ctx: Context = Depends(current_context)) -> Context:
    if not ctx.is_admin:
        raise HTTPException(403, "Action réservée aux administrateurs de l'organisation")
    return ctx


def is_installation_admin(service: ScanService, ctx: Context) -> bool:
    """Opérateur de la plateforme ; hors production, aussi l'administrateur de la première organisation.

    Les réglages d'installation (clé IA payée pour toutes les organisations) leur sont réservés. En
    production, seuls les opérateurs déclarés : le premier visiteur d'une installation neuve ne doit pas
    pouvoir s'en emparer.
    """
    if service.settings.is_operator(ctx.email):
        return True
    if service.settings.secuscan_production:
        return False
    return ctx.is_admin and ctx.org_id == service.storage.installation_org_id()


def require_installation_admin(ctx: Context = Depends(current_context),
                               service: ScanService = Depends(get_service)) -> Context:
    if not is_installation_admin(service, ctx):
        raise HTTPException(403, "Réglage réservé aux administrateurs de l'installation")
    return ctx
