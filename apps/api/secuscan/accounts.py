"""SS-2 — comptes, organisations, membres et invitations."""
import time

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, Response
from pydantic import BaseModel, EmailStr, Field

from .auth import (
    INVITATION_TTL_SECONDS,
    PASSWORD_RESET_TTL_SECONDS,
    SESSION_TTL_SECONDS,
    LoginRateLimiter,
    hash_password,
    new_token,
    password_problem,
    token_hash,
    verify_or_dummy,
)
from .billing import check_member_quota
from .deps import ROLE_LABELS, SESSION_COOKIE, Context, current_context, get_service, require_admin
from .mailer import send_email
from .pipeline import ScanService
from .plans import QuotaExceeded, get_plan

router = APIRouter(prefix="/api")
login_limiter = LoginRateLimiter()
reset_limiter = LoginRateLimiter(max_attempts=3, window_seconds=3600)

RESET_ACK = ("Si un compte existe pour cette adresse, un e-mail contenant un lien de réinitialisation "
             "(valable 1 heure) vient d'être envoyé.")


class RegisterRequest(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    email: EmailStr
    password: str = Field(max_length=200)
    org_name: str | None = Field(default=None, max_length=120)
    invitation_token: str | None = Field(default=None, max_length=200)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(max_length=200)


class ResetRequest(BaseModel):
    email: EmailStr


class NewPasswordRequest(BaseModel):
    password: str = Field(max_length=200)


class SwitchOrgRequest(BaseModel):
    org_id: str = Field(max_length=64)


class InvitationRequest(BaseModel):
    email: EmailStr
    role: str = Field(pattern="^(admin|member)$")


class RoleRequest(BaseModel):
    role: str = Field(pattern="^(owner|admin|member)$")


def _open_session(response: Response, service: ScanService, user_id: str, org_id: str) -> None:
    token = new_token()
    service.storage.create_session(token_hash(token), user_id, org_id, time.time() + SESSION_TTL_SECONDS)
    response.set_cookie(
        SESSION_COOKIE, token, max_age=SESSION_TTL_SECONDS, httponly=True, samesite="lax",
        secure=service.settings.secuscan_cookie_secure, path="/",
    )


def _valid_invitation(service: ScanService, token: str) -> dict:
    inv = service.storage.get_invitation(token_hash(token))
    if not inv or inv["accepted_at"] or inv["expires_at"] < time.time():
        raise HTTPException(404, "Invitation invalide ou expirée")
    return inv


def _me(service: ScanService, ctx: Context) -> dict:
    org = service.storage.get_org(ctx.org_id)
    plan = get_plan(org["plan"] if org else None)
    return {
        "user": {"id": ctx.user_id, "email": ctx.email, "name": ctx.name},
        "org": {"id": ctx.org_id, "name": ctx.org_name, "role": ctx.role, "role_label": ROLE_LABELS[ctx.role],
                "plan": plan.id, "plan_name": plan.name, "features": sorted(plan.features)},
        "organizations": service.storage.memberships_of(ctx.user_id),
    }


# ---------------------------------------------------------------------- authentification
@router.post("/auth/register", status_code=201)
def register(body: RegisterRequest, response: Response, service: ScanService = Depends(get_service)):
    storage = service.storage
    email = body.email.lower()
    if problem := password_problem(body.password):
        raise HTTPException(400, problem)
    if storage.get_user_by_email(email):
        raise HTTPException(409, "Un compte existe déjà avec cette adresse e-mail.")

    invitation = _valid_invitation(service, body.invitation_token) if body.invitation_token else None
    if invitation and invitation["email"] != email:
        raise HTTPException(403, "Cette invitation est destinée à une autre adresse e-mail.")
    if not invitation and not (body.org_name or "").strip():
        raise HTTPException(400, "Le nom de l'organisation est obligatoire.")

    user = storage.create_user(email, body.name.strip(), hash_password(body.password))
    if invitation:
        org_id, role = invitation["org_id"], invitation["role"]
        storage.accept_invitation(invitation["id"])
    else:
        first_org = storage.count_orgs() == 0
        plan = service.settings.secuscan_first_org_plan if first_org else "free"
        org_id, role = storage.create_org(body.org_name.strip(), plan=plan)["id"], "owner"
        if first_org:
            storage.claim_orphan_data(org_id)  # analyses faites avant l'arrivée des comptes
    storage.add_membership(org_id, user["id"], role)
    via = "invitation" if invitation else "création"
    storage.audit("member.joined", user["id"], {"email": email, "role": role, "via": via}, org_id=org_id, actor=email)
    _open_session(response, service, user["id"], org_id)
    return {"ok": True}


@router.post("/auth/login")
def login(body: LoginRequest, request: Request, response: Response, service: ScanService = Depends(get_service)):
    email = body.email.lower()
    ip = request.client.host if request.client else "?"
    keys = (f"email:{email}", f"ip:{ip}")
    if login_limiter.blocked(*keys):
        raise HTTPException(429, "Trop de tentatives de connexion. Réessayez dans quelques minutes.")
    user = service.storage.get_user_by_email(email)
    if not verify_or_dummy(body.password, user["password_hash"] if user else None):
        login_limiter.fail(*keys)
        raise HTTPException(401, "Adresse e-mail ou mot de passe incorrect.")
    memberships = service.storage.memberships_of(user["id"])
    if not memberships:
        raise HTTPException(403, "Ce compte n'appartient plus à aucune organisation.")
    login_limiter.reset(*keys)
    _open_session(response, service, user["id"], memberships[0]["org_id"])
    return {"ok": True}


@router.post("/auth/logout")
def logout(request: Request, response: Response, service: ScanService = Depends(get_service)):
    if token := request.cookies.get(SESSION_COOKIE):
        service.storage.delete_session(token_hash(token))
    response.delete_cookie(SESSION_COOKIE, path="/")
    return {"ok": True}


@router.post("/auth/password-reset")
def request_password_reset(body: ResetRequest, request: Request, tasks: BackgroundTasks,
                           service: ScanService = Depends(get_service)):
    """Toujours la même réponse, que le compte existe ou non (pas d'énumération des comptes).

    L'e-mail part après la réponse : le temps de réponse ne révèle pas si le compte existe.
    """
    email = body.email.lower()
    ip = request.client.host if request.client else "?"
    keys = (f"reset:{email}", f"reset-ip:{ip}")
    if reset_limiter.blocked(*keys):
        raise HTTPException(429, "Trop de demandes. Réessayez dans une heure.")
    reset_limiter.fail(*keys)  # chaque demande compte, qu'elle aboutisse ou non
    user = service.storage.get_user_by_email(email)
    if user:
        token = new_token()
        service.storage.create_password_reset(token_hash(token), user["id"], time.time() + PASSWORD_RESET_TTL_SECONDS)
        link = f"{service.settings.secuscan_public_url.rstrip('/')}/reinitialisation/{token}"
        tasks.add_task(send_email, service.settings, email, "SecuScan — réinitialisation de votre mot de passe", (
            f"Bonjour {user['name']},\n\n"
            "Une réinitialisation du mot de passe de votre compte SecuScan a été demandée.\n"
            f"Pour choisir un nouveau mot de passe, ouvrez ce lien (valable 1 heure, à usage unique) :\n\n{link}\n\n"
            "Si vous n'êtes pas à l'origine de cette demande, ignorez cet e-mail : votre mot de passe reste inchangé.\n"
        ))
    return {"detail": RESET_ACK}


@router.post("/auth/password-reset/{token}")
def reset_password(token: str, body: NewPasswordRequest, service: ScanService = Depends(get_service)):
    storage = service.storage
    reset = storage.get_password_reset(token_hash(token))
    if not reset or reset["used_at"] or reset["expires_at"] < time.time():
        raise HTTPException(404, "Lien de réinitialisation invalide ou expiré. Refaites une demande.")
    if problem := password_problem(body.password):
        raise HTTPException(400, problem)
    storage.set_user_password(reset["user_id"], hash_password(body.password))
    storage.use_password_reset(token_hash(token))
    storage.delete_user_sessions(reset["user_id"])  # toutes les sessions ouvertes sont fermées
    user = storage.get_user(reset["user_id"])
    for membership in storage.memberships_of(reset["user_id"]):
        storage.audit("member.password_reset", reset["user_id"], {"email": user["email"]},
                      org_id=membership["org_id"], actor=user["email"])
    return {"ok": True}


@router.get("/auth/me")
def me(ctx: Context = Depends(current_context), service: ScanService = Depends(get_service)):
    return _me(service, ctx)


@router.post("/auth/switch-org")
def switch_org(body: SwitchOrgRequest, ctx: Context = Depends(current_context), service: ScanService = Depends(get_service)):
    if not service.storage.get_role(body.org_id, ctx.user_id):
        raise HTTPException(403, "Vous n'êtes pas membre de cette organisation.")
    service.storage.set_session_org(ctx.session, body.org_id)
    return {"ok": True}


# ---------------------------------------------------------------------- organisation
@router.get("/org")
def organization(ctx: Context = Depends(current_context), service: ScanService = Depends(get_service)):
    storage = service.storage
    return {
        "id": ctx.org_id, "name": ctx.org_name, "role": ctx.role,
        "members": storage.list_members(ctx.org_id),
        "invitations": storage.list_invitations(ctx.org_id) if ctx.is_admin else [],
    }


@router.post("/org/invitations", status_code=201)
def invite(body: InvitationRequest, ctx: Context = Depends(require_admin), service: ScanService = Depends(get_service)):
    storage = service.storage
    email = body.email.lower()
    if any(m["email"] == email for m in storage.list_members(ctx.org_id)):
        raise HTTPException(409, "Cette personne est déjà membre de l'organisation.")
    try:
        check_member_quota(storage, ctx.org_id)
    except QuotaExceeded as exc:
        raise HTTPException(402, str(exc)) from exc
    token = new_token()
    inv = storage.create_invitation(ctx.org_id, email, body.role, token_hash(token),
                                    time.time() + INVITATION_TTL_SECONDS, ctx.user_id)
    storage.audit("member.invited", inv["id"], {"email": email, "role": body.role}, org_id=ctx.org_id, actor=ctx.email)
    url = f"{service.settings.secuscan_public_url.rstrip('/')}/invitation/{token}"
    delivery = send_email(service.settings, email, f"{ctx.name} vous invite à rejoindre {ctx.org_name} sur SecuScan", (
        f"Bonjour,\n\n{ctx.name} ({ctx.email}) vous invite à rejoindre l'organisation « {ctx.org_name} » sur SecuScan, "
        f"en tant que {ROLE_LABELS[body.role].lower()}.\n\n"
        f"Pour accepter l'invitation (lien valable 7 jours, à usage unique) :\n\n{url}\n"
    ))
    # Le lien n'est renvoyé qu'une fois : seule son empreinte est conservée en base
    return {**inv, "url": url, "email_sent": delivery.sent, "email_detail": delivery.detail}


@router.delete("/org/invitations/{invitation_id}")
def revoke(invitation_id: str, ctx: Context = Depends(require_admin), service: ScanService = Depends(get_service)):
    if not service.storage.revoke_invitation(invitation_id, ctx.org_id):
        raise HTTPException(404, "Invitation introuvable")
    service.storage.audit("member.invitation_revoked", invitation_id, {}, org_id=ctx.org_id, actor=ctx.email)
    return {"ok": True}


@router.patch("/org/members/{user_id}")
def change_role(user_id: str, body: RoleRequest, ctx: Context = Depends(require_admin),
                service: ScanService = Depends(get_service)):
    storage = service.storage
    current = storage.get_role(ctx.org_id, user_id)
    if not current:
        raise HTTPException(404, "Membre introuvable")
    if "owner" in (current, body.role) and ctx.role != "owner":
        raise HTTPException(403, "Seul un propriétaire peut attribuer ou retirer le rôle de propriétaire.")
    if current == "owner" and body.role != "owner" and storage.count_owners(ctx.org_id) <= 1:
        raise HTTPException(409, "L'organisation doit conserver au moins un propriétaire.")
    storage.add_membership(ctx.org_id, user_id, body.role)
    storage.audit("member.role_changed", user_id, {"from": current, "to": body.role}, org_id=ctx.org_id, actor=ctx.email)
    return {"ok": True}


@router.delete("/org/members/{user_id}")
def remove_member(user_id: str, ctx: Context = Depends(current_context), service: ScanService = Depends(get_service)):
    storage = service.storage
    leaving_self = user_id == ctx.user_id
    if not (leaving_self or ctx.is_admin):
        raise HTTPException(403, "Action réservée aux administrateurs de l'organisation")
    current = storage.get_role(ctx.org_id, user_id)
    if not current:
        raise HTTPException(404, "Membre introuvable")
    if current == "owner" and ctx.role != "owner":
        raise HTTPException(403, "Seul un propriétaire peut retirer un propriétaire.")
    if current == "owner" and storage.count_owners(ctx.org_id) <= 1:
        raise HTTPException(409, "L'organisation doit conserver au moins un propriétaire.")
    storage.remove_membership(ctx.org_id, user_id)
    storage.audit("member.removed", user_id, {"self": leaving_self}, org_id=ctx.org_id, actor=ctx.email)
    return {"ok": True}


# ---------------------------------------------------------------------- invitations (côté invité)
@router.get("/invitations/{token}")
def invitation_preview(token: str, service: ScanService = Depends(get_service)):
    inv = _valid_invitation(service, token)
    org = service.storage.get_org(inv["org_id"])
    return {"org_name": org["name"] if org else "", "email": inv["email"], "role": inv["role"],
            "role_label": ROLE_LABELS[inv["role"]], "has_account": bool(service.storage.get_user_by_email(inv["email"]))}


@router.post("/invitations/{token}/accept")
def accept(token: str, ctx: Context = Depends(current_context), service: ScanService = Depends(get_service)):
    inv = _valid_invitation(service, token)
    if inv["email"] != ctx.email:
        raise HTTPException(403, "Cette invitation est destinée à une autre adresse e-mail.")
    storage = service.storage
    # Déjà membre : on conserve le rôle actuel (une invitation ne doit jamais rétrograder)
    if not storage.get_role(inv["org_id"], ctx.user_id):
        storage.add_membership(inv["org_id"], ctx.user_id, inv["role"])
    storage.accept_invitation(inv["id"])
    storage.set_session_org(ctx.session, inv["org_id"])
    storage.audit("member.joined", ctx.user_id, {"email": ctx.email, "role": inv["role"], "via": "invitation"},
                  org_id=inv["org_id"], actor=ctx.email)
    return {"ok": True}
