"""SS-21 — bêta avec équipes pilotes : retours sur les correctifs, questionnaire, indicateurs.

Indicateurs du cahier des charges :
- taux de correctifs acceptés (objectif > 50 %) = retours « appliqué » ou « utile » / retours donnés ;
- équipes qui relancent une analyse la semaine suivante (objectif : au moins 5) ;
- recommandation (NPS) du questionnaire proposé après 14 jours.

Le tableau de bord opérateur (toutes organisations) est réservé aux e-mails listés dans
SECUSCAN_OPERATOR_EMAILS : il ne contient que des compteurs, jamais de code ni d'alerte.
"""
from datetime import UTC, datetime, timedelta
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from .deps import Context, current_context, get_service, require_admin
from .pipeline import ScanService
from .storage import Storage

router = APIRouter(prefix="/api")
SURVEY_AFTER_DAYS = 14
ACCEPTED = {"applied", "helpful"}


class FeedbackRequest(BaseModel):
    verdict: Literal["applied", "helpful", "not_helpful"]
    comment: str = Field(default="", max_length=1000)


class SurveyRequest(BaseModel):
    recommend: int = Field(ge=0, le=10)
    useful: str = Field(default="", max_length=2000)
    missing: str = Field(default="", max_length=2000)


def _finding_in_org(service: ScanService, finding_id: str, ctx: Context):
    finding = service.storage.get_finding(finding_id)
    if not (finding and service.storage.get_scan(finding.scan_id, org_id=ctx.org_id)):
        raise HTTPException(404, "Alerte introuvable")
    return finding


def _parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts)


def org_metrics(storage: Storage, org_id: str) -> dict:
    feedback = storage.feedback_rows(org_id)
    counts = {v: sum(1 for f in feedback if f["verdict"] == v) for v in ("applied", "helpful", "not_helpful")}
    total = sum(counts.values())
    scans = [s for s in storage.list_scans(org_id=org_id) if s.status == "completed"]
    weeks = sorted({_parse(s.created_at).isocalendar()[:2] for s in scans})
    return {
        "feedback": counts,
        "feedback_total": total,
        "acceptance_rate": round(sum(counts[v] for v in ACCEPTED) / total, 3) if total else None,
        "fix_copies": storage.count_fix_copies(org_id).get(org_id, 0),
        "scans": len(scans),
        "active_weeks": len(weeks),
        # A relancé une analyse une autre semaine que celle de sa première analyse
        "returned": len(weeks) >= 2,
        "last_scan": max((s.created_at for s in scans), default=None),
    }


def nps(scores: list[int]) -> int | None:
    if not scores:
        return None
    promoters = sum(1 for s in scores if s >= 9)
    detractors = sum(1 for s in scores if s <= 6)
    return round(100 * (promoters - detractors) / len(scores))


# ---------------------------------------------------------------------- retours sur les correctifs
@router.post("/findings/{finding_id}/feedback")
def give_feedback(finding_id: str, body: FeedbackRequest, ctx: Context = Depends(current_context),
                  service: ScanService = Depends(get_service)):
    finding = _finding_in_org(service, finding_id, ctx)
    service.storage.save_fix_feedback(ctx.org_id, finding, ctx.user_id, body.verdict, body.comment.strip())
    return {"ok": True}


@router.get("/findings/{finding_id}/feedback")
def my_feedback(finding_id: str, ctx: Context = Depends(current_context), service: ScanService = Depends(get_service)):
    _finding_in_org(service, finding_id, ctx)
    return service.storage.fix_feedback_for(finding_id, ctx.user_id)


@router.post("/findings/{finding_id}/fix-copied")
def fix_copied(finding_id: str, ctx: Context = Depends(current_context), service: ScanService = Depends(get_service)):
    _finding_in_org(service, finding_id, ctx)
    service.storage.record_fix_copy(ctx.org_id, finding_id, ctx.user_id)
    return {"ok": True}


# ---------------------------------------------------------------------- questionnaire
@router.get("/beta/survey")
def survey_status(ctx: Context = Depends(current_context), service: ScanService = Depends(get_service)):
    org = service.storage.get_org(ctx.org_id)
    age = datetime.now(UTC) - _parse(org["created_at"])
    answered = service.storage.has_answered_survey(ctx.org_id, ctx.user_id)
    return {"due": age >= timedelta(days=SURVEY_AFTER_DAYS) and not answered, "answered": answered}


@router.post("/beta/survey")
def answer_survey(body: SurveyRequest, ctx: Context = Depends(current_context), service: ScanService = Depends(get_service)):
    service.storage.save_survey(ctx.org_id, ctx.user_id, body.recommend, body.useful.strip(), body.missing.strip())
    return {"ok": True}


# ---------------------------------------------------------------------- indicateurs
@router.get("/beta/metrics")
def metrics(ctx: Context = Depends(require_admin), service: ScanService = Depends(get_service)):
    return org_metrics(service.storage, ctx.org_id)


def _require_operator(ctx: Context = Depends(current_context), service: ScanService = Depends(get_service)) -> Context:
    operators = {e.strip().lower() for e in service.settings.secuscan_operator_emails}
    if ctx.email.lower() not in operators:
        raise HTTPException(403, "Tableau de bord réservé à l'opérateur de la plateforme.")
    return ctx


@router.get("/operator/beta")
def operator_dashboard(ctx: Context = Depends(_require_operator), service: ScanService = Depends(get_service)):
    storage = service.storage
    orgs = []
    for org in storage.list_orgs():
        m = org_metrics(storage, org["id"])
        orgs.append({"name": org["name"], "plan": org["plan"], "created_at": org["created_at"],
                     "members": len(storage.list_members(org["id"])), **m})
    feedback = storage.feedback_rows()
    accepted = sum(1 for f in feedback if f["verdict"] in ACCEPTED)
    by_kind: dict[str, dict[str, int]] = {}
    for f in feedback:
        entry = by_kind.setdefault(f["kind"], {"accepted": 0, "total": 0})
        entry["total"] += 1
        entry["accepted"] += f["verdict"] in ACCEPTED
    surveys = storage.survey_rows()
    return {
        "organizations": orgs,
        "totals": {
            "organizations": len(orgs),
            "active": sum(1 for o in orgs if o["scans"] > 0),
            "returned": sum(1 for o in orgs if o["returned"]),
            "feedback": len(feedback),
            "acceptance_rate": round(accepted / len(feedback), 3) if feedback else None,
            "fix_copies": sum(storage.count_fix_copies().values()),
            "nps": nps([s["recommend"] for s in surveys]),
            "survey_answers": len(surveys),
        },
        "acceptance_by_kind": by_kind,
        "comments": [{"verdict": f["verdict"], "rule_id": f["rule_id"], "comment": f["comment"]}
                     for f in feedback if f["comment"]][-50:],
        "surveys": [{"recommend": s["recommend"], "useful": s["useful"], "missing": s["missing"],
                     "created_at": s["created_at"]} for s in surveys],
    }
