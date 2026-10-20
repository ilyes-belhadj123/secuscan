"""SS-24 — mode formation : exercices de code sécurisé, correction automatique, progression.

La correction proposée par l'apprenant n'est jamais exécutée. Elle réussit si :
1. elle ne contient pas de commentaire de suppression d'alerte (secuscan: ignore, nosec) ;
2. sa syntaxe est valide ;
3. les règles de SecuScan ne détectent plus la faille, ni aucune autre ;
4. les contrôles de structure de l'exercice passent ;
5. l'IA, si elle est disponible, confirme que la faille est corrigée (son avis reste pédagogique :
   sans IA, les étapes 1 à 4 suffisent).
"""
import re
from dataclasses import asdict, dataclass

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from .ai.enricher import AIUnavailable, Enricher
from .ai.safety import sanitize
from .analyzers import sast
from .analyzers.rules import RULES_BY_ID
from .analyzers.syntax import count_errors, first_error
from .deps import Context, current_context, get_service, require_admin
from .ingest import SourceFile
from .pipeline import ScanService
from .training_exercises import EXERCISES, EXERCISES_BY_ID, Exercise

router = APIRouter(prefix="/api/training")
MAX_CODE_CHARS = 20_000
_SUPPRESSION = re.compile(r"secuscan\s*:\s*ignore|#\s*nosec|NOSONAR", re.IGNORECASE)

REVIEW_PROMPT = """Exercice de formation au code sécurisé (correction d'un apprenant)
- Faille à corriger : {cwe} — {title}
- Langage : {language}
- Consigne : {brief}

Code vulnérable d'origine :
```
{original}
```

Correction proposée par l'apprenant :
```
{submission}
```

Juge uniquement si la faille est réellement corrigée, sans casser le comportement attendu. Rédige un
retour pédagogique bienveillant en français, en 2 à 4 phrases, adressé à l'apprenant (tutoiement), sans
donner de charge d'attaque. Réponds avec exactement cet objet JSON :
{{"fixed": true | false, "feedback": "retour pédagogique"}}"""


class SubmitRequest(BaseModel):
    code: str = Field(min_length=1, max_length=MAX_CODE_CHARS)


@dataclass
class CheckResult:
    label: str
    ok: bool
    detail: str = ""


def _summary(ex: Exercise) -> dict:
    return {"id": ex.id, "title": ex.title, "language": ex.language, "cwe": ex.cwe, "difficulty": ex.difficulty}


def grade(ex: Exercise, code: str) -> list[CheckResult]:
    """Contrôles déterministes, sans IA ni exécution du code."""
    checks: list[CheckResult] = []
    suppressed = _SUPPRESSION.search(code)
    checks.append(CheckResult("Aucune alerte masquée par un commentaire", not suppressed,
                              "Corrigez le code plutôt que de faire taire l'alerte." if suppressed else ""))
    errors = count_errors(ex.language, code, ex.filename)
    syntax_ok = errors in (0, None)
    checks.append(CheckResult("Syntaxe valide", syntax_ok,
                              "" if syntax_ok else first_error(ex.language, code, ex.filename) or ""))
    if syntax_ok:
        found = sast.analyze_file(SourceFile(ex.filename, ex.language, code))
        target = [f for f in found if f.rule_id in ex.rules]
        others = [f for f in found if f.rule_id not in ex.rules]
        checks.append(CheckResult(
            "La faille n'est plus détectée", not target,
            "; ".join(f"ligne {f.start_line} : {f.title}" for f in target)))
        checks.append(CheckResult(
            "Aucune nouvelle faille introduite", not others,
            "; ".join(f"ligne {f.start_line} : {RULES_BY_ID[f.rule_id].title if f.rule_id in RULES_BY_ID else f.title}"
                      for f in others)))
    checks += [CheckResult(c.label, bool(c.pattern.search(code))) for c in ex.required]
    checks += [CheckResult(c.label, not c.pattern.search(code)) for c in ex.forbidden]
    return checks


def ai_review(service: ScanService, ex: Exercise, code: str) -> dict | None:
    if not service.settings.ai_enabled:
        return None
    prompt = REVIEW_PROMPT.format(cwe=ex.cwe, title=ex.title, language=ex.language, brief=ex.brief,
                                  original=ex.code, submission=code)
    try:
        data = Enricher(service.settings, service.storage)._complete(prompt)
    except AIUnavailable:
        return None
    feedback, _ = sanitize(str(data.get("feedback") or "").strip())
    return {"fixed": data.get("fixed") is True, "feedback": feedback}


def _progress_for(service: ScanService, ctx: Context) -> dict[str, dict]:
    return service.storage.training_progress(ctx.org_id, ctx.user_id)


@router.get("/exercises")
def list_exercises(ctx: Context = Depends(current_context), service: ScanService = Depends(get_service)):
    progress = _progress_for(service, ctx)
    items = [{**_summary(ex), "passed": progress.get(ex.id, {}).get("passed", False),
              "attempts": progress.get(ex.id, {}).get("attempts", 0)} for ex in EXERCISES]
    return {"exercises": items, "passed": sum(1 for i in items if i["passed"]), "total": len(items)}


def _exercise_or_404(exercise_id: str) -> Exercise:
    ex = EXERCISES_BY_ID.get(exercise_id)
    if not ex:
        raise HTTPException(404, "Exercice introuvable")
    return ex


@router.get("/exercises/{exercise_id}")
def get_exercise(exercise_id: str, ctx: Context = Depends(current_context), service: ScanService = Depends(get_service)):
    ex = _exercise_or_404(exercise_id)
    progress = _progress_for(service, ctx).get(ex.id, {})
    passed = progress.get("passed", False)
    return {
        **_summary(ex), "brief": ex.brief, "code": ex.code, "filename": ex.filename, "hints": list(ex.hints),
        "passed": passed, "attempts": progress.get("attempts", 0), "last_code": progress.get("last_code"),
        "solution": ex.solution if passed else None,  # la solution n'est montrée qu'après réussite
    }


@router.post("/exercises/{exercise_id}/submit")
def submit(exercise_id: str, body: SubmitRequest, ctx: Context = Depends(current_context),
           service: ScanService = Depends(get_service)):
    ex = _exercise_or_404(exercise_id)
    checks = grade(ex, body.code)
    deterministic_ok = all(c.ok for c in checks)
    review = ai_review(service, ex, body.code) if deterministic_ok else None
    passed = deterministic_ok and (review is None or review["fixed"])
    service.storage.record_training_attempt(ctx.org_id, ctx.user_id, ex.id, passed, body.code)
    return {
        "passed": passed, "checks": [asdict(c) for c in checks], "ai": review,
        "solution": ex.solution if passed else None,
    }


@router.get("/progress")
def team_progress(ctx: Context = Depends(require_admin), service: ScanService = Depends(get_service)):
    """Progression des membres de l'organisation (administrateurs)."""
    rows = service.storage.training_team_progress(ctx.org_id)
    members = {m["id"]: m for m in service.storage.list_members(ctx.org_id)}
    return {
        "total": len(EXERCISES),
        "members": [
            {"name": m["name"], "email": m["email"], "passed": rows.get(uid, {}).get("passed", 0),
             "attempts": rows.get(uid, {}).get("attempts", 0), "last_activity": rows.get(uid, {}).get("last_activity")}
            for uid, m in members.items()
        ],
    }

