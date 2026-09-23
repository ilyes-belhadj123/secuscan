"""Couche 4 — enrichissement IA via Claude (OpenRouter).

Mode « live + cache » : chaque réponse est mise en cache par empreinte (modèle, version de prompt,
contenu envoyé). Si l'API est indisponible, on se rabat sur le cache ; à défaut, l'alerte reste
affichée avec l'explication statique de la règle.
"""
import difflib
import hashlib
import json
import logging
import re
import threading
import time
from dataclasses import dataclass

import httpx

from ..analyzers.syntax import patch_is_valid
from ..config import Settings
from ..ingest import SourceFile
from ..models import AIReview, Explanation, Finding, FixSuggestion, Severity
from ..storage import Storage
from ..taxonomy import references_for
from .prompts import DEPENDENCY_TEMPLATE, FINDING_TEMPLATE, LOGIC_TEMPLATE, PROMPT_VERSION, SYSTEM_PROMPT
from .safety import sanitize

log = logging.getLogger(__name__)


class AIUnavailable(RuntimeError):
    pass


class BudgetExceeded(AIUnavailable):
    """Budget IA de l'analyse épuisé : l'alerte garde l'explication générique de sa règle."""


class AIBudget:
    """Plafond d'appels et de jetons pour une analyse (SS-12). Les réponses en cache sont gratuites."""

    def __init__(self, max_calls: int, max_tokens: int):
        self.max_calls = max_calls
        self.max_tokens = max_tokens
        self.calls = 0
        self.tokens = 0
        self.refused = 0
        self._lock = threading.Lock()

    def reserve(self) -> None:
        with self._lock:
            if self.calls >= self.max_calls or self.tokens >= self.max_tokens:
                self.refused += 1
                raise BudgetExceeded("Budget IA de l'analyse atteint : explication générique de la règle.")
            self.calls += 1

    def consume(self, tokens: int) -> None:
        with self._lock:
            self.tokens += tokens

    @property
    def remaining_calls(self) -> int:
        with self._lock:
            return max(0, self.max_calls - self.calls)


LOGIC_MIN_CONFIDENCE = 0.7
MAX_OUTPUT_TOKENS = 4096
MAX_OUTPUT_TOKENS_RETRY = 8192


@dataclass
class LogicFlaw:
    title: str
    cwe: str | None
    severity: Severity
    start_line: int
    end_line: int
    confidence: float
    message: str


@dataclass
class AIStats:
    calls: int = 0
    cache_hits: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0

    def __post_init__(self):
        self._lock = threading.Lock()

    @property
    def tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens

    def add(self, *, call: bool = False, hit: bool = False, prompt_tokens: int = 0, completion_tokens: int = 0) -> None:
        with self._lock:
            self.calls += int(call)
            self.cache_hits += int(hit)
            self.prompt_tokens += prompt_tokens
            self.completion_tokens += completion_tokens

    def cost_usd(self, settings: Settings) -> float:
        return (self.prompt_tokens * settings.secuscan_ai_price_input_per_mtok
                + self.completion_tokens * settings.secuscan_ai_price_output_per_mtok) / 1_000_000


def _extract_json(text: str) -> dict:
    text = text.strip()
    text = re.sub(r"^```(json)?\s*|\s*```$", "", text)
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end == -1:
        raise ValueError("Réponse IA sans objet JSON")
    return json.loads(text[start : end + 1])


def unified_diff(original: str, patched: str, file: str, start_line: int) -> str:
    diff = difflib.unified_diff(
        original.split("\n"), patched.split("\n"),
        fromfile=f"a/{file}", tofile=f"b/{file}", lineterm="", n=3,
    )
    # Recaler les numéros de ligne des hunks sur la position réelle dans le fichier
    out = []
    for line in diff:
        m = re.match(r"^@@ -(\d+)(,\d+)? \+(\d+)(,\d+)? @@", line)
        if m:
            a, b = int(m.group(1)) + start_line - 1, int(m.group(3)) + start_line - 1
            line = f"@@ -{a}{m.group(2) or ''} +{b}{m.group(4) or ''} @@"
        out.append(line)
    return "\n".join(out)


class Enricher:
    def __init__(self, settings: Settings, storage: Storage, budget: AIBudget | None = None):
        self.settings = settings
        self.storage = storage
        self.stats = AIStats()
        self.budget = budget or AIBudget(*settings.ai_budget)

    # ------------------------------------------------------------------ transport
    def _complete(self, prompt: str) -> dict:
        key = hashlib.sha256(
            f"{self.settings.openrouter_model}|{PROMPT_VERSION}|{SYSTEM_PROMPT}|{prompt}".encode()
        ).hexdigest()
        cached = self.storage.cache_get("ai", key)
        if cached is not None:
            self.stats.add(hit=True)
            cached["_cached"] = True
            return cached
        if not self.settings.ai_enabled:
            raise AIUnavailable("Clé OpenRouter absente et aucune réponse en cache.")
        self.budget.reserve()

        payload = {
            "model": self.settings.openrouter_model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.1,
            "max_tokens": MAX_OUTPUT_TOKENS,
            "response_format": {"type": "json_object"},
        }
        headers = {
            "Authorization": f"Bearer {self.settings.openrouter_api_key}",
            "X-Title": "SecuScan",
        }
        last_error: Exception | None = None
        for attempt in range(3):
            try:
                with httpx.Client(timeout=90) as client:
                    resp = client.post(self.settings.openrouter_url, json=payload, headers=headers)
                if resp.status_code in (429, 500, 502, 503, 504):
                    raise httpx.HTTPStatusError("temporaire", request=resp.request, response=resp)
                resp.raise_for_status()
                body = resp.json()
                usage = body.get("usage") or {}
                prompt_tokens = int(usage.get("prompt_tokens", 0))
                completion_tokens = int(usage.get("completion_tokens", 0))
                # Les jetons d'une réponse inexploitable sont quand même facturés : on les compte
                self.stats.add(call=True, prompt_tokens=prompt_tokens, completion_tokens=completion_tokens)
                self.budget.consume(prompt_tokens + completion_tokens)
                choice = body["choices"][0]
                if choice.get("finish_reason") == "length":
                    # Réponse tronquée : on retente une fois avec une limite de sortie plus large
                    payload["max_tokens"] = MAX_OUTPUT_TOKENS_RETRY
                    raise ValueError("réponse tronquée (limite de jetons de sortie atteinte)")
                content = (choice.get("message") or {}).get("content")
                if not content:
                    raise ValueError(f"réponse vide (finish_reason={choice.get('finish_reason')})")
                data = _extract_json(content)
                self.storage.cache_set("ai", key, data)
                return data
            except (httpx.HTTPError, KeyError, IndexError, TypeError, ValueError) as exc:
                last_error = exc
                log.warning("Appel IA échoué (tentative %d) : %s", attempt + 1, exc)
                time.sleep(1.5 * (attempt + 1))
        raise AIUnavailable(f"IA indisponible : {last_error}")

    # ------------------------------------------------------------------ findings code
    def review_code_finding(self, finding: Finding, header: str, file_content: str | None = None) -> AIReview:
        lines = f"{finding.start_line}" if finding.start_line == finding.end_line else (
            f"{finding.start_line}-{finding.end_line}")
        end = finding.snippet_start_line + finding.snippet.count("\n")
        numbered = "\n".join(
            f"{finding.snippet_start_line + i:>4} | {line}" for i, line in enumerate(finding.snippet.split("\n"))
        )
        prompt = FINDING_TEMPLATE.format(
            rule_id=finding.rule_id, title=finding.title, cwe=finding.cwe or "n/a",
            language=finding.language, file=finding.file, lines=lines, message=finding.message,
            header=header or "(aucun)", start=finding.snippet_start_line, end=end, numbered=numbered,
        )
        data = self._complete(prompt)
        filtered = False

        def clean(value) -> str:
            nonlocal filtered
            text, was_filtered = sanitize(str(value or "").strip())
            filtered = filtered or was_filtered
            return text

        verdict = data.get("verdict")
        if verdict not in ("true_positive", "false_positive", "uncertain"):
            verdict = "uncertain"
        try:
            confidence = max(0.0, min(1.0, float(data.get("confidence", 0.5))))
        except (TypeError, ValueError):
            confidence = 0.5

        patched = str(data.get("patched_code") or "").rstrip("\n")
        fix = None
        if patched and patched.strip() != finding.snippet.strip():
            fix = FixSuggestion(
                original_code=finding.snippet,
                patched_code=patched,
                diff=unified_diff(finding.snippet, patched, finding.file, finding.snippet_start_line),
                explanation=clean(data.get("fix_explanation")),
                best_practices=[clean(p) for p in (data.get("best_practices") or [])][:5],
                syntax_valid=patch_is_valid(
                    finding.language, patched, original=finding.snippet, file_content=file_content,
                    start_line=finding.snippet_start_line, filename=finding.file,
                ),
            )
        explanation = Explanation(
            definition=clean(data.get("definition")),
            attack_scenario=clean(data.get("attack_scenario")),
            business_impact=clean(data.get("business_impact")),
            difficulty=clean(data.get("difficulty")) or "moyenne",
            references=references_for(finding.cwe),
        )
        return AIReview(
            verdict=verdict, confidence=confidence, reason=clean(data.get("reason")),
            explanation=explanation, fix=fix, model=self.settings.openrouter_model,
            cached=bool(data.get("_cached")), filtered=filtered,
        )

    # ------------------------------------------------------------------ failles logiques
    def discover_logic_flaws(self, source: SourceFile, flagged_lines: list[int]) -> list[LogicFlaw]:
        """Revue d'un fichier complet : failles que les règles par motif ne couvrent pas."""
        lines = source.content.split("\n")
        numbered = "\n".join(f"{i:>4} | {line}" for i, line in enumerate(lines, start=1))
        prompt = LOGIC_TEMPLATE.format(
            file=source.path, language=source.language, numbered=numbered,
            flagged=", ".join(map(str, sorted(set(flagged_lines)))) or "aucune",
        )
        data = self._complete(prompt)
        flaws = []
        for item in (data.get("findings") or [])[:5]:
            try:
                start = int(item["start_line"])
                end = max(start, int(item.get("end_line", start)))
                confidence = float(item.get("confidence", 0))
                severity = Severity(str(item.get("severity", "medium")).lower())
            except (KeyError, TypeError, ValueError):
                continue
            cwe = str(item.get("cwe", "")).upper()
            if not (1 <= start <= len(lines)) or confidence < LOGIC_MIN_CONFIDENCE:
                continue
            title, _ = sanitize(str(item.get("title") or "Faille logique").strip())
            message, _ = sanitize(str(item.get("message") or "").strip())
            flaws.append(LogicFlaw(
                title=title[:120], cwe=cwe if re.fullmatch(r"CWE-\d+", cwe) else None, severity=severity,
                start_line=start, end_line=min(end, start + 15, len(lines)), confidence=confidence, message=message,
            ))
        return flaws

    # ------------------------------------------------------------------ dépendances
    @staticmethod
    def local_dependency_review(finding: Finding) -> AIReview:
        """Explication et correctif générés sans IA, à partir des advisories OSV (coût nul)."""
        dep = finding.dependency
        assert dep is not None
        top = dep.advisories[:3]
        summaries = " ; ".join(a.summary.rstrip(".") for a in top if a.summary) or "vulnérabilités publiées"
        count = len(dep.advisories)
        fix = None
        if dep.fixed_version:
            patched = finding.snippet.replace(dep.version, dep.fixed_version)
            fix = FixSuggestion(
                original_code=finding.snippet, patched_code=patched,
                diff=unified_diff(finding.snippet, patched, finding.file, finding.snippet_start_line),
                explanation=f"Mettre à jour {dep.package} de {dep.version} vers {dep.fixed_version} (version qui corrige "
                            f"les {count} vulnérabilité(s) connue(s)), puis relancer les tests : une montée de version "
                            f"majeure peut introduire des changements incompatibles.",
                best_practices=[
                    "Automatiser les mises à jour de dépendances (Dependabot, Renovate).",
                    "Versionner le fichier de verrouillage (lockfile).",
                ],
            )
        return AIReview(
            verdict="true_positive", confidence=1.0,
            reason="Version présente dans une base publique de vulnérabilités connues.",
            explanation=Explanation(
                definition=f"La version {dep.version} de {dep.package} est concernée par {count} vulnérabilité(s) "
                           f"publiée(s) : {summaries}.",
                attack_scenario="Les vulnérabilités publiées sont documentées publiquement : un attaquant peut "
                                "rechercher les applications qui utilisent cette version et cibler les points "
                                "d'entrée qui exploitent le composant.",
                business_impact="Selon la vulnérabilité : fuite de données, interruption de service ou prise de "
                                "contrôle, avec des obligations de notification (RGPD) en cas de fuite.",
                difficulty="variable",
                references=[a.url for a in dep.advisories[:5]],
            ),
            fix=fix, model="Base OSV (sans IA)", generated_by="osv",
        )

    def review_dependency(self, finding: Finding) -> AIReview:
        dep = finding.dependency
        assert dep is not None
        advisories = "\n".join(
            f"  - {a.id} ({', '.join(a.aliases) or 'sans CVE'}) [{a.severity.value}] : {a.summary}"
            for a in dep.advisories[:12]
        )
        prompt = DEPENDENCY_TEMPLATE.format(
            ecosystem=dep.ecosystem, package=dep.package, version=dep.version,
            fixed_version=dep.fixed_version or "aucune version corrigée publiée", advisories=advisories,
        )
        data = self._complete(prompt)
        filtered = False

        def clean(value) -> str:
            nonlocal filtered
            text, was_filtered = sanitize(str(value or "").strip())
            filtered = filtered or was_filtered
            return text

        fix = None
        if dep.fixed_version:
            patched = finding.snippet.replace(dep.version, dep.fixed_version)
            fix = FixSuggestion(
                original_code=finding.snippet,
                patched_code=patched,
                diff=unified_diff(finding.snippet, patched, finding.file, finding.snippet_start_line),
                explanation=clean(data.get("fix_explanation")),
                best_practices=[clean(p) for p in (data.get("best_practices") or [])][:5],
            )
        refs = [a.url for a in dep.advisories[:5]]
        return AIReview(
            verdict="true_positive", confidence=1.0,
            reason="Version présente dans une base publique de vulnérabilités connues.",
            explanation=Explanation(
                definition=clean(data.get("definition")),
                attack_scenario=clean(data.get("attack_scenario")),
                business_impact=clean(data.get("business_impact")),
                difficulty=clean(data.get("difficulty")) or "moyenne",
                references=refs,
            ),
            fix=fix, model=self.settings.openrouter_model,
            cached=bool(data.get("_cached")), filtered=filtered,
        )
