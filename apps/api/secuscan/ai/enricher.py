"""Couche 4 — enrichissement IA via Claude (OpenRouter).

Mode « live + cache » : chaque réponse est mise en cache par empreinte (modèle, version de prompt,
contenu envoyé). Si l'API est indisponible, on se rabat sur le cache ; à défaut, l'alerte reste
affichée avec l'explication statique de la règle.
"""
import ast
import difflib
import hashlib
import json
import logging
import re
import textwrap
import threading
import time
from dataclasses import dataclass

import httpx

from ..config import Settings
from ..models import AIReview, Explanation, Finding, FixSuggestion
from ..storage import Storage
from ..taxonomy import references_for
from .prompts import DEPENDENCY_TEMPLATE, FINDING_TEMPLATE, PROMPT_VERSION, SYSTEM_PROMPT
from .safety import sanitize

log = logging.getLogger(__name__)


class AIUnavailable(RuntimeError):
    pass


@dataclass
class AIStats:
    calls: int = 0
    cache_hits: int = 0
    tokens: int = 0

    def __post_init__(self):
        self._lock = threading.Lock()

    def add(self, *, call: bool = False, hit: bool = False, tokens: int = 0) -> None:
        with self._lock:
            self.calls += int(call)
            self.cache_hits += int(hit)
            self.tokens += tokens


def _extract_json(text: str) -> dict:
    text = text.strip()
    text = re.sub(r"^```(json)?\s*|\s*```$", "", text)
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end == -1:
        raise ValueError("Réponse IA sans objet JSON")
    return json.loads(text[start : end + 1])


def _syntax_ok(language: str, code: str) -> bool | None:
    if language != "python":
        return None
    try:
        ast.parse(textwrap.dedent(code))
        return True
    except SyntaxError:
        return False


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
    def __init__(self, settings: Settings, storage: Storage):
        self.settings = settings
        self.storage = storage
        self.stats = AIStats()

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

        payload = {
            "model": self.settings.openrouter_model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.1,
            "max_tokens": 2500,
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
                content = body["choices"][0]["message"]["content"]
                data = _extract_json(content)
                self.stats.add(call=True, tokens=int((body.get("usage") or {}).get("total_tokens", 0)))
                self.storage.cache_set("ai", key, data)
                return data
            except (httpx.HTTPError, KeyError, ValueError) as exc:
                last_error = exc
                log.warning("Appel IA échoué (tentative %d) : %s", attempt + 1, exc)
                time.sleep(1.5 * (attempt + 1))
        raise AIUnavailable(f"IA indisponible : {last_error}")

    # ------------------------------------------------------------------ findings code
    def review_code_finding(self, finding: Finding, header: str) -> AIReview:
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
                syntax_valid=_syntax_ok(finding.language, patched),
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

    # ------------------------------------------------------------------ dépendances
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
