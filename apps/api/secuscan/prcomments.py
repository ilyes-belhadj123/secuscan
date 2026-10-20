"""SS-22 — commentaires automatiques sur les pull requests (GitHub) et merge requests (GitLab).

Lancé depuis la CI par `secuscan scan --pr-comment` : le jeton du pipeline suffit, sans application
OAuth ni serveur public.
- Un commentaire en ligne par alerte située sur une ligne ajoutée par la PR (au plus 25), avec
  l'explication et le correctif de l'IA quand elle est activée ;
- un commentaire de synthèse unique, mis à jour à chaque exécution plutôt que dupliqué ;
- une alerte déjà commentée (même empreinte) ne l'est pas une seconde fois.
Les secrets restent masqués : seule la version masquée du code figure dans les extraits.
"""
import json
import re
from collections.abc import Mapping
from pathlib import Path

import httpx

from .models import SEVERITY_ORDER, Finding, Scan
from .reports import SEVERITY_LABELS

MAX_INLINE = 25
SUMMARY_MARKER = "<!-- secuscan:summary -->"
SEVERITY_ICONS = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "⚪"}
_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


class PRCommentError(RuntimeError):
    pass


# ---------------------------------------------------------------------- diff et contenu
def added_lines(patch: str) -> set[int]:
    """Numéros (côté nouvelle version) des lignes ajoutées ou modifiées par un diff unifié."""
    lines: set[int] = set()
    new: int | None = None
    for raw in patch.split("\n"):
        if m := _HUNK.match(raw):
            new = int(m.group(1))
        elif new is None or raw.startswith(("-", "\\")):
            continue  # ligne supprimée, ou « \ No newline at end of file »
        elif raw.startswith("+"):
            lines.add(new)
            new += 1
        else:
            new += 1
    return lines


def anchor_line(finding: Finding, changed: Mapping[str, set[int]]) -> int | None:
    """Première ligne de l'alerte ajoutée par la PR, ou None si l'alerte ne la concerne pas."""
    added = changed.get(finding.file) or set()
    return next((line for line in range(finding.start_line, finding.end_line + 1) if line in added), None)


def marker(finding: Finding) -> str:
    return f"<!-- secuscan:{finding.fingerprint} -->"


def _fenced(code: str, lang: str = "") -> str:
    """Bloc de code dont la clôture ne peut pas être refermée par le contenu."""
    longest = max((len(run) for run in re.findall(r"`+", code)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}{lang}\n{code}\n{fence}"


def inline_body(finding: Finding) -> str:
    sev = finding.severity.value
    refs = " · ".join(x for x in (f"`{finding.rule_id}`", finding.cwe, finding.owasp and f"OWASP {finding.owasp}") if x)
    parts = [marker(finding), f"**{SEVERITY_ICONS[sev]} SecuScan — {SEVERITY_LABELS[sev]} : {finding.title}**",
             "", refs, "", finding.message]
    ai = finding.ai
    if ai and ai.explanation and ai.explanation.attack_scenario:
        parts += ["", f"**Risque** : {ai.explanation.attack_scenario}"]
    if ai and ai.fix and ai.fix.syntax_valid is not False:
        parts += ["", "**Correctif proposé** :", _fenced(ai.fix.diff, "diff")]
        if ai.fix.explanation:
            parts += ["", ai.fix.explanation]
    elif finding.fix_hint:
        parts += ["", f"**Correction** : {finding.fix_hint}"]
    return "\n".join(parts)


def summary_body(scan: Scan, findings: list[Finding], on_diff: int, fail_on: str, blockers: int) -> str:
    open_findings = [f for f in findings if f.status == "open"]
    counts = {k: sum(1 for f in open_findings if f.severity.value == k) for k in SEVERITY_ICONS}
    status = (f"❌ **Seuil « {fail_on} » dépassé** : {blockers} alerte(s) bloquante(s)." if blockers
              else f"✅ Aucune alerte au niveau du seuil « {fail_on} ».")
    rows = "\n".join(f"| {SEVERITY_ICONS[k]} {SEVERITY_LABELS[k]} | {counts[k]} |" for k in SEVERITY_ICONS)
    return "\n".join([
        SUMMARY_MARKER,
        "## 🛡️ SecuScan — analyse de sécurité",
        "",
        status,
        "",
        f"Score : **{scan.score}/100** · {len(open_findings)} alerte(s) ouverte(s) dans le projet, "
        f"dont **{on_diff} sur les lignes modifiées par cette PR** (commentées en ligne).",
        "",
        "| Sévérité | Alertes |",
        "|---|---|",
        rows,
        "",
        f"<sub>{scan.summary.files_scanned} fichiers · {scan.summary.lines_scanned} lignes analysées · "
        "mis à jour à chaque exécution</sub>",
    ])


# ---------------------------------------------------------------------- fournisseurs
class _Provider:
    client: httpx.Client

    def _pages(self, url: str) -> list[dict]:
        items: list[dict] = []
        page = 1
        while True:
            resp = self.client.get(url, params={"per_page": 100, "page": page})
            resp.raise_for_status()
            batch = resp.json()
            items += batch
            if len(batch) < 100:
                return items
            page += 1


class GitHub(_Provider):
    def __init__(self, client: httpx.Client, repo: str, number: int, head_sha: str):
        self.client, self.repo, self.number, self.head_sha = client, repo, number, head_sha

    @classmethod
    def from_env(cls, env: Mapping[str, str], client: httpx.Client | None = None) -> "GitHub":
        token, repo, event = env.get("GITHUB_TOKEN"), env.get("GITHUB_REPOSITORY"), env.get("GITHUB_EVENT_PATH")
        if not (token and repo and event):
            raise PRCommentError("GITHUB_TOKEN, GITHUB_REPOSITORY et GITHUB_EVENT_PATH sont requis (GitHub Actions).")
        pr = json.loads(Path(event).read_text(encoding="utf-8")).get("pull_request")
        if not pr:
            raise PRCommentError("ce pipeline n'est pas lancé par une pull request.")
        client = client or httpx.Client(
            base_url=env.get("GITHUB_API_URL", "https://api.github.com"), timeout=30,
            headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
                     "X-GitHub-Api-Version": "2022-11-28"},
        )
        return cls(client, repo, int(pr["number"]), str(pr["head"]["sha"]))

    def changed_lines(self) -> dict[str, set[int]]:
        files = self._pages(f"/repos/{self.repo}/pulls/{self.number}/files")
        return {f["filename"]: added_lines(f.get("patch") or "") for f in files}

    def existing_bodies(self) -> list[str]:
        return [c.get("body") or "" for c in self._pages(f"/repos/{self.repo}/pulls/{self.number}/comments")]

    def post_inline(self, comments: list[tuple[Finding, int, str]]) -> None:
        resp = self.client.post(f"/repos/{self.repo}/pulls/{self.number}/reviews", json={
            "commit_id": self.head_sha, "event": "COMMENT",
            "body": f"SecuScan : {len(comments)} alerte(s) sur les lignes modifiées.",
            "comments": [{"path": f.file, "line": line, "side": "RIGHT", "body": body} for f, line, body in comments],
        })
        resp.raise_for_status()

    def upsert_summary(self, body: str) -> None:
        comments = self._pages(f"/repos/{self.repo}/issues/{self.number}/comments")
        existing = next((c for c in comments if SUMMARY_MARKER in (c.get("body") or "")), None)
        if existing:
            resp = self.client.patch(f"/repos/{self.repo}/issues/comments/{existing['id']}", json={"body": body})
        else:
            resp = self.client.post(f"/repos/{self.repo}/issues/{self.number}/comments", json={"body": body})
        resp.raise_for_status()


class GitLab(_Provider):
    def __init__(self, client: httpx.Client, project: str, iid: str, diff_refs: dict):
        self.client, self.project, self.iid, self.diff_refs = client, project, iid, diff_refs
        self.base = f"/projects/{project}/merge_requests/{iid}"

    @classmethod
    def from_env(cls, env: Mapping[str, str], client: httpx.Client | None = None) -> "GitLab":
        token, api = env.get("SECUSCAN_GITLAB_TOKEN"), env.get("CI_API_V4_URL")
        project, iid = env.get("CI_PROJECT_ID"), env.get("CI_MERGE_REQUEST_IID")
        if not (token and api and project):
            raise PRCommentError("SECUSCAN_GITLAB_TOKEN (jeton d'accès au projet, portée « api »), CI_API_V4_URL "
                                 "et CI_PROJECT_ID sont requis (GitLab CI).")
        if not iid:
            raise PRCommentError("ce pipeline n'est pas lancé par une merge request.")
        client = client or httpx.Client(base_url=api, timeout=30, headers={"PRIVATE-TOKEN": token})
        resp = client.get(f"/projects/{project}/merge_requests/{iid}")
        resp.raise_for_status()
        return cls(client, project, iid, resp.json()["diff_refs"])

    def changed_lines(self) -> dict[str, set[int]]:
        diffs = self._pages(f"{self.base}/diffs")
        return {d["new_path"]: added_lines(d.get("diff") or "") for d in diffs if not d.get("deleted_file")}

    def existing_bodies(self) -> list[str]:
        return [n.get("body") or "" for d in self._pages(f"{self.base}/discussions") for n in d.get("notes", [])]

    def post_inline(self, comments: list[tuple[Finding, int, str]]) -> None:
        refs = self.diff_refs
        for f, line, body in comments:
            resp = self.client.post(f"{self.base}/discussions", json={"body": body, "position": {
                "position_type": "text", "base_sha": refs["base_sha"], "start_sha": refs["start_sha"],
                "head_sha": refs["head_sha"], "old_path": f.file, "new_path": f.file, "new_line": line,
            }})
            resp.raise_for_status()

    def upsert_summary(self, body: str) -> None:
        notes = self._pages(f"{self.base}/notes")
        existing = next((n for n in notes if SUMMARY_MARKER in (n.get("body") or "")), None)
        if existing:
            resp = self.client.put(f"{self.base}/notes/{existing['id']}", json={"body": body})
        else:
            resp = self.client.post(f"{self.base}/notes", json={"body": body})
        resp.raise_for_status()


def provider_from_env(env: Mapping[str, str]) -> GitHub | GitLab:
    if env.get("GITHUB_ACTIONS") == "true":
        return GitHub.from_env(env)
    if env.get("GITLAB_CI") == "true":
        return GitLab.from_env(env)
    raise PRCommentError("--pr-comment fonctionne dans GitHub Actions ou GitLab CI.")


def publish(provider: GitHub | GitLab, scan: Scan, findings: list[Finding], fail_on: str, blockers: int) -> str:
    changed = provider.changed_lines()
    already = "\n".join(provider.existing_bodies())
    open_findings = sorted((f for f in findings if f.status == "open"),
                           key=lambda f: (SEVERITY_ORDER[f.severity], f.file, f.start_line))
    on_diff = [(f, line) for f in open_findings if (line := anchor_line(f, changed)) is not None]
    new = [(f, line, inline_body(f)) for f, line in on_diff if marker(f) not in already][:MAX_INLINE]
    if new:
        provider.post_inline(new)
    provider.upsert_summary(summary_body(scan, findings, len(on_diff), fail_on, blockers))
    return (f"Commentaires publiés : {len(new)} en ligne ({len(on_diff) - len(new)} déjà présents ou au-delà de "
            f"{MAX_INLINE}), synthèse mise à jour.")
