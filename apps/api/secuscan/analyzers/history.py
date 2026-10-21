"""Secrets dans l'historique Git : supprimés du code, mais toujours lisibles dans les anciens commits.

Deux temps, pour que la lecture du contenu reste dans l'analyse isolée (SS-4) :
1. `export_history` (worker ou CLI) : `git log -p` sur un dépôt que SecuScan vient de cloner (ou sur
   le dépôt local de l'utilisateur en CLI), réduit aux lignes ajoutées, écrit dans un fichier texte.
   Jamais sur le `.git` d'une archive importée : sa configuration pourrait faire exécuter du code à git.
2. `find_history_secrets` (analyse isolée) : lecture de ce texte, sans git, et détection des secrets
   qui ne figurent plus dans la version actuelle (ceux-là sont déjà signalés normalement).

Seuls l'identifiant court du commit et sa date sont conservés : ni auteur, ni message de commit.
"""
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from ..ingest import IGNORED_DIRS, SourceFile, language_for_filename
from . import secrets

HISTORY_FILE = ".secuscan-history.txt"  # à côté du dossier analysé, jamais dedans
MAX_HISTORY_BYTES = 20 * 1024 * 1024
HISTORY_TIMEOUT_SECONDS = 120
_COMMIT = "@@SECUSCAN-COMMIT "

def _diff_path(header: str) -> str:
    """Chemin d'un en-tête « +++ b/… » ; entre guillemets (caractères spéciaux), séquences octales décodées."""
    if header.startswith('"') and header.endswith('"'):
        header = header[1:-1].encode("latin-1", "backslashreplace").decode("unicode_escape")
        header = header.encode("latin-1").decode("utf-8", "replace")
    return header[2:] if header.startswith("b/") else header

_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")
# Options qui empêchent git d'exécuter un programme pendant l'export (pilotes de diff, pager…)
# core.quotePath=false : chemins accentués écrits tels quels (sinon « "b/caf\303\251.py" »)
_SAFE_GIT = ["git", "-c", "core.hooksPath=/dev/null", "-c", "core.pager=cat", "-c", "core.fsmonitor=false",
             "-c", "diff.external=", "-c", "core.quotePath=false", "--no-pager"]


@dataclass
class HistorySecret:
    match: secrets.SecretMatch
    path: str
    line: int
    commit: str
    date: str
    redacted_line: str


def export_history(repo: Path, out: Path, max_commits: int) -> bool:
    """Écrit les lignes ajoutées par les `max_commits` derniers commits ; False si indisponible."""
    if max_commits <= 0 or not (repo / ".git").exists():
        return False
    cmd = _SAFE_GIT + ["-C", str(repo), "log", f"-n{max_commits}", "--no-merges", "--no-color", "--no-ext-diff",
                       "--no-textconv", "--unified=0", "--diff-filter=AM", f"--format={_COMMIT}%h %cs", "-p"]
    try:
        done = subprocess.run(cmd, capture_output=True, timeout=HISTORY_TIMEOUT_SECONDS,
                              env={"PATH": os.environ.get("PATH", ""), "GIT_CONFIG_NOSYSTEM": "1",
                                   "GIT_TERMINAL_PROMPT": "0", "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
                                   "HOME": str(out.parent)})
    except (subprocess.TimeoutExpired, OSError):
        return False
    if done.returncode != 0:
        return False
    out.write_bytes(_keep_added_lines(done.stdout[:MAX_HISTORY_BYTES]))
    return True


def _keep_added_lines(raw: bytes) -> bytes:
    """Ne garde que ce qui sert à l'analyse : commits, fichiers, positions et lignes ajoutées."""
    kept = []
    for line in raw.split(b"\n"):
        if line.startswith((_COMMIT.encode(), b"@@ ", b"+")):  # « + » : lignes ajoutées et en-têtes +++
            kept.append(line)
    return b"\n".join(kept)


def _skipped(path: str) -> bool:
    return any(part in IGNORED_DIRS for part in path.split("/")[:-1])


def find_history_secrets(text: str, current: set[str]) -> list[HistorySecret]:
    """Secrets ajoutés par un commit et absents de la version actuelle (`current` : leurs empreintes)."""
    found: dict[str, HistorySecret] = {}  # empreinte → occurrence la plus récente (git log : récent d'abord)
    commit = date = path = ""
    lines: list[tuple[int, str]] = []
    next_line = 0

    def flush() -> None:
        if not (path and lines) or _skipped(path):
            return
        source = SourceFile(path, language_for_filename(path) or "text", "\n".join(t for _, t in lines))
        matches = secrets.find_secrets(source)
        redacted = secrets.redact(source, matches).content.split("\n")
        for m in matches:
            if m.fingerprint in current or m.fingerprint in found:
                continue
            found[m.fingerprint] = HistorySecret(m, path, lines[m.line - 1][0], commit, date, redacted[m.line - 1])

    for raw in text.split("\n"):
        if raw.startswith(_COMMIT):
            flush()
            commit, _, date = raw[len(_COMMIT):].partition(" ")
            path, lines = "", []
        elif raw.startswith(("+++ b/", '+++ "b/', "+++ /dev/null")):
            flush()
            path = _diff_path(raw[4:].strip()) if not raw.startswith("+++ /dev/null") else ""
            lines = []
        elif m := _HUNK.match(raw):
            next_line = int(m.group(1))
        elif raw.startswith("+") and path:
            lines.append((next_line, raw[1:]))
            next_line += 1
    flush()
    return list(found.values())
