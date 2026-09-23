"""Import du code : extraction ZIP sécurisée, détection des langages, collecte des fichiers."""
import fnmatch
import os
import re
import shutil
import stat
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from .config import Settings

LANGUAGE_BY_EXTENSION = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".php": "php",
    ".java": "java",
}

MANIFEST_FILES = {
    "requirements.txt": "python",
    "pyproject.toml": "python",
    "package.json": "javascript",
    "package-lock.json": "javascript",
    "composer.json": "php",
    "composer.lock": "php",
    "pom.xml": "java",
}

IGNORED_DIRS = {
    ".git", "node_modules", "vendor", ".venv", "venv", "env", "__pycache__",
    "dist", "build", "target", ".next", ".idea", ".vscode", "coverage",
}


class UploadError(ValueError):
    """Archive refusée (taille, format, chemin malveillant...)."""


@dataclass
class SourceFile:
    path: str  # chemin relatif, séparateurs '/'
    language: str
    content: str


@dataclass
class ManifestFile:
    path: str
    name: str
    content: str


@dataclass
class CodeBase:
    files: list[SourceFile]
    manifests: list[ManifestFile]
    vendored: list[str] = field(default_factory=list)  # bibliothèques tierces ignorées

    @property
    def languages(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.files:
            counts[f.language] = counts.get(f.language, 0) + 1
        return counts

    @property
    def line_count(self) -> int:
        return sum(f.content.count("\n") + 1 for f in self.files)


def safe_extract_zip(archive: Path, dest: Path, settings: Settings) -> None:
    """Extrait une archive en refusant zip-slip, liens symboliques et zip-bombs."""
    try:
        zf = zipfile.ZipFile(archive)
    except zipfile.BadZipFile as exc:
        raise UploadError("Le fichier n'est pas une archive ZIP valide.") from exc

    with zf:
        infos = zf.infolist()
        if len(infos) > settings.max_files:
            raise UploadError(f"Archive trop volumineuse : plus de {settings.max_files} fichiers.")

        total = sum(i.file_size for i in infos)
        compressed = sum(i.compress_size for i in infos) or 1
        if total > settings.max_uncompressed_bytes:
            raise UploadError("Archive trop volumineuse une fois décompressée.")
        if total / compressed > settings.max_compression_ratio:
            raise UploadError("Taux de compression anormal (zip-bomb suspectée).")

        dest_root = dest.resolve()
        for info in infos:
            name = info.filename.replace("\\", "/")
            pure = PurePosixPath(name)
            if pure.is_absolute() or ".." in pure.parts or (pure.parts and pure.parts[0].endswith(":")):
                raise UploadError(f"Chemin interdit dans l'archive : {info.filename}")
            mode = info.external_attr >> 16
            if stat.S_ISLNK(mode):
                continue  # on n'extrait jamais de lien symbolique
            target = (dest_root / pure).resolve()
            if not target.is_relative_to(dest_root):
                raise UploadError(f"Chemin interdit dans l'archive : {info.filename}")
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            written = 0
            with zf.open(info) as src, open(target, "wb") as out:
                while chunk := src.read(64 * 1024):
                    written += len(chunk)
                    if written > info.file_size or written > settings.max_uncompressed_bytes:
                        raise UploadError("Taille décompressée incohérente (zip-bomb suspectée).")
                    out.write(chunk)


def _read_text(path: Path) -> str | None:
    try:
        raw = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in raw[:8192]:
        return None  # binaire
    return raw.decode("utf-8", errors="replace")


# Bibliothèques tierces copiées dans le projet : ce n'est pas le code de l'équipe (bruit massif)
_MINIFIED_NAME = re.compile(r"[.-]min\.(js|mjs|cjs)$|\.bundle\.js$|\.chunk\.js$", re.I)
_VERSION = re.compile(r"\bv?\d+\.\d+")
_LICENSE = re.compile(r"@license|\(c\)|copyright|licensed under|\bMIT\b", re.I)


def is_vendored(rel_path: str, content: str) -> bool:
    """Fichier minifié, ou bibliothèque tierce reconnaissable à son bandeau (version + licence)."""
    if _MINIFIED_NAME.search(rel_path):
        return True
    if not rel_path.endswith((".js", ".mjs", ".cjs")):
        return False
    head = content.lstrip()[:800]
    if head.startswith("/*"):
        banner = head.split("*/", 1)[0]
        if _VERSION.search(banner) and _LICENSE.search(banner):
            return True
    lines = content.split("\n", 200)[:200]
    return sum(1 for line in lines if len(line) > 500) >= 3  # code minifié sans nom explicite


def is_excluded(rel_path: str, patterns: list[str]) -> bool:
    """Motifs de type glob sur le chemin relatif (« tests/* », « *.min.js », « docs/ »)."""
    for pattern in patterns:
        pattern = pattern.strip().lstrip("./")
        if not pattern:
            continue
        if pattern.endswith("/") and (rel_path + "/").startswith(pattern):
            return True
        if fnmatch.fnmatch(rel_path, pattern) or fnmatch.fnmatch(rel_path, pattern.rstrip("/") + "/*"):
            return True
    return False


def collect_codebase(root: Path, settings: Settings, exclude: list[str] | None = None) -> CodeBase:
    files: list[SourceFile] = []
    manifests: list[ManifestFile] = []
    vendored: list[str] = []
    root = root.resolve()
    for path in sorted(root.rglob("*")):
        rel_parts = path.relative_to(root).parts
        if any(part in IGNORED_DIRS for part in rel_parts[:-1]):
            continue
        if path.is_symlink() or not path.is_file():
            continue
        if path.stat().st_size > settings.max_file_bytes:
            continue
        rel = "/".join(rel_parts)
        if exclude and is_excluded(rel, exclude):
            continue
        if path.name in MANIFEST_FILES:
            if (content := _read_text(path)) is not None:
                manifests.append(ManifestFile(path=rel, name=path.name, content=content))
            continue
        language = LANGUAGE_BY_EXTENSION.get(path.suffix.lower())
        if language and (content := _read_text(path)) is not None:
            if is_vendored(rel, content):
                vendored.append(rel)
                continue
            files.append(SourceFile(path=rel, language=language, content=content))
    return CodeBase(files=files, manifests=manifests, vendored=vendored)


def language_for_filename(filename: str) -> str | None:
    return LANGUAGE_BY_EXTENSION.get(Path(filename).suffix.lower())


GIT_URL = re.compile(
    r"^https://(github\.com|gitlab\.com)/[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+){1,3}?(\.git)?/?$"
)
GIT_BRANCH = re.compile(r"^[A-Za-z0-9._/-]{1,100}$")
CLONE_TIMEOUT_SECONDS = 120


def validate_git_url(url: str, branch: str | None) -> str:
    url = url.strip()
    if not GIT_URL.match(url) or ".." in url:
        raise UploadError("URL non supportée : dépôt public https://github.com/… ou https://gitlab.com/… uniquement.")
    if branch and (not GIT_BRANCH.match(branch) or branch.startswith("-") or ".." in branch):
        raise UploadError("Nom de branche invalide.")
    return url.rstrip("/")


def clone_repository(url: str, branch: str | None, dest: Path, settings: Settings, auth_header: str | None = None) -> None:
    """Clone superficiel, sans hooks, LFS, sous-modules ni invite d'identifiants.

    `auth_header` (dépôt privé) est transmis à git par variables d'environnement : il n'apparaît
    ni dans la ligne de commande (liste des processus) ni dans les messages d'erreur.
    """
    if not shutil.which("git"):
        raise UploadError("git n'est pas installé sur le serveur d'analyse.")
    cmd = [
        "git", "-c", "core.hooksPath=/dev/null", "-c", "core.symlinks=false", "-c", "protocol.file.allow=never",
        "-c", "credential.helper=", "clone", "--depth", "1", "--single-branch", "--no-tags",
    ]
    if branch:
        cmd += ["--branch", branch]
    cmd += ["--", url, str(dest)]
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_LFS_SKIP_SMUDGE": "1", "GCM_INTERACTIVE": "never"}
    if auth_header:
        env.update({"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "http.extraHeader",
                    "GIT_CONFIG_VALUE_0": f"Authorization: {auth_header}"})
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=CLONE_TIMEOUT_SECONDS, env=env)
    except subprocess.TimeoutExpired as exc:
        raise UploadError("Le clonage du dépôt a dépassé le délai autorisé.") from exc
    if result.returncode != 0:
        detail = result.stderr.strip().splitlines()[-1] if result.stderr.strip() else ""
        if "not found" in detail.lower() or "could not read" in detail.lower() or "authentication" in detail.lower():
            if auth_header:
                raise UploadError("Dépôt introuvable ou accès refusé : vérifiez les droits du compte connecté.")
            raise UploadError("Dépôt introuvable ou privé : connectez votre compte GitHub / GitLab pour les dépôts privés.")
        if "remote branch" in detail.lower():
            raise UploadError(f"Branche introuvable : {branch}")
        if auth_header:
            detail = detail.replace(auth_header, "****")
        raise UploadError(f"Échec du clonage du dépôt : {detail[:200]}")
    remove_tree(dest / ".git")
    total = sum(p.stat().st_size for p in dest.rglob("*") if p.is_file() and not p.is_symlink())
    if total > settings.max_uncompressed_bytes:
        raise UploadError("Dépôt trop volumineux pour la démo (500 Mo maximum).")


class Workspace:
    """Répertoire temporaire d'analyse, supprimé en fin de scan."""

    def __init__(self, base: Path):
        base.mkdir(parents=True, exist_ok=True)
        self.path = Path(tempfile.mkdtemp(prefix="scan-", dir=base))

    def cleanup(self) -> None:
        remove_tree(self.path)


def remove_tree(path: Path) -> None:
    """Suppression récursive robuste (les objets git sont en lecture seule sous Windows)."""

    def force(func, target, _exc):
        try:
            os.chmod(target, stat.S_IWRITE)
            func(target)
        except OSError:
            pass

    if path.exists():
        shutil.rmtree(path, onexc=force)
