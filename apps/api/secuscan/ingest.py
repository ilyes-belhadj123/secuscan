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
    ".cs": "csharp",
    ".go": "go",
}

MANIFEST_FILES = {
    "requirements.txt": "python",
    "pyproject.toml": "python",
    "package.json": "javascript",
    "package-lock.json": "javascript",
    "composer.json": "php",
    "composer.lock": "php",
    "pom.xml": "java",
    "*.csproj": "csharp",  # le nom du fichier est celui du projet : MonApi.csproj
    "go.mod": "go",
    # Fichiers de verrouillage : versions réellement installées
    "yarn.lock": "javascript",
    "pnpm-lock.yaml": "javascript",
    "poetry.lock": "python",
    "uv.lock": "python",
    "Pipfile.lock": "python",
}
# Variantes de requirements.txt (requirements-dev.txt, requirements.prod.txt)
_REQUIREMENTS_VARIANT = re.compile(r"^requirements[\w.-]*\.txt$", re.I)


# Langages de code applicatif (revue logique IA, suivi des données) ; le reste est de l'infrastructure
CODE_LANGUAGES = {"python", "javascript", "typescript", "php", "java", "csharp", "go"}
_K8S = re.compile(r"^apiVersion:\s*\S+", re.M)
_K8S_KIND = re.compile(r"^kind:\s*\w+", re.M)


def iac_kind(filename: str) -> str | None:
    """Fichier d'infrastructure reconnaissable à son nom : Dockerfile, Terraform, docker-compose."""
    name = filename.lower()
    if name == "dockerfile" or name.startswith("dockerfile.") or name.endswith(".dockerfile"):
        return "dockerfile"
    if name.endswith(".tf"):
        return "terraform"
    if re.fullmatch(r"(docker-)?compose([.-][\w.-]+)?\.ya?ml", name):
        return "compose"
    return None


def yaml_kind(content: str) -> str | None:
    """Un YAML quelconque n'est analysé que s'il décrit des ressources Kubernetes."""
    return "kubernetes" if _K8S.search(content) and _K8S_KIND.search(content) else None


def manifest_kind(filename: str) -> str | None:
    """Clé de MANIFEST_FILES pour un nom de fichier (« MonApi.csproj » → « *.csproj »), ou None."""
    if filename in MANIFEST_FILES:
        return filename
    if filename.lower().endswith(".csproj"):
        return "*.csproj"
    if _REQUIREMENTS_VARIANT.match(filename):
        return "requirements.txt"
    return None

IGNORED_DIRS = {
    ".git", "node_modules", "vendor", ".venv", "venv", "env", "__pycache__",
    "dist", "build", "target", ".next", ".idea", ".vscode", "coverage",
    "bin", "obj",  # sorties de compilation .NET
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


# Fichiers de configuration : lus seulement pour y chercher des secrets (mot de passe de la base dans
# application.properties, jeton dans .npmrc…), sans règles de code ni revue IA
CONFIG_LANGUAGE = "config"
CONFIG_EXTENSIONS = {".properties", ".json", ".yml", ".yaml", ".ini", ".cfg", ".conf", ".toml", ".xml", ".config",
                     ".env", ".tfvars"}
CONFIG_NAMES = {".npmrc", ".pypirc", ".netrc", ".dockercfg", ".git-credentials", "credentials"}


def is_config_file(name: str) -> bool:
    lower = name.lower()
    return (lower in CONFIG_NAMES or lower.startswith(".env") or Path(lower).suffix in CONFIG_EXTENSIONS)


@dataclass
class CodeBase:
    files: list[SourceFile]
    manifests: list[ManifestFile]
    vendored: list[str] = field(default_factory=list)  # bibliothèques tierces ignorées
    configs: list[SourceFile] = field(default_factory=list)  # pour la recherche de secrets uniquement

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
# Dossiers de dépendances recopiées (pas « lib/ » : c'est souvent le code du projet, en Node.js)
_VENDOR_DIR = re.compile(r"/(vendors?|libs|third[-_]?party|bower_components|jspm_packages)/", re.I)


def is_vendored(rel_path: str, content: str) -> bool:
    """Fichier minifié, bibliothèque rangée dans un dossier de dépendances recopiées, ou reconnaissable
    à son bandeau (version + licence)."""
    if _MINIFIED_NAME.search(rel_path):
        return True
    if not rel_path.endswith((".js", ".mjs", ".cjs")):
        return False
    if _VENDOR_DIR.search("/" + rel_path):
        return True
    # Bandeau en tête de fichier, éventuellement après une ou deux lignes (« var $ = require(…) »)
    head = content.lstrip()[:1200]
    start = head.find("/*")
    if 0 <= start < 400:
        banner = head[start:].split("*/", 1)[0]
        if _VERSION.search(banner) and _LICENSE.search(banner):
            return True
    lines = content.split("\n", 200)[:200]
    return sum(1 for line in lines if len(line) > 500) >= 3  # code minifié sans nom explicite


def is_excluded(rel_path: str, patterns: list[str]) -> bool:
    """Motifs de type glob sur le chemin relatif (« tests/* », « *.min.js », « docs/ »)."""
    for pattern in patterns:
        pattern = pattern.strip().removeprefix("./").lstrip("/")  # « .github/ » garde son point
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
    configs: list[SourceFile] = []
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
        if kind := manifest_kind(path.name):
            if (content := _read_text(path)) is not None:
                manifests.append(ManifestFile(path=rel, name=kind, content=content))
            continue
        language = LANGUAGE_BY_EXTENSION.get(path.suffix.lower()) or iac_kind(path.name)
        if not language and path.suffix.lower() in (".yaml", ".yml"):
            if (content := _read_text(path)) is not None and (language := yaml_kind(content)):
                files.append(SourceFile(path=rel, language=language, content=content))
            elif content is not None:
                configs.append(SourceFile(path=rel, language=CONFIG_LANGUAGE, content=content))
            continue
        if not language and is_config_file(path.name):
            if (content := _read_text(path)) is not None and not is_vendored(rel, content):
                configs.append(SourceFile(path=rel, language=CONFIG_LANGUAGE, content=content))
            continue
        if language and (content := _read_text(path)) is not None:
            if is_vendored(rel, content):
                vendored.append(rel)
                continue
            files.append(SourceFile(path=rel, language=language, content=content))
    return CodeBase(files=files, manifests=manifests, vendored=vendored, configs=configs)


def language_for_filename(filename: str) -> str | None:
    name = Path(filename).name
    return LANGUAGE_BY_EXTENSION.get(Path(name).suffix.lower()) or iac_kind(name)


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
        "-c", "credential.helper=", "clone", "--depth", str(max(1, settings.secuscan_history_commits)),
        "--single-branch", "--no-tags",
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
    # Historique relu ici (dépôt que SecuScan vient de cloner, configuration git maîtrisée), puis supprimé
    from .analyzers.history import HISTORY_FILE, export_history  # import local : history dépend de ce module
    export_history(dest, dest.parent / HISTORY_FILE, settings.secuscan_history_commits)
    remove_tree(dest / ".git")
    total = sum(p.stat().st_size for p in dest.rglob("*") if p.is_file() and not p.is_symlink())
    if total > settings.max_uncompressed_bytes:
        raise UploadError("Dépôt trop volumineux pour la démo (500 Mo maximum).")


class Workspace:
    """Répertoire temporaire d'analyse, supprimé en fin de scan."""

    def __init__(self, base: Path):
        base.mkdir(parents=True, exist_ok=True)
        self.path = Path(tempfile.mkdtemp(prefix="scan-", dir=base))

    @classmethod
    def existing(cls, path: Path) -> "Workspace":
        """Répertoire déjà créé (par l'API), repris par le worker qui exécute l'analyse."""
        workspace = cls.__new__(cls)
        workspace.path = path
        return workspace

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
