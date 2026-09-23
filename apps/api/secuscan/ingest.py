"""Import du code : extraction ZIP sécurisée, détection des langages, collecte des fichiers."""
import shutil
import stat
import tempfile
import zipfile
from dataclasses import dataclass
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


def collect_codebase(root: Path, settings: Settings) -> CodeBase:
    files: list[SourceFile] = []
    manifests: list[ManifestFile] = []
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
        if path.name in MANIFEST_FILES:
            if (content := _read_text(path)) is not None:
                manifests.append(ManifestFile(path=rel, name=path.name, content=content))
            continue
        language = LANGUAGE_BY_EXTENSION.get(path.suffix.lower())
        if language and (content := _read_text(path)) is not None:
            files.append(SourceFile(path=rel, language=language, content=content))
    return CodeBase(files=files, manifests=manifests)


def language_for_filename(filename: str) -> str | None:
    return LANGUAGE_BY_EXTENSION.get(Path(filename).suffix.lower())


class Workspace:
    """Répertoire temporaire d'analyse, supprimé en fin de scan."""

    def __init__(self, base: Path):
        base.mkdir(parents=True, exist_ok=True)
        self.path = Path(tempfile.mkdtemp(prefix="scan-", dir=base))

    def cleanup(self) -> None:
        shutil.rmtree(self.path, ignore_errors=True)
