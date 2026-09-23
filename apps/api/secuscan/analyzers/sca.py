"""Couche 3 — dépendances vulnérables (SCA) via la base publique OSV.dev.

Les réponses OSV sont mises en cache localement : une démo déjà jouée une fois
fonctionne ensuite sans réseau.
"""
import json
import logging
import re
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

import httpx
from defusedxml import DefusedXmlException
from defusedxml.ElementTree import fromstring as safe_xml_fromstring

from ..ingest import ManifestFile
from ..models import Advisory, Severity
from ..storage import Storage

log = logging.getLogger(__name__)

OSV_QUERYBATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/{id}"


@dataclass
class Dependency:
    ecosystem: str  # nom d'écosystème OSV : PyPI, npm, Packagist, Maven
    name: str
    version: str
    manifest: str
    line: int


# --------------------------------------------------------------------------- parsers
def _line_of(content: str, needle: str) -> int:
    for i, line in enumerate(content.split("\n"), start=1):
        if needle in line:
            return i
    return 1


def _clean_version(spec: str) -> str | None:
    """Garde uniquement les versions exactes ou quasi exactes (^1.2.3, ~1.2.3, ==1.2.3)."""
    spec = spec.strip().lstrip("^~=v ")
    return spec if re.fullmatch(r"\d+(\.\d+)*([.-][\w.]+)?", spec) else None


def parse_requirements(m: ManifestFile) -> list[Dependency]:
    deps = []
    for i, raw in enumerate(m.content.split("\n"), start=1):
        line = raw.split("#")[0].strip()
        match = re.match(r"^([A-Za-z0-9_.\-\[\]]+)\s*==\s*([\w.\-]+)", line)
        if match:
            name = re.sub(r"\[.*\]", "", match.group(1))
            deps.append(Dependency("PyPI", name, match.group(2), m.path, i))
    return deps


def parse_pyproject(m: ManifestFile) -> list[Dependency]:
    deps = []
    for match in re.finditer(r"[\"']([A-Za-z0-9_.\-]+)\s*==\s*([\w.\-]+)[\"']", m.content):
        deps.append(Dependency("PyPI", match.group(1), match.group(2), m.path, _line_of(m.content, match.group(0))))
    return deps


def parse_package_json(m: ManifestFile) -> list[Dependency]:
    try:
        data = json.loads(m.content)
    except json.JSONDecodeError:
        return []
    deps = []
    for section in ("dependencies", "devDependencies"):
        for name, spec in (data.get(section) or {}).items():
            if isinstance(spec, str) and (version := _clean_version(spec)):
                deps.append(Dependency("npm", name, version, m.path, _line_of(m.content, f'"{name}"')))
    return deps


def parse_package_lock(m: ManifestFile) -> list[Dependency]:
    try:
        data = json.loads(m.content)
    except json.JSONDecodeError:
        return []
    deps = []
    for key, info in (data.get("packages") or {}).items():
        if not (key.startswith("node_modules/") and isinstance(info, dict)):
            continue
        if version := _clean_version(str(info.get("version", ""))):
            name = key.split("node_modules/")[-1]
            deps.append(Dependency("npm", name, version, m.path, _line_of(m.content, f'"{key}"')))
    if not deps:
        # Format lockfile v1 : arbre "dependencies" imbriqué
        stack = list((data.get("dependencies") or {}).items())
        while stack:
            name, info = stack.pop()
            if not isinstance(info, dict):
                continue
            if version := _clean_version(str(info.get("version", ""))):
                deps.append(Dependency("npm", name, version, m.path, _line_of(m.content, f'"{name}"')))
            stack.extend((info.get("dependencies") or {}).items())
    return deps


def parse_composer_json(m: ManifestFile) -> list[Dependency]:
    try:
        data = json.loads(m.content)
    except json.JSONDecodeError:
        return []
    deps = []
    for name, spec in (data.get("require") or {}).items():
        if "/" in name and isinstance(spec, str) and (version := _clean_version(spec)):
            deps.append(Dependency("Packagist", name, version, m.path, _line_of(m.content, f'"{name}"')))
    return deps


def parse_composer_lock(m: ManifestFile) -> list[Dependency]:
    try:
        data = json.loads(m.content)
    except json.JSONDecodeError:
        return []
    deps = []
    for pkg in data.get("packages") or []:
        if (version := _clean_version(str(pkg.get("version", "")))) and pkg.get("name"):
            deps.append(
                Dependency("Packagist", pkg["name"], version, m.path, _line_of(m.content, f'"{pkg["name"]}"'))
            )
    return deps


def parse_pom(m: ManifestFile) -> list[Dependency]:
    try:
        # Le pom.xml vient du dépôt analysé (donnée non fiable) : defusedxml refuse DTD et entités
        # (« billion laughs », entités externes) qui pourraient saturer le serveur d'analyse
        root = safe_xml_fromstring(m.content, forbid_dtd=True)
    except (ET.ParseError, DefusedXmlException):
        log.warning("pom.xml ignoré (XML invalide ou constructions dangereuses) : %s", m.path)
        return []
    ns = {"m": root.tag.split("}")[0].strip("{")} if root.tag.startswith("{") else {}
    prefix = "m:" if ns else ""
    deps = []
    for dep in root.iter(f"{{{ns['m']}}}dependency" if ns else "dependency"):
        group = dep.findtext(f"{prefix}groupId", namespaces=ns)
        artifact = dep.findtext(f"{prefix}artifactId", namespaces=ns)
        version = dep.findtext(f"{prefix}version", namespaces=ns)
        if group and artifact and version and (version := _clean_version(version)):
            deps.append(
                Dependency("Maven", f"{group}:{artifact}", version, m.path, _line_of(m.content, f"<artifactId>{artifact}<"))
            )
    return deps


PARSERS = {
    "requirements.txt": parse_requirements,
    "pyproject.toml": parse_pyproject,
    "package.json": parse_package_json,
    "package-lock.json": parse_package_lock,
    "composer.json": parse_composer_json,
    "composer.lock": parse_composer_lock,
    "pom.xml": parse_pom,
}


# Manifeste à plages de versions → lockfile qui donne les versions réellement installées
_LOCKFILE_FOR = {"package.json": "package-lock.json", "composer.json": "composer.lock"}


def parse_manifests(manifests: list[ManifestFile]) -> list[Dependency]:
    seen: set[tuple[str, str, str]] = set()
    deps: list[Dependency] = []
    paths = {m.path for m in manifests}

    def superseded(m: ManifestFile) -> bool:
        # Avec un lockfile dans le même dossier, les plages (« ^6.0.0 ») du manifeste ne disent pas
        # quelle version est installée : seul le lockfile fait foi (sinon faux positifs)
        lock = _LOCKFILE_FOR.get(m.name)
        return bool(lock) and (m.path[: -len(m.name)] + lock) in paths

    # Les lockfiles sont plus précis : on les traite en premier
    for m in sorted((m for m in manifests if not superseded(m)),
                    key=lambda x: 0 if x.name.endswith(".lock") or "lock" in x.name else 1):
        for dep in PARSERS[m.name](m):
            key = (dep.ecosystem, dep.name.lower(), dep.version)
            if key not in seen:
                seen.add(key)
                deps.append(dep)
    return deps


# --------------------------------------------------------------------------- versions
def version_key(version: str) -> tuple:
    parts = re.split(r"[.\-]", version)
    return tuple((0, int(p)) if p.isdigit() else (-1, p) for p in parts)


# --------------------------------------------------------------------------- OSV
_OSV_SEVERITY = {"CRITICAL": Severity.critical, "HIGH": Severity.high, "MODERATE": Severity.medium,
                 "MEDIUM": Severity.medium, "LOW": Severity.low}


OSV_BATCH_SIZE = 500  # l'API refuse les lots de plus de 1 000 requêtes


class OSVClient:
    def __init__(self, storage: Storage, offline: bool = False):
        self.storage = storage
        self.offline = offline
        self.errors: list[str] = []  # remontées à l'utilisateur : ne jamais échouer en silence

    def _get_json(self, method: str, url: str, **kwargs):
        with httpx.Client(timeout=20) as client:
            resp = client.request(method, url, **kwargs)
            resp.raise_for_status()
            return resp.json()

    def vuln_ids(self, deps: list[Dependency]) -> dict[int, list[str]]:
        result: dict[int, list[str]] = {}
        missing: list[int] = []
        for i, dep in enumerate(deps):
            cached = self.storage.cache_get("osv-query", f"{dep.ecosystem}|{dep.name}|{dep.version}")
            if cached is not None:
                result[i] = cached
            else:
                missing.append(i)
        if missing and self.offline:
            self.errors.append(f"{len(missing)} dépendance(s) non vérifiée(s) : mode hors ligne et absentes du cache.")
        elif missing:
            failed = 0
            for start in range(0, len(missing), OSV_BATCH_SIZE):
                chunk = missing[start : start + OSV_BATCH_SIZE]
                queries = [
                    {"package": {"name": deps[i].name, "ecosystem": deps[i].ecosystem}, "version": deps[i].version}
                    for i in chunk
                ]
                try:
                    data = self._get_json("POST", OSV_QUERYBATCH, json={"queries": queries})
                except httpx.HTTPError as exc:
                    log.warning("OSV indisponible : %s", exc)
                    failed += len(chunk)
                    continue
                for i, res in zip(chunk, data.get("results", []), strict=False):
                    ids = [v["id"] for v in res.get("vulns") or []]
                    dep = deps[i]
                    self.storage.cache_set("osv-query", f"{dep.ecosystem}|{dep.name}|{dep.version}", ids)
                    result[i] = ids
            if failed:
                self.errors.append(
                    f"{failed} dépendance(s) sur {len(deps)} non vérifiée(s) : base de vulnérabilités OSV injoignable."
                )
        return result

    def vuln(self, vuln_id: str) -> dict | None:
        cached = self.storage.cache_get("osv-vuln", vuln_id)
        if cached is not None or self.offline:
            return cached
        try:
            data = self._get_json("GET", OSV_VULN.format(id=vuln_id))
        except httpx.HTTPError as exc:
            log.warning("OSV %s indisponible : %s", vuln_id, exc)
            return None
        self.storage.cache_set("osv-vuln", vuln_id, data)
        return data


def _fixed_version(vuln: dict, dep: Dependency) -> str | None:
    candidates = []
    for affected in vuln.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("name", "").lower() != dep.name.lower():
            continue
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                if "fixed" in event:
                    candidates.append(event["fixed"])
    above = [c for c in candidates if version_key(c) > version_key(dep.version)]
    return min(above, key=version_key) if above else None


def _severity(vuln: dict) -> Severity:
    label = str((vuln.get("database_specific") or {}).get("severity", "")).upper()
    return _OSV_SEVERITY.get(label, Severity.medium)


@dataclass
class VulnerableDependency:
    dependency: Dependency
    advisories: list[Advisory]

    @property
    def severity(self) -> Severity:
        order = [Severity.critical, Severity.high, Severity.medium, Severity.low]
        return min((a.severity for a in self.advisories), key=order.index)

    @property
    def fixed_version(self) -> str | None:
        fixes = [a.fixed_version for a in self.advisories if a.fixed_version]
        return max(fixes, key=version_key) if fixes else None


def scan_dependencies(deps: list[Dependency], client: OSVClient) -> list[VulnerableDependency]:
    ids_by_dep = client.vuln_ids(deps)
    all_ids = sorted({vid for ids in ids_by_dep.values() for vid in ids})
    with ThreadPoolExecutor(max_workers=8) as pool:
        vulns = dict(zip(all_ids, pool.map(client.vuln, all_ids), strict=True))
    if missing_details := sum(1 for v in vulns.values() if v is None):
        client.errors.append(f"{missing_details} fiche(s) de vulnérabilité non récupérée(s) depuis OSV.")

    results = []
    for i, ids in ids_by_dep.items():
        dep = deps[i]
        details = [vulns[v] for v in ids if vulns.get(v)]
        # Dédoublonnage : on préfère les advisories GHSA (qui portent une sévérité)
        ghsa_aliases = {a for d in details if d["id"].startswith("GHSA") for a in d.get("aliases", [])}
        advisories = []
        for d in details:
            if not d["id"].startswith("GHSA") and (d["id"] in ghsa_aliases or
                                                    any(a.startswith("GHSA") for a in d.get("aliases", []))):
                continue
            advisories.append(
                Advisory(
                    id=d["id"],
                    aliases=[a for a in d.get("aliases", []) if a.startswith("CVE")],
                    summary=(d.get("summary") or d.get("details", "")[:200]).strip(),
                    severity=_severity(d),
                    fixed_version=_fixed_version(d, dep),
                    url=f"https://osv.dev/vulnerability/{d['id']}",
                )
            )
        if advisories:
            order = [Severity.critical, Severity.high, Severity.medium, Severity.low]
            advisories.sort(key=lambda a: order.index(a.severity))
            results.append(VulnerableDependency(dep, advisories))
    return results
