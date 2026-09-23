"""SS-23 — commande `secuscan` pour l'intégration continue.

Usage (dans apps/api) :
    uv run python -m secuscan.cli scan CHEMIN [--fail-on high] [--format text|json|sarif] [--output FICHIER]

Configuration facultative : fichier `.secuscan.yml` à la racine du projet analysé (voir
docs/integration-ci.md). Les options de la ligne de commande priment sur le fichier.

Codes retour :
    0  aucune alerte au niveau du seuil ou au-dessus
    1  seuil dépassé : au moins une alerte au niveau du seuil ou au-dessus
    2  erreur d'utilisation ou de configuration
    3  erreur pendant l'analyse
"""
import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .config import Settings, get_settings
from .models import SEVERITY_ORDER, Finding, Scan, Severity
from .pipeline import ScanService, new_id
from .reports import SEVERITY_LABELS, build_json
from .sarif import build_sarif
from .storage import Storage

EXIT_OK, EXIT_THRESHOLD, EXIT_USAGE, EXIT_ERROR = 0, 1, 2, 3
LEVELS = ["critical", "high", "medium", "low", "none"]
CONFIG_KEYS = {"fail_on", "exclude", "ignore_rules", "ai", "offline"}


class ConfigError(ValueError):
    pass


@dataclass
class CliConfig:
    fail_on: str = "high"
    exclude: list[str] = field(default_factory=list)
    ignore_rules: list[str] = field(default_factory=list)
    ai: bool = False
    offline: bool = False


def load_config(path: Path | None) -> CliConfig:
    config = CliConfig()
    if path is None or not path.exists():
        return config
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path} : YAML invalide ({exc})") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"{path} : un objet (clé: valeur) est attendu")
    if unknown := set(data) - CONFIG_KEYS:
        raise ConfigError(f"{path} : clé(s) inconnue(s) {sorted(unknown)} ; clés possibles : {sorted(CONFIG_KEYS)}")
    if "fail_on" in data:
        if str(data["fail_on"]) not in LEVELS:
            raise ConfigError(f"{path} : fail_on doit valoir {' | '.join(LEVELS)}")
        config.fail_on = str(data["fail_on"])
    for key in ("exclude", "ignore_rules"):
        if key in data:
            value = data[key] or []
            if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
                raise ConfigError(f"{path} : {key} doit être une liste de chaînes")
            setattr(config, key, value)
    for key in ("ai", "offline"):
        if key in data:
            if not isinstance(data[key], bool):
                raise ConfigError(f"{path} : {key} doit valoir true ou false")
            setattr(config, key, data[key])
    return config


def blocking(findings: list[Finding], fail_on: str) -> list[Finding]:
    if fail_on == "none":
        return []
    threshold = SEVERITY_ORDER[Severity(fail_on)]
    return [f for f in findings if f.status == "open" and SEVERITY_ORDER[f.severity] <= threshold]


def run_scan(root: Path, config: CliConfig, base: Settings | None = None) -> tuple[Scan, list[Finding]]:
    base = base or get_settings()
    settings = base.model_copy(update={
        "secuscan_ai_disabled": base.secuscan_ai_disabled or not config.ai,
        "secuscan_offline": base.secuscan_offline or config.offline,
    })
    service = ScanService(settings, Storage(settings.data_dir / "cli.db"))
    scan = Scan(id=new_id(), project_name=f"cli:{root.resolve().name}", source="upload")
    service.storage.save_scan(scan)
    findings = service.run(scan, root, exclude=config.exclude)
    if config.ignore_rules:
        ignored = set(config.ignore_rules)
        for f in findings:
            if f.rule_id in ignored and f.status == "open":
                f.status = "dismissed"
                f.dismiss_reason, f.dismiss_justification = "not_applicable", "Règle ignorée par .secuscan.yml"
    return scan, findings


def render_text(scan: Scan, findings: list[Finding], fail_on: str) -> str:
    open_findings = sorted((f for f in findings if f.status == "open"),
                           key=lambda f: (SEVERITY_ORDER[f.severity], f.file, f.start_line))
    s = scan.summary
    lines = [
        f"SecuScan — {s.files_scanned} fichiers, {s.lines_scanned} lignes analysées en {s.duration_seconds} s",
        f"Score : {scan.score}/100 · {len(open_findings)} alerte(s) ouverte(s) · seuil de blocage : {fail_on}",
        "",
    ]
    for f in open_findings:
        lines.append(f"  {SEVERITY_LABELS[f.severity.value].upper():9} {f.file}:{f.start_line}  {f.rule_id}  {f.title}")
    for warning in s.warnings:
        lines.append(f"  ⚠ {warning}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="secuscan", description="Analyse de sécurité du code (SecuScan)")
    sub = parser.add_subparsers(dest="command", required=True)
    scan_cmd = sub.add_parser("scan", help="analyser un dossier")
    scan_cmd.add_argument("path", nargs="?", default=".", type=Path)
    scan_cmd.add_argument("--config", type=Path, help="fichier de configuration (défaut : CHEMIN/.secuscan.yml)")
    scan_cmd.add_argument("--fail-on", choices=LEVELS, help="sévérité minimale qui fait échouer la commande")
    scan_cmd.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    scan_cmd.add_argument("--output", type=Path, help="écrire le rapport dans un fichier")
    scan_cmd.add_argument("--exclude", action="append", default=[], help="motif à exclure (répétable)")
    scan_cmd.add_argument("--ai", action="store_true", help="activer l'enrichissement IA (clé OpenRouter requise)")
    scan_cmd.add_argument("--offline", action="store_true", help="sans appel réseau (base OSV depuis le cache)")
    args = parser.parse_args(argv)

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if not args.path.is_dir():
        print(f"Erreur : {args.path} n'est pas un dossier.", file=sys.stderr)
        return EXIT_USAGE
    try:
        config = load_config(args.config or args.path / ".secuscan.yml")
    except ConfigError as exc:
        print(f"Erreur de configuration : {exc}", file=sys.stderr)
        return EXIT_USAGE
    if args.config and not args.config.exists():
        print(f"Erreur : fichier de configuration introuvable : {args.config}", file=sys.stderr)
        return EXIT_USAGE
    config.fail_on = args.fail_on or config.fail_on
    config.exclude += args.exclude
    config.ai = config.ai or args.ai
    config.offline = config.offline or args.offline

    try:
        scan, findings = run_scan(args.path, config)
    except Exception as exc:  # noqa: BLE001 — code retour dédié aux erreurs d'analyse
        print(f"Erreur pendant l'analyse : {exc}", file=sys.stderr)
        return EXIT_ERROR

    if args.format == "sarif":
        report = json.dumps(build_sarif(findings), ensure_ascii=False, indent=2)
    elif args.format == "json":
        report = json.dumps(build_json(scan, findings), ensure_ascii=False, indent=2)
    else:
        report = render_text(scan, findings, config.fail_on)
    if args.output:
        args.output.write_text(report, encoding="utf-8")
    else:
        print(report)

    blockers = blocking(findings, config.fail_on)
    if blockers:
        print(f"\nÉchec : {len(blockers)} alerte(s) de sévérité « {config.fail_on} » ou supérieure.", file=sys.stderr)
        return EXIT_THRESHOLD
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
