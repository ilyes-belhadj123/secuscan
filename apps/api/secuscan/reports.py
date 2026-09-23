"""Exports de rapport : PDF (reportlab) et JSON (schéma publié)."""
import io
from datetime import datetime
from html import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    KeepTogether,
    PageBreak,
    Paragraph,
    Preformatted,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from .models import SEVERITY_ORDER, Finding, Scan
from .scoring import grade

REPORT_SCHEMA_ID = "https://secuscan.example.com/schemas/report-v1.json"

SEVERITY_LABELS = {"critical": "Critique", "high": "Élevée", "medium": "Moyenne", "low": "Faible"}
SEVERITY_COLORS = {
    "critical": colors.HexColor("#B42318"),
    "high": colors.HexColor("#C4320A"),
    "medium": colors.HexColor("#B54708"),
    "low": colors.HexColor("#475467"),
}
KIND_LABELS = {"sast": "Code", "ai": "Logique (IA)", "secret": "Secret", "dependency": "Dépendance"}
INK = colors.HexColor("#101828")
MUTED = colors.HexColor("#667085")
LINE = colors.HexColor("#EAECF0")
BRAND = colors.HexColor("#1D4ED8")


def _styles():
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("t", parent=base["Title"], fontSize=20, textColor=INK, spaceAfter=4, alignment=0),
        "subtitle": ParagraphStyle("st", parent=base["Normal"], fontSize=10, textColor=MUTED),
        "h2": ParagraphStyle("h2", parent=base["Heading2"], fontSize=13, textColor=INK, spaceBefore=10),
        "h3": ParagraphStyle("h3", parent=base["Heading3"], fontSize=11, textColor=INK, spaceAfter=2),
        "body": ParagraphStyle("b", parent=base["Normal"], fontSize=9, leading=12.5, textColor=INK),
        "small": ParagraphStyle("s", parent=base["Normal"], fontSize=8, leading=10.5, textColor=MUTED),
        "score": ParagraphStyle("sc", parent=base["Normal"], fontSize=34, leading=38, alignment=TA_CENTER,
                                textColor=INK, fontName="Helvetica-Bold"),
        "code": ParagraphStyle("c", parent=base["Code"], fontSize=7, leading=8.6, textColor=INK,
                               backColor=colors.HexColor("#F9FAFB"), borderPadding=4),
    }


def _p(text: str, style) -> Paragraph:
    return Paragraph(escape(text or "").replace("\n", "<br/>"), style)


def _footer(label: str):
    def draw(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(MUTED)
        canvas.drawString(18 * mm, 10 * mm, f"{label} — rapport confidentiel")
        canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"Page {doc.page}")
        canvas.restoreState()

    return draw


def _sorted(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (SEVERITY_ORDER[f.severity], f.file, f.start_line))


def build_pdf(
    scan: Scan, findings: list[Finding], prepared_for: str | None = None, prepared_by: str | None = None
) -> bytes:
    """Rapport PDF. `prepared_by` renseigné = marque blanche : le nom de l'ESN remplace SecuScan."""
    st = _styles()
    buf = io.BytesIO()
    brand = prepared_by or "SecuScan"
    doc = SimpleDocTemplate(
        buf, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=16 * mm, bottomMargin=18 * mm,
        title=f"Rapport d'analyse de sécurité — {scan.project_name}", author=brand,
    )
    open_findings = _sorted([f for f in findings if f.status == "open"])
    date = datetime.fromisoformat(scan.completed_at or scan.created_at).strftime("%d/%m/%Y %H:%M")
    s = scan.summary
    story = []
    if prepared_by:
        story.append(Paragraph(f"<font color='#1D4ED8'><b>{escape(prepared_by)}</b></font>", st["h3"]))
    story += [
        _p("Rapport d'analyse de sécurité", st["title"]),
        _p(f"Projet : {scan.project_name}  ·  Analyse du {date} (UTC)  ·  Réf. {scan.id}", st["subtitle"]),
    ]
    if prepared_for or prepared_by:
        parts = ([f"Préparé pour : {prepared_for}"] if prepared_for else []) + (
            [f"Réalisé par : {prepared_by}"] if prepared_by else [])
        story.append(_p("  ·  ".join(parts), st["subtitle"]))
    story.append(Spacer(1, 8 * mm))

    # Synthèse : score + répartition
    score = scan.score if scan.score is not None else 0
    sev_rows = [["Sévérité", "Alertes"]] + [
        [SEVERITY_LABELS[k], str(s.by_severity.get(k, 0))] for k in ("critical", "high", "medium", "low")
    ]
    sev_table = Table(sev_rows, colWidths=[40 * mm, 22 * mm])
    sev_style = [
        ("FONT", (0, 0), (-1, 0), "Helvetica-Bold", 8.5),
        ("FONT", (0, 1), (-1, -1), "Helvetica", 9),
        ("TEXTCOLOR", (0, 0), (-1, 0), MUTED),
        ("LINEBELOW", (0, 0), (-1, -1), 0.5, LINE),
        ("ALIGN", (1, 0), (1, -1), "RIGHT"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]
    for i, k in enumerate(("critical", "high", "medium", "low"), start=1):
        sev_style.append(("TEXTCOLOR", (0, i), (0, i), SEVERITY_COLORS[k]))
    sev_table.setStyle(TableStyle(sev_style))

    score_cell = [
        _p(f"{score}/100", st["score"]),
        Paragraph(f"<para alignment='center'>Note <b>{grade(score)}</b> — score de sécurité</para>", st["small"]),
    ]
    stats = (
        f"{s.files_scanned} fichiers · {s.lines_scanned} lignes analysées\n"
        f"Langages : {', '.join(f'{k} ({v})' for k, v in s.languages.items()) or 'n/a'}\n"
        f"{s.total} alertes ouvertes · {s.false_positives} faux positifs écartés par l'IA · "
        f"{s.dismissed} ignorées avec justification"
    )
    summary = Table(
        [[score_cell, sev_table], [_p(stats, st["small"]), ""]],
        colWidths=[70 * mm, 104 * mm],
    )
    summary.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("SPAN", (0, 1), (1, 1)),
        ("BOX", (0, 0), (-1, -1), 0.6, LINE),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    story += [summary, Spacer(1, 4 * mm)]
    if s.warnings:
        story.append(_p("Limites de cette analyse : " + " ".join(s.warnings), st["small"]))
        story.append(Spacer(1, 3 * mm))

    if s.by_owasp:
        story.append(_p("Catégories OWASP Top 10 les plus représentées", st["h2"]))
        rows = [[k, str(v)] for k, v in list(s.by_owasp.items())[:6]]
        t = Table(rows, colWidths=[150 * mm, 24 * mm])
        t.setStyle(TableStyle([
            ("FONT", (0, 0), (-1, -1), "Helvetica", 9),
            ("LINEBELOW", (0, 0), (-1, -1), 0.5, LINE),
            ("ALIGN", (1, 0), (1, -1), "RIGHT"),
        ]))
        story.append(t)

    # Tableau récapitulatif
    story.append(_p("Liste des alertes", st["h2"]))
    rows = [["#", "Sévérité", "Type", "Alerte", "Emplacement"]]
    for i, f in enumerate(open_findings, start=1):
        rows.append([
            str(i), SEVERITY_LABELS[f.severity.value], KIND_LABELS[f.kind],
            _p(f.title, st["body"]), _p(f"{f.file}:{f.start_line}", st["small"]),
        ])
    table = Table(rows, colWidths=[8 * mm, 18 * mm, 20 * mm, 72 * mm, 56 * mm], repeatRows=1)
    style = [
        ("FONT", (0, 0), (-1, 0), "Helvetica-Bold", 8),
        ("FONT", (0, 1), (-1, -1), "Helvetica", 8),
        ("TEXTCOLOR", (0, 0), (-1, 0), MUTED),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, LINE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]
    for i, f in enumerate(open_findings, start=1):
        style.append(("TEXTCOLOR", (1, i), (1, i), SEVERITY_COLORS[f.severity.value]))
    table.setStyle(TableStyle(style))
    story += [table, PageBreak()]

    # Détail
    story.append(_p("Détail des alertes et correctifs proposés", st["h2"]))
    for i, f in enumerate(open_findings, start=1):
        block = [
            _p(f"{i}. {f.title}", st["h3"]),
            Paragraph(
                f"<font color='{SEVERITY_COLORS[f.severity.value].hexval().replace('0x', '#')}'>"
                f"<b>{SEVERITY_LABELS[f.severity.value]}</b></font> · {escape(f.file)}:{f.start_line}"
                f" · {escape(f.cwe or '')} · {escape(f.owasp or '')}",
                st["small"],
            ),
            Spacer(1, 2 * mm),
        ]
        exp = f.ai.explanation if f.ai else None
        if exp and exp.definition:
            block += [_p(f"Le problème : {exp.definition}", st["body"]),
                      _p(f"Impact métier : {exp.business_impact}", st["body"])]
        else:
            block.append(_p(f.message, st["body"]))
        if f.ai and f.ai.fix:
            block += [Spacer(1, 1.5 * mm), _p(f"Correctif : {f.ai.fix.explanation}", st["body"])]
            diff_lines = f.ai.fix.diff.split("\n")[2:30]
            block.append(Preformatted("\n".join(diff_lines), st["code"], maxLineLength=110))
        elif f.fix_hint:
            block.append(_p(f"Correctif : {f.fix_hint}", st["body"]))
        block.append(Spacer(1, 5 * mm))
        story.append(KeepTogether(block[:4]))
        story += block[4:]

    # Annexes : faux positifs et alertes ignorées
    fps = [f for f in findings if f.status == "false_positive"]
    dismissed = [f for f in findings if f.status == "dismissed"]
    if fps or dismissed:
        story.append(_p("Annexe — alertes écartées", st["h2"]))
        for f in fps:
            story.append(_p(f"[Faux positif IA] {f.title} — {f.file}:{f.start_line} — "
                            f"{f.ai.reason if f.ai else ''}", st["small"]))
        for f in dismissed:
            story.append(_p(f"[Ignorée] {f.title} — {f.file}:{f.start_line} — "
                            f"{f.dismiss_justification or ''}", st["small"]))

    story += [Spacer(1, 6 * mm), _p(
        "Les correctifs sont des suggestions générées automatiquement : ils doivent être relus et testés "
        "avant intégration. Aucune valeur de secret n'apparaît dans ce rapport.", st["small"])]
    footer = _footer(brand)
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buf.getvalue()


def build_json(scan: Scan, findings: list[Finding]) -> dict:
    return {
        "$schema": REPORT_SCHEMA_ID,
        "generator": "SecuScan",
        "scan": scan.model_dump(mode="json"),
        "findings": [f.model_dump(mode="json") for f in _sorted(findings)],
    }


def report_json_schema() -> dict:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": REPORT_SCHEMA_ID,
        "title": "Rapport SecuScan",
        "type": "object",
        "required": ["scan", "findings"],
        "properties": {
            "generator": {"type": "string"},
            "scan": Scan.model_json_schema(),
            "findings": {"type": "array", "items": Finding.model_json_schema()},
        },
    }
