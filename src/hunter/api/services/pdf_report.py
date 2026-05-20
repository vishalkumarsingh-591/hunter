"""PDF export for scan findings.

The renderer is deliberately defensive: it never embeds raw repository content
verbatim (only bounded excerpts: file path + line number) and it truncates any
overlong fields so a malicious or pathological scan cannot blow up the PDF.
"""

from __future__ import annotations

import html
import io
from datetime import datetime
from typing import Iterable

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfgen.canvas import Canvas
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    KeepTogether,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

from hunter.api.schemas import FindingSummary, FindingsPage, ScanDetail

BRAND_NAVY = colors.HexColor("#0b1f3a")
BRAND_NAVY_LIGHT = colors.HexColor("#132d52")
BRAND_ORANGE = colors.HexColor("#f57c20")
BRAND_ORANGE_SOFT = colors.HexColor("#fff4eb")
TEXT_MUTED = colors.HexColor("#64748b")
SURFACE_BORDER = colors.HexColor("#e2e8f0")
SURFACE_ALT = colors.HexColor("#f8fafc")

SEV_FILL: dict[str, colors.Color] = {
    "CRITICAL": colors.HexColor("#dc2626"),
    "HIGH": colors.HexColor("#ea580c"),
    "MEDIUM": colors.HexColor("#f59e0b"),
    "LOW": colors.HexColor("#0284c7"),
    "INFO": colors.HexColor("#94a3b8"),
}

MAX_FINDINGS_IN_PDF = 500
MAX_FIELD_CHARS = 240


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "Title",
            parent=base["Title"],
            fontSize=24,
            leading=28,
            textColor=BRAND_NAVY,
            alignment=TA_LEFT,
        ),
        "subtitle": ParagraphStyle(
            "Subtitle",
            parent=base["Heading2"],
            fontSize=11,
            leading=14,
            textColor=TEXT_MUTED,
            alignment=TA_LEFT,
        ),
        "h2": ParagraphStyle(
            "H2",
            parent=base["Heading2"],
            fontSize=14,
            leading=18,
            spaceBefore=12,
            spaceAfter=6,
            textColor=BRAND_NAVY,
        ),
        "body": ParagraphStyle(
            "Body",
            parent=base["BodyText"],
            fontSize=9.5,
            leading=12,
            textColor=colors.HexColor("#0f172a"),
        ),
        "small": ParagraphStyle(
            "Small",
            parent=base["BodyText"],
            fontSize=8.5,
            leading=11,
            textColor=TEXT_MUTED,
        ),
        "mono": ParagraphStyle(
            "Mono",
            parent=base["BodyText"],
            fontName="Courier",
            fontSize=8.5,
            leading=11,
            textColor=colors.HexColor("#0f172a"),
        ),
        "finding_title": ParagraphStyle(
            "FindingTitle",
            parent=base["BodyText"],
            fontSize=10,
            leading=13,
            textColor=BRAND_NAVY,
            spaceAfter=2,
        ),
    }


def _safe(text: str | None, limit: int = MAX_FIELD_CHARS) -> str:
    if not text:
        return ""
    s = text.strip()
    if len(s) > limit:
        s = s[: limit - 1] + "…"
    return html.escape(s)


def _fmt_dt(dt: datetime | None) -> str:
    if not dt:
        return "—"
    return dt.strftime("%Y-%m-%d %H:%M UTC")


def _sev_badge(severity: str) -> Table:
    fill = SEV_FILL.get(severity.upper(), TEXT_MUTED)
    t = Table([[severity.upper()]], colWidths=[18 * mm], rowHeights=[6 * mm])
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), fill),
                ("TEXTCOLOR", (0, 0), (-1, -1), colors.white),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("ROUNDEDCORNERS", [3, 3, 3, 3]),
            ]
        )
    )
    return t


def _draw_header_footer(canvas: Canvas, doc: BaseDocTemplate) -> None:
    width, height = A4
    # Top accent band
    canvas.setFillColor(BRAND_NAVY)
    canvas.rect(0, height - 8 * mm, width, 8 * mm, fill=1, stroke=0)
    canvas.setFillColor(BRAND_ORANGE)
    canvas.rect(0, height - 9 * mm, width, 1 * mm, fill=1, stroke=0)
    # Footer
    canvas.setStrokeColor(SURFACE_BORDER)
    canvas.setLineWidth(0.5)
    canvas.line(15 * mm, 15 * mm, width - 15 * mm, 15 * mm)
    canvas.setFillColor(TEXT_MUTED)
    canvas.setFont("Helvetica", 8)
    canvas.drawString(15 * mm, 10 * mm, "Hunter — Static security analysis")
    canvas.drawRightString(width - 15 * mm, 10 * mm, f"Page {doc.page}")


def _summary_table(scan: ScanDetail, total: int, styles: dict[str, ParagraphStyle]) -> Table:
    rows = [
        [Paragraph("<b>Source</b>", styles["body"]), Paragraph(_safe(scan.source_type), styles["body"])],
        [
            Paragraph("<b>Label</b>", styles["body"]),
            Paragraph(_safe(scan.source_label or scan.plugin_slug), styles["body"]),
        ],
        [Paragraph("<b>Plugin slug</b>", styles["body"]), Paragraph(_safe(scan.plugin_slug), styles["body"])],
        [Paragraph("<b>Scan ID</b>", styles["body"]), Paragraph(_safe(scan.scan_id), styles["mono"])],
        [Paragraph("<b>Status</b>", styles["body"]), Paragraph(_safe(scan.status), styles["body"])],
        [Paragraph("<b>Started</b>", styles["body"]), Paragraph(_fmt_dt(scan.started_at), styles["body"])],
        [Paragraph("<b>Finished</b>", styles["body"]), Paragraph(_fmt_dt(scan.finished_at), styles["body"])],
        [Paragraph("<b>Findings</b>", styles["body"]), Paragraph(str(total), styles["body"])],
    ]
    if scan.snapshot_id:
        rows.append(
            [
                Paragraph("<b>Snapshot</b>", styles["body"]),
                Paragraph(_safe(scan.snapshot_id), styles["mono"]),
            ]
        )
    if scan.error_message:
        rows.append(
            [
                Paragraph("<b>Error</b>", styles["body"]),
                Paragraph(_safe(scan.error_message, 600), styles["body"]),
            ]
        )

    table = Table(rows, colWidths=[35 * mm, 130 * mm])
    table.setStyle(
        TableStyle(
            [
                ("BOX", (0, 0), (-1, -1), 0.5, SURFACE_BORDER),
                ("INNERGRID", (0, 0), (-1, -1), 0.3, SURFACE_BORDER),
                ("BACKGROUND", (0, 0), (0, -1), SURFACE_ALT),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    return table


def _counts_table(
    title: str,
    counts: dict[str, int],
    styles: dict[str, ParagraphStyle],
    color_for: callable | None = None,
) -> Table:
    items = sorted(counts.items(), key=lambda kv: kv[1], reverse=True) or [("(none)", 0)]
    total = sum(c for _, c in counts.items()) or 1
    rows = [
        [
            Paragraph(f"<b>{html.escape(title)}</b>", styles["body"]),
            Paragraph("<b>Count</b>", styles["body"]),
            Paragraph("<b>Share</b>", styles["body"]),
        ]
    ]
    for name, count in items:
        share = f"{(count / total) * 100:.1f}%" if counts else "—"
        rows.append(
            [
                Paragraph(_safe(name, 80), styles["body"]),
                Paragraph(str(count), styles["body"]),
                Paragraph(share, styles["body"]),
            ]
        )
    table = Table(rows, colWidths=[90 * mm, 25 * mm, 25 * mm])
    style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), BRAND_NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("BOX", (0, 0), (-1, -1), 0.5, SURFACE_BORDER),
        ("INNERGRID", (0, 0), (-1, -1), 0.3, SURFACE_BORDER),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (1, 0), (2, -1), "RIGHT"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]
    for i, (name, _) in enumerate(items, start=1):
        if color_for and (col := color_for(name)) is not None:
            style_cmds.append(("BACKGROUND", (0, i), (0, i), col))
            style_cmds.append(("TEXTCOLOR", (0, i), (0, i), colors.white))
    table.setStyle(TableStyle(style_cmds))
    return table


def _findings_table(
    findings: Iterable[FindingSummary], styles: dict[str, ParagraphStyle]
) -> Table:
    header = [
        Paragraph("<b>Severity</b>", styles["body"]),
        Paragraph("<b>Title</b>", styles["body"]),
        Paragraph("<b>Location</b>", styles["body"]),
        Paragraph("<b>Conf.</b>", styles["body"]),
    ]
    rows: list[list] = [header]
    for f in findings:
        loc = _safe(f.file_path or "", 70)
        if f.start_line is not None:
            loc = f"{loc}:{f.start_line}" if loc else f"line {f.start_line}"
        conf = f"{int(round(f.confidence_score * 100))}%" if f.confidence_score is not None else "—"
        rows.append(
            [
                _sev_badge(f.severity),
                Paragraph(
                    f"<b>{_safe(f.title or f.rule_id, 140)}</b><br/>"
                    f'<font color="#64748b" size="8">{_safe(f.rule_id, 80)} · '
                    f"{_safe(f.vuln_type, 40)}</font>",
                    styles["body"],
                ),
                Paragraph(loc or "—", styles["mono"]),
                Paragraph(conf, styles["body"]),
            ]
        )
    table = Table(rows, colWidths=[22 * mm, 90 * mm, 50 * mm, 13 * mm], repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), BRAND_NAVY),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("BOX", (0, 0), (-1, -1), 0.5, SURFACE_BORDER),
                ("INNERGRID", (0, 0), (-1, -1), 0.3, SURFACE_BORDER),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, SURFACE_ALT]),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    return table


def _sev_color(name: str) -> colors.Color | None:
    return SEV_FILL.get(name.upper())


def build_scan_report_pdf(scan: ScanDetail, findings: FindingsPage) -> bytes:
    buf = io.BytesIO()
    doc = BaseDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=15 * mm,
        rightMargin=15 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title=f"Hunter scan report — {scan.plugin_slug or scan.scan_id}",
        author="Hunter",
    )
    frame = Frame(
        doc.leftMargin,
        doc.bottomMargin,
        doc.width,
        doc.height,
        leftPadding=0,
        rightPadding=0,
        topPadding=0,
        bottomPadding=0,
    )
    doc.addPageTemplates([PageTemplate(id="body", frames=[frame], onPage=_draw_header_footer)])
    styles = _styles()

    story: list = []
    story.append(Paragraph("Hunter Security Report", styles["title"]))
    story.append(
        Paragraph(
            f"Static analysis of <b>{_safe(scan.source_label or scan.plugin_slug)}</b>",
            styles["subtitle"],
        )
    )
    story.append(
        Paragraph(
            f"Generated {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
            styles["small"],
        )
    )
    story.append(Spacer(1, 8))

    story.append(Paragraph("Scan summary", styles["h2"]))
    story.append(_summary_table(scan, findings.total, styles))
    story.append(Spacer(1, 12))

    if findings.severity_counts:
        story.append(Paragraph("Severity breakdown", styles["h2"]))
        story.append(_counts_table("Severity", findings.severity_counts, styles, color_for=_sev_color))
        story.append(Spacer(1, 10))

    if findings.vuln_type_counts:
        story.append(Paragraph("Vulnerability types", styles["h2"]))
        story.append(_counts_table("Type", findings.vuln_type_counts, styles))
        story.append(Spacer(1, 10))

    if not findings.items:
        story.append(Paragraph("Findings", styles["h2"]))
        story.append(
            Paragraph(
                "<i>No findings recorded for this scan.</i>",
                styles["small"],
            )
        )
    else:
        # Order by severity then by rule for deterministic output.
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        ordered = sorted(
            findings.items,
            key=lambda f: (sev_order.get(f.severity.upper(), 9), f.rule_id, f.file_path or ""),
        )[:MAX_FINDINGS_IN_PDF]
        truncated = len(findings.items) > MAX_FINDINGS_IN_PDF

        story.append(PageBreak())
        story.append(Paragraph(f"Findings ({len(ordered)} of {findings.total})", styles["h2"]))
        if truncated:
            story.append(
                Paragraph(
                    f"<i>Showing the first {MAX_FINDINGS_IN_PDF} findings sorted by severity. "
                    f"Open the scan in the dashboard to browse the full list.</i>",
                    styles["small"],
                )
            )
            story.append(Spacer(1, 4))
        story.append(KeepTogether(_findings_table(ordered, styles)))

    doc.build(story)
    return buf.getvalue()


def report_filename(scan: ScanDetail) -> str:
    base = (scan.plugin_slug or "hunter-scan").strip() or "hunter-scan"
    safe = "".join(c if c.isalnum() or c in "-_" else "-" for c in base)[:80]
    short_id = scan.scan_id[:8] if scan.scan_id else "report"
    return f"hunter-report-{safe}-{short_id}.pdf"
