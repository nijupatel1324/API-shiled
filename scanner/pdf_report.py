"""
PDF Report Generator

Renders the structured JSON audit report into a professional, multi-page
PDF document using ReportLab.

Layout:
  - Cover header with security grade + posture score
  - Executive summary stats table
  - Findings table grouped by severity
  - Remediation advisories
"""

import logging
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether
)

logger = logging.getLogger("api-shield.pdf_report")

SEVERITY_COLORS = {
    "CRITICAL": colors.HexColor("#991b1b"),
    "HIGH": colors.HexColor("#c2410c"),
    "MEDIUM": colors.HexColor("#b45309"),
    "LOW": colors.HexColor("#1e3a8a"),
    "INFO": colors.HexColor("#334155"),
}


def _only_findings_with_severity(findings):
    out = []
    for f in findings:
        if isinstance(f, dict) and f.get("severity"):
            out.append(f)
    return out


def generate_pdf_report(report_data: dict, output_path: str) -> str:
    """
    Builds the PDF from the JSON report structure produced by
    ReportGenerator.generate_json_report().

    :param report_data: The JSON report dict.
    :param output_path: Destination filename.
    :return: The output path.
    """
    styles = getSampleStyleSheet()
    dark = colors.HexColor("#0f172a")
    card = colors.HexColor("#1e293b")
    muted = colors.HexColor("#64748b")

    title_style = ParagraphStyle(
        "Title", parent=styles["Title"], textColor=colors.HexColor("#38bdf8"),
        fontSize=22, spaceAfter=4,
    )
    h2 = ParagraphStyle(
        "H2", parent=styles["Heading2"], textColor=colors.HexColor("#e2e8f0"),
        fontSize=14, spaceBefore=12, spaceAfter=6,
    )
    body = ParagraphStyle(
        "Body", parent=styles["BodyText"], textColor=colors.HexColor("#cbd5e1"),
        fontSize=9, leading=13,
    )
    small = ParagraphStyle(
        "Small", parent=body, fontSize=8, leading=11,
    )

    project = report_data.get("project", {})
    exec_summary = report_data.get("executive_summary", {})
    findings = _only_findings_with_severity(report_data.get("all_findings", []))
    advisories = report_data.get("remediation_advisories", [])
    breakdown = exec_summary.get("risk_breakdown", {})
    grade = exec_summary.get("security_grade", "F")
    score = exec_summary.get("security_score", 0)
    generated_at = report_data.get("report_metadata", {}).get("generated_at", "")

    doc = SimpleDocTemplate(
        output_path, pagesize=A4,
        leftMargin=18 * mm, rightMargin=18 * mm, topMargin=16 * mm, bottomMargin=16 * mm,
        title=f"API-SHIELD Audit Report - {project.get('name', 'API')}",
        author="API-SHIELD",
    )

    story = []

    # ── Header ──────────────────────────────────────────────────────
    story.append(Paragraph("API-SHIELD", title_style))
    story.append(Paragraph("Automated Security Audit Report", ParagraphStyle(
        "sub", parent=body, fontSize=11, textColor=muted, spaceAfter=10)))
    story.append(Paragraph(
        f"Target: <b>{project.get('base_url', 'N/A')}</b> &nbsp;|&nbsp; "
        f"Audited: {generated_at} &nbsp;|&nbsp; Project: {project.get('name', 'N/A')}",
        small,
    ))
    story.append(Spacer(1, 8))

    # ── Grade / score banner ────────────────────────────────────────
    grade_color = SEVERITY_COLORS.get(
        "HIGH" if grade in {"F", "D"} else "MEDIUM" if grade == "C" else "LOW")
    grade_table = Table(
        [[Paragraph("SECURITY GRADE", ParagraphStyle("gl", parent=small, textColor=muted)),
          Paragraph(str(grade), ParagraphStyle("gv", parent=title_style,
                                                textColor=colors.white, fontSize=34)),
          Paragraph("SECURITY SCORE", ParagraphStyle("sl", parent=small, textColor=muted)),
          Paragraph(f"{score} / 100", ParagraphStyle("sv", parent=body, fontSize=18,
                                                      textColor=colors.white)),
          ]],
        colWidths=[40 * mm, 30 * mm, 40 * mm, 40 * mm],
    )
    grade_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), grade_color),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (0, 0), (0, 0), "LEFT"),
        ("ALIGN", (4, 0), (4, 0), "RIGHT"),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
    ]))
    story.append(grade_table)
    story.append(Spacer(1, 10))

    # ── Executive summary ───────────────────────────────────────────
    story.append(Paragraph("1. Executive Summary", h2))

    stats = [
        ["Endpoint Inventory & Findings", ""],
        ["Total Endpoints Scanned", str(exec_summary.get("total_endpoints", 0))],
        ["Total Vulnerabilities Found", str(exec_summary.get("total_findings", 0))],
        ["Critical", str(breakdown.get("CRITICAL", 0))],
        ["High", str(breakdown.get("HIGH", 0))],
        ["Medium", str(breakdown.get("MEDIUM", 0))],
        ["Low", str(breakdown.get("LOW", 0))],
        ["Secure Endpoints", str(breakdown.get("SECURE", 0))],
    ]
    stats_table = Table(stats, colWidths=[90 * mm, 60 * mm])
    stats_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("BACKGROUND", (0, 0), (-1, 0), card),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#334155")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [card, dark]),
        ("BACKGROUND", (0, 1), (-1, -1), card),
        ("TEXTCOLOR", (0, 1), (-1, -1), colors.HexColor("#cbd5e1")),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(stats_table)
    story.append(PageBreak())

    # ── Findings ────────────────────────────────────────────────────
    story.append(Paragraph("2. Detailed Vulnerability Findings", h2))

    def _sev_row(f):
        sev = str(f.get("severity", "INFO")).upper()
        color = SEVERITY_COLORS.get(sev, colors.grey)
        return Table(
            [[Paragraph(f"<b>[{sev}]</b> {f.get('title', 'Finding')}",
                        ParagraphStyle("ft", parent=body, fontSize=10,
                                       textColor=colors.white)),
              ]],
            colWidths=[160 * mm],
        ).with_colors()

    for f in findings:
        sev = str(f.get("severity", "INFO")).upper()
        color = SEVERITY_COLORS.get(sev, colors.grey)
        title = f"<b>[{sev}]</b> {f.get('title', 'Finding')}"
        endpoint = f"{f.get('method', 'N/A')} {f.get('endpoint', 'N/A')}"
        owasp = f.get("owasp", "N/A")
        rec = f.get("recommendation", "")

        header_tbl = Table([[
            Paragraph(title, ParagraphStyle(
                "find-title", parent=body, fontSize=10, textColor=colors.white)),
        ]], colWidths=[160 * mm])
        header_tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), color),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))

        body_rows = [
            Paragraph(f"<b>Endpoint:</b> <font face='Courier'>{endpoint}</font>", small),
            Paragraph(f"<b>OWASP:</b> {owasp}", small),
            Paragraph(f"<b>Description:</b> {f.get('description', '')}", small),
        ]
        if f.get("evidence"):
            body_rows.append(Paragraph(f"<b>Evidence:</b> {f.get('evidence', '')}", small))
        body_rows.append(Paragraph(f"<b>Recommendation:</b> {rec}", small))

        body_tbl = Table([[b] for b in body_rows], colWidths=[160 * mm])
        body_tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), card),
            ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#cbd5e1")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))

        story.append(KeepTogether([header_tbl, body_tbl, Spacer(1, 8)]))

    # ── Advisories ──────────────────────────────────────────────────
    story.append(PageBreak())
    story.append(Paragraph("3. Remediation Advisories", h2))
    for adv in advisories:
        adv_sev = str(adv.get("severity", "MEDIUM")).upper()
        color = SEVERITY_COLORS.get(adv_sev, colors.grey)
        card_tbl = Table([[
            Paragraph(
                f"<b>{adv.get('title', 'Advisory')}</b>",
                ParagraphStyle("adv", parent=body, fontSize=10, textColor=colors.white)),
        ]], colWidths=[160 * mm])
        card_tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), color),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        steps = "<br/>".join(
            f"&bull; {s}" for s in adv.get("remediation_steps", []))
        affected = ", ".join(adv.get("affected_endpoints", []))
        body_tbl = Table([[
            Paragraph(
                f"<b>OWASP:</b> {adv.get('owasp')}<br/>"
                f"<b>CWE:</b> {adv.get('cwe')}<br/>"
                f"<b>Impact:</b> {adv.get('impact', '')}<br/>"
                f"<b>Affected:</b> {affected}<br/><br/>"
                f"<b>Remediation:</b><br/>{steps}",
                small,
            )
        ]], colWidths=[160 * mm])
        body_tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), card),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(KeepTogether([card_tbl, body_tbl, Spacer(1, 8)]))

    # ── Footer ──────────────────────────────────────────────────────
    story.append(Spacer(1, 16))
    story.append(Paragraph(
        "Generated by API-SHIELD — a defensive API security assessment tool. "
        "Only authorized targets should be scanned.",
        ParagraphStyle("foot", parent=small, textColor=muted),
    ))

    doc.build(story)
    logger.info("PDF report written to %s", output_path)
    return output_path