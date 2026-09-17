"""Report generation: HTML, PDF and JSON.

Reports are written into reports/output/ as
    report_<scan_id>_<format>.<ext>

The generator takes the scan record plus its findings. Secrets found as
evidence are already masked by the scanner before they reach this module.
"""

import datetime
import json
import logging
import os

from config import Config

logger = logging.getLogger("api_shield.reports")

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

OWASP_MAP = {
    "API1": "API1 - Broken Object Level Authorization",
    "API2": "API2 - Broken Authentication",
    "API3": "API3 - Broken Object Property Level Authorization",
    "API4": "API4 - Unrestricted Resource Consumption",
    "API5": "API5 - Broken Function Level Authorization",
    "API6": "API6 - Unrestricted Access to Sensitive Business Flows",
    "API7": "API7 - Server Side Request Forgery",
    "API8": "API8 - Security Misconfiguration",
    "API9": "API9 - Improper Inventory Management",
    "API10": "API10 - Unsafe Consumption of APIs",
}


def _ensure_output_dir():
    os.makedirs(Config.REPORT_OUTPUT_DIR, exist_ok=True)
    return Config.REPORT_OUTPUT_DIR


def _finding_to_dict(f):
    return {
        "title": f.title,
        "severity": f.severity,
        "endpoint": f.endpoint,
        "method": f.method,
        "category": f.category,
        "description": f.description,
        "evidence": f.evidence,
        "recommendation": f.recommendation,
    }


def build_context(scan, findings):
    findings = sorted(
        findings, key=lambda f: (SEVERITY_ORDER.index(f.severity) if f.severity in SEVERITY_ORDER else 9)
    )
    return {
        "scan": scan,
        "target": scan.target.base_url if scan.target else scan.target_id,
        "scan_date": datetime.datetime.utcfromtimestamp(
            scan.started_at or 0
        ).strftime("%Y-%m-%d %H:%M:%S"),
        "score": int(scan.score or 0),
        "counts": {
            s: sum(1 for f in findings if f.severity == s) for s in SEVERITY_ORDER
        },
        "findings": findings,
        "findings_json": [_finding_to_dict(f) for f in findings],
        "total": len(findings),
        "endpoints_count": scan.endpoints_count,
        "tests_completed": scan.tests_completed,
        "owasp_map": OWASP_MAP,
    }


def generate_json(scan, findings):
    outdir = _ensure_output_dir()
    path = os.path.join(outdir, f"report_{scan.id}_json.json")
    payload = {
        "target": scan.target.base_url if scan.target else scan.target_id,
        "scan_id": scan.id,
        "date": datetime.datetime.utcfromtimestamp(scan.started_at or 0).isoformat(),
        "score": int(scan.score or 0),
        "findings": [_finding_to_dict(f) for f in findings],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    logger.info("JSON report written: %s", path)
    return path


def generate_html(scan, findings, template_name="report.html"):
    from flask import render_template

    ctx = build_context(scan, findings)
    html = render_template(template_name, **ctx)
    outdir = _ensure_output_dir()
    path = os.path.join(outdir, f"report_{scan.id}_html.html")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)
    logger.info("HTML report written: %s", path)
    return path


def generate_pdf(scan, findings):
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        SimpleDocTemplate,
        Paragraph,
        Spacer,
        Table,
        TableStyle,
    )

    ctx = build_context(scan, findings)
    outdir = _ensure_output_dir()
    path = os.path.join(outdir, f"report_{scan.id}_pdf.pdf")

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "TitleX", parent=styles["Title"], fontSize=22, textColor=colors.HexColor("#0a1929")
    )
    h2 = ParagraphStyle(
        "H2X", parent=styles["Heading2"], textColor=colors.HexColor("#0a1929"), spaceBefore=14
    )

    doc = SimpleDocTemplate(
        path, pagesize=A4,
        rightMargin=18 * mm, leftMargin=18 * mm, topMargin=18 * mm, bottomMargin=18 * mm,
    )
    story = []

    story.append(Paragraph("API-SHIELD Security Report", title_style))
    story.append(Spacer(1, 2))
    story.append(Paragraph(f"Target: {ctx['target']}", styles["Normal"]))
    story.append(Paragraph(f"Scan date: {ctx['scan_date']} (Scan ID: {scan.id})", styles["Normal"]))
    story.append(Paragraph(f"Security Score: {ctx['score']} / 100", styles["Normal"]))
    story.append(Spacer(1, 8))

    story.append(Paragraph("Vulnerability Summary", h2))
    summary_rows = [["Severity", "Count"], *[[s, str(ctx["counts"][s])] for s in SEVERITY_ORDER]]
    summary_table = Table(summary_rows, colWidths=[70 * mm, 70 * mm])
    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0a1929")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
            ]
        )
    )
    story.append(summary_table)
    story.append(Spacer(1, 12))

    story.append(Paragraph("Detailed Findings", h2))
    for i, f in enumerate(ctx["findings"], start=1):
        story.append(
            Paragraph(
                f"{i}. [{f.severity}] {f.title}  ({ctx['owasp_map'].get(f.category, '') or 'Uncategorised'})",
                styles["Heading4"],
            )
        )
        story.append(Paragraph(f"Endpoint: {f.method} {f.endpoint}", styles["Normal"]))
        story.append(Paragraph(f"Description: {f.description}", styles["Normal"]))
        evidence = (f.evidence or "None recorded.")[:400]
        story.append(Paragraph(f"Evidence: {evidence}", styles["Normal"]))
        story.append(Paragraph(f"Recommendation: {f.recommendation}", styles["Normal"]))
        story.append(Spacer(1, 8))

    doc.build(story)
    logger.info("PDF report written: %s", path)
    return path


def generate(scan, findings, format="html"):
    """Generate a report in the chosen format and record it.

    Returns the created Report DB row (caller persists it).
    """
    from models.scan import Report

    format = format.lower()
    if format == "json":
        path = generate_json(scan, findings)
    elif format == "pdf":
        path = generate_pdf(scan, findings)
    else:
        path = generate_html(scan, findings)
    return Report(scan_id=scan.id, report_type=format, file_path=path)