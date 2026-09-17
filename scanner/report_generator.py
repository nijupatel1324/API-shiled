"""
Phase 18 — Executive Security Audit Report Generator

Produces professional, executive-ready and developer-focused security audit
reports in HTML, Markdown, and structured JSON formats.

Features:
  1. Executive Summary with Letter Grade (A-F), Posture Score (0-100), and Risk Matrix.
  2. OWASP API Security Top 10 Compliance Scorecard.
  3. Detailed Endpoint Findings with Severity badges, Evidence, and Root Cause.
  4. Prioritized Engineering Remediation Roadmap with before/after code patches.
  5. Standalone, CSS-styled responsive HTML output suitable for offline presentation.
"""

import json
from datetime import datetime, timezone


class ReportGenerator:
    def __init__(self, project_data: dict, risk_data: dict, advisories: list, findings: list):
        """
        :param project_data: Metadata about the project (name, base_url, owner, etc.)
        :param risk_data: Output from RiskEngine.evaluate_project
        :param advisories: Output from RemediationEngine.generate_advisories_for_findings
        :param findings: Raw or grouped findings from all test modules
        """
        self.project = project_data
        self.risk = risk_data
        self.advisories = advisories
        self.findings = [f for f in findings if "severity" in f]
        self.timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    def generate_json_report(self) -> dict:
        """Returns the full audit report as a structured JSON object."""
        return {
            "report_metadata": {
                "generator": "API-SHIELD Audit Reporting Engine",
                "version": "1.0.0",
                "generated_at": self.timestamp
            },
            "project": self.project,
            "executive_summary": {
                "security_grade": self.risk.get("grade", "F"),
                "security_score": self.risk.get("security_score", 0),
                "total_endpoints": self.risk.get("endpoints_audited", 0),
                "total_findings": len(self.findings),
                "risk_breakdown": self.risk.get("endpoint_breakdown_by_risk", {})
            },
            "remediation_advisories": self.advisories,
            "all_findings": self.findings
        }

    def generate_markdown_report(self) -> str:
        """Returns the audit report as a GitHub-flavored Markdown document."""
        grade = self.risk.get("grade", "F")
        score = self.risk.get("security_score", 0)
        breakdown = self.risk.get("endpoint_breakdown_by_risk", {})

        md = [
            f"# API Security Audit Report: {self.project.get('name', 'API Project')}",
            f"**Target Host:** `{self.project.get('base_url')}`  ",
            f"**Audit Date:** {self.timestamp}  ",
            f"**Security Grade:** `{grade}` ({score}/100)  ",
            "\n---\n",
            "## 1. Executive Summary",
            f"API-SHIELD performed an automated, non-destructive security evaluation of the target API. "
            f"The assessment covered transport security, access control, input validation, authentication enforcement, "
            f"and configuration posture.\n",
            "| Metric | Value |",
            "| :--- | :--- |",
            f"| **Overall Security Grade** | **{grade}** |",
            f"| **Security Posture Score** | **{score} / 100** |",
            f"| **Total Endpoints Tested** | {self.risk.get('endpoints_audited', 0)} |",
            f"| **Total Vulnerabilities**  | {len(self.findings)} |",
            f"| **Critical Endpoints**     | {breakdown.get('CRITICAL', 0)} |",
            f"| **High-Risk Endpoints**    | {breakdown.get('HIGH', 0)} |",
            f"| **Medium-Risk Endpoints**  | {breakdown.get('MEDIUM', 0)} |",
            f"| **Low-Risk Endpoints**     | {breakdown.get('LOW', 0)} |",
            f"| **Secure Endpoints**       | {breakdown.get('SECURE', 0)} |",
            "\n---\n",
            "## 2. OWASP API Security Top 10 Scorecard",
            "| Category | Name | Status |",
            "| :--- | :--- | :--- |"
        ]

        # OWASP mapping summary
        owasp_checks = [
            ("API1:2023", "Broken Object Level Authorization (BOLA)", any("API1" in f.get("owasp", "") for f in self.findings)),
            ("API2:2023", "Broken Authentication", any("API2" in f.get("owasp", "") for f in self.findings)),
            ("API3:2023", "Broken Object Property Level Authorization", any("API3" in f.get("owasp", "") for f in self.findings)),
            ("API7:2023", "Security Misconfiguration (TLS / Headers / CORS)", any("API7" in f.get("owasp", "") for f in self.findings)),
            ("API8:2023", "Information Disclosure / Error Handling", any("API8" in f.get("owasp", "") for f in self.findings))
        ]

        for code, name, failed in owasp_checks:
            status = "**FAIL (Exposures Found)**" if failed else "*PASS (No Findings)*"
            md.append(f"| {code} | {name} | {status} |")

        md.extend([
            "\n---\n",
            "## 3. Developer Remediation Roadmap & Patches\n"
        ])

        for idx, adv in enumerate(self.advisories, 1):
            md.extend([
                f"### {idx}. [{adv.get('severity', 'HIGH')}] {adv.get('title')}",
                f"- **OWASP:** `{adv.get('owasp')}`",
                f"- **CWE:** `{adv.get('cwe')}`",
                f"- **Impact:** {adv.get('impact')}",
                f"- **Affected Endpoints:** `{', '.join(adv.get('affected_endpoints', []))}`\n",
                "**Remediation Steps:**"
            ])
            for step in adv.get("remediation_steps", []):
                md.append(f"1. {step}")

            remediated_code = adv.get("code_patch", {}).get("remediated", "").strip()
            if remediated_code:
                md.extend([
                    "\n**Recommended Implementation:**",
                    "```python",
                    remediated_code,
                    "```"
                ])
            md.append("\n---\n")

        md.extend([
            "## 4. Comprehensive Vulnerability Log",
            f"Total findings identified: {len(self.findings)}\n"
        ])

        for f in self.findings:
            md.extend([
                f"#### [{f.get('severity')}] {f.get('title')}",
                f"- **Endpoint:** `{f.get('method')} {f.get('endpoint')}`",
                f"- **OWASP:** `{f.get('owasp')}`",
                f"- **Evidence:** {f.get('evidence')}",
                f"- **Recommendation:** {f.get('recommendation')}\n"
            ])

        return "\n".join(md)

    def generate_html_report(self) -> str:
        """Generates a standalone, beautifully styled HTML security report."""
        grade = self.risk.get("grade", "F")
        score = self.risk.get("security_score", 0)
        breakdown = self.risk.get("endpoint_breakdown_by_risk", {})

        # Grade color mapping
        grade_color = "#e53e3e" if grade == "F" else "#dd6b20" if grade == "D" else "#d69e2e" if grade == "C" else "#319795" if grade == "B" else "#38a169"

        # Construct advisories HTML
        advisories_html = ""
        for adv in self.advisories:
            steps_li = "".join([f"<li>{s}</li>" for s in adv.get("remediation_steps", [])])
            patch = adv.get("code_patch", {}).get("remediated", "").replace("<", "&lt;").replace(">", "&gt;")
            endpoints_badges = "".join([f"<span class='badge badge-gray'>{ep}</span> " for ep in adv.get("affected_endpoints", [])])

            advisories_html += f"""
            <div class="card advisory-card">
                <div class="card-header">
                    <span class="badge badge-high">{adv.get('owasp', 'Security')}</span>
                    <h3>{adv.get('title')}</h3>
                </div>
                <p class="meta"><strong>CWE:</strong> {adv.get('cwe')} | <strong>Affected:</strong> {endpoints_badges}</p>
                <p class="impact">{adv.get('impact')}</p>
                <h4>Remediation Steps:</h4>
                <ol>{steps_li}</ol>
                <h4>Recommended Patch:</h4>
                <pre><code>{patch}</code></pre>
            </div>
            """

        # Construct findings table HTML
        findings_rows = ""
        for f in self.findings:
            sev = f.get("severity", "LOW").upper()
            badge_class = f"badge-{sev.lower()}"
            findings_rows += f"""
            <tr>
                <td><span class="badge {badge_class}">{sev}</span></td>
                <td><strong>{f.get('title')}</strong></td>
                <td><code>{f.get('method')} {f.get('endpoint')}</code></td>
                <td><small>{f.get('owasp')}</small></td>
                <td><small>{f.get('recommendation')}</small></td>
            </tr>
            """

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>API-SHIELD Security Audit - {self.project.get('name')}</title>
    <style>
        :root {{
            --bg-primary: #0f172a;
            --bg-card: #1e293b;
            --text-primary: #f8fafc;
            --text-muted: #94a3b8;
            --border-color: #334155;
            --font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        }}
        body {{
            background-color: var(--bg-primary);
            color: var(--text-primary);
            font-family: var(--font-family);
            margin: 0;
            padding: 30px 20px;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1100px;
            margin: 0 auto;
        }}
        header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 2px solid var(--border-color);
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        .brand {{
            font-size: 1.8rem;
            font-weight: 800;
            letter-spacing: -0.5px;
            color: #38bdf8;
        }}
        .grade-badge {{
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 80px;
            height: 80px;
            border-radius: 50%;
            font-size: 2.5rem;
            font-weight: 900;
            color: white;
            background-color: {grade_color};
            box-shadow: 0 4px 14px rgba(0,0,0,0.3);
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }}
        .stat-box {{
            background-color: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 20px;
            text-align: center;
        }}
        .stat-value {{
            font-size: 2rem;
            font-weight: 800;
            color: #38bdf8;
        }}
        .stat-label {{
            color: var(--text-muted);
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .card {{
            background-color: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 25px;
            margin-bottom: 25px;
        }}
        .card-header {{
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 15px;
        }}
        .card-header h3 {{
            margin: 0;
            font-size: 1.3rem;
        }}
        .badge {{
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
        }}
        .badge-critical {{ background-color: #991b1b; color: #fecaca; }}
        .badge-high {{ background-color: #c2410c; color: #ffedd5; }}
        .badge-medium {{ background-color: #b45309; color: #fef3c7; }}
        .badge-low {{ background-color: #1e3a8a; color: #dbeafe; }}
        .badge-gray {{ background-color: #334155; color: #cbd5e1; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }}
        th, td {{
            text-align: left;
            padding: 12px 15px;
            border-bottom: 1px solid var(--border-color);
        }}
        th {{
            background-color: rgba(0,0,0,0.2);
            color: var(--text-muted);
            font-size: 0.85rem;
            text-transform: uppercase;
        }}
        pre {{
            background-color: #090d16;
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 15px;
            overflow-x: auto;
            color: #38bdf8;
            font-size: 0.9rem;
        }}
        code {{
            font-family: "SFMono-Regular", Consolas, Menlo, monospace;
        }}
        footer {{
            text-align: center;
            color: var(--text-muted);
            font-size: 0.85rem;
            margin-top: 50px;
            border-top: 1px solid var(--border-color);
            padding-top: 20px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div>
                <div class="brand">API-SHIELD</div>
                <h2>Automated Security Audit Report</h2>
                <p style="color: var(--text-muted); margin: 0;">
                    Project: <strong>{self.project.get('name')}</strong> | 
                    Target: <code>{self.project.get('base_url')}</code> | 
                    Audited: {self.timestamp}
                </p>
            </div>
            <div style="text-align: center;">
                <div class="grade-badge">{grade}</div>
                <div style="margin-top: 5px; font-weight: 700;">Score: {score}/100</div>
            </div>
        </header>

        <div class="stats-grid">
            <div class="stat-box">
                <div class="stat-value">{self.risk.get('endpoints_audited', 0)}</div>
                <div class="stat-label">Endpoints Scanned</div>
            </div>
            <div class="stat-box">
                <div class="stat-value" style="color: #f87171;">{len(self.findings)}</div>
                <div class="stat-label">Total Vulnerabilities</div>
            </div>
            <div class="stat-box">
                <div class="stat-value" style="color: #fb923c;">{breakdown.get('CRITICAL', 0) + breakdown.get('HIGH', 0)}</div>
                <div class="stat-label">High / Critical Endpoints</div>
            </div>
            <div class="stat-box">
                <div class="stat-value" style="color: #4ade80;">{breakdown.get('SECURE', 0)}</div>
                <div class="stat-label">Hardened Endpoints</div>
            </div>
        </div>

        <section>
            <h2>Prioritized Engineering Remediation Roadmap</h2>
            <p style="color: var(--text-muted);">
                Actionable fix advisories ranked by attack severity and operational risk.
            </p>
            {advisories_html}
        </section>

        <section style="margin-top: 40px;">
            <h2>Complete Vulnerability Findings Log</h2>
            <div class="card" style="padding: 0; overflow-x: auto;">
                <table>
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th>Vulnerability</th>
                            <th>Target Endpoint</th>
                            <th>OWASP Mapping</th>
                            <th>Recommended Remediation</th>
                        </tr>
                    </thead>
                    <tbody>
                        {findings_rows}
                    </tbody>
                </table>
            </div>
        </section>

        <footer>
            Generated automatically by API-SHIELD Dynamic Security Scanner &bull; Confirmed Defensive Evaluation
        </footer>
    </div>
</body>
</html>
"""
        return html
