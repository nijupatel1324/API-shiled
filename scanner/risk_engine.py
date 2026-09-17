"""
Phase 16 — Risk Scoring Engine

Translates raw vulnerability findings into actionable risk metrics,
calculates per-endpoint risk levels, assigns overall project security
grades, and persists risk ratings back to the database.

RISK METHODOLOGY:
  1. Severity Weights:
       - CRITICAL : 10 pts (e.g. Remote Code Execution, Credential Leak)
       - HIGH     : 7  pts (e.g. BOLA, Plaintext HTTP, SQLi/Mass Assignment)
       - MEDIUM   : 4  pts (e.g. Missing HSTS, Sensitive error disclosure)
       - LOW      : 1  pt  (e.g. Wildcard CORS on public endpoint, Missing X-Frame)
       - INFO     : 0  pts (Informational observations)

  2. Endpoint Risk Classification:
       - CRITICAL : Any CRITICAL finding OR Endpoint Score >= 15
       - HIGH     : Any HIGH finding OR Endpoint Score >= 7
       - MEDIUM   : Any MEDIUM finding OR Endpoint Score >= 4
       - LOW      : Endpoint Score > 0
       - SECURE   : 0 Findings (or only INFO)

  3. Overall Project Posture:
       - Security Score : 100 - min(100, total_weighted_penalty)
       - Letter Grade   :
           A : 90 - 100 (Strong security posture)
           B : 80 - 89  (Minor hygiene issues)
           C : 70 - 79  (Moderate misconfigurations)
           D : 60 - 69  (Significant security gaps)
           F : < 60     (Critical or high severity exposures)
"""

import logging
from datetime import datetime, timezone
from database.models import db, Endpoint, Project

logger = logging.getLogger('api-shield.risk_engine')

SEVERITY_WEIGHTS = {
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 4,
    "LOW": 1,
    "INFO": 0
}


class RiskEngine:
    def __init__(self, severity_weights: dict = None):
        self.weights = severity_weights or SEVERITY_WEIGHTS

    def evaluate_endpoint(self, findings: list) -> dict:
        """
        Calculates the risk score and risk level for a single endpoint
        given its list of findings.
        """
        score = 0
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

        for f in findings:
            sev = f.get("severity", "INFO").upper()
            if sev in self.weights:
                counts[sev] = counts.get(sev, 0) + 1
                score += self.weights[sev]

        # Determine level based on severity presence and aggregate score
        if counts["CRITICAL"] > 0 or score >= 15:
            level = "CRITICAL"
        elif counts["HIGH"] > 0 or score >= 7:
            level = "HIGH"
        elif counts["MEDIUM"] > 0 or score >= 4:
            level = "MEDIUM"
        elif score > 0:
            level = "LOW"
        else:
            level = "SECURE"

        return {
            "score": score,
            "risk_level": level,
            "total_findings": sum(counts.values()),
            "severity_counts": counts
        }

    def evaluate_project(self, endpoints: list, all_findings: list) -> dict:
        """
        Evaluates the entire project's security posture.
        :param endpoints: List of Endpoint model instances or dicts.
        :param all_findings: Complete list of all findings across all modules.
        :return: Comprehensive project risk report.
        """
        endpoint_evaluations = {}
        findings_by_url = {}

        # Group findings by endpoint URL
        for f in all_findings:
            ep_url = f.get("endpoint", "N/A")
            if ep_url not in findings_by_url:
                findings_by_url[ep_url] = []
            findings_by_url[ep_url].append(f)

        # Count endpoints by risk tier
        level_counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "SECURE": 0,
            "UNKNOWN": 0
        }

        total_risk_points = 0

        for ep in endpoints:
            ep_path = ep.path if hasattr(ep, 'path') else ep.get('path', '')
            ep_method = ep.method if hasattr(ep, 'method') else ep.get('method', 'GET')
            ep_id = ep.id if hasattr(ep, 'id') else ep.get('id', None)

            # Match findings that belong to this endpoint
            matching_findings = [
                f for f in all_findings
                if ep_path in f.get("endpoint", "") and (f.get("method") == ep_method or f.get("method") == "N/A")
            ]

            eval_res = self.evaluate_endpoint(matching_findings)
            level = eval_res["risk_level"]
            level_counts[level] = level_counts.get(level, 0) + 1
            total_risk_points += eval_res["score"]

            endpoint_evaluations[f"{ep_method} {ep_path}"] = {
                "endpoint_id": ep_id,
                "path": ep_path,
                "method": ep_method,
                "risk_level": level,
                "risk_score": eval_res["score"],
                "findings_count": eval_res["total_findings"],
                "findings": matching_findings
            }

        # Project-level checks (like TLS findings which have endpoint = base_url)
        project_level_findings = [
            f for f in all_findings
            if f.get("method") == "N/A" and not any(
                (ep.path if hasattr(ep, 'path') else ep.get('path', '')) in f.get("endpoint", "")
                for ep in endpoints
            )
        ]
        for f in project_level_findings:
            sev = f.get("severity", "INFO").upper()
            total_risk_points += self.weights.get(sev, 0)

        # Overall security score: 100 down to 0
        # Capped to 0 minimum
        security_score = max(0, 100 - total_risk_points)

        # Letter Grade
        if security_score >= 90:
            grade = "A"
        elif security_score >= 80:
            grade = "B"
        elif security_score >= 70:
            grade = "C"
        elif security_score >= 60:
            grade = "D"
        else:
            grade = "F"

        # Remediation priorities: sort findings by severity weight descending
        prioritized_remediations = sorted(
            all_findings,
            key=lambda x: self.weights.get(x.get("severity", "INFO").upper(), 0),
            reverse=True
        )

        return {
            "security_score": security_score,
            "grade": grade,
            "total_risk_points": total_risk_points,
            "endpoints_audited": len(endpoints),
            "endpoint_breakdown_by_risk": level_counts,
            "endpoints": list(endpoint_evaluations.values()),
            "project_level_findings": project_level_findings,
            "top_priorities": prioritized_remediations[:5]
        }

    def sync_endpoint_risks_to_db(self, project_id: int, all_findings: list):
        """
        Updates each Endpoint row in SQLite with its calculated risk_level
        and updates the last_tested timestamp.
        """
        endpoints = Endpoint.query.filter_by(project_id=project_id).all()
        now = datetime.now(timezone.utc)

        for ep in endpoints:
            matching = [
                f for f in all_findings
                if ep.path in f.get("endpoint", "") and (f.get("method") == ep.method or f.get("method") == "N/A")
            ]
            eval_res = self.evaluate_endpoint(matching)
            ep.risk_level = eval_res["risk_level"]
            ep.last_tested = now

        db.session.commit()
        logger.info(f"Synchronized risk levels to database for Project #{project_id}")
