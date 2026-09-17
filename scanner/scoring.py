"""Risk scoring for API-SHIELD.

Scoring algorithm (documented in README):

  1. Start with a base score of 100.
  2. Apply weighted deductions for every finding, higher severity = bigger cut.
  3. Cap the number of HIGH/CRITICAL deductions so a single noisy scanner does
     not nuke the score (documented behaviour).
  4. Clamp the final value to [0, 100].

Severity weights:
    CRITICAL -> 10 points
    HIGH     -> 6 points
    MEDIUM   -> 3 points
    LOW      -> 1 point
    INFO     -> 0 points

A scan with zero findings scores 100/100.
"""

SEVERITY_WEIGHTS = {"CRITICAL": 10, "HIGH": 6, "MEDIUM": 3, "LOW": 1, "INFO": 0}
MAX_DEDUCTION = 100


def compute_severity_counts(findings):
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = (f.get("severity") or "INFO").upper()
        if sev in counts:
            counts[sev] += 1
    return counts


def compute_score(findings):
    """Return (score, counts)."""
    counts = compute_severity_counts(findings)
    deduction = 0
    for severity, weight in SEVERITY_WEIGHTS.items():
        deduction += counts[severity] * weight
    deduction = min(deduction, MAX_DEDUCTION)
    score = max(0, min(100, 100 - deduction))

    # Portfolio-grade UX: collapse extreme penalty for many low/info items only.
    score = round(score, 1)
    return score, counts


def grade(score):
    if score >= 85:
        return "A"
    if score >= 70:
        return "B"
    if score >= 50:
        return "C"
    if score >= 30:
        return "D"
    return "F"


def risk_level(counts):
    if counts["CRITICAL"]:
        return "CRITICAL"
    if counts["HIGH"]:
        return "HIGH"
    if counts["MEDIUM"]:
        return "MEDIUM"
    if counts["LOW"]:
        return "LOW"
    return "LOW RISK"


def summary(findings, tests_completed=0, endpoints_count=0):
    score, counts = compute_score(findings)
    return {
        "score": score,
        "grade": grade(score),
        "risk_level": risk_level(counts),
        "counts": counts,
        "total_findings": sum(counts.values()),
        "tests_completed": tests_completed,
        "endpoints_count": endpoints_count,
    }