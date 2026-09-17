"""RiskEngine scoring/grade unit tests."""

from scanner.risk_engine import RiskEngine, SEVERITY_WEIGHTS


def test_severity_weights_match_methodology():
    assert SEVERITY_WEIGHTS["CRITICAL"] == 10
    assert SEVERITY_WEIGHTS["HIGH"] == 7
    assert SEVERITY_WEIGHTS["MEDIUM"] == 4
    assert SEVERITY_WEIGHTS["LOW"] == 1
    assert SEVERITY_WEIGHTS["INFO"] == 0


def test_critical_findings_cap_score_at_f():
    engine = RiskEngine()
    endpoints = [{"path": "/api/users", "method": "GET"}]
    findings = [
        {"title": "Credential leak", "severity": "CRITICAL",
         "endpoint": "/api/users", "method": "GET"},
        {"title": "Auth bypass", "severity": "HIGH",
         "endpoint": "/api/users", "method": "GET"},
    ]
    report = engine.evaluate_project(endpoints=endpoints, all_findings=findings)
    assert report["total_risk_points"] == 17
    assert report["security_score"] == 83  # 100 - 17
    assert report["grade"] == "B"


def test_clean_project_gets_an_a():
    engine = RiskEngine()
    report = engine.evaluate_project(
        endpoints=[{"path": "/api/health", "method": "GET"}],
        all_findings=[{"title": "OK", "severity": "INFO",
                       "endpoint": "/api/health", "method": "GET"}],
    )
    assert report["security_score"] == 100
    assert report["grade"] == "A"


def test_heavily_compromised_project_scores_an_f():
    engine = RiskEngine()
    findings = [
        {"title": f"A{i}", "severity": s, "endpoint": "/api/x", "method": "GET"}
        for i, s in enumerate(["CRITICAL", "CRITICAL", "HIGH", "HIGH",
                               "MEDIUM", "MEDIUM", "MEDIUM", "LOW"])
    ]
    report = engine.evaluate_project(
        endpoints=[{"path": "/api/x", "method": "GET"}], all_findings=findings,
    )
    # 2*10 + 2*7 + 3*4 + 1 = 47 pts -> score 53
    assert report["security_score"] == 53
    assert report["grade"] == "F"


def test_endpoint_risk_tiers():
    engine = RiskEngine()
    findings = [{"title": "no auth", "severity": "HIGH",
                 "endpoint": "/api/users", "method": "GET"}]
    report = engine.evaluate_project(
        endpoints=[{"path": "/api/users", "method": "GET"}], all_findings=findings,
    )
    assert report["endpoint_breakdown_by_risk"]["HIGH"] == 1


def test_project_level_findings_count_towards_score():
    engine = RiskEngine()
    findings = [{"title": "Plaintext HTTP", "severity": "HIGH",
                 "endpoint": "http://127.0.0.1:5001", "method": "N/A"}]
    report = engine.evaluate_project([], findings)
    assert report["total_risk_points"] == 7
    assert report["security_score"] == 93


def test_top_priorities_sorted_by_severity():
    engine = RiskEngine()
    findings = [
        {"title": "low one", "severity": "LOW", "endpoint": "x", "method": "GET"},
        {"title": "crit one", "severity": "CRITICAL", "endpoint": "x", "method": "GET"},
    ]
    report = engine.evaluate_project([], findings)
    assert report["top_priorities"][0]["title"] == "crit one"