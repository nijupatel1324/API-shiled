"""Scan orchestration.

Runs the discovery + security modules in sequence against an authorized
target and returns structured results. The engine enforces limits,
timeouts and the private-host allowlist.
"""

import json
import logging
import threading
import time
from urllib.parse import urlparse

import requests

from config import Config
from scanner import ScanContext
from scanner.discovery import validate_target_url
import scanner.authentication as auth_mod
import scanner.authorization as authz_mod
import scanner.injection as injection_mod
import scanner.rate_limit as rate_mod
import scanner.headers as headers_mod
import scanner.cors as cors_mod
import scanner.tls as tls_mod
import scanner.sensitive_data as sensitive_mod
import scanner.scoring as scoring_mod

logger = logging.getLogger("api_shield.engine")

# In-memory scan job registry: scan_id -> {"status":..., "progress":...}
JOBS = {}
_findings_global = []
_scan_lock = threading.Lock()


def _new_job_id():
    return int(time.time() * 1000)


def _normalize_endpoints(endpoints):
    from scanner.discovery import Endpoint

    normalized = []
    for ep in endpoints or []:
        if isinstance(ep, Endpoint):
            normalized.append(ep)
        elif isinstance(ep, dict):
            normalized.append(
                Endpoint(
                    ep.get("method", "GET"),
                    ep.get("path", "/"),
                    source=ep.get("source", "api"),
                )
            )
        elif isinstance(ep, (list, tuple)) and len(ep) >= 2:
            normalized.append(Endpoint(ep[0], ep[1]))
    return normalized


def create_scan_job(target_url, endpoints=None, test_credentials=None, options=None):
    """Kick off a scan in a background thread; returns the job id."""
    job_id = _new_job_id()
    JOBS[job_id] = {"status": "running", "progress": 0, "message": "Starting scan..."}
    options = options or {}

    thread = threading.Thread(
        target=_run_scan,
        args=(job_id, target_url),
        kwargs={
            "endpoints": endpoints,
            "test_credentials": test_credentials,
            "options": options,
        },
        daemon=True,
    )
    thread.start()
    return job_id


def get_job(job_id):
    result = JOBS.get(job_id)
    return result


def _run_scan(job_id, target_url, endpoints=None, test_credentials=None, options=None):
    """Background worker."""
    start = time.time()
    ctx = None
    try:
        base_url = validate_target_url(target_url)
        _set(job_id, "message", "Validated target")

        session = requests.Session()
        session.headers.update({"User-Agent": "API-SHIELD/1.0 (authorized scanning only)"})

        ctx = ScanContext(
            base_url=base_url,
            session=session,
            test_credentials=test_credentials or {},
        )
        logger.info("Scan started for %s", base_url)

        if endpoints is None:
            _set(job_id, "message", "Discovering endpoints...")
            from scanner.discovery import discover_from_url

            endpoints = discover_from_url(
                base_url, session=session, limit=Config.MAX_ENDPOINTS_PER_SCAN
            )
            logger.info("API discovery completed: %d endpoints", len(endpoints))
        ctx.endpoints = _normalize_endpoints(endpoints)
        _set(job_id, "message", "Discovery completed")

        _set(job_id, "message", "Checking TLS / HTTPS...")
        tls_mod.run_tls_check(ctx)
        _update_progress(ctx, job_id, 0.15)

        _set(job_id, "message", "Analysing security headers...")
        headers_mod.run_header_analysis(ctx)
        _update_progress(ctx, job_id, 0.3)

        _set(job_id, "message", "Checking CORS...")
        cors_mod.run_cors_analysis(ctx)
        _update_progress(ctx, job_id, 0.45)

        _set(job_id, "message", "Checking sensitive data exposure...")
        sensitive_mod.run_sensitive_data_analysis(ctx)
        _update_progress(ctx, job_id, 0.6)

        _set(job_id, "message", "Testing authentication...")
        auth_mod.run_authentication_checks(ctx)
        _update_progress(ctx, job_id, 0.75)

        _set(job_id, "message", "Testing authorization...")
        authz_mod.run_authorization_checks(ctx, test_credentials or {})
        _update_progress(ctx, job_id, 0.85)

        _set(job_id, "message", "Testing injection indicators...")
        injection_mod.run_injection_checks(ctx)
        _update_progress(ctx, job_id, 0.95)

        _set(job_id, "message", "Testing rate limiting...")

        tests_before_rate = ctx.tests_completed
        rate_mod.run_rate_limit_check(ctx)

        _set(job_id, "message", "Scoring...")
        _set(job_id, "progress", 1.0)

        score, counts = scoring_mod.compute_score(ctx.findings)

        result = {
            "status": "completed",
            "target": base_url,
            "score": score,
            "counts": counts,
            "findings": ctx.findings,
            "endpoints_count": len(ctx.endpoints),
            "tests_completed": ctx.tests_completed,
            "duration": round(time.time() - start, 2),
        }
        JOBS[job_id] = {**JOBS[job_id], **result}
        logger.info(
            "Scan completed for %s: score=%s findings=%s",
            base_url, score, sum(counts.values()),
        )
    except Exception as exc:
        logger.exception("Scan %s failed", job_id)
        JOBS[job_id] = {
            **JOBS.get(job_id, {}),
            "status": "failed",
            "message": f"Scan failed: {exc}",
            "findings": ctx.findings if ctx else [],
        }


def _set(job_id, key, value):
    if job_id in JOBS:
        JOBS[job_id][key] = value


def _update_progress(ctx, job_id, progress):
    _set(job_id, "progress", min(1.0, progress + (ctx.tests_completed % 10) / 100.0))
    _set(job_id, "tests_completed", ctx.tests_completed)


def job_to_result(job):
    """Convert a completed job dict into the persisted scan payload."""
    return {
        "target": job.get("target"),
        "score": job.get("score"),
        "counts": job.get("counts", {}),
        "findings": job.get("findings", []),
        "endpoints_count": job.get("endpoints_count", 0),
        "tests_completed": job.get("tests_completed", 0),
        "duration": job.get("duration", 0),
    }