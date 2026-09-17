"""
Recurring scan scheduler.

Runs a daemon loop that periodically wakes up, finds enabled ScanSchedule
entries whose next_run_at is due, and launches asynchronous scans for their
targets (via scanner.orchestrator.start_async_scan). The loop is lightweight
and only fires scans that are already within the authorized allowlist.
"""

import logging
import threading
import time

from config import Config

logger = logging.getLogger("api-shield.scheduler")


def promise_due_schedules(now_ts=None) -> list:
    """Return enabled schedules whose next run is due or unset."""
    from models import ScanSchedule

    now_ts = time.time() if now_ts is None else now_ts
    return [
        s for s in ScanSchedule.query.filter_by(enabled=True).all()
        if s.next_run_at is None or now_ts >= s.next_run_at
    ]


def _scheduler_cycle(app) -> None:
    """Fires all due schedules once. Meant to run inside an app context."""
    from database.models import db, Project
    from models import Target
    from scanner.orchestrator import start_async_scan

    now_ts = time.time()
    for sched in promise_due_schedules(now_ts):
        target = Target.query.get(sched.target_id)
        if not target:
            continue
        project = Project.query.filter_by(base_url=target.base_url).first()
        if not project:
            logger.warning("Scheduling skipped: no project for %s", target.base_url)
            continue
        try:
            scan_id = start_async_scan(app, project.id)
            logger.info(
                "Scheduled scan #%s fired for %s (every %sh)",
                scan_id, target.base_url, sched.interval_hours,
            )
        except Exception as exc:
            logger.exception("Scheduled scan failed for %s: %s", target.base_url, exc)
        sched.last_run_at = now_ts
        sched.next_run_at = now_ts + max(1, sched.interval_hours) * 3600
        db.session.commit()


def _run_scheduler(app, stop_event) -> None:
    while not stop_event.is_set():
        try:
            with app.app_context():
                _scheduler_cycle(app)
        except Exception:
            logger.exception("Scheduler cycle failed")
        stop_event.wait(Config.SCHEDULER_POLL_SECONDS)
    logger.info("Scheduler stopped")


def start_scheduler(app):
    """Launch the background scheduler thread; returns its stop event."""
    stop_event = threading.Event()
    thread = threading.Thread(
        target=_run_scheduler,
        args=(app, stop_event),
        daemon=True,
        name="api-shield-scheduler",
    )
    thread.start()
    logger.info("Recurring scan scheduler started (poll every %ss)",
                Config.SCHEDULER_POLL_SECONDS)
    return stop_event