import time

from sqlalchemy import Column, Integer, String, Text, Float, DateTime, Boolean, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from models.database import db


def _default_timestamp():
    return time.time()


class User(db.Model):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(80), unique=True, nullable=False, index=True)
    email = Column(String(120), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, server_default=func.now())

    scans = relationship("Scan", back_populates="user")

    def set_password(self, password):
        from flask_bcrypt import generate_password_hash

        self.password_hash = generate_password_hash(password).decode("utf-8")

    def check_password(self, password):
        from flask_bcrypt import check_password_hash

        return check_password_hash(self.password_hash, password)


class Target(db.Model):
    __tablename__ = "targets"

    id = Column(Integer, primary_key=True)
    name = Column(String(120), nullable=False)
    base_url = Column(String(500), nullable=False, index=True)
    scan_type = Column(String(50), default="manual")
    notes = Column(Text, default="")
    created_at = Column(DateTime, server_default=func.now())

    scans = relationship("Scan", back_populates="target")


class Scan(db.Model):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False)
    status = Column(String(20), default="pending")
    started_at = Column(Float, default=_default_timestamp)
    completed_at = Column(Float, nullable=True)
    score = Column(Float, nullable=True)
    endpoints_count = Column(Integer, default=0)
    tests_completed = Column(Integer, default=0)
    severity_counts = Column(Text, default="{}")

    user = relationship("User", back_populates="scans")
    target = relationship("Target", back_populates="scans")
    findings = relationship(
        "Finding",
        back_populates="scan",
        cascade="all, delete-orphan",
        order_by="Finding.severity_order",
    )


class Report(db.Model):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    report_type = Column(String(20), nullable=False)  # html/pdf/json
    file_path = Column(String(500), nullable=False)
    generated_at = Column(Float, default=_default_timestamp)

    scan = relationship("Scan")


class ScanSchedule(db.Model):
    """Recurring scan schedule: re-scans a target every N hours."""

    __tablename__ = "scan_schedules"

    id = Column(Integer, primary_key=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False)
    interval_hours = Column(Integer, default=24, nullable=False)
    enabled = Column(Boolean, default=True)
    created_at = Column(Float, default=_default_timestamp)
    last_run_at = Column(Float, nullable=True)
    next_run_at = Column(Float, nullable=True)

    target = relationship("Target")