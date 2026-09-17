import time

from sqlalchemy import Column, Integer, String, Text, Float, ForeignKey
from sqlalchemy.orm import relationship

from models.database import db

SEVERITY_ORDER = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4, "INFO": 5}


def _default_timestamp():
    return time.time()


class Finding(db.Model):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    title = Column(String(200), nullable=False)
    severity = Column(String(10), nullable=False, default="INFO")
    severity_order = Column(Integer, default=5)
    endpoint = Column(String(500), default="")
    method = Column(String(10), default="")
    category = Column(String(100), default="")
    description = Column(Text, default="")
    evidence = Column(Text, default="")
    recommendation = Column(Text, default="")
    status = Column(String(20), default="open")
    created_at = Column(Float, default=_default_timestamp)

    scan = relationship("Scan", back_populates="findings")

    def to_dict(self):
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "title": self.title,
            "severity": self.severity,
            "endpoint": self.endpoint,
            "method": self.method,
            "category": self.category,
            "description": self.description,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "status": self.status,
        }

    @staticmethod
    def severity_rank(severity):
        return SEVERITY_ORDER.get(severity, 5)