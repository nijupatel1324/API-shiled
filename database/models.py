from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timezone

db = SQLAlchemy()

class Project(db.Model):
    __tablename__ = 'projects'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    base_url = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)
    api_specification = db.Column(db.Text, nullable=True) 
    created_date = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_scan = db.Column(db.DateTime, nullable=True)
    owner = db.Column(db.String(100), nullable=False, default="admin") 
    
    # Relationship to endpoints
    endpoints = db.relationship('Endpoint', backref='project', lazy=True, cascade="all, delete-orphan")

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "base_url": self.base_url,
            "description": self.description,
            "created_date": self.created_date.isoformat() if self.created_date else None,
            "last_scan": self.last_scan.isoformat() if self.last_scan else None,
            "owner": self.owner
        }

class Endpoint(db.Model):
    __tablename__ = 'endpoints'

    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'), nullable=False)
    path = db.Column(db.String(255), nullable=False)
    method = db.Column(db.String(10), nullable=False)
    auth_required = db.Column(db.Boolean, default=False)
    parameters_count = db.Column(db.Integer, default=0)
    has_body = db.Column(db.Boolean, default=False)
    risk_level = db.Column(db.String(20), default="Unknown") # Will be updated by Risk Engine
    last_tested = db.Column(db.DateTime, nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "project_id": self.project_id,
            "path": self.path,
            "method": self.method,
            "auth_required": self.auth_required,
            "parameters": self.parameters_count,
            "has_body": self.has_body,
            "risk": self.risk_level,
            "last_tested": self.last_tested.isoformat() if self.last_tested else None
        }
