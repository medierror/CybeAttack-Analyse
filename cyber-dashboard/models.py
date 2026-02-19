from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class ScanLog(db.Model):
    """Stores metadata for each uploaded log file scan."""

    __tablename__ = "scan_logs"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    filename = db.Column(db.String(256), nullable=False)
    upload_time = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )
    total_lines = db.Column(db.Integer, default=0)
    total_attacks = db.Column(db.Integer, default=0)
    clean_lines = db.Column(db.Integer, default=0)
    status = db.Column(db.String(32), default="completed")

    # Relationship
    threats = db.relationship(
        "Threat", backref="scan_log", lazy=True, cascade="all, delete-orphan"
    )

    def to_dict(self):
        return {
            "id": self.id,
            "filename": self.filename,
            "upload_time": self.upload_time.isoformat(),
            "total_lines": self.total_lines,
            "total_attacks": self.total_attacks,
            "clean_lines": self.clean_lines,
            "status": self.status,
        }


class Threat(db.Model):
    """Stores individual threats detected within a scan."""

    __tablename__ = "threats"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    scan_log_id = db.Column(
        db.Integer, db.ForeignKey("scan_logs.id"), nullable=False
    )
    line_number = db.Column(db.Integer, nullable=False)
    attack_type = db.Column(db.String(64), nullable=False)
    severity = db.Column(db.String(16), nullable=False)  # Low, Medium, High, Critical
    matched_pattern = db.Column(db.String(256), nullable=True)
    raw_line = db.Column(db.Text, nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "line_number": self.line_number,
            "attack_type": self.attack_type,
            "severity": self.severity,
            "matched_pattern": self.matched_pattern,
            "raw_line": self.raw_line[:200],  # Truncate for display
        }
