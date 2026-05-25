from datetime import datetime, timezone
import json
from factory import db


class Scan(db.Model):
    __tablename__ = 'scan'
    site_tree = db.Column(db.Text, nullable=True)
    discovered_forms = db.Column(db.Text, nullable=True)
    id = db.Column(db.Integer, primary_key=True)
    target_url = db.Column(db.String(255), nullable=False)
    scan_mode = db.Column(db.String(20), default='full', nullable=False)
    status = db.Column(db.String(50), default='PENDING', nullable=False)
    start_time = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    end_time = db.Column(db.DateTime, nullable=True)
    auth_cookies = db.Column(db.Text, nullable=True)
    site_tree = db.Column(db.Text, nullable=True)

    vulnerabilities = db.relationship(
        'Vulnerability',
        backref='scan',
        lazy=True,
        cascade="all, delete-orphan"
    )

    recon_findings = db.relationship(
        'ReconFinding',
        backref='scan',
        lazy=True,
        cascade="all, delete-orphan"
    )

    def __repr__(self):
        return f"<Scan {self.id}: '{self.target_url}'>"

    def to_dict(self):
        return {
            'id': self.id,
            'target_url': self.target_url,
            'scan_mode': self.scan_mode,
            'status': self.status,
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'vulnerability_count': len(self.vulnerabilities),
            'site_tree': json.loads(self.site_tree) if self.site_tree else {},
            'discovered_forms': json.loads(self.discovered_forms) if self.discovered_forms else []
        }


class ReconFinding(db.Model):
    __tablename__ = 'recon_finding'

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=False)
    tool = db.Column(db.String(50), nullable=False)
    finding_type = db.Column(db.String(100), nullable=False)
    details = db.Column(db.Text, nullable=False)

    def __repr__(self):
        return f"<ReconFinding {self.id}: '{self.tool} - {self.finding_type}'>"

    def get_details_as_dict(self):
        try:
            return json.loads(self.details)
        except json.JSONDecodeError:
            return {}


class Vulnerability(db.Model):
    __tablename__ = 'vulnerability'

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=False)
    type = db.Column(db.String(100), nullable=False)
    subcategory = db.Column(db.String(100), nullable=True)
    url = db.Column(db.String(500), nullable=False)
    severity = db.Column(db.String(50), nullable=False)
    details = db.Column(db.Text, nullable=False)

    cvss_score = db.Column(db.Float, nullable=True)
    cvss_vector = db.Column(db.String(100), nullable=True)
    cwe = db.Column(db.String(50), nullable=True)

    def __repr__(self):
        return f"<Vulnerability {self.id}: '{self.type}'>"

    def get_details_as_dict(self):
        try:
            return json.loads(self.details)
        except json.JSONDecodeError:
            return {}

    def to_dict(self):
        return {
            'id': self.id,
            'scan_id': self.scan_id,
            'type': self.type,
            'subcategory': self.subcategory,
            'url': self.url,
            'severity': self.severity,
            'cvss_score': self.cvss_score,
            'cvss_vector': self.cvss_vector,
            'cwe': self.cwe,
            'details': self.get_details_as_dict()
        }