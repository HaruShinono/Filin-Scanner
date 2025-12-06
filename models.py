# models.py (ĐÃ SỬA LỖI)

from datetime import datetime
import json
# Import đối tượng 'db' duy nhất từ factory.py
from factory import db

# KHÔNG còn dòng 'db = SQLAlchemy()' ở đây nữa

class Scan(db.Model):
    """
    Đại diện cho một lần quét (một phiên làm việc).
    Tương ứng với bảng 'scan' trong cơ sở dữ liệu.
    """
    __tablename__ = 'scan'

    id = db.Column(db.Integer, primary_key=True)
    target_url = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(50), default='PENDING', nullable=False)
    start_time = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    end_time = db.Column(db.DateTime, nullable=True)
    auth_cookies = db.Column(db.Text, nullable=True)
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
            'status': self.status,
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'vulnerability_count': len(self.vulnerabilities)
        }

class Vulnerability(db.Model):
    """
    Đại diện cho một lỗ hổng bảo mật được tìm thấy.
    Tương ứng với bảng 'vulnerability' trong cơ sở dữ liệu.
    """
    __tablename__ = 'vulnerability'

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=False)
    type = db.Column(db.String(100), nullable=False)
    subcategory = db.Column(db.String(100), nullable=True)
    url = db.Column(db.String(500), nullable=False)
    severity = db.Column(db.String(50), nullable=False)
    details = db.Column(db.Text, nullable=False)

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
            'details': self.get_details_as_dict()
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