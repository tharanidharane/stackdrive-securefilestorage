from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import uuid

db = SQLAlchemy()


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    aws_connected = db.Column(db.Boolean, default=False)
    aws_account_id = db.Column(db.String(20), nullable=True)
    aws_region = db.Column(db.String(30), nullable=True)
    quarantine_bucket = db.Column(db.String(100), nullable=True)
    secure_bucket = db.Column(db.String(100), nullable=True)
    kms_key_arn = db.Column(db.String(200), nullable=True)
    aws_access_key = db.Column(db.String(255), nullable=True)
    aws_secret_key = db.Column(db.String(255), nullable=True)

    files = db.relationship('File', backref='owner', lazy='dynamic')

    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'created_at': self.created_at.isoformat(),
            'aws_connected': self.aws_connected,
            'aws_account_id': self.aws_account_id,
            'aws_region': self.aws_region,
            'quarantine_bucket': self.quarantine_bucket,
            'secure_bucket': self.secure_bucket,
            'kms_key_arn': self.kms_key_arn,
        }


class File(db.Model):
    __tablename__ = 'files'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False, index=True)
    name = db.Column(db.String(255), nullable=False)
    size = db.Column(db.Float, nullable=False)  # in bytes
    size_display = db.Column(db.String(20), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='quarantine')  # quarantine, scanning, safe, blocked
    risk = db.Column(db.Integer, nullable=True)
    checks = db.Column(db.String(100), default='Awaiting scan')
    sha256_hash = db.Column(db.String(64), nullable=True)
    storage_path = db.Column(db.String(500), nullable=True)

    pipeline_stages = db.relationship('PipelineStage', backref='file', lazy='dynamic',
                                       order_by='PipelineStage.stage_order')

    def to_dict(self):
        stages = [s.to_dict() for s in self.pipeline_stages.all()]
        return {
            'id': self.id,
            'name': self.name,
            'size': round(self.size / (1024 * 1024), 1),
            'sizeUnit': 'MB',
            'uploadedAt': self.uploaded_at.isoformat(),
            'status': self.status,
            'risk': self.risk,
            'checks': self.checks,
            'sha256': self.sha256_hash,
            'pipelineStages': stages,
        }


class PipelineStage(db.Model):
    __tablename__ = 'pipeline_stages'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    file_id = db.Column(db.String(36), db.ForeignKey('files.id'), nullable=False, index=True)
    stage_order = db.Column(db.Integer, nullable=False)
    name = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, running, pass, fail, skipped
    detail = db.Column(db.String(255), default='Pending')
    started_at = db.Column(db.DateTime, nullable=True)
    completed_at = db.Column(db.DateTime, nullable=True)

    def to_dict(self):
        return {
            'name': self.name,
            'status': self.status,
            'detail': self.detail,
        }


class Notification(db.Model):
    __tablename__ = 'notifications'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False, index=True)
    file_name = db.Column(db.String(255), nullable=False)
    detected_at = db.Column(db.DateTime, default=datetime.utcnow)
    layer = db.Column(db.String(100), nullable=False)
    threat_type = db.Column(db.String(255), nullable=False)
    action = db.Column(db.String(100), default='Deleted from quarantine')
    read = db.Column(db.Boolean, default=False)

    def to_dict(self):
        return {
            'id': self.id,
            'fileName': self.file_name,
            'detectedAt': self.detected_at.isoformat(),
            'layer': self.layer,
            'threatType': self.threat_type,
            'action': self.action,
            'read': self.read,
        }
