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
            'created_at': self.created_at.isoformat() + 'Z',
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
    storage_path = db.Column(db.String(500), nullable=True)  # Clean S3 path (no keys!)

    # ── Encryption Metadata (Zero-Trust: NO plaintext keys ever stored) ──
    encryption_version = db.Column(db.Integer, default=2)     # 2=PQC+KMS production (No legacy fallback)
    kms_encrypted_key = db.Column(db.LargeBinary, nullable=True)   # KMS-encrypted AES-256 key blob
    aes_nonce = db.Column(db.LargeBinary, nullable=True)           # AES-GCM nonce (16 bytes)
    aes_tag = db.Column(db.LargeBinary, nullable=True)             # AES-GCM auth tag (16 bytes)
    kem_ciphertext = db.Column(db.LargeBinary, nullable=True)      # ML-KEM-768 encapsulated key
    kem_public_key = db.Column(db.LargeBinary, nullable=True)      # ML-KEM-768 public key
    dsa_signature = db.Column(db.LargeBinary, nullable=True)       # ML-DSA-65 signature
    dsa_public_key = db.Column(db.LargeBinary, nullable=True)      # ML-DSA-65 public key
    secrets_manager_arn = db.Column(db.String(500), nullable=True)  # ARN for PQC private keys

    # ── Sandbox Analysis Metadata ──
    sandbox_trace_log = db.Column(db.Text, nullable=True)           # Truncated strace output
    sandbox_entropy = db.Column(db.Float, nullable=True)            # Computed file entropy
    sandbox_flags = db.Column(db.Text, nullable=True)               # JSON-encoded array of threat flags
    sandbox_risk_score = db.Column(db.Integer, nullable=True)       # Heuristic risk score (normalized 0-100)
    sandbox_status_detail = db.Column(db.String(50), nullable=True) # E.g., normal_exit, timeout, oom_killed

    pipeline_stages = db.relationship('PipelineStage', backref='file', lazy='dynamic',
                                       order_by='PipelineStage.stage_order')

    def to_dict(self):
        stages = [s.to_dict() for s in self.pipeline_stages.all()]
        
        # Calculate size and unit dynamically
        if self.size < 1024:
            size_val = self.size
            unit = 'B'
        elif self.size < 1024 * 1024:
            size_val = round(self.size / 1024, 1)
            unit = 'KB'
        elif self.size < 1024 * 1024 * 1024:
            size_val = round(self.size / (1024 * 1024), 1)
            unit = 'MB'
        else:
            size_val = round(self.size / (1024 * 1024 * 1024), 1)
            unit = 'GB'

        try:
            import json
            flags_list = json.loads(self.sandbox_flags) if self.sandbox_flags else []
        except:
            flags_list = []

        return {
            'id': self.id,
            'name': self.name,
            'size': size_val,
            'sizeUnit': unit,
            'uploadedAt': self.uploaded_at.isoformat() + 'Z',
            'status': self.status,
            'risk': self.risk,
            'checks': self.checks,
            'sha256': self.sha256_hash,
            'pipelineStages': stages,
            'sandbox': {
                'traceLog': self.sandbox_trace_log,
                'entropy': self.sandbox_entropy,
                'flags': flags_list,
                'riskScore': self.sandbox_risk_score,
                'statusDetail': self.sandbox_status_detail,
            } if self.sandbox_status_detail else None
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
            'detectedAt': self.detected_at.isoformat() + 'Z',
            'layer': self.layer,
            'threatType': self.threat_type,
            'action': self.action,
            'read': self.read,
        }
