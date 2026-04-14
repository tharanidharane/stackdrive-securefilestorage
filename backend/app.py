"""
StackDrive — Flask Backend API
Zero-Trust Secure Cloud File Ingestion Gateway
"""
import os
import uuid
import threading
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, send_file, Response, stream_with_context
from werkzeug.utils import secure_filename
import boto3
from botocore.exceptions import ClientError
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required,
    get_jwt_identity, get_jwt
)
from flask_mail import Mail, Message
import bcrypt
import io
import base64
from Crypto.Cipher import AES

from config import Config
from models import db, User, File, PipelineStage, Notification
from pipeline import init_pipeline_stages, run_pipeline, compute_sha256

app = Flask(__name__)
app.config.from_object(Config)

# SMTP Config (Real Flask-Mail setup)
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'stackdrive.alert@example.com')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', 'dummy-pass-123')
mail = Mail(app)

# Init extensions
CORS(app, origins=['http://localhost:5173', 'http://127.0.0.1:5173'],
     supports_credentials=True)
jwt = JWTManager(app)
db.init_app(app)

# Ensure storage dirs exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['SECURE_FOLDER'], exist_ok=True)

# Create tables
with app.app_context():
    db.create_all()


# ════════════════════════════════════════
# AUTH ENDPOINTS
# ════════════════════════════════════════

@app.route('/api/auth/signup', methods=['POST'])
def signup():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Request body required'}), 400
    
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    
    if not email or '@' not in email:
        return jsonify({'error': 'Valid email required'}), 400
    if len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400
    
    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'An account with this email already exists'}), 409
    
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    user = User(email=email, password_hash=password_hash)
    db.session.add(user)
    db.session.commit()
    
    token = create_access_token(identity=user.id, additional_claims={'email': user.email})
    
    return jsonify({
        'message': 'Account created successfully',
        'token': token,
        'user': user.to_dict(),
    }), 201


@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Request body required'}), 400
    
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'error': 'No account found with this email'}), 401
    
    if not bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
        return jsonify({'error': 'Incorrect password'}), 401
    
    token = create_access_token(identity=user.id, additional_claims={'email': user.email})
    
    return jsonify({
        'message': 'Login successful',
        'token': token,
        'user': user.to_dict(),
    }), 200


@app.route('/api/auth/me', methods=['GET'])
@jwt_required()
def get_me():
    user = User.query.get(get_jwt_identity())
    if not user:
        return jsonify({'error': 'User not found'}), 404
    return jsonify({'user': user.to_dict()}), 200


# ════════════════════════════════════════
# AWS CONNECTION ENDPOINTS
# ════════════════════════════════════════

import time
import json

@app.route('/api/aws/connect', methods=['POST'])
@jwt_required()
def connect_aws():
    data = request.get_json()
    access_key = data.get('access_key')
    secret_key = data.get('secret_key')
    region = data.get('region', 'ap-south-1')
    
    if not access_key or not secret_key:
        return jsonify({'error': 'AWS keys are required'}), 400

    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    try:
        session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region
        )
        
        # 1. Verify credentials via STS
        sts = session.client('sts')
        identity = sts.get_caller_identity()
        account_id = identity['Account']
        
        # 2. Create S3 Buckets
        s3 = session.client('s3')
        bucket_suffix = uuid.uuid4().hex[:8]
        q_bucket = f'stackdrive-quarantine-{bucket_suffix}'
        s_bucket = f'stackdrive-secure-{bucket_suffix}'
        
        bucket_config = None
        if region != 'us-east-1':
            bucket_config = {'LocationConstraint': region}
            
        for b in [q_bucket, s_bucket]:
            if bucket_config:
                s3.create_bucket(Bucket=b, CreateBucketConfiguration=bucket_config)
            else:
                s3.create_bucket(Bucket=b)
                
            # Block public access
            s3.put_public_access_block(
                Bucket=b,
                PublicAccessBlockConfiguration={
                    'BlockPublicAcls': True,
                    'IgnorePublicAcls': True,
                    'BlockPublicPolicy': True,
                    'RestrictPublicBuckets': True
                }
            )

        # 3. Create KMS Key
        kms = session.client('kms')
        key_resp = kms.create_key(
            Description='StackDrive Customer Managed Key',
            KeyUsage='ENCRYPT_DECRYPT',
            Origin='AWS_KMS'
        )
        kms_key_arn = key_resp['KeyMetadata']['Arn']
        kms.create_alias(
            AliasName=f'alias/stackdrive-key-{bucket_suffix}',
            TargetKeyId=key_resp['KeyMetadata']['KeyId']
        )
        
        # 4. Save to DB
        user.aws_connected = True
        user.aws_account_id = account_id
        user.aws_region = region
        user.aws_access_key = access_key
        user.aws_secret_key = secret_key
        user.quarantine_bucket = q_bucket
        user.secure_bucket = s_bucket
        user.kms_key_arn = kms_key_arn
        
        db.session.commit()
        
        return jsonify({
            'message': 'AWS environment provisioned successfully',
            'user': user.to_dict()
        }), 200
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        return jsonify({'error': f"AWS Provisioning Failed: {error_code} - {str(e)}"}), 400
    except Exception as e:
        return jsonify({'error': f"Unexpected error: {str(e)}"}), 500


@app.route('/api/aws/status', methods=['GET'])
@jwt_required()
def aws_status():
    user = User.query.get(get_jwt_identity())
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify({
        'connected': user.aws_connected,
        'account_id': user.aws_account_id,
        'region': user.aws_region,
        'quarantine_bucket': user.quarantine_bucket,
        'secure_bucket': user.secure_bucket,
        'kms_key_arn': user.kms_key_arn,
    }), 200


@app.route('/api/aws/disconnect', methods=['POST'])
@jwt_required()
def disconnect_aws():
    user = User.query.get(get_jwt_identity())
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    user.aws_connected = False
    user.aws_account_id = None
    user.aws_region = None
    user.quarantine_bucket = None
    user.secure_bucket = None
    user.kms_key_arn = None
    db.session.commit()
    
    return jsonify({'message': 'AWS account disconnected', 'user': user.to_dict()}), 200


# ════════════════════════════════════════
# FILE UPLOAD
# ════════════════════════════════════════

@app.route('/api/upload', methods=['POST'])
@jwt_required()
def upload_file():
    user = User.query.get(get_jwt_identity())
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    if not user.aws_connected:
        return jsonify({'error': 'AWS account not connected. Go to Settings to connect.'}), 403
    
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if not file.filename:
        return jsonify({'error': 'No file selected'}), 400
    
    if not file.filename.lower().endswith('.zip'):
        return jsonify({'error': 'Only .zip files are accepted'}), 400
    
    file_id = str(uuid.uuid4())
    safe_name = secure_filename(file.filename)
    
    # Calculate file size from stream
    file.seek(0, 2)
    file_size = file.tell()
    file.seek(0)
    
    if file_size > app.config['MAX_CONTENT_LENGTH']:
        return jsonify({'error': 'File exceeds 500MB limit'}), 413
    
    # Direct Upload to AWS Quarantine Bucket
    try:
        session = boto3.Session(
            aws_access_key_id=user.aws_access_key,
            aws_secret_access_key=user.aws_secret_key,
            region_name=user.aws_region
        )
        s3 = session.client('s3')
        s3.upload_fileobj(file, user.quarantine_bucket, safe_name)
    except Exception as e:
        return jsonify({'error': f"Failed to upload to AWS S3: {str(e)}"}), 500
    
    # Format size display
    size_mb = file_size / (1024 * 1024)
    if size_mb >= 1024:
        size_display = f"{size_mb / 1024:.1f} GB"
    else:
        size_display = f"{size_mb:.1f} MB"
    
    # Create file record
    file_record = File(
        id=file_id,
        user_id=user.id,
        name=file.filename,
        size=file_size,
        size_display=size_display,
        status='quarantine',
    )
    db.session.add(file_record)
    db.session.commit()
    
    # Initialize pipeline stages
    init_pipeline_stages(file_id)
    
    # Run pipeline in background thread
    thread = threading.Thread(
        target=run_pipeline,
        args=(file_id, safe_name, user.id),
        daemon=True,
    )
    thread.start()
    
    return jsonify({
        'message': 'File uploaded to quarantine — pipeline starting',
        'file': file_record.to_dict(),
    }), 201


# ════════════════════════════════════════
# FILE MANAGEMENT
# ════════════════════════════════════════

@app.route('/api/files', methods=['GET'])
@jwt_required()
def get_files():
    user_id = get_jwt_identity()
    status = request.args.get('status')
    
    query = File.query.filter_by(user_id=user_id)
    if status and status != 'all':
        query = query.filter_by(status=status)
    
    files = query.order_by(File.uploaded_at.desc()).all()
    return jsonify({'files': [f.to_dict() for f in files]}), 200


@app.route('/api/files/<file_id>', methods=['GET'])
@jwt_required()
def get_file(file_id):
    user_id = get_jwt_identity()
    file = File.query.filter_by(id=file_id, user_id=user_id).first()
    if not file:
        return jsonify({'error': 'File not found'}), 404
    return jsonify({'file': file.to_dict()}), 200


@app.route('/api/files/<file_id>/download', methods=['GET'])
@jwt_required()
def download_file(file_id):
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    file = File.query.filter_by(id=file_id, user_id=user.id).first()
    if not file:
        return jsonify({'error': 'File not found'}), 404
    if file.status != 'safe':
        return jsonify({'error': 'Only verified safe files can be downloaded'}), 403
    if not file.storage_path or not file.storage_path.startswith('s3://'):
        return jsonify({'error': 'File not available in AWS S3'}), 404
        
    try:
        session = boto3.Session(
            aws_access_key_id=user.aws_access_key,
            aws_secret_access_key=user.aws_secret_key,
            region_name=user.aws_region
        )
        s3 = session.client('s3')
        
        raw_path = file.storage_path.split('?aes=')
        s3_url = raw_path[0]
        
        parts = s3_url.replace('s3://', '').split('/', 1)
        bucket = parts[0]
        key = parts[1]
        
        obj = s3.get_object(Bucket=bucket, Key=key)
        raw_download = obj['Body'].read()
        
        # Strip the simulated Quantum structural headers dynamically
        ml_kem_len = 1088 + 41
        ml_dsa_len = 3293 + 37
        aes_blob = raw_download[ml_kem_len:-ml_dsa_len]
        
        # Deconstruct AES container
        nonce = aes_blob[:16]
        tag = aes_blob[-16:]
        ciphertext = aes_blob[16:-16]
        
        # Pull the true random AES-256 key
        if len(raw_path) > 1:
            aes_key = base64.urlsafe_b64decode(raw_path[1])
        else:
            aes_key = bytes.fromhex(file.sha256_hash) # Legacy fallback
            
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
        
        return send_file(
            io.BytesIO(decrypted_data),
            as_attachment=True,
            download_name=file.name,
            mimetype='application/octet-stream'
        )
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'S3 Retrieval & Decryption Failed: {str(e)}'}), 500


@app.route('/api/files/<file_id>', methods=['DELETE'])
@jwt_required()
def delete_file(file_id):
    user_id = get_jwt_identity()
    file = File.query.filter_by(id=file_id, user_id=user_id).first()
    if not file:
        return jsonify({'error': 'File not found'}), 404
    
    user = User.query.get(user_id)
    if file.storage_path and file.storage_path.startswith('s3://'):
        try:
            session = boto3.Session(
                aws_access_key_id=user.aws_access_key,
                aws_secret_access_key=user.aws_secret_key,
                region_name=user.aws_region
            )
            s3 = session.client('s3')
            
            s3_url = file.storage_path.split('?aes=')[0]
            parts = s3_url.replace('s3://', '').split('/', 1)
            s3.delete_object(Bucket=parts[0], Key=parts[1])
        except Exception:
            pass
    
    # Delete pipeline stages
    PipelineStage.query.filter_by(file_id=file_id).delete()
    db.session.delete(file)
    db.session.commit()
    
    return jsonify({'message': 'File deleted'}), 200


@app.route('/api/pipeline/<file_id>', methods=['GET'])
@jwt_required()
def get_pipeline(file_id):
    user_id = get_jwt_identity()
    file = File.query.filter_by(id=file_id, user_id=user_id).first()
    if not file:
        return jsonify({'error': 'File not found'}), 404
    
    stages = PipelineStage.query.filter_by(file_id=file_id)\
        .order_by(PipelineStage.stage_order).all()
    
    return jsonify({
        'file_id': file_id,
        'status': file.status,
        'stages': [s.to_dict() for s in stages],
    }), 200


# ════════════════════════════════════════
# DASHBOARD METRICS
# ════════════════════════════════════════

@app.route('/api/dashboard/metrics', methods=['GET'])
@jwt_required()
def dashboard_metrics():
    user_id = get_jwt_identity()
    
    safe_count = File.query.filter_by(user_id=user_id, status='safe').count()
    blocked_count = File.query.filter_by(user_id=user_id, status='blocked').count()
    scanning_count = File.query.filter_by(user_id=user_id, status='scanning').count()
    quarantine_count = File.query.filter_by(user_id=user_id, status='quarantine').count()
    
    # Today's counts
    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    safe_today = File.query.filter(
        File.user_id == user_id,
        File.status == 'safe',
        File.uploaded_at >= today_start
    ).count()
    blocked_today = File.query.filter(
        File.user_id == user_id,
        File.status == 'blocked',
        File.uploaded_at >= today_start
    ).count()
    
    return jsonify({
        'filesSafe': {'value': safe_count, 'today': safe_today, 'label': 'Files Safe',
                      'sublabel': f'+{safe_today} today' if safe_today else 'No new files today'},
        'threatsBlocked': {'value': blocked_count, 'today': blocked_today, 'label': 'Threats Blocked',
                          'sublabel': f'+{blocked_today} today' if blocked_today else 'No threats today'},
        'scanningNow': {'value': scanning_count, 'today': 0, 'label': 'Scanning Now',
                       'sublabel': f'~{scanning_count * 2} min remaining' if scanning_count else 'All clear'},
        'inQuarantine': {'value': quarantine_count, 'today': 0, 'label': 'In Quarantine',
                        'sublabel': f'{quarantine_count} queued' if quarantine_count else 'Queue empty'},
    }), 200


# ════════════════════════════════════════
# NOTIFICATIONS
# ════════════════════════════════════════

@app.route('/api/notifications', methods=['GET'])
@jwt_required()
def get_notifications():
    user_id = get_jwt_identity()
    notifications = Notification.query.filter_by(user_id=user_id)\
        .order_by(Notification.detected_at.desc()).limit(50).all()
    
    unread_count = Notification.query.filter_by(user_id=user_id, read=False).count()
    
    return jsonify({
        'notifications': [n.to_dict() for n in notifications],
        'unread_count': unread_count,
    }), 200


@app.route('/api/notifications/read', methods=['POST'])
@jwt_required()
def mark_notifications_read():
    user_id = get_jwt_identity()
    Notification.query.filter_by(user_id=user_id, read=False)\
        .update({'read': True})
    db.session.commit()
    return jsonify({'message': 'All notifications marked as read'}), 200


# ════════════════════════════════════════
# SECURITY STATS
# ════════════════════════════════════════

@app.route('/api/security/stats', methods=['GET'])
@jwt_required()
def security_stats():
    user_id = get_jwt_identity()
    
    total_files = File.query.filter_by(user_id=user_id).count()
    safe_files = File.query.filter_by(user_id=user_id, status='safe').count()
    blocked_files = File.query.filter_by(user_id=user_id, status='blocked').count()
    
    pass_rate = (safe_files / total_files * 100) if total_files > 0 else 0
    
    # Layer stats
    layer_names = ['Hash Check', 'ZIP Validation', 'ClamAV Scan', 'Sandbox Analysis']
    layer_stats = []
    for name in layer_names:
        passed = PipelineStage.query.join(File).filter(
            File.user_id == user_id,
            PipelineStage.name == name,
            PipelineStage.status == 'pass'
        ).count()
        failed = PipelineStage.query.join(File).filter(
            File.user_id == user_id,
            PipelineStage.name == name,
            PipelineStage.status == 'fail'
        ).count()
        layer_stats.append({'name': name, 'passed': passed, 'failed': failed})
    
    # Recent threats
    threats = Notification.query.filter_by(user_id=user_id)\
        .order_by(Notification.detected_at.desc()).limit(10).all()
    
    return jsonify({
        'totalScanned': total_files,
        'passRate': round(pass_rate, 1),
        'avgScanTime': '2m 14s',
        'activeThreats': blocked_files,
        'layerStats': layer_stats,
        'recentThreats': [t.to_dict() for t in threats],
    }), 200


# ════════════════════════════════════════
# ERROR HANDLERS
# ════════════════════════════════════════

@app.errorhandler(413)
def too_large(e):
    return jsonify({'error': 'File exceeds 500MB limit'}), 413

@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Resource not found'}), 404

@app.errorhandler(500)
def server_error(e):
    return jsonify({'error': 'Internal server error'}), 500

@jwt.expired_token_loader
def expired_token(jwt_header, jwt_payload):
    return jsonify({'error': 'Session expired. Please log in again.'}), 401

@jwt.invalid_token_loader
def invalid_token(error):
    return jsonify({'error': 'Invalid authentication token'}), 401

@jwt.unauthorized_loader
def missing_token(error):
    return jsonify({'error': 'Authentication required'}), 401


if __name__ == '__main__':
    app.run(debug=True, use_reloader=False, port=5000)
