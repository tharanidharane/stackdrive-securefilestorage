"""
StackDrive — Flask Backend API
Zero-Trust Secure Cloud File Ingestion Gateway
"""
from dotenv import load_dotenv
load_dotenv()  # Load .env file (VT_API_KEY, Fargate config, etc.)
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
    get_jwt_identity, get_jwt, verify_jwt_in_request
)
from flask_mail import Mail, Message
import bcrypt
import io

import gc
from config import Config, HOST_SCAN_DIR
from models import db, User, File, PipelineStage, Notification, OTP, AuditLog
from pipeline import init_pipeline_stages, run_pipeline, compute_sha256, migrate_old_stage_names, warmup_clamav, dispatch_pipeline, cleanup_stuck_scans
from encryption import verify_pqc_available

verify_pqc_available()

app = Flask(__name__)
app.config.from_object(Config)

# SMTP Config (Real Flask-Mail setup)
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'true').lower() == 'true'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'stackdrive.alert@example.com')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', 'dummy-pass-123')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', os.environ.get('MAIL_USERNAME', 'stackdrive.alert@example.com'))
mail = Mail(app)

# Init extensions
CORS(app, origins=[
    'http://localhost:5173', 'http://127.0.0.1:5173',
    'http://localhost:5174', 'http://127.0.0.1:5174'
], supports_credentials=True, expose_headers=['X-Decryption-Warning'])

jwt = JWTManager(app)
db.init_app(app)

# Create tables
with app.app_context():
    db.create_all()
    # Migrate old pipeline stage names to new naming convention
    migrate_old_stage_names()
    # Recover scans that were interrupted
    cleanup_stuck_scans()
    # Pre-warm ClamAV daemon container in background asynchronously
    warmup_clamav()


# Google OAuth Config
client_config = {
    "web": {
        "client_id": os.environ.get("GOOGLE_CLIENT_ID"),
        "client_secret": os.environ.get("GOOGLE_CLIENT_SECRET"),
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "redirect_uris": [os.environ.get("GOOGLE_REDIRECT_URI")]
    }
}


# ════════════════════════════════════════
# AUTH HELPER FUNCTIONS
# ════════════════════════════════════════

def send_login_notification(user_id, user_agent_str, remote_addr, login_method):
    from user_agents import parse
    try:
        ua = parse(user_agent_str)
        device_name = f"{ua.browser.family} {ua.browser.version_string} on {ua.os.family} {ua.os.version_string}"
    except Exception:
        device_name = "Unknown Device"

    ip_address = remote_addr
    login_time = datetime.utcnow().strftime('%B %d, %Y at %I:%M %p UTC')
    
    location = "Location lookup not available"
    try:
        import requests
        resp = requests.get(f"http://ip-api.com/json/{ip_address}?fields=city,country", timeout=2)
        if resp.status_code == 200:
            data = resp.json()
            city = data.get('city')
            country = data.get('country')
            if city and country:
                location = f"{city}, {country}"
    except Exception as e:
        print(f"Location lookup error: {e}")

    try:
        with app.app_context():
            user = User.query.get(user_id)
            if not user:
                return
            
            html_body = f"""
            <div style="font-family: Arial, sans-serif; background-color: #0f172a; color: #f1f5f9; padding: 24px; border-radius: 8px; max-width: 500px; margin: 0 auto; border: 1px solid #334155;">
              <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 20px;">
                <span style="font-size: 20px;">🔐</span>
                <h2 style="margin: 0; color: #38bdf8; font-size: 18px;">StackDrive Security Alert</h2>
              </div>
              <p style="margin-bottom: 20px; font-size: 15px; color: #cbd5e1;">A new sign-in was detected on your account</p>
              <table style="width: 100%; border-collapse: collapse; margin-bottom: 24px; font-size: 14px; color: #94a3b8;">
                <tr>
                  <td style="padding: 6px 0; width: 120px;">👤 <strong>Account:</strong></td>
                  <td style="padding: 6px 0; color: #f1f5f9;">{user.email}</td>
                </tr>
                <tr>
                  <td style="padding: 6px 0;">🖥️ <strong>Device:</strong></td>
                  <td style="padding: 6px 0; color: #f1f5f9;">{device_name}</td>
                </tr>
                <tr>
                  <td style="padding: 6px 0;">🌐 <strong>IP Address:</strong></td>
                  <td style="padding: 6px 0; color: #f1f5f9;">{ip_address}</td>
                </tr>
                <tr>
                  <td style="padding: 6px 0;">📍 <strong>Location:</strong></td>
                  <td style="padding: 6px 0; color: #f1f5f9;">{location}</td>
                </tr>
                <tr>
                  <td style="padding: 6px 0;">🕐 <strong>Time:</strong></td>
                  <td style="padding: 6px 0; color: #f1f5f9;">{login_time}</td>
                </tr>
                <tr>
                  <td style="padding: 6px 0;">🔑 <strong>Method:</strong></td>
                  <td style="padding: 6px 0; color: #f1f5f9;">{login_method}</td>
                </tr>
              </table>
              
              <div style="background-color: #1e293b; padding: 14px; border-radius: 6px; margin-bottom: 16px; border-left: 4px solid #10b981;">
                <strong style="color: #10b981; display: block; margin-bottom: 4px;">This was you?</strong>
                <span style="font-size: 13px; color: #cbd5e1;">No action needed. You're all set.</span>
              </div>
              
              <div style="background-color: #1e293b; padding: 14px; border-radius: 6px; margin-bottom: 24px; border-left: 4px solid #ef4444;">
                <strong style="color: #ef4444; display: block; margin-bottom: 4px;">⚠️ Wasn't you?</strong>
                <span style="font-size: 13px; color: #cbd5e1; display: block; margin-bottom: 12px;">Secure your account immediately by resetting your password:</span>
                <a href="http://localhost:5173/forgot" style="display: inline-block; background-color: #ef4444; color: white; padding: 8px 16px; border-radius: 4px; text-decoration: none; font-size: 13px; font-weight: bold;">Secure My Account</a>
              </div>
              
              <hr style="border: 0; border-top: 1px solid #334155; margin-bottom: 16px;">
              <p style="font-size: 11px; color: #64748b; margin: 0; text-align: center;">StackDrive Zero-Trust Security Platform<br>This is an automated security alert. Do not reply to this email.</p>
            </div>
            """
            sender = app.config.get('MAIL_DEFAULT_SENDER') or app.config.get('MAIL_USERNAME')
            msg = Message(
                subject="New sign-in to your StackDrive account",
                sender=sender,
                recipients=[user.email],
                html=html_body
            )
            mail.send(msg)
    except Exception as e:
        print(f"Error sending login notification email: {e}")


def handle_successful_login(user, user_agent_str, remote_addr, login_method):
    from user_agents import parse
    try:
        ua = parse(user_agent_str)
        device_name = f"{ua.browser.family} {ua.browser.version_string} on {ua.os.family} {ua.os.version_string}"
    except Exception:
        device_name = "Unknown Device"

    user.last_login_at = datetime.utcnow()
    user.last_login_ip = remote_addr
    user.last_login_device = device_name
    db.session.commit()
    
    # Send email notification asynchronously using background thread
    threading.Thread(
        target=send_login_notification,
        args=(user.id, user_agent_str, remote_addr, login_method),
        daemon=True
    ).start()


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
    otp_verified = data.get('otp_verified', False)
    
    if not email or '@' not in email:
        return jsonify({'error': 'Valid email required'}), 400
    if len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400
    
    # Check OTP verification status
    if not otp_verified:
        five_minutes_ago = datetime.utcnow() - timedelta(minutes=15)
        recent_otp = OTP.query.filter_by(email=email, purpose='signup', used=True)\
            .filter(OTP.created_at >= five_minutes_ago)\
            .first()
        if not recent_otp:
            return jsonify({'error': 'Email not verified — complete OTP verification first'}), 403

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
    
    if not user.password_hash:
        return jsonify({'error': 'Please sign in with Google'}), 401
        
    if not bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
        return jsonify({'error': 'Incorrect password'}), 401
    
    token = create_access_token(identity=user.id, additional_claims={'email': user.email})
    
    # Trigger login notification & last login metadata update
    handle_successful_login(user, request.headers.get('User-Agent', ''), request.remote_addr, 'Email + Password')
    
    return jsonify({
        'message': 'Login successful',
        'token': token,
        'user': user.to_dict(),
    }), 200


@app.route('/api/auth/send-otp', methods=['POST'])
def send_otp():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Request body required'}), 400
    
    email = data.get('email', '').strip().lower()
    purpose = data.get('purpose', '')
    
    if not email or '@' not in email:
        return jsonify({'error': 'Valid email required'}), 400
    if purpose not in ['login', 'signup', 'reset']:
        return jsonify({'error': 'Invalid purpose'}), 400
        
    user = User.query.filter_by(email=email).first()
    if purpose == 'signup':
        if user:
            return jsonify({'error': 'An account with this email already exists'}), 409
    elif purpose in ['login', 'reset']:
        if not user:
            return jsonify({'error': 'No account found with this email'}), 404
            
    # Generate 6-digit random OTP
    import random
    otp_code = f"{random.randint(100000, 999999)}"
    
    # Delete any previous unused OTPs for this email+purpose
    OTP.query.filter_by(email=email, purpose=purpose, used=False).delete()
    
    # Save new OTP to DB with expires_at = now + 10 minutes
    expires_at = datetime.utcnow() + timedelta(minutes=10)
    otp_record = OTP(
        email=email,
        otp_code=otp_code,
        purpose=purpose,
        expires_at=expires_at,
        used=False
    )
    db.session.add(otp_record)
    db.session.commit()
    
    # Send email via Flask-Mail
    try:
        sender = app.config.get('MAIL_DEFAULT_SENDER') or app.config.get('MAIL_USERNAME')
        msg = Message(
            subject="StackDrive — Your Verification Code",
            sender=sender,
            recipients=[email],
            body=f"Your StackDrive verification code is: {otp_code}\n\nThis code expires in 10 minutes. Do not share it with anyone."
        )
        mail.send(msg)
    except Exception as e:
        print(f"Failed to send OTP email: {e}")
        return jsonify({'error': f"Failed to send OTP email: {str(e)}"}), 500
        
    return jsonify({'message': 'OTP sent to your email'}), 200


@app.route('/api/auth/verify-otp', methods=['POST'])
def verify_otp():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Request body required'}), 400
        
    email = data.get('email', '').strip().lower()
    otp_code = data.get('otp', '').strip()
    purpose = data.get('purpose', '')
    
    if not email or not otp_code or purpose not in ['login', 'signup', 'reset']:
        return jsonify({'error': 'Missing required fields'}), 400
        
    # Find the latest unused, unexpired OTP for this email+purpose
    now = datetime.utcnow()
    otp_record = OTP.query.filter_by(email=email, purpose=purpose, used=False)\
        .filter(OTP.expires_at > now)\
        .order_by(OTP.created_at.desc()).first()
        
    if not otp_record or otp_record.otp_code != otp_code:
        return jsonify({'error': 'Invalid or expired OTP'}), 400
        
    # Mark OTP as used
    otp_record.used = True
    db.session.commit()
    
    if purpose == 'login':
        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        token = create_access_token(identity=user.id, additional_claims={'email': user.email})
        
        # Trigger login notification & last login metadata update
        handle_successful_login(user, request.headers.get('User-Agent', ''), request.remote_addr, 'Email + OTP')
        
        return jsonify({
            'user': user.to_dict(),
            'token': token
        }), 200
    else:  # signup or reset
        return jsonify({
            'verified': True,
            'email': email
        }), 200


@app.route('/api/auth/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Request body required'}), 400
        
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    
    if not email or '@' not in email:
        return jsonify({'error': 'Valid email required'}), 400
    if len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400
        
    # Check OTP verification status
    five_minutes_ago = datetime.utcnow() - timedelta(minutes=15)
    recent_otp = OTP.query.filter_by(email=email, purpose='reset', used=True)\
        .filter(OTP.created_at >= five_minutes_ago)\
        .first()
    if not recent_otp:
        return jsonify({'error': 'Email not verified — complete OTP verification first'}), 403
        
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'error': 'No account found with this email'}), 404
        
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    user.password_hash = password_hash
    db.session.commit()
    
    return jsonify({'message': 'Password reset successfully'}), 200


@app.route('/api/auth/google', methods=['GET'])
def google_auth():
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
    from google_auth_oauthlib.flow import Flow
    
    flow = Flow.from_client_config(
        client_config,
        scopes=[
            "openid",
            "https://www.googleapis.com/auth/userinfo.email",
            "https://www.googleapis.com/auth/userinfo.profile"
        ],
        redirect_uri=os.environ.get("GOOGLE_REDIRECT_URI")
    )
    auth_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true'
    )
    return jsonify({"auth_url": auth_url}), 200


@app.route('/api/auth/google/callback', methods=['GET'])
def google_callback():
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
    from flask import redirect
    import urllib.parse
    import json
    from google_auth_oauthlib.flow import Flow
    from google.oauth2 import id_token
    from google.auth.transport import requests as google_requests
    
    flow = Flow.from_client_config(
        client_config,
        scopes=[
            "openid",
            "https://www.googleapis.com/auth/userinfo.email",
            "https://www.googleapis.com/auth/userinfo.profile"
        ],
        redirect_uri=os.environ.get("GOOGLE_REDIRECT_URI")
    )
    
    code = request.args.get('code')
    if not code:
        return jsonify({"error": "Authorization code missing"}), 400
        
    try:
        flow.fetch_token(code=code)
        credentials = flow.credentials
        
        id_info = id_token.verify_oauth2_token(
            credentials.id_token,
            google_requests.Request(),
            os.environ.get("GOOGLE_CLIENT_ID"),
            clock_skew_in_seconds=10
        )
        
        email = id_info.get('email').strip().lower()
        google_id = id_info.get('sub')
        
        user = User.query.filter_by(email=email).first()
        if not user:
            user = User(
                email=email,
                google_id=google_id,
                is_google_user=True,
                password_hash=None
            )
            db.session.add(user)
            db.session.commit()
        else:
            if not user.google_id:
                user.google_id = google_id
                user.is_google_user = True
                db.session.commit()
                
        token = create_access_token(identity=user.id, additional_claims={'email': user.email})
        
        # Trigger login notification & last login metadata update
        handle_successful_login(user, request.headers.get('User-Agent', ''), request.remote_addr, 'Google OAuth')
        
        user_json = urllib.parse.quote(json.dumps(user.to_dict()))
        redirect_url = f"http://localhost:5173/auth/google/callback?token={token}&user={user_json}"
        return redirect(redirect_url)
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"Authentication failed: {str(e)}"}), 500


@app.route('/api/auth/me', methods=['GET'])
@jwt_required()
def get_me():
    user = User.query.get(get_jwt_identity())
    if not user:
        return jsonify({'error': 'User not found'}), 404
    return jsonify({'user': user.to_dict()}), 200


def _get_aws_session(user):
    import logging
    import boto3

    # Prefer IAM role assumption (production path)
    if hasattr(user, 'iam_role_arn') and user.iam_role_arn:
        sts = boto3.client('sts')
        assumed = sts.assume_role(
            RoleArn=user.iam_role_arn,
            RoleSessionName=f"stackdrive-user-{user.id}",
            DurationSeconds=900,
        )
        creds = assumed['Credentials']
        return boto3.Session(
            aws_access_key_id=creds['AccessKeyId'],
            aws_secret_access_key=creds['SecretAccessKey'],
            aws_session_token=creds['SessionToken'],
            region_name=getattr(user, 'aws_region', None) or 'us-east-1',
        )

    logging.warning("AWS credentials read from DB — migrate to IAM roles or environment variables")
    return boto3.Session(
        aws_access_key_id=user.aws_access_key,
        aws_secret_access_key=user.aws_secret_key,
        region_name=getattr(user, 'aws_region', None) or 'us-east-1'
    )


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

            # Enable CORS for direct browser uploads on the quarantine bucket
            if b == q_bucket:
                s3.put_bucket_cors(
                    Bucket=b,
                    CORSConfiguration={
                        'CORSRules': [{
                            'AllowedHeaders': ['*'],
                            'AllowedMethods': ['PUT', 'POST', 'GET'],
                            'AllowedOrigins': [
                                'http://localhost:5173', 'http://127.0.0.1:5173',
                                'http://localhost:5174', 'http://127.0.0.1:5174'
                            ],
                            'ExposeHeaders': ['ETag'],
                            'MaxAgeSeconds': 3600
                        }]
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
# FILE UPLOAD — PRESIGNED MULTIPART (FAST)
# ════════════════════════════════════════

def calculate_chunk_size(file_size):
    # Minimum chunk size for S3 is 5MB.
    # We keep the chunk size smaller (around 8MB - 12MB) to allow maximum upload parallelism
    # while staying above S3's 5MB minimum part size.
    if file_size <= 100 * 1024 * 1024:
        return 8 * 1024 * 1024       # 8 MB chunks
    else:
        return 12 * 1024 * 1024      # 12 MB chunks (allows parallel throughput up to 15 concurrent chunks)


@app.route('/api/upload/initiate', methods=['POST'])
@jwt_required()
def initiate_upload():
    """
    Step 1: Initiate a multipart upload on S3 and return presigned URLs
    for each chunk so the browser can upload directly to S3.
    
    Request body: { fileName: str, fileSize: int }
    Response: { uploadId, fileId, s3Key, chunkSize, presignedUrls: [...], totalParts }
    """
    user = User.query.get(get_jwt_identity())
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    if not user.aws_connected:
        return jsonify({'error': 'AWS account not connected. Go to Settings to connect.'}), 403
    
    data = request.get_json()
    file_name = data.get('fileName', '')
    file_size = data.get('fileSize', 0)
    
    if not file_name:
        return jsonify({'error': 'File name is required'}), 400

    max_size = int(app.config.get('MAX_CONTENT_LENGTH', 500 * 1024 * 1024))
    if int(file_size) > max_size:
        return jsonify({'error': 'File exceeds 500MB limit'}), 413

    safe_name = secure_filename(file_name)
    file_id = str(uuid.uuid4())
    s3_key = safe_name

    try:
        session = _get_aws_session(user)
        s3 = session.client('s3')

        # Initiate multipart upload
        mpu = s3.create_multipart_upload(
            Bucket=user.quarantine_bucket,
            Key=s3_key,
        )
        upload_id = mpu['UploadId']

        # Calculate total parts based on dynamic chunk size
        chunk_size = calculate_chunk_size(file_size)
        total_parts = max(1, -(-file_size // chunk_size))  # Ceiling division

        # Generate presigned URLs for each part
        presigned_urls = []
        for part_number in range(1, total_parts + 1):
            url = s3.generate_presigned_url(
                'upload_part',
                Params={
                    'Bucket': user.quarantine_bucket,
                    'Key': s3_key,
                    'UploadId': upload_id,
                    'PartNumber': part_number,
                },
                ExpiresIn=3600,  # 1 hour
            )
            presigned_urls.append(url)

        # Format size display
        if file_size < 1024:
            size_display = f"{file_size} B"
        elif file_size < 1024 * 1024:
            size_display = f"{file_size / 1024:.1f} KB"
        elif file_size < 1024 * 1024 * 1024:
            size_display = f"{file_size / (1024 * 1024):.1f} MB"
        else:
            size_display = f"{file_size / (1024 * 1024 * 1024):.1f} GB"

        # Create file record in DB immediately (status = quarantine)
        file_record = File(
            id=file_id,
            user_id=user.id,
            name=file_name,
            size=file_size,
            size_display=size_display,
            status='quarantine',
        )
        db.session.add(file_record)
        db.session.commit()

        return jsonify({
            'uploadId': upload_id,
            'fileId': file_id,
            's3Key': s3_key,
            'chunkSize': chunk_size,
            'totalParts': total_parts,
            'presignedUrls': presigned_urls,
        }), 200

    except ClientError as e:
        return jsonify({'error': f"S3 multipart initiation failed: {str(e)}"}), 500
    except Exception as e:
        return jsonify({'error': f"Unexpected error: {str(e)}"}), 500


@app.route('/api/upload/complete', methods=['POST'])
@jwt_required()
def complete_upload():
    """
    Step 2: Complete the multipart upload after all parts are uploaded.
    Then kick off the security pipeline.
    
    Request body: { uploadId, fileId, s3Key, parts: [{PartNumber, ETag}, ...] }
    """
    user = User.query.get(get_jwt_identity())
    if not user:
        return jsonify({'error': 'User not found'}), 404

    data = request.get_json()
    upload_id = data.get('uploadId')
    file_id = data.get('fileId')
    s3_key = data.get('s3Key')
    parts = data.get('parts', [])
    sha256 = data.get('sha256')

    if not upload_id or not file_id or not s3_key or not parts:
        return jsonify({'error': 'Missing required fields'}), 400

    file_record = File.query.filter_by(id=file_id, user_id=user.id).first()
    if not file_record:
        return jsonify({'error': 'File record not found'}), 404

    if sha256:
        file_record.sha256_hash = sha256
        db.session.commit()

    try:
        session = _get_aws_session(user)
        s3 = session.client('s3')

        # Complete the multipart upload on S3
        s3.complete_multipart_upload(
            Bucket=user.quarantine_bucket,
            Key=s3_key,
            UploadId=upload_id,
            MultipartUpload={
                'Parts': sorted(parts, key=lambda p: p['PartNumber'])
            }
        )

        # Initialize pipeline stages
        init_pipeline_stages(file_id)

        # Extract just the filename from s3_key for pipeline
        safe_name = s3_key.split('/')[-1]

        # Run pipeline in background via dispatcher
        dispatch_pipeline(file_id, s3_key, user.id, temp_filepath=None, temp_dir=None)

        return jsonify({
            'message': 'File uploaded to quarantine — pipeline starting',
            'file': file_record.to_dict(),
        }), 201

    except ClientError as e:
        return jsonify({'error': f"S3 multipart completion failed: {str(e)}"}), 500
    except Exception as e:
        return jsonify({'error': f"Unexpected error: {str(e)}"}), 500


@app.route('/api/upload/local', methods=['POST'])
@jwt_required()
def upload_local():
    """
    Direct local upload for high-performance scanning.
    Bypasses S3 quarantine entirely.
    """
    import tempfile
    user = User.query.get(get_jwt_identity())
    if not user:
        return jsonify({'error': 'User not found'}), 404
        
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
        
    sha256 = request.form.get('sha256')
    try:
        file_size = int(request.form.get('fileSize', 0))
    except (ValueError, TypeError):
        file_size = 0
        
    file_id = str(uuid.uuid4())
    safe_name = secure_filename(file.filename)
    s3_key = safe_name
    
    # Check max content length (500MB)
    max_size = int(app.config.get('MAX_CONTENT_LENGTH', 500 * 1024 * 1024))
    if file_size > max_size:
        return jsonify({'error': 'File exceeds 500MB limit'}), 413
        
    # Format size display
    if file_size < 1024:
        size_display = f"{file_size} B"
    elif file_size < 1024 * 1024:
        size_display = f"{file_size / 1024:.1f} KB"
    elif file_size < 1024 * 1024 * 1024:
        size_display = f"{file_size / (1024 * 1024):.1f} MB"
    else:
        size_display = f"{file_size / (1024 * 1024 * 1024):.1f} GB"
        
    try:
        # Save file locally in a temp dir with permissions readable by ClamAV / Sandbox
        temp_dir = tempfile.mkdtemp(dir=HOST_SCAN_DIR)
        os.chmod(temp_dir, 0o755)
        temp_filepath = os.path.join(temp_dir, safe_name)
        file.save(temp_filepath)
        os.chmod(temp_filepath, 0o644)
        
        # Create file record
        file_record = File(
            id=file_id,
            user_id=user.id,
            name=file.filename,
            size=file_size,
            size_display=size_display,
            status='quarantine',
            sha256_hash=sha256
        )
        db.session.add(file_record)
        db.session.commit()
        
        # Initialize pipeline stages
        init_pipeline_stages(file_id)
        
        # Run pipeline in background using the local temp file path
        dispatch_pipeline(file_id, s3_key, user.id, temp_filepath=temp_filepath, temp_dir=temp_dir)
        
        return jsonify({
            'message': 'File uploaded locally — pipeline starting',
            'file': file_record.to_dict(),
        }), 201
        
    except Exception as e:
        return jsonify({'error': f"Local upload failed: {str(e)}"}), 500



@app.route('/api/upload/abort', methods=['POST'])
@jwt_required()
def abort_upload():
    """
    Abort a multipart upload if something goes wrong on the frontend.
    Cleans up incomplete parts from S3.
    
    Request body: { uploadId, fileId, s3Key }
    """
    user = User.query.get(get_jwt_identity())
    if not user:
        return jsonify({'error': 'User not found'}), 404

    data = request.get_json()
    upload_id = data.get('uploadId')
    file_id = data.get('fileId')
    s3_key = data.get('s3Key')

    try:
        session = _get_aws_session(user)
        s3 = session.client('s3')

        # Abort the multipart upload
        s3.abort_multipart_upload(
            Bucket=user.quarantine_bucket,
            Key=s3_key,
            UploadId=upload_id,
        )
    except Exception:
        pass

    # Clean up DB record
    if file_id:
        file_record = File.query.filter_by(id=file_id, user_id=user.id).first()
        if file_record:
            db.session.delete(file_record)
            db.session.commit()

    return jsonify({'message': 'Upload aborted'}), 200


# ════════════════════════════════════════
# LEGACY UPLOAD (Fallback for small files or non-multipart)
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
    

    
    file_id = str(uuid.uuid4())
    safe_name = secure_filename(file.filename)
    
    # Calculate file size from stream
    file.seek(0, 2)
    file_size = file.tell()
    file.seek(0)
    
    if file_size > app.config['MAX_CONTENT_LENGTH']:
        return jsonify({'error': 'File exceeds 500MB limit'}), 413
    
    import tempfile
    
    # Save the file locally first instead of blocking user request for S3 upload
    temp_dir = tempfile.mkdtemp(dir=HOST_SCAN_DIR)
    os.chmod(temp_dir, 0o755)
    temp_filepath = os.path.join(temp_dir, safe_name)
    try:
        file.save(temp_filepath)
        os.chmod(temp_filepath, 0o644)
    except Exception as e:
        return jsonify({'error': f"Failed to save file: {str(e)}"}), 500
    
    # Format size display
    if file_size < 1024:
        size_display = f"{file_size} B"
    elif file_size < 1024 * 1024:
        size_display = f"{file_size / 1024:.1f} KB"
    elif file_size < 1024 * 1024 * 1024:
        size_display = f"{file_size / (1024 * 1024):.1f} MB"
    else:
        size_display = f"{file_size / (1024 * 1024 * 1024):.1f} GB"
    
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
    
    s3_key = safe_name
    # Run pipeline in background via dispatcher
    dispatch_pipeline(file_id, s3_key, user.id, temp_filepath=temp_filepath, temp_dir=temp_dir)
    
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

    is_recovery = request.args.get('recovery') == 'true'
    if is_recovery:
        if file.status not in ['safe', 'Integrity Verification Failed']:
            return jsonify({'error': 'Only safe or integrity failed files can be downloaded in recovery mode'}), 403
    else:
        if file.status != 'safe':
            return jsonify({'error': 'Only verified safe files can be downloaded'}), 403

    if not file.storage_path or not file.storage_path.startswith('s3://'):
        return jsonify({'error': 'File not available in AWS S3'}), 404
        
    try:
        from encryption import create_encryption_engine, HybridEncryptionEngine

        # strictly enforce v2 hybrid decryption
        engine, _ = create_encryption_engine(user)
        decrypted_data, warnings = engine.decrypt_file(file)

        # Check for integrity failure
        integrity_warnings = []
        if warnings:
            integrity_warnings = [
                w for w in warnings 
                if any(kw in w.lower() for kw in ["modified", "failed", "corrupted", "invalid", "tampered", "mismatch"])
            ]

        has_failed = (decrypted_data is None) or (len(integrity_warnings) > 0)
        
        if has_failed:
            reasons = integrity_warnings if integrity_warnings else (warnings if warnings else ["Decryption/Integrity failure"])
            
            if not is_recovery:
                # Mark file status
                file.status = "Integrity Verification Failed"
                
                # Log security incident
                audit_log = AuditLog(
                    user_id=user.id,
                    file_id=file.id,
                    event_type='INTEGRITY_FAILED',
                    failure_reason="; ".join(reasons),
                    recovery_requested=False,
                    ip_address=request.remote_addr,
                    browser_info=request.user_agent.string
                )
                db.session.add(audit_log)
                
                # Add notification
                notif = Notification(
                    user_id=user.id,
                    file_name=file.name,
                    layer="Decryption Engine",
                    threat_type="Integrity Verification Failed",
                    action="Blocked download attempt due to tampering"
                )
                db.session.add(notif)
                db.session.commit()
                
                return jsonify({
                    "status": "integrity_failed",
                    "message": "The file failed cryptographic verification.",
                    "recovery_available": True,
                    "reasons": reasons
                }), 400
            else:
                if decrypted_data is None:
                    return jsonify({'error': 'Recovery failed: the file is completely unrecoverable.'}), 500

        download_name = file.name
        headers = {}
        if is_recovery:
            name_parts = file.name.rsplit('.', 1)
            if len(name_parts) == 2:
                download_name = f"{name_parts[0]}_corrupted.{name_parts[1]}"
            else:
                download_name = f"{file.name}_corrupted"
            
            # Log recovery download requested
            audit_log = AuditLog(
                user_id=user.id,
                file_id=file.id,
                event_type='RECOVERY_DOWNLOAD_REQUESTED',
                failure_reason="; ".join(integrity_warnings) if integrity_warnings else "User requested recovery download",
                recovery_requested=True,
                ip_address=request.remote_addr,
                browser_info=request.user_agent.string
            )
            db.session.add(audit_log)
            db.session.commit()
            
            # Set recovery headers
            headers["X-Integrity-Status"] = "FAILED"
            headers["X-Recovery-Download"] = "TRUE"
            headers["X-Recovery-Reason"] = "; ".join(integrity_warnings) if integrity_warnings else "Verification failed"

        response = send_file(
            io.BytesIO(decrypted_data if decrypted_data is not None else b''),
            as_attachment=True,
            download_name=download_name,
            mimetype='application/octet-stream'
        )
        
        for k, v in headers.items():
            response.headers[k] = v

        if warnings:
            response.headers['X-Decryption-Warning'] = "; ".join(warnings)
            
        if decrypted_data is not None:
            del decrypted_data
        gc.collect()
        
        return response
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'Decryption Failed: {str(e)}'}), 500


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
            session = _get_aws_session(user)
            s3 = session.client('s3')
            
            # Clean S3 path handling (no ?aes= param)
            parts = file.storage_path.replace('s3://', '').split('/', 1)
            s3.delete_object(Bucket=parts[0], Key=parts[1])

            # Clean up PQC private keys from Secrets Manager (v2 files only)
            if file.secrets_manager_arn:
                try:
                    sm = session.client('secretsmanager')
                    secret_name = f"stackdrive/{user.id}/{file_id}/pqc-keys"
                    sm.delete_secret(
                        SecretId=secret_name,
                        ForceDeleteWithoutRecovery=True
                    )
                except Exception as e:
                    print(f"Failed to delete secret: {e}")
                    pass  # Best-effort cleanup
        except Exception as e:
            print(f"Failed to delete from S3: {e}")
            pass
    
    # Delete related database entries to satisfy foreign key constraints
    PipelineStage.query.filter_by(file_id=file_id).delete()
    SharedFile.query.filter_by(file_id=file_id).delete()
    AuditLog.query.filter_by(file_id=file_id).delete()
    
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
    
    completed_files_count = safe_files + blocked_files
    pass_rate = (safe_files / completed_files_count * 100) if completed_files_count > 0 else 0
    
    # Calculate average scan time dynamically across all completed files for this user
    completed_files = File.query.filter_by(user_id=user_id).filter(File.status.in_(['safe', 'blocked'])).all()
    total_duration = 0.0
    count_duration = 0
    for f in completed_files:
        stages = PipelineStage.query.filter_by(file_id=f.id).all()
        started_times = [s.started_at for s in stages if s.started_at]
        completed_times = [s.completed_at for s in stages if s.completed_at]
        if started_times and completed_times:
            file_start = min(started_times)
            file_end = max(completed_times)
            duration = (file_end - file_start).total_seconds()
            if duration > 0:
                total_duration += duration
                count_duration += 1
                
    avg_seconds = (total_duration / count_duration) if count_duration > 0 else 0
    if avg_seconds > 60:
        mins = int(avg_seconds // 60)
        secs = int(avg_seconds % 60)
        avg_scan_time_display = f"{mins}m {secs}s"
    elif avg_seconds > 0:
        avg_scan_time_display = f"{int(round(avg_seconds))}s"
    else:
        avg_scan_time_display = "—"
    
    # Layer stats
    layer_names = ['SHA-256 + VirusTotal', 'File Heuristic Analysis', 'ClamAV (Docker)', 'Sandbox (Docker)']
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
        'avgScanTime': avg_scan_time_display,
        'activeThreats': blocked_files,
        'layerStats': layer_stats,
        'recentThreats': [t.to_dict() for t in threats],
    }), 200


# ════════════════════════════════════════
# AI COPILOT (Gemini / Intelligent Fallback)
# ════════════════════════════════════════

@app.route('/api/copilot/chat', methods=['POST'])
@jwt_required()
def copilot_chat():
    """AI Copilot chat endpoint powered by Gemini API or local intelligent engine."""
    data = request.get_json()
    if not data or not data.get('message', '').strip():
        return jsonify({'error': 'Message is required'}), 400

    user_id = get_jwt_identity()
    user_message = data['message'].strip()
    file_id = data.get('file_id')

    from copilot import handle_copilot_message, call_gemini

    # Load system prompt
    import os
    prompt_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        'stackdrive_copilot_system_prompt.md'
    )
    try:
        with open(prompt_path, 'r', encoding='utf-8') as f:
            system_prompt = f.read()
    except FileNotFoundError:
        system_prompt = "You are StackDrive Bot."

    # Try Gemini first
    reply = None
    if os.environ.get('GEMINI_API_KEY'):
        reply = call_gemini(user_id, user_message, system_prompt, file_id)

    # Fallback to local intelligent engine
    if not reply:
        try:
            reply = handle_copilot_message(user_id, user_message, file_id)
        except Exception as e:
            print(f"[COPILOT] Error: {e}")
            return jsonify({'reply': "I encountered an internal error. Please try again."}), 500

    if not reply:
        return jsonify({'reply': "I didn't understand that."}), 200



    # Format reply (remove tags from UI view)
    reply = reply.replace('[REPORT_START]', '').replace('[REPORT_END]', '').strip()
    return jsonify({'reply': reply}), 200

@app.route('/api/copilot/report_data/<file_id>', methods=['GET'])
@jwt_required()
def get_report_data(file_id):
    user_id = get_jwt_identity()
    user_obj = User.query.get(user_id)
    file_obj = File.query.filter_by(id=file_id, user_id=user_id).first()
    if not file_obj:
        return jsonify({'error': 'File not found'}), 404
        
    import os
    from copilot import call_gemini, handle_copilot_message
    
    prompt_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        'stackdrive_copilot_system_prompt.md'
    )
    try:
        with open(prompt_path, 'r', encoding='utf-8') as f:
            system_prompt = f.read()
    except FileNotFoundError:
        system_prompt = "You are StackDrive Copilot."

    user_message = f"generate a report for {file_obj.name}"
    
    reply = None
    if os.environ.get('GEMINI_API_KEY'):
        reply = call_gemini(user_id, user_message, system_prompt)
        
    if not reply:
        try:
            reply = handle_copilot_message(user_id, user_message)
        except:
            pass

    if not reply:
        return jsonify({'error': 'Failed to generate report text'}), 500

    import re
    report_text = reply
    match = re.search(r'\[REPORT_START\](.*?)\[REPORT_END\]', reply, re.DOTALL)
    if match:
        report_text = match.group(1).strip()
        
    return jsonify({'report': report_text}), 200


@app.route('/api/copilot/history', methods=['DELETE'])
@jwt_required()
def clear_copilot_history():
    """Clear conversation history for the current user."""
    user_id = get_jwt_identity()
    from copilot import clear_conversation_history
    clear_conversation_history(user_id)
    return jsonify({'message': 'Conversation history cleared'}), 200


# ════════════════════════════════════════
# SECURE FILE SHARING
# ════════════════════════════════════════
from models import SharedFile, ShareAuditLog
import secrets
from datetime import datetime, timedelta
import io
import gc

def watermark_pdf(pdf_bytes, text):
    try:
        from pypdf import PdfReader, PdfWriter
        from reportlab.pdfgen import canvas
        from reportlab.lib.pagesizes import letter

        # Create watermark PDF in memory
        watermark_io = io.BytesIO()
        can = canvas.Canvas(watermark_io, pagesize=letter)
        can.setFont("Helvetica", 14)
        can.setFillColorRGB(0.7, 0.7, 0.7, alpha=0.3)
        
        can.saveState()
        can.translate(300, 400)
        can.rotate(45)
        watermark_msg = f"Shared with: {text}"
        can.drawCentredString(0, 0, watermark_msg)
        can.restoreState()
        can.save()
        
        watermark_io.seek(0)
        watermark_pdf = PdfReader(watermark_io)
        watermark_page = watermark_pdf.pages[0]
        
        reader = PdfReader(io.BytesIO(pdf_bytes))
        writer = PdfWriter()
        
        for page in reader.pages:
            page.merge_page(watermark_page, over=True)
            writer.add_page(page)
            
        output_io = io.BytesIO()
        writer.write(output_io)
        return output_io.getvalue()
    except Exception as e:
        print(f"[WATERMARK ERROR] PDF Watermarking failed: {e}")
        return pdf_bytes

def watermark_text(text_bytes, text):
    try:
        content = text_bytes.decode('utf-8', errors='ignore')
        watermark = f"\n\n[ SECURE WATERMARK: Shared with {text} ]\n"
        return (content + watermark).encode('utf-8')
    except Exception as e:
        print(f"[WATERMARK ERROR] Text Watermarking failed: {e}")
        return text_bytes

def process_shared_download(token, password=None, email=None):
    link = SharedFile.query.filter_by(share_token=token).first()
    if not link:
        log = ShareAuditLog(
            event_type='expired_attempt',
            ip_address=request.remote_addr,
            share_token=token,
            detail="Invalid token download attempt"
        )
        db.session.add(log)
        db.session.commit()
        return jsonify({'error': 'Share link not found'}), 404
        
    if link.revoked:
        log = ShareAuditLog(
            event_type='expired_attempt',
            ip_address=request.remote_addr,
            file_id=link.file_id,
            share_token_id=link.id,
            share_token=token,
            detail="Revoked link download attempt"
        )
        db.session.add(log)
        db.session.commit()
        return jsonify({'error': 'This sharing link has been revoked.'}), 403
        
    if link.is_expired():
        log = ShareAuditLog(
            event_type='expired_attempt',
            ip_address=request.remote_addr,
            file_id=link.file_id,
            share_token_id=link.id,
            share_token=token,
            detail="Expired link download attempt"
        )
        db.session.add(log)
        db.session.commit()
        return jsonify({'error': 'This sharing link has expired.'}), 403
        
    if link.max_downloads != -1 and link.current_downloads >= link.max_downloads:
        log = ShareAuditLog(
            event_type='expired_attempt',
            ip_address=request.remote_addr,
            file_id=link.file_id,
            share_token_id=link.id,
            share_token=token,
            detail="Download limit exceeded attempt"
        )
        db.session.add(log)
        db.session.commit()
        return jsonify({'error': 'This sharing link has reached its download limit.'}), 403

    if link.password_hash:
        if not password or not bcrypt.checkpw(password.encode('utf-8'), link.password_hash.encode('utf-8')):
            log = ShareAuditLog(
                event_type='wrong_password_attempt',
                ip_address=request.remote_addr,
                file_id=link.file_id,
                share_token_id=link.id,
                share_token=token,
                detail=f"Incorrect password attempt for download (provided: {bool(password)}, email: {email})"
            )
            db.session.add(log)
            db.session.commit()
            return jsonify({'error': 'Incorrect password'}), 401

    file_obj = link.file
    user_obj = User.query.get(file_obj.user_id)
    
    is_recovery = (request.args.get('recovery') == 'true') or (request.is_json and request.json and request.json.get('recovery') == True)
    
    from encryption import create_encryption_engine
    try:
        engine, _ = create_encryption_engine(user_obj)
        decrypted_data, warnings = engine.decrypt_file(file_obj)
        
        # Check for integrity failure
        integrity_warnings = []
        if warnings:
            integrity_warnings = [
                w for w in warnings 
                if any(kw in w.lower() for kw in ["modified", "failed", "corrupted", "invalid", "tampered", "mismatch"])
            ]

        has_failed = (decrypted_data is None) or (len(integrity_warnings) > 0)
        
        if has_failed:
            reasons = integrity_warnings if integrity_warnings else (warnings if warnings else ["Decryption/Integrity failure"])
            
            if not is_recovery:
                # Mark file status
                file_obj.status = "Integrity Verification Failed"
                
                # Log security incident
                audit_log = AuditLog(
                    user_id=user_obj.id,
                    file_id=file_obj.id,
                    event_type='INTEGRITY_FAILED',
                    failure_reason="; ".join(reasons),
                    recovery_requested=False,
                    ip_address=request.remote_addr,
                    browser_info=request.user_agent.string
                )
                db.session.add(audit_log)
                
                # Create a security alert notification for owner
                notif = Notification(
                    user_id=link.owner_id,
                    file_name=file_obj.name,
                    layer="Share Service",
                    threat_type="Integrity Verification Failed",
                    action="Blocked shared download attempt due to tampering"
                )
                db.session.add(notif)
                db.session.commit()
                
                return jsonify({
                    "status": "integrity_failed",
                    "message": "The file failed cryptographic verification.",
                    "recovery_available": True,
                    "reasons": reasons
                }), 400
            else:
                if decrypted_data is None:
                    return jsonify({'error': 'Recovery failed: the file is completely unrecoverable.'}), 500

    except Exception as e:
        print(f'[DECRYPTION ERROR] {e}')
        return jsonify({'error': f'Failed to decrypt shared file: {str(e)}'}), 500

    # Apply watermarking if applicable
    email_clean = (email or '').strip()
    if email_clean and decrypted_data is not None:
        if file_obj.name.lower().endswith('.pdf'):
            decrypted_data = watermark_pdf(decrypted_data, email_clean)
        elif file_obj.name.lower().endswith('.txt'):
            decrypted_data = watermark_text(decrypted_data, email_clean)

    # Increment downloads
    link.current_downloads += 1
    db.session.commit()

    # Log audit
    log = ShareAuditLog(
        event_type='download_completed',
        ip_address=request.remote_addr,
        file_id=link.file_id,
        share_token_id=link.id,
        share_token=token,
        detail=f"File downloaded successfully by {email_clean or 'Anonymous'} (IP: {request.remote_addr}){' [RECOVERY]' if is_recovery else ''}"
    )
    db.session.add(log)
    
    # Notify owner
    try:
        notif = Notification(
            user_id=link.owner_id,
            file_name=file_obj.name,
            layer="Share Service",
            threat_type="File Downloaded" if not is_recovery else "Recovery File Downloaded",
            action=f"Downloaded by {email_clean or 'Anonymous recipient'} (IP: {request.remote_addr})"
        )
        db.session.add(notif)
    except Exception as e:
        print(f"Notification creation failed: {e}")

    # If it is recovery, rename file and set headers
    download_name = file_obj.name
    headers = {}
    if is_recovery:
        name_parts = file_obj.name.rsplit('.', 1)
        if len(name_parts) == 2:
            download_name = f"{name_parts[0]}_corrupted.{name_parts[1]}"
        else:
            download_name = f"{file_obj.name}_corrupted"
        
        # Log recovery download requested in AuditLog
        audit_log = AuditLog(
            user_id=user_obj.id,
            file_id=file_obj.id,
            event_type='RECOVERY_DOWNLOAD_REQUESTED',
            failure_reason="; ".join(integrity_warnings) if integrity_warnings else "User requested recovery download via share link",
            recovery_requested=True,
            ip_address=request.remote_addr,
            browser_info=request.user_agent.string
        )
        db.session.add(audit_log)
        
        # Set recovery headers
        headers["X-Integrity-Status"] = "FAILED"
        headers["X-Recovery-Download"] = "TRUE"
        headers["X-Recovery-Reason"] = "; ".join(integrity_warnings) if integrity_warnings else "Verification failed"

    db.session.commit()

    # Send email notification to owner
    try:
        owner_user = User.query.get(link.owner_id)
        msg = Message(
            subject=f"[StackDrive] Shared File Downloaded: {file_obj.name}",
            sender=app.config['MAIL_USERNAME'],
            recipients=[owner_user.email],
            body=f"Hello,\n\nYour shared file '{file_obj.name}' was successfully downloaded by {email_clean or 'an anonymous user'} (IP: {request.remote_addr}) on {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC.\n\nLink details:\nShare Token: {token}\nTotal downloads: {link.current_downloads}\n\nBest regards,\nStackDrive Security Team"
        )
        threading.Thread(target=lambda: mail.send(msg)).start()
    except Exception as e:
        print(f"Failed to send email notification: {e}")

    # Stream the decrypted file
    response = send_file(
        io.BytesIO(decrypted_data if decrypted_data is not None else b''),
        as_attachment=True,
        download_name=download_name,
        mimetype='application/octet-stream'
    )
    
    for k, v in headers.items():
        response.headers[k] = v

    if warnings:
        response.headers['X-Decryption-Warning'] = "; ".join(warnings)
    
    # Explicitly clear memory buffers
    if decrypted_data is not None:
        del decrypted_data
    gc.collect()
    
    return response

@app.before_request
def handle_options_share():
    if request.method == 'OPTIONS' and '/share' in request.path:
        return '', 200

@app.route('/api/files/<file_id>/share', methods=['POST'])
@jwt_required()
def create_share_link(file_id):
    user_id = get_jwt_identity()
    user_obj = User.query.get(user_id)
    file_obj = File.query.filter_by(id=file_id, user_id=user_id).first()
    
    if not file_obj or file_obj.status != 'safe':
        return jsonify({'error': 'File not found or not safe to share'}), 404
        
    data = request.json or {}
    expiry_option = data.get('expires_in', '24h')
    max_downloads = int(data.get('max_downloads', -1))
    password = data.get('password')
    
    import re
    match = re.match(r'^(\d+)([mhd])$', expiry_option)
    if match:
        amount = int(match.group(1))
        unit = match.group(2)
        if unit == 'm':
            delta = timedelta(minutes=amount)
        elif unit == 'h':
            delta = timedelta(hours=amount)
        elif unit == 'd':
            delta = timedelta(days=amount)
        else:
            delta = timedelta(hours=24)
    else:
        delta = timedelta(hours=24)
        
    expires_at = datetime.utcnow() + delta
    
    password_hash = None
    if password:
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
    token = secrets.token_urlsafe(32)
    
    link = SharedFile(
        file_id=file_obj.id,
        owner_id=user_id,
        share_token=token,
        expires_at=expires_at,
        max_downloads=max_downloads,
        password_hash=password_hash
    )
    
    db.session.add(link)
    db.session.commit()
    
    # Log audit
    log = ShareAuditLog(
        event_type='link_created',
        ip_address=request.remote_addr,
        file_id=file_obj.id,
        share_token_id=link.id,
        share_token=token,
        detail=f"Share link created by owner {user_obj.email} (max downloads: {max_downloads}, expires: {expires_at})"
    )
    db.session.add(log)
    db.session.commit()
    
    return jsonify({
        'message': 'Share link created',
        'token': token,
        'expires_at': link.expires_at.isoformat() + 'Z'
    }), 200

@app.route('/api/share/<token>/info', methods=['GET'])
def get_share_info(token):
    link = SharedFile.query.filter_by(share_token=token).first()
    if not link:
        log = ShareAuditLog(
            event_type='expired_attempt',
            ip_address=request.remote_addr,
            share_token=token,
            detail="Invalid token accessed"
        )
        db.session.add(log)
        db.session.commit()
        return jsonify({'error': 'Share link not found'}), 404
        
    if link.revoked:
        log = ShareAuditLog(
            event_type='expired_attempt',
            ip_address=request.remote_addr,
            file_id=link.file_id,
            share_token_id=link.id,
            share_token=token,
            detail="Revoked link accessed"
        )
        db.session.add(log)
        db.session.commit()
        return jsonify({'error': 'This sharing link has been revoked.'}), 403
        
    if link.is_expired():
        log = ShareAuditLog(
            event_type='expired_attempt',
            ip_address=request.remote_addr,
            file_id=link.file_id,
            share_token_id=link.id,
            share_token=token,
            detail="Expired link accessed"
        )
        db.session.add(log)
        db.session.commit()
        return jsonify({'error': 'This sharing link has expired.'}), 403
        
    if link.max_downloads != -1 and link.current_downloads >= link.max_downloads:
        log = ShareAuditLog(
            event_type='expired_attempt',
            ip_address=request.remote_addr,
            file_id=link.file_id,
            share_token_id=link.id,
            share_token=token,
            detail="Limit exceeded link accessed"
        )
        db.session.add(log)
        db.session.commit()
        return jsonify({'error': 'This sharing link has reached its download limit.'}), 403
        
    # Log access
    log = ShareAuditLog(
        event_type='link_accessed',
        ip_address=request.remote_addr,
        file_id=link.file_id,
        share_token_id=link.id,
        share_token=token,
        detail="Landing page accessed"
    )
    db.session.add(log)
    db.session.commit()
    
    return jsonify({
        'share': {
            'fileName': link.file.name,
            'fileSize': link.file.size_display,
            'expiresAt': link.expires_at.isoformat() + 'Z',
            'maxDownloads': link.max_downloads,
            'downloads': link.current_downloads,
            'passwordProtected': link.password_hash is not None
        }
    }), 200

@app.route('/api/share/<token>', methods=['GET'])
def download_shared_file_get(token):
    password = request.args.get('password')
    email = request.args.get('email')
    return process_shared_download(token, password, email)

@app.route('/api/share/<token>/download', methods=['POST'])
def download_shared_file_post(token):
    data = request.json or {}
    password = data.get('password')
    email = data.get('email')
    return process_shared_download(token, password, email)

@app.route('/api/shares', methods=['GET'])
@jwt_required()
def get_user_shares():
    user_id = get_jwt_identity()
    shares = SharedFile.query.filter_by(owner_id=user_id).order_by(SharedFile.created_at.desc()).all()
    return jsonify({'shares': [s.to_dict() for s in shares]}), 200

@app.route('/api/shares/<share_id>/revoke', methods=['POST'])
@jwt_required()
def revoke_share(share_id):
    user_id = get_jwt_identity()
    share = SharedFile.query.filter_by(id=share_id, owner_id=user_id).first()
    if not share:
        return jsonify({'error': 'Share link not found'}), 404
        
    share.revoked = True
    db.session.commit()
    
    # Log audit
    log = ShareAuditLog(
        event_type='link_revoked',
        ip_address=request.remote_addr,
        file_id=share.file_id,
        share_token_id=share.id,
        share_token=share.share_token,
        detail="Share link revoked by owner"
    )
    db.session.add(log)
    db.session.commit()
    
    return jsonify({'message': 'Share link revoked successfully', 'share': share.to_dict()}), 200

@app.route('/api/shares/<share_id>/extend', methods=['POST'])
@jwt_required()
def extend_share(share_id):
    user_id = get_jwt_identity()
    share = SharedFile.query.filter_by(id=share_id, owner_id=user_id).first()
    if not share:
        return jsonify({'error': 'Share link not found'}), 404
        
    data = request.json or {}
    hours = int(data.get('hours', 24))
    
    base_time = max(share.expires_at, datetime.utcnow())
    share.expires_at = base_time + timedelta(hours=hours)
    share.revoked = False  # Auto un-revoke if extended
    db.session.commit()
    
    # Log audit
    log = ShareAuditLog(
        event_type='link_extended',
        ip_address=request.remote_addr,
        file_id=share.file_id,
        share_token_id=share.id,
        share_token=share.share_token,
        detail=f"Share link extended by {hours} hours"
    )
    db.session.add(log)
    db.session.commit()
    
    return jsonify({'message': 'Share link extended successfully', 'share': share.to_dict()}), 200

@app.route('/api/shares/<share_id>/audit', methods=['GET'])
@jwt_required()
def get_share_audit(share_id):
    user_id = get_jwt_identity()
    share = SharedFile.query.filter_by(id=share_id, owner_id=user_id).first()
    if not share:
        return jsonify({'error': 'Share link not found'}), 404
        
    logs = ShareAuditLog.query.filter_by(share_token_id=share_id).order_by(ShareAuditLog.timestamp.desc()).all()
    log_dicts = [l.to_dict() for l in logs]
    return jsonify({
        'logs': log_dicts,
        'audit': log_dicts
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
    app.run(host='0.0.0.0', debug=True, use_reloader=False, port=5000)
