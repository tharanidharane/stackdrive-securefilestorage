import sys
import os
import base64
import boto3
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from app import app
from models import db, File, User
from Crypto.Cipher import AES

with app.app_context():
    # Get newest file
    file = File.query.order_by(File.uploaded_at.desc()).first()
    if not file:
        print("No file found.")
        sys.exit(0)
    print(f"Testing file {file.id} ({file.name})")
    print(f"Storage path: {file.storage_path}")
    
    user = User.query.get(file.user_id)
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
    
    print(f"Bucket: {bucket}, Key: {key}")
    try:
        obj = s3.get_object(Bucket=bucket, Key=key)
        raw_download = obj['Body'].read()
        print(f"Raw download length: {len(raw_download)}")
        
        ml_kem_len = 1088 + 41
        ml_dsa_len = 3293 + 37
        aes_blob = raw_download[ml_kem_len:-ml_dsa_len]
        print(f"AES blob length: {len(aes_blob)}")
        
        nonce = aes_blob[:16]
        tag = aes_blob[-16:]
        ciphertext = aes_blob[16:-16]
        
        if len(raw_path) > 1:
            aes_key = base64.urlsafe_b64decode(raw_path[1])
            print("Using Base64 random key")
        else:
            aes_key = bytes.fromhex(file.sha256_hash)
            print("Using SHA256 deterministic key")
            
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
        print("SUCCESS! File decrypted correctly.")
    except Exception as e:
        print(f"DECRYPTION / S3 ERROR: {type(e).__name__}: {str(e)}")
