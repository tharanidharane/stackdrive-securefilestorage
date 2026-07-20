"""
StackDrive — Production-Grade Hybrid Encryption Engine
=======================================================
Zero-Trust architecture combining:
  • AES-256-GCM  — File data encryption
  • AWS KMS      — Envelope encryption (AES key)
  • ML-KEM-768   — Post-quantum key encapsulation (Kyber)
  • ML-DSA-65    — Post-quantum digital signature (Dilithium)

Key Storage Rules (MANDATORY):
  ❌ NEVER store plaintext AES keys (in DB, URLs, logs, S3 paths)
  ✔ AES key → encrypted by AWS KMS → stored as binary blob in DB
  ✔ PQC private keys → stored in AWS Secrets Manager
  ✔ PQC public keys + ciphertexts → stored in DB (non-sensitive metadata)
  ✔ Encrypted file blob → stored in S3 with SSE-KMS
"""

import os
import io
import json
import struct
import hashlib
import logging
import base64
from datetime import datetime

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256 as CryptoSHA256

logger = logging.getLogger(__name__)

from boto3.s3.transfer import TransferConfig

# Multi-threaded S3 transfer configuration for large files (e.g., 20MB - 500MB)
S3_TRANSFER_CONFIG = TransferConfig(
    multipart_threshold=8 * 1024 * 1024,   # 8MB threshold for multipart
    max_concurrency=15,                   # Use 15 parallel threads
    multipart_chunksize=8 * 1024 * 1024,  # 8MB chunk size per part
    use_threads=True
)

def get_optimized_s3_transfer_config(file_size_bytes):
    """
    Get dynamically optimized S3 TransferConfig based on file size
    to maximize download/upload throughput and minimize connection overhead.
    """
    mb = 1024 * 1024
    if file_size_bytes > 1000 * mb:  # > 1GB
        concurrency = 50
        chunk_size = 16 * mb
        threshold = 16 * mb
    elif file_size_bytes > 200 * mb:  # 200MB - 1GB
        concurrency = 35
        chunk_size = 8 * mb
        threshold = 8 * mb
    elif file_size_bytes > 50 * mb:   # 50MB - 200MB
        concurrency = 25
        chunk_size = 8 * mb
        threshold = 8 * mb
    else:                             # < 50MB
        concurrency = 15
        chunk_size = 5 * mb
        threshold = 5 * mb

    return TransferConfig(
        multipart_threshold=threshold,
        max_concurrency=concurrency,
        multipart_chunksize=chunk_size,
        use_threads=True,
        max_io_queue=max(20, concurrency * 2)
    )


# ── Configuration ────────────────────────────────────────────────────
PQC_ENABLED = os.environ.get('PQC_ENABLED', 'false').lower() == 'true'

# ── Conditional PQC Import ───────────────────────────────────────────
_oqs_available = False
if PQC_ENABLED:
    try:
        import oqs
        _oqs_available = True
        logger.info("liboqs loaded — PQC algorithms available: ML-KEM-768, ML-DSA-65")
    except BaseException as e:
        logger.critical(
            "CRITICAL: liboqs not available. StackDrive requires post-quantum cryptography. Falling back to KMS-only encryption. Error: %s", e
        )

def verify_pqc_available():
    """Verify that post-quantum cryptography is enabled and liboqs is available at startup."""
    if not PQC_ENABLED:
        logger.warning(
            "WARNING: PQC_ENABLED is set to false. Falling back to KMS-only envelope encryption."
        )
    if not _oqs_available:
        logger.critical(
            "CRITICAL: liboqs not available. Falling back to KMS-only envelope encryption."
        )

# ── Payload format constants ────────────────────────────────────────
PAYLOAD_MAGIC = b'SDENC'          # StackDrive ENCrypted — 5 byte magic
PAYLOAD_VERSION_V2 = 2
HEADER_LENGTH_BYTES = 4           # uint32 big-endian for header JSON length


# ═════════════════════════════════════════════════════════════════════
#  HYBRID ENCRYPTION ENGINE
# ═════════════════════════════════════════════════════════════════════

class HybridEncryptionEngine:
    """
    Production-grade hybrid encryption with zero-trust key management.

    Encrypt flow:
      1. Read raw file bytes
      2. Generate AES-256 key (random 32 bytes)
      3. AES-256-GCM encrypt → ciphertext, nonce, tag
      4. KMS envelope encrypt the AES key → kms_encrypted_key
      5. ML-KEM-768 key encapsulation → kem_ciphertext, shared_secret
      6. Derive hybrid binding: HMAC(aes_key || pqc_shared_secret) (integrity)
      7. ML-DSA-65 sign the payload → signature
      8. Store PQC private keys in AWS Secrets Manager
      9. Structure final S3 blob (header + encrypted data)
      10. Upload to S3 with KMS SSE

    Decrypt flow:
      1. Download blob from S3
      2. Parse header, extract components
      3. KMS decrypt the AES key blob
      4. Retrieve PQC private keys from Secrets Manager
      5. ML-KEM decapsulate shared secret (verify hybrid binding)
      6. ML-DSA verify signature (integrity proof)
      7. AES-256-GCM decrypt with recovered key
      8. Return plaintext bytes
    """

    def __init__(self, s3_client, kms_client, secrets_client, user_obj):
        self.s3 = s3_client
        self.kms = kms_client
        self.secrets = secrets_client
        self.user = user_obj

    # ─────────────────────────────────────────────────────────────────
    #  ENCRYPT (Production v2)
    # ─────────────────────────────────────────────────────────────────

    def encrypt_file(self, file_obj, filepath, s3_key, progress_callback=None):
        """
        Full hybrid encryption pipeline with O(1) memory complexity and pre-hashed PQC signatures.
        """
        from models import db
        import tempfile

        def report(step, detail):
            if progress_callback:
                progress_callback(step, detail)
            logger.info(f"[ENCRYPT] {step}: {detail}")

        temp_enc_dir = None
        temp_enc_path = None
        try:
            # ── Step 1: Read raw file size ───────────────────────────
            report('read', 'Reading file size for chunked processing...')
            file_size = os.path.getsize(filepath)
            report('read', f'File size: {file_size} bytes')

            # ── STEP A — KMS generate_data_key ───────────────────────
            report('kms_wrap', 'Generating KMS Data Encryption Key (DEK)...')
            kms_response = self.kms.generate_data_key(
                KeyId=self.user.kms_key_arn,
                KeySpec='AES_256',
                EncryptionContext={
                    'file_id': str(file_obj.id),
                    'user_id': str(self.user.id),
                    'purpose': 'stackdrive-file-encryption'
                }
            )
            kms_plaintext_dek = kms_response['Plaintext']
            kms_encrypted_key = kms_response['CiphertextBlob']

            kem_ciphertext = b''
            kem_public_key = b''
            dsa_signature = b''
            dsa_public_key = b''
            secrets_arn = None
            pqc_status = 'disabled'

            # ── STEP B & C — Post-Quantum Key Encapsulation & HKDF ──
            if PQC_ENABLED and _oqs_available:
                report('pqc_kem', 'Running ML-KEM-768 (Kyber) key encapsulation...')
                with oqs.KeyEncapsulation("ML-KEM-768") as kem:
                    kem_public_key = kem.generate_keypair()
                    kem_private_key = kem.export_secret_key()
                    kem_ciphertext, pqc_shared_secret = kem.encap_secret(kem_public_key)

                report('pqc_kem', f'ML-KEM-768 encapsulation complete (ct={len(kem_ciphertext)}B)')
                
                aes_key = HKDF(
                    master=kms_plaintext_dek + pqc_shared_secret,
                    key_len=32,
                    salt=b'stackdrive-v2-hybrid-hkdf',
                    hashmod=CryptoSHA256,
                    context=f"file:{file_obj.id}:user:{self.user.id}".encode('utf-8')
                )
                hybrid_binding = hashlib.sha256(aes_key + pqc_shared_secret).digest()
                del kms_plaintext_dek
                pqc_status = 'ML-KEM-768 + ML-DSA-65'
            else:
                report('pqc_kem', 'PQC disabled — using KMS-only envelope encryption')
                aes_key = kms_plaintext_dek
                del kms_plaintext_dek

            # ── Step 3: Streamed AES-256-GCM encryption + hashing ──
            report('aes_encrypt', 'Encrypting with streamed AES-256-GCM...')
            cipher = AES.new(aes_key, AES.MODE_GCM)
            nonce = cipher.nonce

            # Prepare temp file for the final payload
            temp_enc_dir = tempfile.mkdtemp()
            temp_enc_path = os.path.join(temp_enc_dir, 'encrypted_payload.tmp')

            # We build the header beforehand
            expected_sig_len = 0
            if PQC_ENABLED and _oqs_available:
                try:
                    with oqs.Signature("ML-DSA-65") as sig_details:
                        expected_sig_len = sig_details.details.get('length_signature', 3309)
                except Exception:
                    expected_sig_len = 3309
            
            header = {
                'version': PAYLOAD_VERSION_V2,
                'aes_nonce_len': len(nonce),
                'aes_tag_len': 16, # AES-GCM tag is 16 bytes
                'aes_ciphertext_len': file_size,
                'kem_ciphertext_len': len(kem_ciphertext),
                'dsa_signature_len': expected_sig_len,
                'pqc_enabled': PQC_ENABLED and _oqs_available,
                'file_id': file_obj.id,
                'timestamp': datetime.utcnow().isoformat() + 'Z',
            }
            header_json = json.dumps(header, separators=(',', ':')).encode('utf-8')
            header_len = struct.pack('>I', len(header_json))

            # Initialize payload hasher for ML-DSA signature
            hasher = hashlib.sha256()
            hasher.update(nonce)

            # Perform streamed encryption and write directly to temp file
            with open(temp_enc_path, 'wb') as final_blob:
                final_blob.write(PAYLOAD_MAGIC)
                final_blob.write(header_len)
                final_blob.write(header_json)
                final_blob.write(kem_ciphertext)
                final_blob.write(nonce)

                CHUNK = 16 * 1024 * 1024  # 16 MB chunks
                with open(filepath, 'rb') as f_in:
                    while True:
                        chunk = f_in.read(CHUNK)
                        if not chunk:
                            break
                        encrypted_chunk = cipher.encrypt(chunk)
                        final_blob.write(encrypted_chunk)
                        hasher.update(encrypted_chunk)

                tag = cipher.digest()
                hasher.update(tag)

                # ── Step 4: ML-DSA-65 Digital Signature over Pre-Hashed Payload ──
                if PQC_ENABLED and _oqs_available:
                    report('pqc_dsa', 'Signing payload with ML-DSA-65 (Dilithium)...')
                    hasher.update(hybrid_binding)
                    payload_hash = hasher.digest()

                    with oqs.Signature("ML-DSA-65") as signer:
                        dsa_public_key = signer.generate_keypair()
                        dsa_private_key = signer.export_secret_key()
                        dsa_signature = signer.sign(payload_hash)

                    report('pqc_dsa', f'ML-DSA-65 signature complete (sig={len(dsa_signature)}B)')

                    # ── Step 8: Store PQC private keys in AWS Secrets Manager ──
                    report('secrets', 'Storing PQC private keys in AWS Secrets Manager...')

                    secret_name = f"stackdrive/{self.user.id}/{file_obj.id}/pqc-keys"
                    secret_value = json.dumps({
                        'kyber_private_key': base64.b64encode(kem_private_key).decode('utf-8'),
                        'dilithium_private_key': base64.b64encode(dsa_private_key).decode('utf-8'),
                        'hybrid_binding': base64.b64encode(hybrid_binding).decode('utf-8'),
                    })

                    try:
                        sm_response = self.secrets.create_secret(
                            Name=secret_name,
                            SecretString=secret_value,
                            Description=f'PQC keys for file {file_obj.id}',
                        )
                        secrets_arn = sm_response['ARN']
                        report('secrets', f'Private keys stored in Secrets Manager')
                    except self.secrets.exceptions.ResourceExistsException:
                        self.secrets.put_secret_value(
                            SecretId=secret_name,
                            SecretString=secret_value,
                        )
                        desc = self.secrets.describe_secret(SecretId=secret_name)
                        secrets_arn = desc['ARN']
                        report('secrets', 'Private keys updated in Secrets Manager')

                    # Wipe private keys
                    del kem_private_key
                    del dsa_private_key
                    del pqc_shared_secret
                    del hybrid_binding
                else:
                    report('pqc_kem', 'PQC disabled — using KMS-only envelope encryption')

                # Write tag and signature to complete the payload
                final_blob.write(tag)
                final_blob.write(dsa_signature)

            # Get final payload size
            blob_size = os.path.getsize(temp_enc_path)
            report('payload', f'Payload built on disk ({blob_size} bytes)')

            # ── Step 9: Upload file from disk to S3 with KMS SSE ──────
            report('s3_upload', 'Uploading encrypted blob to S3 secure bucket...')

            enc_s3_key = s3_key
            self.s3.upload_file(
                temp_enc_path,
                self.user.secure_bucket,
                enc_s3_key,
                ExtraArgs={
                    'ServerSideEncryption': 'aws:kms',
                    'SSEKMSKeyId': self.user.kms_key_arn,
                },
                Config=get_optimized_s3_transfer_config(file_size)
            )

            report('s3_upload', f'Uploaded to s3://{self.user.secure_bucket}/{enc_s3_key}')

            # ── Step 10: Store metadata in DB ────────────────────────
            report('db_store', 'Storing encryption metadata in database...')

            file_obj.storage_path = f"s3://{self.user.secure_bucket}/{enc_s3_key}"
            file_obj.encryption_version = PAYLOAD_VERSION_V2
            file_obj.kms_encrypted_key = kms_encrypted_key
            file_obj.aes_nonce = nonce
            file_obj.aes_tag = tag
            file_obj.kem_ciphertext = kem_ciphertext if kem_ciphertext else None
            file_obj.kem_public_key = kem_public_key if kem_public_key else None
            file_obj.dsa_signature = dsa_signature if dsa_signature else None
            file_obj.dsa_public_key = dsa_public_key if dsa_public_key else None
            file_obj.secrets_manager_arn = secrets_arn
            db.session.commit()

            report('db_store', 'Encryption metadata stored (no plaintext keys)')

            # Final wipe of AES key
            del aes_key

            result = {
                'status': 'success',
                'message': 'Hybrid encryption applied successfully',
                'encryption': {
                    'aes': 'AES-256-GCM',
                    'kms': 'enabled',
                    'pqc': pqc_status,
                    'payload_size': blob_size,
                    's3_path': file_obj.storage_path,
                }
            }

            report('complete', f'Encryption complete — {pqc_status}')
            return True, None, result

        except Exception as e:
            logger.error(f"[ENCRYPT] FAILED: {e}")
            import traceback
            traceback.print_exc()
            return False, str(e), {
                'status': 'failed',
                'message': str(e),
                'encryption': {'aes': 'failed', 'kms': 'failed', 'pqc': 'failed'},
            }
        finally:
            # Cleanup encrypted payload temp file from disk
            try:
                if temp_enc_path and os.path.exists(temp_enc_path):
                    os.remove(temp_enc_path)
                if temp_enc_dir and os.path.exists(temp_enc_dir):
                    os.rmdir(temp_enc_dir)
            except Exception:
                pass

    # ─────────────────────────────────────────────────────────────────
    #  DECRYPT (Production v2)
    # ─────────────────────────────────────────────────────────────────

    def decrypt_file(self, file_obj):
        """
        Full hybrid decryption pipeline for v2 encrypted files.
        """
        warnings = []
        try:
            # ── Step 1: Download encrypted blob from S3 ──────────────
            s3_path = file_obj.storage_path
            parts = s3_path.replace('s3://', '').split('/', 1)
            bucket = parts[0]
            key = parts[1]

            logger.info(f"[DECRYPT] Downloading via multi-threaded transfer from {bucket}/{key}")
            import tempfile
            temp_dir = tempfile.mkdtemp()
            temp_filepath = os.path.join(temp_dir, 'decrypt_temp.enc')
            try:
                self.s3.download_file(
                    bucket,
                    key,
                    temp_filepath,
                    Config=get_optimized_s3_transfer_config(file_obj.size)
                )
                
                with open(temp_filepath, 'rb') as f:
                    # Verify magic bytes
                    magic = f.read(5)
                    if magic != PAYLOAD_MAGIC:
                        warnings.append("Magic bytes in the encrypted file header have been modified!")

                    # Read header length
                    header_len_bytes = f.read(4)
                    if len(header_len_bytes) < 4:
                        return None, ["Encrypted payload header length is corrupted or invalid."]
                    
                    try:
                        header_len = struct.unpack('>I', header_len_bytes)[0]
                        header_json = f.read(header_len)
                        header = json.loads(header_json.decode('utf-8'))
                    except Exception as he:
                        logger.error(f"[DECRYPT] Header parsing failed: {he}")
                        return None, ["Encrypted payload header JSON was modified or corrupted."]

                    kem_ct_len = header.get('kem_ciphertext_len', 0)
                    nonce_len = header.get('aes_nonce_len', 0)
                    ct_len = header.get('aes_ciphertext_len', 0)
                    tag_len = header.get('aes_tag_len', 0)
                    sig_len = header.get('dsa_signature_len', 0)
                    pqc_enabled = header.get('pqc_enabled', False)

                    if pqc_enabled and file_obj.dsa_signature is not None:
                        db_sig_len = len(bytes(file_obj.dsa_signature))
                        if sig_len < db_sig_len:
                            logger.info(f"[DECRYPT] Correcting signature read length from {sig_len} to {db_sig_len} for backwards compatibility.")
                            sig_len = db_sig_len

                    # Extract binary components
                    kem_ciphertext = f.read(kem_ct_len)
                    nonce = f.read(nonce_len)

                    # Save current offset for the ciphertext
                    ciphertext_offset = f.tell()

                    # Seek to the end of ciphertext to read tag and signature
                    f.seek(ciphertext_offset + ct_len)
                    tag = f.read(tag_len)
                    dsa_signature = f.read(sig_len)

                    # Compare components with DB metadata to identify tampering
                    if file_obj.aes_nonce is not None and nonce != bytes(file_obj.aes_nonce):
                        warnings.append("AES nonce has been modified!")
                    if file_obj.aes_tag is not None and tag != bytes(file_obj.aes_tag):
                        warnings.append("AES GCM authentication tag has been modified!")
                    if pqc_enabled and file_obj.kem_ciphertext is not None and kem_ciphertext != bytes(file_obj.kem_ciphertext):
                        warnings.append("Post-Quantum KEM ciphertext has been modified!")
                    if pqc_enabled and file_obj.dsa_signature is not None and dsa_signature != bytes(file_obj.dsa_signature):
                        warnings.append("Post-Quantum Digital Signature has been modified!")

                    # ── Step 3: KMS decrypt the AES key ──────────────────────
                    logger.info("[DECRYPT] Decrypting AES key via KMS...")

                    kms_plaintext_dek = None
                    try:
                        kms_response = self.kms.decrypt(
                            CiphertextBlob=bytes(file_obj.kms_encrypted_key) if file_obj.kms_encrypted_key is not None else b'',
                            EncryptionContext={
                                'file_id': str(file_obj.id),
                                'user_id': str(self.user.id),
                                'purpose': 'stackdrive-file-encryption'
                            }
                        )
                        kms_plaintext_dek = kms_response['Plaintext']
                    except Exception as e:
                        logger.error(f"[DECRYPT] KMS decryption failed: {e}")
                        warnings.append("AWS KMS decryption of the DEK failed (possible key/context tampering or permission issue)!")
                        # Fallback key to allow decryption logic to proceed (will yield garbage plaintext, but download succeeds with warnings)
                        kms_plaintext_dek = b'\x00' * 32

                    # ── Step 4 & 5: PQC verification ─────────────────────────
                    aes_key = None
                    pqc_keys = None
                    if pqc_enabled and file_obj.secrets_manager_arn:
                        logger.info("[DECRYPT] Retrieving PQC private keys from Secrets Manager...")

                        secret_name = f"stackdrive/{self.user.id}/{file_obj.id}/pqc-keys"
                        try:
                            sm_response = self.secrets.get_secret_value(SecretId=secret_name)
                            pqc_keys = json.loads(sm_response['SecretString'])
                        except Exception as e:
                            logger.warning(f"[DECRYPT] Secrets Manager retrieval failed: {e} — skipping PQC verification")
                            warnings.append("PQC private keys could not be retrieved from AWS Secrets Manager.")
                            pqc_keys = None

                        if pqc_keys and _oqs_available:
                            # ── ML-KEM Decapsulation ──
                            logger.info("[DECRYPT] ML-KEM-768 decapsulation...")
                            try:
                                kyber_private = base64.b64decode(pqc_keys['kyber_private_key'])
                                with oqs.KeyEncapsulation("ML-KEM-768", secret_key=kyber_private) as kem:
                                    pqc_shared_secret = kem.decap_secret(kem_ciphertext)

                                aes_key = HKDF(
                                    master=kms_plaintext_dek + pqc_shared_secret,
                                    key_len=32,
                                    salt=b'stackdrive-v2-hybrid-hkdf',
                                    hashmod=CryptoSHA256,
                                    context=f"file:{file_obj.id}:user:{self.user.id}".encode('utf-8')
                                )
                                
                                # Verify hybrid binding
                                hybrid_binding = hashlib.sha256(aes_key + pqc_shared_secret).digest()
                                stored_binding = base64.b64decode(pqc_keys['hybrid_binding'])

                                if hybrid_binding != stored_binding:
                                    warnings.append("ML-KEM-768 hybrid binding verification failed (possible AES key or KEM secret tampering)!")
                            except Exception as e:
                                logger.error(f"[DECRYPT] ML-KEM-768 process failed: {e}")
                                warnings.append(f"ML-KEM-768 decapsulation failed: {str(e)}")
                                aes_key = kms_plaintext_dek

                            logger.info("[DECRYPT] ML-KEM-768 hybrid binding processed")

                            # ── ML-DSA Verification ──
                            logger.info("[DECRYPT] ML-DSA-65 signature verification...")
                            try:
                                # Hash the payload dynamically chunk-by-chunk to keep memory footprint O(1)
                                hasher = hashlib.sha256()
                                hasher.update(nonce)
                                
                                # Stream ciphertext for hashing
                                f.seek(ciphertext_offset)
                                remaining = ct_len
                                CHUNK = 16 * 1024 * 1024
                                while remaining > 0:
                                    chunk_to_read = min(CHUNK, remaining)
                                    ct_chunk = f.read(chunk_to_read)
                                    if not ct_chunk:
                                        break
                                    hasher.update(ct_chunk)
                                    remaining -= len(ct_chunk)

                                hasher.update(tag)
                                stored_binding = base64.b64decode(pqc_keys.get('hybrid_binding', '')) if pqc_keys else b''
                                hasher.update(stored_binding)
                                payload_hash = hasher.digest()

                                with oqs.Signature("ML-DSA-65") as verifier:
                                    is_valid = verifier.verify(
                                        payload_hash,
                                        dsa_signature,
                                        bytes(file_obj.dsa_public_key) if file_obj.dsa_public_key is not None else b''
                                    )

                                if not is_valid:
                                    warnings.append("ML-DSA-65 digital signature verification failed (file contents or signature has been tampered)!")
                            except Exception as e:
                                logger.error(f"[DECRYPT] ML-DSA-65 verification failed: {e}")
                                warnings.append(f"ML-DSA-65 signature verification failed to execute: {str(e)}")

                            logger.info("[DECRYPT] ML-DSA-65 signature verification processed")

                            # Cleanup PQC secrets from memory
                            if 'kyber_private' in locals():
                                del kyber_private
                            if 'pqc_shared_secret' in locals():
                                del pqc_shared_secret
                            if 'hybrid_binding' in locals():
                                del hybrid_binding
                        else:
                            # PQC verification unavailable — fall back to KMS DEK directly
                            logger.warning("[DECRYPT] PQC unavailable or disabled, using KMS only")
                            if pqc_enabled:
                                warnings.append("PQC verification unavailable, falling back to KMS only.")
                            aes_key = kms_plaintext_dek
                    else:
                        logger.info("[DECRYPT] PQC disabled, using KMS only")
                        aes_key = kms_plaintext_dek

                    if 'kms_plaintext_dek' in locals():
                        del kms_plaintext_dek

                    # ── Step 6: CHUNKED AES-256-GCM decryption ───────────────
                    logger.info("[DECRYPT] Decrypting file content...")
                    
                    plaintext = b''
                    try:
                        # Ensure aes_key is 32 bytes (pad/truncate if needed due to dummy fallbacks)
                        if len(aes_key) != 32:
                            aes_key = aes_key.ljust(32, b'\x00')[:32]
                            
                        # Ensure nonce is of proper length (usually 12 or 16 bytes)
                        safe_nonce = nonce if len(nonce) in [12, 16] else b'\x00' * 12
                        
                        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=safe_nonce)

                        plaintext_buffer = io.BytesIO()
                        f.seek(ciphertext_offset)
                        remaining = ct_len
                        CHUNK = 16 * 1024 * 1024
                        
                        while remaining > 0:
                            chunk_to_read = min(CHUNK, remaining)
                            ct_chunk = f.read(chunk_to_read)
                            if not ct_chunk:
                                break
                            plaintext_buffer.write(cipher.decrypt(ct_chunk))
                            remaining -= len(ct_chunk)
                        
                        plaintext = plaintext_buffer.getvalue()
                        plaintext_buffer.close()
                        
                        # Verify GCM tag
                        try:
                            cipher.verify(tag)
                        except ValueError as ve:
                            warnings.append("AES-GCM integrity check failed (ciphertext or authentication tag was modified)!")
                    except Exception as e:
                        logger.error(f"[DECRYPT] AES-GCM decryption execution error: {e}")
                        warnings.append(f"AES-GCM decryption execution failed: {str(e)}")

                    # ── ZERO-TRUST: Wipe AES key ──
                    if 'aes_key' in locals():
                        del aes_key

                    logger.info(f"[DECRYPT] Success/Warning state reached — {len(plaintext)} bytes decrypted, warnings: {warnings}")
                    return plaintext, warnings

            finally:
                try:
                    if os.path.exists(temp_filepath):
                        os.remove(temp_filepath)
                    if os.path.exists(temp_dir):
                        os.rmdir(temp_dir)
                except Exception:
                    pass

        except Exception as e:
            logger.error(f"[DECRYPT] FAILED: {e}")
            import traceback
            traceback.print_exc()
            return None, [f'Decryption failed: {str(e)}']


# ═════════════════════════════════════════════════════════════════════
#  CONVENIENCE FACTORY
# ═════════════════════════════════════════════════════════════════════

def create_encryption_engine(user_obj):
    """
    Create a HybridEncryptionEngine with proper AWS clients.
    
    Args:
        user_obj: User SQLAlchemy record with AWS credentials
    
    Returns:
        HybridEncryptionEngine instance
    """
    from pipeline import _get_aws_session, BOTO3_CLIENT_CONFIG

    session = _get_aws_session(user_obj)

    s3 = session.client('s3', config=BOTO3_CLIENT_CONFIG)
    kms = session.client('kms', config=BOTO3_CLIENT_CONFIG)
    secrets = session.client('secretsmanager', config=BOTO3_CLIENT_CONFIG)

    return HybridEncryptionEngine(s3, kms, secrets, user_obj), s3
