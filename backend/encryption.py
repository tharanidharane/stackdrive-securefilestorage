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

# ── Configuration ────────────────────────────────────────────────────
PQC_ENABLED = os.environ.get('PQC_ENABLED', 'false').lower() == 'true'

# ── Conditional PQC Import ───────────────────────────────────────────
_oqs_available = False
if PQC_ENABLED:
    try:
        import oqs
        _oqs_available = True
        logger.info("liboqs loaded — PQC algorithms available: ML-KEM-768, ML-DSA-65")
    except ImportError:
        logger.warning(
            "PQC_ENABLED=true but liboqs-python not installed. "
            "Falling back to KMS-only encryption. "
            "Install: https://github.com/open-quantum-safe/liboqs-python"
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
        Full hybrid encryption pipeline.

        Args:
            file_obj: SQLAlchemy File record
            filepath: Path to plaintext file on disk
            s3_key: S3 object key prefix
            progress_callback: fn(step_name, detail) for UI updates

        Returns:
            (success: bool, error: str|None, result: dict)
        """
        from models import db

        def report(step, detail):
            if progress_callback:
                progress_callback(step, detail)
            logger.info(f"[ENCRYPT] {step}: {detail}")

        try:
            # ── Step 1: Read raw file size ───────────────────────────
            report('read', 'Reading file size for chunked processing...')
            file_size = os.path.getsize(filepath)
            report('read', f'File size: {file_size} bytes')
            if file_size > 500 * 1024 * 1024:
                logger.warning("[ENCRYPT] File exceeds 500MB, multipart upload recommended")

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

            # ── Step 3: CHUNKED AES-256-GCM encryption ───────────────
            report('aes_encrypt', 'Encrypting with chunked AES-256-GCM...')
            cipher = AES.new(aes_key, AES.MODE_GCM)
            
            # Optimized block processing:
            # - For small/moderate files (<= 50MB), encrypt the whole file in a single native call to bypass loop overhead.
            # - For large files, stream directly to a BytesIO buffer with 16MB chunks to minimize
            #   Python iteration overhead AND avoid double-memory from list+join.
            if file_size <= 50 * 1024 * 1024:
                with open(filepath, 'rb') as f:
                    plaintext = f.read()
                ciphertext = cipher.encrypt(plaintext)
                del plaintext
            else:
                ct_buffer = io.BytesIO()
                CHUNK = 16 * 1024 * 1024  # 16 MB chunks — fewer iterations
                with open(filepath, 'rb') as f:
                    while True:
                        chunk = f.read(CHUNK)
                        if not chunk:
                            break
                        ct_buffer.write(cipher.encrypt(chunk))
                ciphertext = ct_buffer.getvalue()
                ct_buffer.close()
                
            tag = cipher.digest()
            nonce = cipher.nonce

            report('aes_encrypt', f'Encrypted {len(ciphertext)} bytes (nonce={len(nonce)}B, tag={len(tag)}B)')

            if PQC_ENABLED and _oqs_available:

                # ── ML-DSA-65 Digital Signature ──
                report('pqc_dsa', 'Signing payload with ML-DSA-65 (Dilithium)...')

                # Sign over: nonce + ciphertext + tag + hybrid_binding
                sign_payload = nonce + ciphertext + tag + hybrid_binding

                with oqs.Signature("ML-DSA-65") as signer:
                    dsa_public_key = signer.generate_keypair()
                    dsa_private_key = signer.export_secret_key()
                    dsa_signature = signer.sign(sign_payload)

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
                    # Update if secret already exists (re-encryption scenario)
                    self.secrets.put_secret_value(
                        SecretId=secret_name,
                        SecretString=secret_value,
                    )
                    # Retrieve the ARN
                    desc = self.secrets.describe_secret(SecretId=secret_name)
                    secrets_arn = desc['ARN']
                    report('secrets', 'Private keys updated in Secrets Manager')

                # ── ZERO-TRUST: Wipe private keys from local memory ──
                del kem_private_key
                del dsa_private_key
                del pqc_shared_secret
                del hybrid_binding

                pqc_status = 'ML-KEM-768 + ML-DSA-65'

            else:
                report('pqc_kem', 'PQC disabled — using KMS-only envelope encryption')

            # ── Step 7: Structure final encrypted payload ────────────
            report('payload', 'Building encrypted payload...')

            header = {
                'version': PAYLOAD_VERSION_V2,
                'aes_nonce_len': len(nonce),
                'aes_tag_len': len(tag),
                'aes_ciphertext_len': len(ciphertext),
                'kem_ciphertext_len': len(kem_ciphertext),
                'dsa_signature_len': len(dsa_signature),
                'pqc_enabled': PQC_ENABLED and _oqs_available,
                'file_id': file_obj.id,
                'timestamp': datetime.utcnow().isoformat() + 'Z',
            }
            header_json = json.dumps(header, separators=(',', ':')).encode('utf-8')
            header_len = struct.pack('>I', len(header_json))

            # Final binary layout:
            # [MAGIC 5B][HEADER_LEN 4B][HEADER JSON][KEM_CT][NONCE][CIPHERTEXT][TAG][SIGNATURE]
            final_blob = io.BytesIO()
            final_blob.write(PAYLOAD_MAGIC)
            final_blob.write(header_len)
            final_blob.write(header_json)
            final_blob.write(kem_ciphertext)
            final_blob.write(nonce)
            final_blob.write(ciphertext)
            final_blob.write(tag)
            final_blob.write(dsa_signature)

            blob_size = final_blob.tell()
            final_blob.seek(0)

            report('payload', f'Payload built ({blob_size} bytes)')

            # ── Step 9: Upload to S3 with KMS SSE ────────────────────
            report('s3_upload', 'Uploading encrypted blob to S3 secure bucket...')

            enc_s3_key = s3_key
            self.s3.upload_fileobj(
                final_blob,
                self.user.secure_bucket,
                enc_s3_key,
                ExtraArgs={
                    'ServerSideEncryption': 'aws:kms',
                    'SSEKMSKeyId': self.user.kms_key_arn,
                },
                Config=S3_TRANSFER_CONFIG
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

            # ── ZERO-TRUST: Final wipe of AES key ──
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

    # ─────────────────────────────────────────────────────────────────
    #  DECRYPT (Production v2)
    # ─────────────────────────────────────────────────────────────────

    def decrypt_file(self, file_obj):
        """
        Full hybrid decryption pipeline for v2 encrypted files.

        Args:
            file_obj: SQLAlchemy File record with encryption metadata

        Returns:
            (plaintext_bytes: bytes|None, error: str|None)
        """
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
                    Config=S3_TRANSFER_CONFIG
                )
                
                with open(temp_filepath, 'rb') as f:
                    # Verify magic bytes
                    magic = f.read(5)
                    if magic != PAYLOAD_MAGIC:
                        return None, 'Invalid encrypted payload (bad magic bytes)'

                    # Read header length
                    header_len_bytes = f.read(4)
                    if len(header_len_bytes) < 4:
                        return None, 'Invalid encrypted payload (missing header length)'
                    header_len = struct.unpack('>I', header_len_bytes)[0]

                    # Read and parse header JSON
                    header_json = f.read(header_len)
                    header = json.loads(header_json.decode('utf-8'))

                    kem_ct_len = header['kem_ciphertext_len']
                    nonce_len = header['aes_nonce_len']
                    ct_len = header['aes_ciphertext_len']
                    tag_len = header['aes_tag_len']
                    sig_len = header['dsa_signature_len']
                    pqc_enabled = header.get('pqc_enabled', False)

                    # Extract binary components
                    kem_ciphertext = f.read(kem_ct_len)
                    nonce = f.read(nonce_len)

                    # Save current offset for the ciphertext
                    ciphertext_offset = f.tell()

                    # Seek to the end of ciphertext to read tag and signature
                    f.seek(ciphertext_offset + ct_len)
                    tag = f.read(tag_len)
                    dsa_signature = f.read(sig_len)

                    # Seek back to ciphertext start offset
                    f.seek(ciphertext_offset)

                    # ── Step 3: KMS decrypt the AES key ──────────────────────
                    logger.info("[DECRYPT] Decrypting AES key via KMS...")

                    kms_response = self.kms.decrypt(
                        CiphertextBlob=file_obj.kms_encrypted_key,
                        EncryptionContext={
                            'file_id': str(file_obj.id),
                            'user_id': str(self.user.id),
                            'purpose': 'stackdrive-file-encryption'
                        }
                    )
                    kms_plaintext_dek = kms_response['Plaintext']

                    ciphertext = None

                    # ── Step 4 & 5: PQC verification ─────────────────────────
                    if pqc_enabled and file_obj.secrets_manager_arn:
                        logger.info("[DECRYPT] Retrieving PQC private keys from Secrets Manager...")

                        secret_name = f"stackdrive/{self.user.id}/{file_obj.id}/pqc-keys"
                        try:
                            sm_response = self.secrets.get_secret_value(SecretId=secret_name)
                            pqc_keys = json.loads(sm_response['SecretString'])
                        except Exception as e:
                            logger.warning(f"[DECRYPT] Secrets Manager retrieval failed: {e} — skipping PQC verification")
                            pqc_keys = None

                        if pqc_keys and _oqs_available:
                            # ── ML-KEM Decapsulation ──
                            logger.info("[DECRYPT] ML-KEM-768 decapsulation...")

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
                                del aes_key
                                return None, 'Hybrid binding verification FAILED — possible key tampering'

                            logger.info("[DECRYPT] ML-KEM-768 hybrid binding verified ✓")

                            # ── ML-DSA Verification ──
                            logger.info("[DECRYPT] ML-DSA-65 signature verification...")

                            # Read the ciphertext for PQC signature verification
                            ciphertext = f.read(ct_len)
                            sign_payload = nonce + ciphertext + tag + hybrid_binding

                            with oqs.Signature("ML-DSA-65") as verifier:
                                is_valid = verifier.verify(
                                    sign_payload,
                                    dsa_signature,
                                    file_obj.dsa_public_key
                                )

                            if not is_valid:
                                del aes_key
                                return None, 'ML-DSA-65 signature verification FAILED — payload may be tampered'

                            logger.info("[DECRYPT] ML-DSA-65 signature verified ✓")

                            # Cleanup PQC secrets from memory
                            del kyber_private
                            del pqc_shared_secret
                            del hybrid_binding
                        else:
                            # PQC verification unavailable — fall back to KMS DEK directly
                            logger.warning(
                                "[DECRYPT] PQC verification skipped — "
                                "pqc_keys unavailable or liboqs not installed. "
                                "Falling back to KMS DEK for decryption."
                            )
                            aes_key = kms_plaintext_dek
                    else:
                        aes_key = kms_plaintext_dek

                    del kms_plaintext_dek

                    # ── Step 6: AES-256-GCM decryption ───────────────────────
                    logger.info("[DECRYPT] AES-256-GCM decryption...")

                    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
                    
                    if ciphertext is not None:
                        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
                        del ciphertext
                    else:
                        # Stream the ciphertext in chunks directly from file to optimize memory
                        f.seek(ciphertext_offset)
                        plaintext_buffer = io.BytesIO()
                        CHUNK = 16 * 1024 * 1024  # 16 MB chunks
                        remaining = ct_len
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
                        cipher.verify(tag)

                    # ── ZERO-TRUST: Wipe AES key ──
                    del aes_key

                    logger.info(f"[DECRYPT] Success — {len(plaintext)} bytes decrypted")
                    return plaintext, None

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
            return None, f'Decryption failed: {str(e)}'


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
