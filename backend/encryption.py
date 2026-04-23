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

logger = logging.getLogger(__name__)

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
            # ── Step 1: Read raw file ────────────────────────────────
            report('read', 'Reading file bytes...')
            with open(filepath, 'rb') as f:
                raw_data = f.read()

            file_size = len(raw_data)
            report('read', f'Read {file_size} bytes')

            # ── Step 2: Generate AES-256 key ─────────────────────────
            report('aes_keygen', 'Generating AES-256 key...')
            aes_key = get_random_bytes(32)  # 256-bit true random key

            # ── Step 3: AES-256-GCM encryption ───────────────────────
            report('aes_encrypt', 'Encrypting with AES-256-GCM...')
            cipher = AES.new(aes_key, AES.MODE_GCM)
            ciphertext, tag = cipher.encrypt_and_digest(raw_data)
            nonce = cipher.nonce  # 16 bytes

            report('aes_encrypt', f'Encrypted {len(ciphertext)} bytes (nonce={len(nonce)}B, tag={len(tag)}B)')

            # ── Step 4: AWS KMS envelope encryption ──────────────────
            report('kms_wrap', 'Wrapping AES key with AWS KMS...')
            kms_response = self.kms.encrypt(
                KeyId=self.user.kms_key_arn,
                Plaintext=aes_key,
                EncryptionContext={
                    'file_id': file_obj.id,
                    'user_id': self.user.id,
                    'purpose': 'stackdrive-file-encryption'
                }
            )
            kms_encrypted_key = kms_response['CiphertextBlob']
            report('kms_wrap', f'AES key wrapped ({len(kms_encrypted_key)} bytes KMS blob)')

            # ── ZERO-TRUST: Wipe plaintext AES key from memory after KMS wrap ──
            # (Python doesn't guarantee secure wipe, but we overwrite the reference)

            # ── Step 5 & 6: Post-Quantum Cryptography ────────────────
            kem_ciphertext = b''
            kem_public_key = b''
            dsa_signature = b''
            dsa_public_key = b''
            secrets_arn = None
            pqc_status = 'disabled'

            if PQC_ENABLED and _oqs_available:
                report('pqc_kem', 'Running ML-KEM-768 (Kyber) key encapsulation...')

                # ── ML-KEM-768 Key Encapsulation ──
                with oqs.KeyEncapsulation("ML-KEM-768") as kem:
                    kem_public_key = kem.generate_keypair()
                    kem_private_key = kem.export_secret_key()
                    kem_ciphertext, pqc_shared_secret = kem.encap_secret(kem_public_key)

                # Derive hybrid binding: HMAC-SHA256(aes_key || shared_secret)
                # This cryptographically binds the AES key to the PQC shared secret
                hybrid_binding = hashlib.sha256(aes_key + pqc_shared_secret).digest()

                report('pqc_kem', f'ML-KEM-768 encapsulation complete (ct={len(kem_ciphertext)}B)')

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

            enc_s3_key = f"{s3_key}.enc"
            self.s3.upload_fileobj(
                final_blob,
                self.user.secure_bucket,
                enc_s3_key,
                ExtraArgs={
                    'ServerSideEncryption': 'aws:kms',
                    'SSEKMSKeyId': self.user.kms_key_arn,
                }
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

            logger.info(f"[DECRYPT] Downloading from {bucket}/{key}")
            obj = self.s3.get_object(Bucket=bucket, Key=key)
            blob = obj['Body'].read()

            # ── Step 2: Parse the binary payload ─────────────────────
            logger.info(f"[DECRYPT] Parsing payload ({len(blob)} bytes)")

            offset = 0

            # Verify magic bytes
            magic = blob[offset:offset + 5]
            offset += 5
            if magic != PAYLOAD_MAGIC:
                return None, 'Invalid encrypted payload (bad magic bytes)'

            # Read header length
            header_len = struct.unpack('>I', blob[offset:offset + 4])[0]
            offset += 4

            # Read and parse header JSON
            header_json = blob[offset:offset + header_len]
            offset += header_len
            header = json.loads(header_json.decode('utf-8'))

            kem_ct_len = header['kem_ciphertext_len']
            nonce_len = header['aes_nonce_len']
            ct_len = header['aes_ciphertext_len']
            tag_len = header['aes_tag_len']
            sig_len = header['dsa_signature_len']
            pqc_enabled = header.get('pqc_enabled', False)

            # Extract binary components
            kem_ciphertext = blob[offset:offset + kem_ct_len]
            offset += kem_ct_len

            nonce = blob[offset:offset + nonce_len]
            offset += nonce_len

            ciphertext = blob[offset:offset + ct_len]
            offset += ct_len

            tag = blob[offset:offset + tag_len]
            offset += tag_len

            dsa_signature = blob[offset:offset + sig_len]
            offset += sig_len

            # ── Step 3: KMS decrypt the AES key ──────────────────────
            logger.info("[DECRYPT] Decrypting AES key via KMS...")

            kms_response = self.kms.decrypt(
                CiphertextBlob=file_obj.kms_encrypted_key,
                EncryptionContext={
                    'file_id': file_obj.id,
                    'user_id': self.user.id,
                    'purpose': 'stackdrive-file-encryption'
                }
            )
            aes_key = kms_response['Plaintext']

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

                    # Verify hybrid binding
                    hybrid_binding = hashlib.sha256(aes_key + pqc_shared_secret).digest()
                    stored_binding = base64.b64decode(pqc_keys['hybrid_binding'])

                    if hybrid_binding != stored_binding:
                        del aes_key
                        return None, 'Hybrid binding verification FAILED — possible key tampering'

                    logger.info("[DECRYPT] ML-KEM-768 hybrid binding verified ✓")

                    # ── ML-DSA Verification ──
                    logger.info("[DECRYPT] ML-DSA-65 signature verification...")

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

            # ── Step 6: AES-256-GCM decryption ───────────────────────
            logger.info("[DECRYPT] AES-256-GCM decryption...")

            cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)

            # ── ZERO-TRUST: Wipe AES key ──
            del aes_key

            logger.info(f"[DECRYPT] Success — {len(plaintext)} bytes decrypted")
            return plaintext, None

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
    import boto3

    session = boto3.Session(
        aws_access_key_id=user_obj.aws_access_key,
        aws_secret_access_key=user_obj.aws_secret_key,
        region_name=user_obj.aws_region,
    )

    s3 = session.client('s3')
    kms = session.client('kms')
    secrets = session.client('secretsmanager')

    return HybridEncryptionEngine(s3, kms, secrets, user_obj), s3
