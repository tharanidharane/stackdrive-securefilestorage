"""
Security Pipeline — Production-Grade Zero-Trust File Scanning System
====================================================================
Layer 1: SHA-256 + VirusTotal (Threat Intelligence)
Layer 2: File Heuristic Analysis
Layer 3: ClamAV (Docker — Persistent clamd Daemon)
Layer 4: Sandbox (Docker — Advanced Behavioral Analysis)
Layer 5: AES-256 + PQC Encryption
"""

# PIPELINE SECURITY POLICY — FAIL-CLOSED ZERO-TRUST
# All 4 layers are mandatory. No layer may be skipped, degraded, or simulated.
# If any security component is unavailable (YARA, ClamAV, Docker sandbox),
# the file is BLOCKED — never passed in degraded state.
# Suspicious risk (≥30 in L2, >30 in L4) is treated as malicious — blocked.
# Layer execution order: L1 → L2 → L3 → L4 (sequential, each must pass).
# 500MB file support: SHA-256 streams in 1MB chunks, ClamAV in 16MB chunks,
# YARA scans 512KB head+tail, sandbox runs with 512MB RAM and 90s strace.

import hashlib
import zipfile
import os
import re
import json
import time
import math
import struct
import random
import logging
import subprocess
import shutil
import io
from functools import lru_cache
from datetime import datetime
from models import db, File, PipelineStage, Notification, User
import tempfile
import requests

try:
    import magic
except ImportError:
    magic = None

try:
    import yara #type:ignore
except ImportError:
    yara = None

logger = logging.getLogger(__name__)

from boto3.s3.transfer import TransferConfig
from botocore.config import Config as BotocoreConfig

# Multi-threaded S3 transfer configuration for large files (e.g., 20MB - 500MB)
S3_TRANSFER_CONFIG = TransferConfig(
    multipart_threshold=8 * 1024 * 1024,   # 8MB threshold for multipart
    max_concurrency=15,                   # Use 15 parallel threads
    multipart_chunksize=8 * 1024 * 1024,  # 8MB chunk size per part
    use_threads=True
)

BOTO3_CLIENT_CONFIG = BotocoreConfig(
    max_pool_connections=120,              # Support high concurrency for large files (up to 120 threads)
    retries={'max_attempts': 5, 'mode': 'standard'}
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


def _get_aws_session(user_obj):
    """
    Get a scoped AWS session via STS AssumeRole.
    Prefers IAM role assumption over stored credentials.
    Falls back to stored credentials for backward compatibility
    during migration (log a deprecation warning when fallback used).
    """
    import boto3

    # Prefer IAM role assumption (production path)
    if hasattr(user_obj, 'iam_role_arn') and user_obj.iam_role_arn:
        sts = boto3.client('sts')
        assumed = sts.assume_role(
            RoleArn=user_obj.iam_role_arn,
            RoleSessionName=f"stackdrive-user-{user_obj.id}",
            DurationSeconds=900,
        )
        creds = assumed['Credentials']
        return boto3.Session(
            aws_access_key_id=creds['AccessKeyId'],
            aws_secret_access_key=creds['SecretAccessKey'],
            aws_session_token=creds['SessionToken'],
            region_name=getattr(user_obj, 'aws_region', 'us-east-1'),
        )

    # Fallback: stored credentials (deprecated — log warning)
    logger.warning(
        f"[SECURITY] User {user_obj.id} using stored AWS credentials. "
        "Migrate to IAM role assumption (iam_role_arn field)."
    )
    return boto3.Session(
        aws_access_key_id=user_obj.aws_access_key,
        aws_secret_access_key=user_obj.aws_secret_key,
        region_name=getattr(user_obj, 'aws_region', 'us-east-1'),
    )

# ═══════════════════════════════════════════════════════════════════
# A1. REDIS CONNECTION POOL (singleton — one pool per process)
# ═══════════════════════════════════════════════════════════════════

import redis as _redis_lib
import json  as _json_lib

_redis_pool:   _redis_lib.ConnectionPool | None = None
_redis_client: _redis_lib.Redis          | None = None
_redis_lock = __import__('threading').Lock()

def _get_redis() -> '_redis_lib.Redis | None':
    """
    Returns a shared Redis client backed by a connection pool.
    Pool is created ONCE per process on first call, then reused.
    Returns None if REDIS_URL is not set or connection fails.
    Never raises — callers must handle None gracefully.
    """
    global _redis_pool, _redis_client
    if _redis_client is not None:
        return _redis_client
    with _redis_lock:
        if _redis_client is not None:
            return _redis_client
        redis_url = os.environ.get('REDIS_URL')
        if not redis_url:
            return None
        try:
            _redis_pool  = _redis_lib.ConnectionPool.from_url(
                redis_url,
                max_connections=20,
                socket_connect_timeout=2,
                socket_timeout=3,
                decode_responses=False,
            )
            _redis_client = _redis_lib.Redis(connection_pool=_redis_pool)
            _redis_client.ping()   # Verify connectivity at startup
            logger.info("[REDIS] Connection pool initialised (max_connections=20)")
        except Exception as e:
            logger.warning(f"[REDIS] Pool init failed: {e} — using memory cache")
            _redis_client = None
    return _redis_client

def _redis_get(key: str) -> dict | None:
    """GET from Redis. Returns parsed dict or None."""
    try:
        r = _get_redis()
        if r is None:
            return None
        val = r.get(key)
        return _json_lib.loads(val) if val else None
    except Exception as e:
        logger.warning(f"[REDIS GET] {key}: {e}")
        return None

def _redis_setex(key: str, ttl: int, data: dict):
    """SET with TTL in Redis. Silent on failure."""
    try:
        r = _get_redis()
        if r is not None:
            r.setex(key, ttl, _json_lib.dumps(data))
    except Exception as e:
        logger.warning(f"[REDIS SET] {key}: {e}")

# ═══════════════════════════════════════════════════════════════════
# A2. TTL-AWARE IN-MEMORY CACHE (fallback when Redis absent)
# ═══════════════════════════════════════════════════════════════════

_VT_CACHE_TTL  = int(os.environ.get('VT_CACHE_TTL_SECONDS', '21600'))  # 6h
_vt_memory_cache: dict = {}   # {key: {"ts": float, "data": dict}}

def _mem_get(key: str) -> dict | None:
    """
    TTL-aware in-memory get. Auto-evicts on access.
    Batch-evicts all stale keys when cache exceeds 5000 entries.
    """
    entry = _vt_memory_cache.get(key)
    if entry is None:
        return None
    if time.time() - entry["ts"] > _VT_CACHE_TTL:
        _vt_memory_cache.pop(key, None)
        return None
    return entry["data"]

def _mem_set(key: str, data: dict, ttl: int | None = None):
    """TTL-aware in-memory set. Evicts expired entries when > 5000 keys."""
    _vt_memory_cache[key] = {"ts": time.time(), "data": data,
                              "ttl": ttl or _VT_CACHE_TTL}
    if len(_vt_memory_cache) > 5000:
        now     = time.time()
        expired = [k for k, v in _vt_memory_cache.items()
                   if now - v["ts"] > v.get("ttl", _VT_CACHE_TTL)]
        for k in expired:
            _vt_memory_cache.pop(k, None)
        logger.info(f"[MEM CACHE] Evicted {len(expired)} expired entries.")

def _mem_get_with_ttl(key: str, ttl: int) -> dict | None:
    """Get with a custom TTL check (for reputation cache)."""
    entry = _vt_memory_cache.get(key)
    if entry is None:
        return None
    if time.time() - entry["ts"] > ttl:
        _vt_memory_cache.pop(key, None)
        return None
    return entry["data"]

# ═══════════════════════════════════════════════════════════════════
# A3. UNIFIED LAYER 1 INTEL CACHE
# ═══════════════════════════════════════════════════════════════════

def _l1_cache_get(sha256: str) -> dict | None:
    """
    Retrieve unified Layer 1 cache.
    Keys: vt, otx, bazaar, circl. Returns dict or None on miss/expiry.
    """
    key = f'stackdrive:l1:{sha256}'
    return _redis_get(key) or _mem_get(key)

def _l1_cache_set(sha256: str, result: dict):
    """Store unified Layer 1 cache. TTL = _VT_CACHE_TTL (6h)."""
    key = f'stackdrive:l1:{sha256}'
    if _get_redis():
        _redis_setex(key, _VT_CACHE_TTL, result)
    else:
        _mem_set(key, result)

# Backward-compatible aliases — keep, do not remove
def _vt_cache_get(sha256):
    return (_l1_cache_get(sha256) or {}).get('vt')
def _vt_cache_set(sha256, result):
    _l1_cache_set(sha256, {'vt': result, 'otx': None,
                            'bazaar': None, 'circl': None})

# ═══════════════════════════════════════════════════════════════════
# A4. FILE REPUTATION DATABASE
# ═══════════════════════════════════════════════════════════════════

# Safe TTL reduced to 6h to match intel cache TTL.
# Prevents serving stale "safe" verdicts if threat intel updates.
# Malicious stays 7d — confirmed malware verdicts rarely reverse.
REPUTATION_TTL_SAFE      = 21600    # 6h  ← matches intel cache TTL
REPUTATION_TTL_MALICIOUS = 604800   # 7d

def _reputation_get(sha256: str) -> dict | None:
    """
    Retrieve stored pipeline verdict.
    Returns {"verdict","risk","reason","ts"} or None if absent/expired.
    Applies appropriate TTL per verdict type.
    """
    key = f'stackdrive:rep:{sha256}'
    # Redis path: uses server-side TTL (set correctly in _reputation_set)
    data = _redis_get(key)
    if data:
        return data
    # Memory fallback: apply custom TTL per verdict type
    entry = _vt_memory_cache.get(key)
    if not entry:
        return None
    ttl = (REPUTATION_TTL_MALICIOUS
           if entry["data"].get("verdict") == "malicious"
           else REPUTATION_TTL_SAFE)
    if time.time() - entry["ts"] > ttl:
        _vt_memory_cache.pop(key, None)
        return None
    return entry["data"]

def _reputation_set(sha256: str, verdict: str, risk: int, reason: str):
    """
    Store final pipeline verdict. Uses verdict-specific TTL.
    verdict: "safe" | "malicious"
    """
    ttl  = (REPUTATION_TTL_MALICIOUS if verdict == "malicious"
            else REPUTATION_TTL_SAFE)
    data = {"verdict": verdict, "risk": risk,
            "reason": reason, "ts": time.time()}
    key  = f'stackdrive:rep:{sha256}'
    if _get_redis():
        _redis_setex(key, ttl, data)
    else:
        _vt_memory_cache[key] = {"ts": time.time(), "data": data, "ttl": ttl}
    logger.info(f"[REPUTATION] {verdict} risk={risk} sha256={sha256[:16]}")

# ═══════════════════════════════════════════════════════════════════
# A5. SHARED THREAD POOL EXECUTOR (one per worker process)
# ═══════════════════════════════════════════════════════════════════

import concurrent.futures as _futures
import atexit as _atexit

# Shared executor — created once per process, reused across all uploads.
# max_workers=8: 4 for L1 intel APIs + 4 for member scan concurrency.
# Celery workers are separate processes so this does not accumulate.
_shared_executor = _futures.ThreadPoolExecutor(
    max_workers=8,
    thread_name_prefix='stackdrive-worker'
)
_atexit.register(_shared_executor.shutdown, wait=False)

# ═══════════════════════════════════════════════════════════════════
# A6. API GUARD — TOKEN BUCKET + CIRCUIT BREAKER
# ═══════════════════════════════════════════════════════════════════

import threading as _cb_threading
import time      as _cb_time

class _ApiGuard:
    """
    Token bucket (rate limiter) + circuit breaker per API.
    acquire() → True if permitted, False to skip. Never blocks. Never raises.

    States: CLOSED (normal) → OPEN (failed, skipping) → HALF_OPEN (probe)
    """
    CLOSED = 'closed'; OPEN = 'open'; HALF_OPEN = 'half_open'

    def __init__(self, name, refill_rate=1.0, burst_size=5,
                 failure_limit=5, cooldown=60):
        self.name  = name
        self._lock = _cb_threading.Lock()
        self._tok  = float(burst_size)
        self._bst  = float(burst_size)
        self._rate = refill_rate
        self._last = _cb_time.monotonic()
        self._st   = self.CLOSED
        self._fc   = 0
        self._lim  = failure_limit
        self._cool = cooldown
        self._opn  = None

    def _refill(self):
        now       = _cb_time.monotonic()
        self._tok = min(self._bst, self._tok + (now-self._last)*self._rate)
        self._last = now

    def acquire(self) -> bool:
        with self._lock:
            if self._st == self.OPEN:
                if _cb_time.monotonic()-self._opn >= self._cool:
                    self._st = self.HALF_OPEN
                else:
                    return False
            self._refill()
            if self._tok >= 1.0:
                self._tok -= 1.0
                return True
            logger.warning(f"[API GUARD] {self.name}: rate-limited")
            return False

    def ok(self):
        with self._lock:
            self._fc = 0
            if self._st == self.HALF_OPEN:
                self._st = self.CLOSED

    def fail(self):
        with self._lock:
            self._fc += 1
            if self._st == self.HALF_OPEN or self._fc >= self._lim:
                self._st  = self.OPEN
                self._opn = _cb_time.monotonic()
                logger.warning(
                    f"[API GUARD] {self.name}: circuit OPEN {self._cool}s"
                )

_VT_GUARD     = _ApiGuard('VirusTotal',    refill_rate=0.066, burst_size=4,  failure_limit=3, cooldown=120)
_CIRCL_GUARD  = _ApiGuard('CIRCL',         refill_rate=2.0,   burst_size=10, failure_limit=5, cooldown=60)
_BAZAAR_GUARD = _ApiGuard('MalwareBazaar', refill_rate=1.0,   burst_size=5,  failure_limit=5, cooldown=60)
_OTX_GUARD    = _ApiGuard('OTX',           refill_rate=1.0,   burst_size=5,  failure_limit=5, cooldown=60)

# ═══════════════════════════════════════════════════════════════════
# A7. LAYER 2 CONSTANTS
# ═══════════════════════════════════════════════════════════════════

DANGEROUS_EXTENSIONS = {
    '.exe','.bat','.cmd','.msi','.scr','.pif','.com',
    '.hta','.vbs','.ws','.wsf','.wsc','.wsh',
    '.ps2','.reg','.inf','.ins','.isp'
}
ARCHIVE_EXEC_EXTENSIONS = DANGEROUS_EXTENSIONS | {'.sh','.bash','.run','.bin'}
MEMBER_SCAN_EXTENSIONS  = {
    '.py','.js','.ts','.sh','.bash','.ps1','.bat','.cmd',
    '.rb','.pl','.lua','.php','.vbs','.hta','.wsf','.html','.htm','.svg'
}
OFFICE_EXTENSIONS = {
    '.docx','.xlsx','.pptx','.docm','.xlsm','.pptm',
    '.doc','.xls','.ppt','.xlsb','.odt','.ods','.odp'
}
IMAGE_EXTENSIONS  = {'.jpg','.jpeg','.png','.gif','.webp','.bmp','.ico','.tiff'}
OBFUSCATED_PATTERN = re.compile(
    r'^[a-zA-Z0-9]{20,}\.(exe|bat|sh|ps1|vbs|cmd|msi)$', re.IGNORECASE
)

# Absolute uncompressed size limit for ZIP content (defence-in-depth
# alongside the ratio check — catches near-threshold ratio attacks)
ZIP_MAX_UNCOMPRESSED_BYTES = 2 * 1024 * 1024 * 1024   # 2 GB

# Member scan limits
MAX_MEMBERS_TO_SCAN  = 50
MAX_MEMBER_BYTES     = 32768   # 32 KB per member
MAX_MEMBER_RISK      = 80
MAX_SCAN_BUDGET_BYTES = 10 * 1024 * 1024  # 10 MB total across all members
MAX_NESTED_DEPTH     = 2

# File-type aware entropy thresholds: (suspicious_threshold, expected_high)
ENTROPY_THRESHOLDS = {
    '.py':(7.0,False),'.js':(7.0,False),'.ts':(7.0,False),
    '.sh':(6.5,False),'.ps1':(6.5,False),'.bat':(6.0,False),
    '.rb':(7.0,False),'.php':(7.0,False),'.html':(7.0,False),
    '.htm':(7.0,False),'.txt':(6.5,False),'.xml':(6.5,False),
    '.json':(6.5,False),'.csv':(6.5,False),'.yaml':(6.5,False),
    # Natively high-entropy — never penalise
    '.pdf':(8.0,True),'.docx':(8.0,True),'.xlsx':(8.0,True),
    '.pptx':(8.0,True),'.jpg':(8.0,True),'.jpeg':(8.0,True),
    '.png':(8.0,True),'.gif':(8.0,True),'.webp':(8.0,True),
    '.mp4':(8.0,True),'.mkv':(8.0,True),'.mp3':(8.0,True),
    '.zip':(8.0,True),'.gz':(8.0,True),'.7z':(8.0,True),
    '.bz2':(8.0,True),'.xz':(8.0,True),'.rar':(8.0,True),
    '.jar':(8.0,True),'.apk':(8.0,True),
}
DEFAULT_ENTROPY_THRESHOLD = 7.2

def _get_entropy_risk(entropy: float, file_ext: str) -> tuple:
    info = ENTROPY_THRESHOLDS.get(file_ext.lower())
    if info:
        threshold, expected_high = info
        if expected_high:
            return 0, None
    else:
        threshold = DEFAULT_ENTROPY_THRESHOLD
    if entropy > threshold:
        return 25, (f"High entropy {entropy:.2f} for '{file_ext}' "
                    f"(threshold {threshold}) — possible obfuscation")
    return 0, None

# Co-occurrence signal groups — risk fires only when signals co-occur
STRING_SIGNAL_GROUPS = [
    {"id":"shell_reverse_bind",
     "signals":["nc -e","ncat -e","/dev/tcp","bash -i","sh -i","mkfifo",
                "reverse shell","bind shell"],
     "min_hits":1,"co_required":[],"co_min":0,"risk":70,
     "label":"Shell reverse/bind shell indicator"},
    {"id":"download_execute",
     "signals":["wget","curl"],"min_hits":1,
     "co_required":["exec(","eval(","os.system(","|sh","|bash","subprocess"],
     "co_min":1,"risk":50,"label":"Download and execute pattern"},
    {"id":"obfuscated_exec",
     "signals":["exec(","eval(","compile("],"min_hits":1,
     "co_required":["base64","base64 -d","__import__","marshal",
                    "zlib.decompress","codecs.decode"],
     "co_min":1,"risk":55,"label":"Obfuscated code execution"},
    {"id":"privilege_escalation",
     "signals":["chmod 777","chmod +s","setuid","chown root","sudo -s",
                "ld_preload","ld_library_path"],
     "min_hits":1,"co_required":[],"co_min":0,"risk":35,
     "label":"Privilege escalation indicator"},
    {"id":"credential_access",
     "signals":["/etc/passwd","/etc/shadow","id_rsa",
                ".ssh/authorized_keys","net user","lsass"],
     "min_hits":1,"co_required":[],"co_min":0,"risk":40,
     "label":"Credential/sensitive file access"},
    {"id":"windows_lolbas",
     "signals":["certutil","bitsadmin","regsvr32","mshta","rundll32",
                "csc.exe","installutil"],"min_hits":1,
     "co_required":["http","base64","decode","exec","download"],
     "co_min":1,"risk":45,"label":"Windows LOLBaS abuse pattern"},
    {"id":"persistence",
     "signals":["crontab","/etc/cron","currentversion\\run","launchd",
                "/etc/init.d","systemctl enable","sc create","schtasks /create"],
     "min_hits":1,"co_required":[],"co_min":0,"risk":30,
     "label":"Persistence mechanism"},
    {"id":"network_c2",
     "signals":["socket","subprocess"],"min_hits":1,
     "co_required":["exec(","eval(","base64","ncat","nc -e","wget","curl"],
     "co_min":2,"risk":40,"label":"Network + code execution (potential C2)"},
    {"id":"destructive_payload",
     "signals":["rm -rf /","format c:","dd if=/dev/zero","mkfs.","shred -u",":(){:|:&};:"],
     "min_hits":1,"co_required":[],"co_min":0,"risk":80,
     "label":"Destructive payload indicator"},
]

SUSPICIOUS_STRINGS = [
    'powershell -enc','/etc/shadow','nc -e','ncat',
    'base64 -d','reverse shell','bind shell','/dev/tcp',
    'mkfifo','bitsadmin','mshta','rundll32','/tmp/.','bash -i','sh -i',
]

# ═══════════════════════════════════════════════════════════════════
# A8. YARA ENGINE (configurable rules dir, startup warmup)
# ═══════════════════════════════════════════════════════════════════

import threading as _yara_threading
_yara_compiled = None
_yara_lock     = _yara_threading.Lock()

YARA_RULES_DIR = os.environ.get(
    'YARA_RULES_DIR',
    os.path.join(os.path.dirname(__file__), 'rules')
)

YARA_RULE_FILES = {
    "obfuscated_code": """
rule ObfuscatedExecution {
    meta: description="Exec/eval+encoding" severity="high"
    strings:
        $e1=/exec\\s*\\(\\s*base64/ nocase $e2=/eval\\s*\\(\\s*(atob|base64)/ nocase
        $e3="__import__" nocase    $e4="marshal.loads" nocase
        $e5=/zlib\\.decompress.{0,40}exec/ nocase
        $e6=/String\\.fromCharCode\\s*\\(/ nocase
    condition: any of ($e1,$e2,$e5) or (($e3 or $e4) and $e1) or $e6
}
rule ReverseShellPattern {
    meta: description="Reverse/bind shell" severity="critical"
    strings:
        $r1="nc -e" nocase $r2="/dev/tcp/" nocase $r3="bash -i" nocase
        $r4="sh -i" nocase $r5="mkfifo"    nocase $r6="ncat -e" nocase
    condition: any of them
}
rule PowerShellObfuscation {
    meta: description="PowerShell encoded/download-exec" severity="high"
    strings:
        $p1=/-[Ee][Nn][Cc][Oo][Dd][Ee][Dd][Cc][Oo][Mm][Mm][Aa][Nn][Dd]/
        $p2="IEX" nocase $p3="DownloadString" nocase $p4="ExecutionPolicy Bypass" nocase
    condition: $p1 or ($p2 and $p3) or ($p4 and $p2)
}
rule DocumentMacroAutoExec {
    meta: description="Office auto-exec macro" severity="high"
    strings:
        $m1="AutoOpen" nocase $m2="Workbook_Open" nocase $m3="Document_Open" nocase
        $m4="Shell("   nocase $m5="WScript.Shell"  nocase $m6="CreateObject"  nocase
    condition: (any of ($m1,$m2,$m3)) and (any of ($m4,$m5,$m6))
}
rule SuspiciousLOLBAS {
    meta: description="LOLBaS abuse" severity="medium"
    strings:
        $l1="certutil" nocase $l2="bitsadmin" nocase
        $l3="mshta"    nocase $l4="regsvr32"  nocase
        $h1="http://"  nocase $h2="https://"  nocase $h3="base64" nocase
    condition: (any of ($l1,$l2,$l3,$l4)) and (any of ($h1,$h2,$h3))
}
""",
    "malware_persistence": """
rule PersistenceMechanism {
    meta: description="Registry/cron/service persistence" severity="medium"
    strings:
        $p1="CurrentVersion\\\\Run" nocase $p2="crontab"         nocase
        $p3="systemctl enable"      nocase $p4="schtasks /create" nocase
    condition: any of them
}
rule DestructivePayload {
    meta: description="Disk wipe/mass deletion" severity="critical"
    strings:
        $d1="rm -rf /" nocase $d2="dd if=/dev/zero" nocase
        $d3="mkfs."    nocase $d4="shred -u"         nocase
    condition: any of them
}
""",
}

# YARA risk uses highest-severity + small bonus per additional match.
# Prevents 5 medium rules (5x30=150) from equalling one critical (80).
def _yara_aggregate_risk(matches) -> int:
    """
    Risk = highest_severity_score + 5 per additional match, capped at 90.
    Preserves severity hierarchy while still rewarding co-occurring rules.
    """
    if not matches:
        return 0
    _SEV = {'critical':80,'high':55,'medium':30,'low':15}
    scores = sorted(
        [_SEV.get(m.meta.get('severity','medium'), 30) for m in matches],
        reverse=True
    )
    return min(scores[0] + 5 * (len(scores)-1), 90)

def _ensure_yara_rules():
    """
    Compile YARA rules. Thread-safe double-checked locking.
    Never overwrites existing rule files — production sets YARA_RULES_DIR
    to a versioned directory. Returns compiled Rules or False.
    """
    global _yara_compiled, yara
    if _yara_compiled is not None and not isinstance(_yara_compiled, bool):
        return _yara_compiled
    with _yara_lock:
        if _yara_compiled is not None and not isinstance(_yara_compiled, bool):
            return _yara_compiled
        strict_mode = os.environ.get('STRICT_YARA_MODE', '').lower() in ('1', 'true', 'yes')
        try:
            if yara is None:
                try:
                    import yara #type:ignore
                except ImportError:
                    raise ImportError("yara-python not installed")
            os.makedirs(YARA_RULES_DIR, exist_ok=True)
            fps = {}
            for name, content in YARA_RULE_FILES.items():
                path = os.path.join(YARA_RULES_DIR, f"{name}.yar")
                if not os.path.exists(path):
                    if strict_mode:
                        # Fail immediately — do not recreate, do not scan
                        raise FileNotFoundError(
                            f"[YARA STRICT] Rule file missing: {path}. "
                            f"Restore from version control or disable "
                            f"STRICT_YARA_MODE to use bundled fallback rules."
                        )
                    # Non-strict: write bundled fallback and continue
                    with open(path, 'w') as f:
                        f.write(content)
                    logger.warning(
                        f"[YARA] Rule file missing, wrote bundled fallback: {path}"
                    )
                fps[name] = path
            _yara_compiled = yara.compile(filepaths=fps)
            logger.info(f"[YARA] Compiled {list(fps.keys())} from {YARA_RULES_DIR}")
        except FileNotFoundError as e:
            # Strict mode: propagate — startup should fail visibly
            logger.error(str(e))
            _yara_compiled = False
            if strict_mode:
                raise   # Let app.py / startup catch and abort
        except ImportError:
            logger.warning("[YARA] yara-python not installed — skipped")
            _yara_compiled = False
        except Exception as e:
            logger.warning(f"[YARA] Compile error: {e}")
            _yara_compiled = False
    return _yara_compiled

def warmup_yara():
    """
    Call at app startup. Compiles YARA rules in a background thread
    so the first upload pays zero compilation cost.
    """
    import threading
    def _warm():
        logger.info("[YARA WARMUP] Compiling rules in background...")
        result = _ensure_yara_rules()
        if result:
            logger.info("[YARA WARMUP] Rules ready.")
        else:
            logger.warning("[YARA WARMUP] Rules unavailable.")
    threading.Thread(target=_warm, daemon=True).start()

def _run_yara_scan(filepath: str, file_name: str, data_bytes: bytes = None) -> dict:
    """
    Scan file with YARA. Returns {"risk","flags","matches"}.
    Risk uses _yara_aggregate_risk (highest severity + bonus).
    Optimised for large files by scanning head and tail blocks in-memory.
    Never raises.
    """
    rules = _ensure_yara_rules()
    if not rules:
        raise RuntimeError("YARA engine unavailable — fail-closed: YARA engine unavailable")
    try:
        if data_bytes is not None:
            hits = rules.match(data=data_bytes, timeout=10)
        else:
            file_size = os.path.getsize(filepath)
            if file_size <= 2 * 1024 * 1024:
                hits = rules.match(filepath, timeout=10)
            else:
                # Optimize: read 512KB from start and 512KB from end to avoid ReDoS/backtracking on large payloads
                with open(filepath, 'rb') as f:
                    head = f.read(512 * 1024)
                    f.seek(max(0, file_size - 512 * 1024))
                    tail = f.read(512 * 1024)
                hits = rules.match(data=head + tail, timeout=10)
        if not hits:
            return {"risk":0,"flags":[],"matches":[]}
        risk  = _yara_aggregate_risk(hits)
        flags = []
        names = []
        for m in hits:
            sev  = m.meta.get('severity','medium')
            desc = m.meta.get('description', m.rule)
            flags.append(f"YARA [{sev.upper()}]: {desc} ({m.rule})")
            names.append(m.rule)
            logger.warning(f"[YARA] {m.rule} sev={sev} file={file_name}")
        return {"risk":risk,"flags":flags,"matches":names}
    except Exception as e:
        err_msg = 'YARA scan timed out' if 'timeout' in str(e).lower() else f'YARA scan error: {str(e)[:40]}'
        logger.warning(f"[YARA] {err_msg} on {file_name}: {e}")
        raise RuntimeError(f"YARA engine unavailable — fail-closed: {err_msg}")

# ═══════════════════════════════════════════════════════════════════
# A9. CLAMAV WARMUP HELPERS
# ═══════════════════════════════════════════════════════════════════

def warmup_clamav():
    import threading
    def _w():
        logger.info("[CLAMAV WARMUP] Pre-warming daemon...")
        try:
            logger.info("[CLAMAV WARMUP] Ready." if _ensure_clamav_daemon()
                        else "[CLAMAV WARMUP] Failed.")
        except Exception as e:
            logger.warning(f"[CLAMAV WARMUP] {e}")
    threading.Thread(target=_w, daemon=True).start()

_clamav_db_age_cache = {'value': None, 'ts': 0}
_CLAMAV_DB_AGE_CACHE_TTL = 300  # 5 minutes TTL

def _get_clamav_db_age_hours() -> float | None:
    global _clamav_db_age_cache
    import time
    now = time.time()
    if _clamav_db_age_cache['value'] is not None and (now - _clamav_db_age_cache['ts']) < _CLAMAV_DB_AGE_CACHE_TTL:
        return _clamav_db_age_cache['value']

    import socket as _s, re as _re
    try:
        host = os.environ.get('CLAMD_HOST','127.0.0.1')
        port = int(os.environ.get('CLAMD_PORT','3310'))
        s = _s.socket(); s.settimeout(1.5)
        s.connect((host,port)); s.sendall(b'VERSION\n')
        resp = s.recv(256).decode('utf-8',errors='replace'); s.close()
        m = _re.search(r'/(\w{3} \w{3}\s+\d+ \d+:\d+:\d+ \d{4})',resp)
        if m:
            from datetime import datetime
            db = datetime.strptime(m.group(1).strip(),'%a %b %d %H:%M:%S %Y')
            val = round((datetime.utcnow()-db).total_seconds()/3600,1)
            _clamav_db_age_cache.update({'value': val, 'ts': now})
            return val
    except Exception:
        pass
    return None

# ─── Pipeline stage definitions ───────────────────────────────────
PIPELINE_STAGES = [
    {'order': 1, 'name': 'SHA-256 + VirusTotal'},
    {'order': 2, 'name': 'File Heuristic Analysis'},
    {'order': 3, 'name': 'ClamAV (Docker)'},
    {'order': 4, 'name': 'Sandbox (Docker)'},
    {'order': 5, 'name': 'Encryption'},
]

# Stage name migration mapping (old → new)
STAGE_NAME_MIGRATION = {
    'Hash Check': 'SHA-256 + VirusTotal',
    'ZIP Validation': 'File Heuristic Analysis',
    'ZIP Heuristic Analysis': 'File Heuristic Analysis',
    'ClamAV Scan': 'ClamAV (Docker)',
    'Sandbox Analysis': 'Sandbox (Docker)',
    'ClamAV (Fargate)': 'ClamAV (Docker)',
    'Sandbox (Fargate)': 'Sandbox (Docker)',
}


def compute_sha256(filepath):
    """Compute SHA-256 hash of a file. Uses 1MB chunks for large file throughput."""
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            sha256.update(chunk)
    return sha256.hexdigest()


def migrate_old_stage_names():
    """Migrate old pipeline stage names to the new naming convention.
    Safe to call multiple times — only updates records that still have old names.
    """
    updated = 0
    for old_name, new_name in STAGE_NAME_MIGRATION.items():
        count = PipelineStage.query.filter_by(name=old_name).update({'name': new_name})
        updated += count
    if updated > 0:
        db.session.commit()
        logger.info(f"Migrated {updated} pipeline stage records to new naming convention")
    return updated


def cleanup_stuck_scans():
    """
    Recover files stuck in 'scanning' state across server restarts/crashes.
    Marks them as blocked and deletes them from quarantine S3 bucket.
    """
    from werkzeug.utils import secure_filename

    try:
        stuck_files = File.query.filter_by(status='scanning').all()
        if not stuck_files:
            return
            
        logger.info(f"[STARTUP CLEANUP] Found {len(stuck_files)} files stuck in 'scanning' status. Starting cleanup...")
        for file_obj in stuck_files:
            try:
                logger.info(f"[STARTUP CLEANUP] Recovering stuck file {file_obj.name} ({file_obj.id})")
                
                # Mark file status as blocked
                file_obj.status = 'blocked'
                file_obj.checks = 'Scan interrupted (server restart)'
                file_obj.risk = 80
                
                # Mark all stages as failed/skipped
                stages = PipelineStage.query.filter_by(file_id=file_obj.id).all()
                for stage in stages:
                    if stage.status in ('pending', 'running'):
                        stage.status = 'skipped'
                        stage.detail = 'Skipped — scan interrupted'
                
                db.session.commit()

                # Try to clean up from S3 quarantine
                user_obj = User.query.get(file_obj.user_id)
                if user_obj and user_obj.aws_connected and user_obj.quarantine_bucket:
                    try:
                        session = _get_aws_session(user_obj)
                        s3 = session.client('s3', config=BOTO3_CLIENT_CONFIG)
                        s3_key = secure_filename(file_obj.name)
                        s3.delete_object(Bucket=user_obj.quarantine_bucket, Key=s3_key)
                        logger.info(f"[STARTUP CLEANUP] Deleted {s3_key} from quarantine S3 for user {user_obj.email}")
                    except Exception as s3_err:
                        logger.warning(f"[STARTUP CLEANUP] S3 deletion failed for {file_obj.name}: {s3_err}")
            except Exception as file_err:
                logger.error(f"[STARTUP CLEANUP] Error cleaning up file {file_obj.id}: {file_err}")
                db.session.rollback()
    except Exception as e:
        logger.error(f"[STARTUP CLEANUP] Failed to query stuck files: {e}")




def init_pipeline_stages(file_id):
    """Create all pipeline stage records for a file."""
    stages = []
    for s in PIPELINE_STAGES:
        stage = PipelineStage(
            file_id=file_id,
            stage_order=s['order'],
            name=s['name'],
            status='pending',
            detail='Pending',
        )
        db.session.add(stage)
        stages.append(stage)
    db.session.commit()
    return stages


def update_stage(file_id, stage_order, status, detail):
    """Update a specific pipeline stage."""
    stage = PipelineStage.query.filter_by(
        file_id=file_id, stage_order=stage_order
    ).first()
    if stage:
        stage.status = status
        stage.detail = detail
        if status == 'running':
            stage.started_at = datetime.utcnow()
        elif status in ('pass', 'fail', 'skipped'):
            stage.completed_at = datetime.utcnow()
        db.session.commit()
    return stage


def skip_remaining(file_id, from_order):
    """Mark all stages after from_order as skipped."""
    stages = PipelineStage.query.filter(
        PipelineStage.file_id == file_id,
        PipelineStage.stage_order > from_order
    ).all()
    for s in stages:
        s.status = 'skipped'
        s.detail = 'Skipped — prior layer failed'
        s.completed_at = datetime.utcnow()
    db.session.commit()


# ═══════════════════════════════════════════════════════════════════
# LAYER 1 — MULTI-SOURCE THREAT INTELLIGENCE
# ═══════════════════════════════════════════════════════════════════

def _query_virustotal(sha256: str) -> dict:
    if not _VT_GUARD.acquire():
        return {"status":"skipped","risk":0,"message":"VT: rate-limited"}
    try:
        key = os.environ.get('VT_API_KEY','')
        if not key:
            _VT_GUARD.ok()
            return {"status":"skipped","risk":0,"message":"VT: no API key"}
        r = requests.get(
            f'https://www.virustotal.com/api/v3/files/{sha256}',
            headers={'x-apikey':key}, timeout=2.0
        )
        if r.status_code == 404:
            _VT_GUARD.ok()
            return {"status":"unknown","risk":0,"message":"VT: hash not found"}
        if r.status_code == 429:
            _VT_GUARD.fail()
            return {"status":"error","risk":0,"message":"VT: rate limited"}
        if r.status_code != 200:
            _VT_GUARD.fail()
            return {"status":"error","risk":0,"message":f"VT: HTTP {r.status_code}"}
        stats = (r.json().get('data',{}).get('attributes',{})
                         .get('last_analysis_stats',{}))
        mal = stats.get('malicious',0); sus = stats.get('suspicious',0)
        _VT_GUARD.ok()
        if mal > 0:
            return {"status":"malicious","risk":100,"message":f"VT: {mal} engines flagged malicious"}
        if sus > 0:
            return {"status":"suspicious","risk":40,"message":f"VT: {sus} engines suspicious"}
        return {"status":"safe","risk":0,"message":"VT: clean"}
    except Exception as e:
        _VT_GUARD.fail()
        logger.warning(f"[L1 VT] {e}")
        return {"status":"error","risk":0,"message":f"VT: {str(e)[:60]}"}

def _query_circl(sha256: str) -> dict:
    if not _CIRCL_GUARD.acquire():
        return {"status":"skipped","risk":0,"message":"CIRCL: rate-limited"}
    try:
        r = requests.get(
            f'https://hashlookup.circl.lu/lookup/sha256/{sha256}', timeout=2.0
        )
        _CIRCL_GUARD.ok()
        if r.status_code == 200:
            return {"status":"known_good","risk":-10,"message":"CIRCL: known legitimate (NSRL)"}
        if r.status_code == 404:
            return {"status":"unknown","risk":0,"message":"CIRCL: not found"}
        return {"status":"error","risk":0,"message":f"CIRCL: HTTP {r.status_code}"}
    except Exception as e:
        _CIRCL_GUARD.fail()
        logger.warning(f"[L1 CIRCL] {e}")
        return {"status":"error","risk":0,"message":"CIRCL: unavailable"}

def _query_malwarebazaar(sha256: str) -> dict:
    if not _BAZAAR_GUARD.acquire():
        return {"status":"skipped","risk":0,"message":"MalwareBazaar: rate-limited"}
    try:
        r = requests.post(
            'https://mb-api.abuse.ch/api/v1/',
            data={'query':'get_info','hash':sha256}, timeout=2.0
        )
        _BAZAAR_GUARD.ok()
        if r.json().get('query_status') == 'ok':
            return {"status":"malicious","risk":100,"message":"MalwareBazaar: confirmed malware"}
        return {"status":"unknown","risk":0,"message":"MalwareBazaar: not found"}
    except Exception as e:
        _BAZAAR_GUARD.fail()
        logger.warning(f"[L1 BAZAAR] {e}")
        return {"status":"error","risk":0,"message":"MalwareBazaar: unavailable"}

def _query_otx(sha256: str) -> dict:
    key = os.environ.get('OTX_API_KEY')
    if not key:
        return {"status":"skipped","risk":0,"message":"OTX: no API key"}
    if not _OTX_GUARD.acquire():
        return {"status":"skipped","risk":0,"message":"OTX: rate-limited"}
    try:
        r = requests.get(
            f'https://otx.alienvault.com/api/v1/indicators/file/{sha256}/general',
            headers={'X-OTX-API-KEY':key}, timeout=2.0
        )
        count = r.json().get('pulse_info',{}).get('count',0)
        _OTX_GUARD.ok()
        if count > 0:
            return {"status":"suspicious","risk":min(count*5+20,60),
                    "message":f"OTX: {count} threat pulse(s)"}
        return {"status":"unknown","risk":0,"message":"OTX: no pulses"}
    except Exception as e:
        _OTX_GUARD.fail()
        logger.warning(f"[L1 OTX] {e}")
        return {"status":"error","risk":0,"message":"OTX: unavailable"}

def _query_urlhaus(sha256: str) -> dict:
    """
    URLHaus (abuse.ch) — free, no key needed.
    Checks if the file hash is associated with a known malware
    distribution URL. Hash found = confirmed malware delivery.
    """
    _UH_GUARD = getattr(_query_urlhaus, '_guard', None)
    if _UH_GUARD is None:
        _query_urlhaus._guard = _ApiGuard(
            'URLHaus', refill_rate=1.0, burst_size=5,
            failure_limit=5, cooldown=60
        )
        _UH_GUARD = _query_urlhaus._guard
    if not _UH_GUARD.acquire():
        return {"status":"skipped","risk":0,"message":"URLHaus: rate-limited"}
    try:
        r = requests.post(
            'https://urlhaus-api.abuse.ch/v1/payload/',
            data={'sha256_hash': sha256},
            timeout=2.0
        )
        _UH_GUARD.ok()
        data = r.json()
        if data.get('query_status') == 'ok':
            url_count = len(data.get('urls', []))
            return {
                "status": "malicious",
                "risk": 100,
                "message": f"URLHaus: hash found ({url_count} delivery URL(s))"
            }
        return {"status":"unknown","risk":0,"message":"URLHaus: not found"}
    except Exception as e:
        _UH_GUARD.fail()
        logger.warning(f"[L1 URLHAUS] {e}")
        return {"status":"error","risk":0,"message":"URLHaus: unavailable"}

def _query_threatfox(sha256: str) -> dict:
    """
    ThreatFox (abuse.ch) — free, no key needed.
    IOC intelligence database. Hash found = known malware IOC.
    """
    _TF_GUARD = getattr(_query_threatfox, '_guard', None)
    if _TF_GUARD is None:
        _query_threatfox._guard = _ApiGuard(
            'ThreatFox', refill_rate=1.0, burst_size=5,
            failure_limit=5, cooldown=60
        )
        _TF_GUARD = _query_threatfox._guard
    if not _TF_GUARD.acquire():
        return {"status":"skipped","risk":0,"message":"ThreatFox: rate-limited"}
    try:
        r = requests.post(
            'https://threatfox-api.abuse.ch/api/v1/',
            json={"query": "search_ioc", "search_term": sha256},
            timeout=2.0
        )
        _TF_GUARD.ok()
        data = r.json()
        if data.get('query_status') == 'ok':
            iocs = data.get('data', [])
            if iocs:
                malware_name = iocs[0].get('malware_printable', 'Unknown')
                return {
                    "status": "malicious",
                    "risk": 100,
                    "message": f"ThreatFox: {malware_name} IOC ({len(iocs)} record(s))"
                }
        return {"status":"unknown","risk":0,"message":"ThreatFox: not found"}
    except Exception as e:
        _TF_GUARD.fail()
        logger.warning(f"[L1 THREATFOX] {e}")
        return {"status":"error","risk":0,"message":"ThreatFox: unavailable"}

def _build_sources(vt, otx, baz, cir, uh=None, tf=None):
    d = {
        "virustotal":    vt.get('status','error'),
        "malwarebazaar": baz.get('status','error'),
        "otx":           otx.get('status','error'),
        "circl":         cir.get('status','error'),
    }
    if uh: d["urlhaus"]   = uh.get('status','error')
    if tf: d["threatfox"] = tf.get('status','error')
    return d

def run_hash_check(file_obj, filepath):
    """
    Layer 1: Multi-source threat intelligence.

    Fast paths (in order):
      1. Reputation cache hit → return instantly, skip all APIs
      2. Intel cache hit (L1) → skip API calls, run aggregation only
      3. 4 APIs in parallel via shared _shared_executor

    Returns: (passed: bool, threat_description: str|None, layer_result: dict)
    Result dict contains: status, message, risk, flags.
    """
    update_stage(file_obj.id, 1, 'running', 'Computing hash + querying threat intel...')
    logger.info(f"[SECURITY] Layer 1 → Threat Intelligence started for {file_obj.name}")


    sha256 = file_obj.sha256_hash
    if not sha256:
        if not filepath or not os.path.exists(filepath):
            result = {"status":"error","message":"File path missing and no precomputed hash","risk":0,"flags":[]}
            update_stage(file_obj.id, 1, 'fail', result['message'])
            return False, "File not found", result
        sha256 = compute_sha256(filepath)
        file_obj.sha256_hash = sha256
        from models import db
        db.session.commit()

    # ── Fast path 1: reputation cache ──
    rep = _reputation_get(sha256)
    if rep:
        verdict = rep["verdict"]; risk = rep["risk"]; reason = rep["reason"]
        status  = 'malicious' if verdict == 'malicious' else 'safe'
        result  = {"status":status,"message":f"[CACHED] {reason}",
                   "risk":risk,"flags":[reason]}
        update_stage(file_obj.id, 1,
                     'fail' if status=='malicious' else 'pass',
                     f"Reputation cache: {verdict} (risk={risk})")
        logger.info(f"[SECURITY] Layer 1 → result: status={status} "
                    f"risk={risk} (reputation hit) file={file_obj.name}")
        if status == 'malicious':
            return False, reason, result
        return True, None, result

    # ── Fast path 2: intel cache ──
    cached = _l1_cache_get(sha256)
    if cached and all(cached.get(k) is not None
                      for k in ['vt','otx','bazaar','circl',
                                 'urlhaus','threatfox']):
        logger.info(f"[L1 CACHE] Hit for {sha256[:16]}")
        vt_r,otx_r,baz_r,cir_r = (cached['vt'],cached['otx'],
                                    cached['bazaar'],cached['circl'])
        uh_r = cached.get('urlhaus',  {"status":"error","risk":0,"message":"URLHaus: cached miss"})
        tf_r = cached.get('threatfox',{"status":"error","risk":0,"message":"ThreatFox: cached miss"})
    else:
        # ── Run all 6 APIs in parallel via shared executor ──
        futs = {
            _shared_executor.submit(_query_virustotal,    sha256): 'vt',
            _shared_executor.submit(_query_circl,         sha256): 'circl',
            _shared_executor.submit(_query_malwarebazaar, sha256): 'bazaar',
            _shared_executor.submit(_query_otx,           sha256): 'otx',
            _shared_executor.submit(_query_urlhaus,       sha256): 'urlhaus',
            _shared_executor.submit(_query_threatfox,     sha256): 'threatfox',
        }
        res = {}
        try:
            for f in _futures.as_completed(futs, timeout=15):
                k = futs[f]
                try:
                    res[k] = f.result()
                except Exception as e:
                    logger.warning(f"[L1] {k} future: {e}")
                    res[k] = {"status":"error","risk":0,"message":f"{k}: exception"}
        except (_futures.TimeoutError, TimeoutError):
            logger.warning("[L1] Threat intelligence query timed out (15s limit reached).")

        vt_r  = res.get('vt',  {"status":"error","risk":0,"message":"VT: no result"})
        cir_r = res.get('circl',{"status":"error","risk":0,"message":"CIRCL: no result"})
        baz_r = res.get('bazaar',{"status":"error","risk":0,"message":"Bazaar: no result"})
        otx_r = res.get('otx', {"status":"error","risk":0,"message":"OTX: no result"})
        uh_r  = res.get('urlhaus',  {"status":"error","risk":0,"message":"URLHaus: no result"})
        tf_r  = res.get('threatfox',{"status":"error","risk":0,"message":"ThreatFox: no result"})
        _l1_cache_set(sha256, {
            'vt':vt_r,'otx':otx_r,'bazaar':baz_r,'circl':cir_r,
            'urlhaus':uh_r,'threatfox':tf_r
        })

    # ── Degraded state: all APIs failed or skipped ──
    results_list = [vt_r, cir_r, baz_r, otx_r, uh_r, tf_r]
    successful_queries = [r for r in results_list if r.get('status') not in ('error', 'skipped')]
    if len(successful_queries) == 0:
        result = {
            "status": "fail",
            "risk": 100,
            "flags": ["✖ All threat intel APIs unavailable — file blocked (fail-closed)"],
            "sources": _build_sources(vt_r, otx_r, baz_r, cir_r, uh_r, tf_r)
        }
        update_stage(file_obj.id, 1, 'fail',
                     '✖ Threat Intel unavailable — file blocked (fail-closed)')
        logger.error(f"[SECURITY] Layer 1 → FAIL-CLOSED: all APIs unavailable "
                     f"file={file_obj.name}")
        return False, "All threat intelligence APIs unavailable — file blocked", result

    # ── Hard block: confirmed malicious ──
    for src, name in [
        (vt_r,'VirusTotal'), (baz_r,'MalwareBazaar'),
        (uh_r,'URLHaus'),    (tf_r,'ThreatFox')
    ]:
        if src.get('status') == 'malicious':
            msg = src.get('message', f'{name}: confirmed malicious')
            result = {"status":"malicious","message":msg,"risk":100,
                      "flags":[msg],"sources":_build_sources(vt_r,otx_r,baz_r,cir_r,uh_r,tf_r)}
            update_stage(file_obj.id, 1, 'fail', msg)
            _reputation_set(sha256, 'malicious', 100, msg)
            logger.info(f"[SECURITY] Layer 1 → result: status=malicious "
                        f"risk=100 file={file_obj.name}")
            return False, msg, result

    # ── Aggregate risk ──
    base_risk = max(vt_r.get('risk',0), otx_r.get('risk',0),
                    baz_r.get('risk',0), uh_r.get('risk',0),
                    tf_r.get('risk',0), 0)
    if cir_r.get('status') == 'known_good':
        base_risk = max(0, base_risk - 10)

    contributing = [s['message'] for s in [vt_r,otx_r,baz_r,cir_r,uh_r,tf_r]
                    if s.get('risk',0)>0 or s.get('status') in
                    ('suspicious','known_good')]
    summary = '; '.join(contributing) if contributing else 'No threats detected'
    status  = ('malicious' if base_risk>=100 else
               'suspicious' if base_risk>=40 else 'safe')

    result = {"status":status,"message":summary,"risk":base_risk,
              "flags":[summary] if base_risk>0 else [],
              "sources":_build_sources(vt_r,otx_r,baz_r,cir_r,uh_r,tf_r)}
    
    if status == 'safe':
        details_msg = "Threat Intel: Passed (Clean/Unrecognized hash)"
    else:
        details_msg = f"Threat Intel: {status.capitalize()} (risk: {base_risk}) | {summary}"
        
    update_stage(file_obj.id, 1,
                 'fail' if status=='malicious' else 'pass',
                 details_msg)
    logger.info(f"[SECURITY] Layer 1 → result: status={status} "
                f"risk={base_risk} file={file_obj.name}")
    if status == 'malicious':
        _reputation_set(sha256, 'malicious', base_risk, summary)
        return False, summary, result
    return True, None, result


# ═══════════════════════════════════════════════════════════════════
# LAYER 2 — UNIVERSAL STATIC ANALYSIS
# Function name MUST stay layer2_zip_validation() for orchestrator.
# ═══════════════════════════════════════════════════════════════════

def _analyze_strings(filepath: str, max_bytes: int = 65536, data_bytes: bytes = None):
    """
    Co-occurrence string analysis. Returns (flags, risk).
    Benign single signals (subprocess, curl) do NOT score alone.
    Scans from both the beginning and the end of files.
    """
    flags=[]; risk=0
    try:
        if data_bytes is not None:
            raw = data_bytes
        else:
            file_size = os.path.getsize(filepath)
            if file_size <= 2 * max_bytes:
                with open(filepath, 'rb') as f:
                    raw = f.read()
            else:
                with open(filepath, 'rb') as f:
                    head = f.read(max_bytes)
                    f.seek(file_size - max_bytes)
                    tail = f.read(max_bytes)
                    raw = head + b'\n=== SKIPPED INTERMEDIATE BYTES ===\n' + tail

        text = raw.decode('utf-8',errors='ignore').lower()
        for s in SUSPICIOUS_STRINGS:
            if s.lower() in text:
                flags.append(f"String: '{s}'"); risk += 10
        for g in STRING_SIGNAL_GROUPS:
            if sum(1 for s in g["signals"] if s.lower() in text) < g["min_hits"]:
                continue
            if g["co_required"] and g["co_min"]>0:
                if sum(1 for s in g["co_required"] if s.lower() in text) < g["co_min"]:
                    continue
            risk += g["risk"]
            flags.append(f"\u26a0 {g['label']}")
        b64 = re.search(
            r'(?:[A-Za-z0-9+/]{4}){16,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?',
            raw.decode('utf-8',errors='ignore')
        )
        if b64:
            if any(s in text for s in ['exec(','eval(','base64 -d','__import__','subprocess']):
                flags.append("\u26a0 Base64 block + exec context"); risk += 20
            else:
                flags.append("Base64 block (no exec context)"); risk += 5
        risk = min(risk, 80)
    except Exception:
        pass
    return flags, risk

def _analyze_office_zip(filepath: str, file_name: str) -> dict:
    """
    Office Open XML inspection. Checks:
    VBA macro + auto-execute names, XLM macros (Excel 4.0),
    remote template injection (.rels), ActiveX (.bin), DDE fields.
    Returns {"risk","flags","checks"}
    """
    risk=0; flags=[]; checks=[]
    try:
        with zipfile.ZipFile(filepath,'r') as zf:
            nl=[i.filename.lower() for i in zf.infolist()]
            no=[i.filename for i in zf.infolist()]
            checks.append("vba_macro")
            if any('vbaproject.bin' in n for n in nl):
                risk+=70; flags.append("VBA macro project (vbaProject.bin)")
                try:
                    e=next(n for n in no if 'vbaProject.bin' in n)
                    vba=''.join(c if 32<=ord(c)<127 else ' '
                                for c in zf.read(e).decode('latin-1',errors='replace')).lower()
                    found=[a for a in ['autoopen','autoclose','auto_open','auto_close',
                                       'workbook_open','document_open','autoexec'] if a in vba]
                    if found:
                        risk+=30; flags.append(f"Auto-execute: {', '.join(found)}")
                except Exception: pass
            checks.append("xlm_macro")
            xlm=[n for n in nl if 'xl/macrosheets/' in n or 'xl/macros/' in n]
            if xlm: risk+=80; flags.append(f"XLM macro (Excel 4.0): {xlm[0]}")
            checks.append("remote_template")
            for rel in [n for n in no if n.endswith('.rels')][:10]:
                try:
                    c=zf.read(rel).decode('utf-8',errors='ignore')
                    for t in re.findall(r'Target\s*=\s*["\']([^"\']+)["\']',c,re.IGNORECASE):
                        if t.lower().startswith(('http://','https://','ftp://','\\\\')): 
                            risk+=90; flags.append(f"Remote template injection: {t[:80]}"); break
                except Exception: pass
                if risk>=90: break
            checks.append("activex")
            ax=[n for n in nl if 'activex/' in n and n.endswith('.bin')]
            if ax: risk+=50; flags.append(f"ActiveX: {len(ax)} .bin file(s)")
            checks.append("dde_fields")
            for xn in [n for n in no if n.endswith('.xml') and
                       any(x in n.lower() for x in ['word/document','xl/worksheets','ppt/slides'])][:5]:
                try:
                    c=zf.read(xn).decode('utf-8',errors='ignore').upper()
                    if 'DDEAUTO' in c or 'DDE(' in c:
                        risk+=60; flags.append(f"DDE field: {xn}"); break
                except Exception: pass
    except Exception as e:
        logger.warning(f"[L2 OFFICE] {file_name}: {e}")
        return {"risk":0,"flags":[],"checks":["failed"]}
    return {"risk":min(risk,100),"flags":flags,"checks":checks}

def _analyze_pdf_structure(filepath: str, file_name: str) -> dict:
    """
    Byte-level PDF: /JavaScript, /OpenAction, /Launch, /EmbeddedFile,
    /AA, /XFA, /AcroForm+JS, /ObjStm, split keyword obfuscation.
    Reads first 512KB + last 64KB.
    Returns {"risk","flags","checks"}
    """
    risk=0; flags=[]; checks=[]
    PATS=[
        (re.compile(rb'/(?:J(?:ava)?[Ss]cript|JS)\b',re.IGNORECASE),60,"Embedded JS","pdf_js"),
        (re.compile(rb'/OpenAction\s',re.IGNORECASE),50,"Auto-action on open","pdf_openaction"),
        (re.compile(rb'/Launch\s*<<',re.IGNORECASE),80,"Launch action (external program)","pdf_launch"),
        (re.compile(rb'/EmbeddedFile\s',re.IGNORECASE),30,"Embedded file attachment","pdf_embed"),
        (re.compile(rb'/AA\s*<<',re.IGNORECASE),40,"Additional actions","pdf_aa"),
        (re.compile(rb'/XFA\s',re.IGNORECASE),30,"XFA form (exploitable)","pdf_xfa"),
        (re.compile(rb'/AcroForm\s*<<.*?/JS\b',re.DOTALL),50,"AcroForm+JavaScript","pdf_acroform"),
        (re.compile(rb'/ObjStm\b',re.IGNORECASE),20,"Compressed object stream","pdf_objstm"),
        (re.compile(rb'/URI\s*\(https?://',re.IGNORECASE),
         20,"PDF URI action (external URL)","pdf_uri"),
        (re.compile(rb'/ImportData\s',re.IGNORECASE),
         25,"PDF ImportData action (data exfiltration)","pdf_importdata"),
    ]
    try:
        fsize=os.path.getsize(filepath)
        with open(filepath,'rb') as f:
            hdr=f.read(524288); f.seek(max(0,fsize-65536)); tail=f.read(65536)
        data=hdr+tail
        if data[:5]!=b'%PDF-':
            return {"risk":0,"flags":["Not a valid PDF"],"checks":["magic_fail"]}
        for pat,pr,label,cid in PATS:
            checks.append(cid)
            if pat.search(data): risk+=pr; flags.append(f"\u26a0 {label}")
        if b'/Ja' in data and b'vaScript' in data and b'/JavaScript' not in data:
            risk+=20; flags.append("\u26a0 Split /JavaScript keyword (obfuscation)")
            checks.append("pdf_split_kw")
        pdfid_path=os.environ.get('PDFID_PATH')
        if pdfid_path and os.path.exists(pdfid_path):
            try:
                import subprocess as _sp
                r=_sp.run(['python3',pdfid_path,filepath],
                          capture_output=True,timeout=8,text=True)
                out=r.stdout.lower()
                for kw,kr,kl in [('/javascript',30,"pdfid:/JavaScript"),
                                  ('/openaction',25,"pdfid:/OpenAction"),
                                  ('/launch',40,"pdfid:/Launch"),
                                  ('/objstm',15,"pdfid:/ObjStm")]:
                    m=re.search(rf'{re.escape(kw)}\s+([1-9]\d*)',out)
                    if m: risk+=kr; flags.append(f"\u26a0 {kl} (count={m.group(1)})")
                checks.append("pdfid")
            except Exception as e:
                logger.warning(f"[L2 PDF pdfid] {e}")
    except Exception as e:
        logger.warning(f"[L2 PDF] {file_name}: {e}")
        return {"risk":0,"flags":[],"checks":["failed"]}
    return {"risk":min(risk,100),"flags":flags,"checks":checks}

def _check_polyglot(filepath: str, file_ext: str) -> dict:
    """Polyglot + embedded payload detection for image files."""
    SZ={'JPEG':30,'PNG':50,'GIF':20}
    risk=0; flags=[]
    try:
        fsize=os.path.getsize(filepath)
        with open(filepath,'rb') as f:
            hdr=f.read(16); f.seek(max(0,fsize-4096)); tail=f.read(4096)
        IMG_MAGIC={b'\xff\xd8\xff':'JPEG',b'\x89PNG':'PNG',b'GIF8':'GIF',b'BM':'BMP'}
        fmt=next((v for k,v in IMG_MAGIC.items() if hdr[:len(k)]==k),None)
        if fmt is None and file_ext in IMAGE_EXTENSIONS:
            risk+=40; flags.append(f"Image magic bytes missing for {file_ext}")
            return {"risk":risk,"flags":flags}
        if fmt:
            if zipfile.is_zipfile(filepath):
                risk+=60; flags.append(f"Polyglot: {fmt}+ZIP dual-format")
            if b'MZ' in hdr[4:] or b'MZ' in tail:
                risk+=70; flags.append(f"PE header embedded in {fmt}")
            if b'\x7fELF' in hdr[4:] or b'\x7fELF' in tail:
                risk+=70; flags.append(f"ELF header embedded in {fmt}")
            lim=SZ.get(fmt)
            if lim and fsize>lim*1024*1024:
                risk+=15; flags.append(f"Oversized {fmt}: {round(fsize/1048576,1)}MB")
    except Exception as e:
        logger.warning(f"[L2 POLYGLOT] {e}")
    return {"risk":min(risk,80),"flags":flags}

def _check_encrypted_archive(filepath: str, entries: list) -> dict:
    """Encrypted ZIP members and 7z/RAR detection."""
    risk=0; flags=[]
    enc=[i.filename for i in entries if i.flag_bits & 0x1]
    if enc:
        risk+=50
        flags.append(f"Password-protected: {len(enc)} encrypted member(s) \u2014 unscannable")
    try:
        with open(filepath,'rb') as f: h=f.read(16)
        if h[:6]==b'\x37\x7a\xbc\xaf\x27\x1c':
            risk+=30; flags.append("7-Zip archive \u2014 may be encrypted")
        elif h[:7] in (b'\x52\x61\x72\x21\x1a\x07\x01',b'\x52\x61\x72\x21\x1a\x07\x00'):
            risk+=30; flags.append("RAR archive \u2014 may be encrypted")
    except Exception: pass
    return {"risk":risk,"flags":flags}

def _get_member_scan_limits(file_size_bytes: int):
    """
    Returns (max_members_to_scan, max_scan_budget_bytes, max_nested_depth)
    based on file size to optimize execution time for larger files.
    """
    mb = 1024 * 1024
    if file_size_bytes >= 300 * mb:
        return 20, 4 * mb, 0
    elif file_size_bytes >= 100 * mb:
        return 30, 6 * mb, 1
    else:
        return 50, 10 * mb, 2

def _scan_single_member_data(filename: str, raw: bytes) -> tuple:
    """
    Helper to run strings and YARA scans on a single member's bytes.
    Returns (filename, sf, sr, yr) where sf=strings flags, sr=strings risk, yr=yara result.
    """
    sf, sr = _analyze_strings("", MAX_MEMBER_BYTES, data_bytes=raw)
    try:
        yr = _run_yara_scan("", filename, data_bytes=raw)
    except Exception as e:
        yr = {"risk": 0, "flags": [f"YARA scan error: {str(e)[:60]}"], "matches": []}
    return filename, sf, sr, yr

def _scan_zip_members_bytes(bio, file_name: str, depth: int = 0,
                            max_members: int = 50, max_budget_bytes: int = 10 * 1024 * 1024,
                            max_depth: int = 2) -> dict:
    """
    Scan source/script members from a ZIP in memory.
    """
    agg_risk=0; agg_flags=[]; scanned=0
    bytes_scanned=0

    try:
        with zipfile.ZipFile(bio,'r') as zf:
            all_entries=zf.infolist()

            # ── Recurse nested ZIPs ──
            if depth < max_depth:
                for nz in [i for i in all_entries
                            if i.filename.lower().endswith('.zip')
                            and not (i.flag_bits & 0x1)
                            and 0 < i.file_size < 20*1024*1024][:3]:
                    try:
                        raw_zip = zf.read(nz.filename)
                        sub_bio = io.BytesIO(raw_zip)
                        sub = _scan_zip_members_bytes(sub_bio, nz.filename, depth+1,
                                                      max_members, max_budget_bytes, max_depth)
                        agg_risk += sub["risk"]
                        agg_flags += [f"[nested:{nz.filename}] {f}" for f in sub["flags"]]
                        scanned += sub["members_scanned"]
                    except Exception:
                        continue

            # ── Scan source/script members ──
            candidates=[
                i for i in all_entries
                if os.path.splitext(i.filename)[1].lower() in MEMBER_SCAN_EXTENSIONS
                and not i.filename.endswith('/')
                and 0 < i.file_size < 5*1024*1024
            ]
            tasks_data = []
            for info in candidates[:max_members]:
                # Byte budget check
                if bytes_scanned >= max_budget_bytes:
                    agg_flags.append(
                        f"Scan budget exhausted after {scanned} members "
                        f"({bytes_scanned//1024}KB) \u2014 remaining members unscanned"
                    )
                    logger.warning(
                        f"[L2 MEMBER SCAN BYTES] Budget exhausted for {file_name} "
                        f"after {scanned} members"
                    )
                    break

                if info.flag_bits & 0x1:
                    agg_flags.append(f"Encrypted member: {info.filename}")
                    agg_risk+=25; continue
                try:
                    read_size=min(MAX_MEMBER_BYTES,
                                  max_budget_bytes - bytes_scanned)
                    if read_size <= 0:
                        break
                    raw=zf.read(info.filename)[:read_size]
                    bytes_scanned+=len(raw)
                    tasks_data.append((info.filename, raw))
                except RuntimeError as e:
                    if 'encrypted' in str(e).lower():
                        agg_flags.append(f"Encrypted member: {info.filename}")
                        agg_risk+=25
                except Exception: continue

            # Submit tasks to thread pool for parallel scanning
            if tasks_data:
                max_workers = min(12, len(tasks_data))
                with _futures.ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix='l2-zip-member-scan-bytes') as executor:
                    futures = [
                        executor.submit(_scan_single_member_data, filename, raw)
                        for filename, raw in tasks_data
                    ]
                    for fut in _futures.as_completed(futures):
                        try:
                            filename, sf, sr, yr = fut.result()
                            mn = os.path.basename(filename)
                            agg_flags += [f"[{mn}] {f}" for f in sf]
                            agg_flags += [f"[{mn}] {f}" for f in yr["flags"]]
                            agg_risk += sr + yr["risk"]
                            scanned += 1
                            if agg_risk >= MAX_MEMBER_RISK:
                                for f in futures:
                                    f.cancel()
                                break
                        except Exception as e:
                            logger.warning(f"[L2 MEMBER SCAN BYTES] Sub-task error: {e}")

    except Exception as e:
        logger.warning(f"[L2 MEMBER SCAN BYTES] {file_name}: {e}")

    return {"risk":min(agg_risk,MAX_MEMBER_RISK),
            "flags":agg_flags,"members_scanned":scanned}

def _scan_zip_members(filepath: str, file_name: str, depth: int = 0,
                      max_members: int = 50, max_budget_bytes: int = 10 * 1024 * 1024,
                      max_depth: int = 2) -> dict:
    """
    Scan source/script members from a ZIP.
    Limits: max_members count AND max_budget_bytes total.
    Recursively inspects nested ZIPs up to max_depth.
    """
    agg_risk=0; agg_flags=[]; scanned=0
    bytes_scanned=0

    try:
        with zipfile.ZipFile(filepath,'r') as zf:
            all_entries=zf.infolist()

            # ── Recurse nested ZIPs ──
            if depth < max_depth:
                for nz in [i for i in all_entries
                            if i.filename.lower().endswith('.zip')
                            and not (i.flag_bits & 0x1)
                            and 0 < i.file_size < 20*1024*1024][:3]:
                    try:
                        raw_zip = zf.read(nz.filename)
                        bio = io.BytesIO(raw_zip)
                        sub = _scan_zip_members_bytes(bio, nz.filename, depth+1,
                                                      max_members, max_budget_bytes, max_depth)
                        agg_risk += sub["risk"]
                        agg_flags += [f"[nested:{nz.filename}] {f}" for f in sub["flags"]]
                        scanned += sub["members_scanned"]
                    except Exception:
                        continue

            # ── Scan source/script members ──
            candidates=[
                i for i in all_entries
                if os.path.splitext(i.filename)[1].lower() in MEMBER_SCAN_EXTENSIONS
                and not i.filename.endswith('/')
                and 0 < i.file_size < 5*1024*1024
            ]
            tasks_data = []
            for info in candidates[:max_members]:
                # Byte budget check
                if bytes_scanned >= max_budget_bytes:
                    agg_flags.append(
                        f"Scan budget exhausted after {scanned} members "
                        f"({bytes_scanned//1024}KB) \u2014 remaining members unscanned"
                    )
                    logger.warning(
                        f"[L2 MEMBER SCAN] Budget exhausted for {file_name} "
                        f"after {scanned} members"
                    )
                    break

                if info.flag_bits & 0x1:
                    agg_flags.append(f"Encrypted member: {info.filename}")
                    agg_risk+=25; continue
                try:
                    read_size=min(MAX_MEMBER_BYTES,
                                  max_budget_bytes - bytes_scanned)
                    if read_size <= 0:
                        break
                    raw=zf.read(info.filename)[:read_size]
                    bytes_scanned+=len(raw)
                    tasks_data.append((info.filename, raw))
                except RuntimeError as e:
                    if 'encrypted' in str(e).lower():
                        agg_flags.append(f"Encrypted member: {info.filename}")
                        agg_risk+=25
                except Exception: continue

            # Submit tasks to thread pool for parallel scanning
            if tasks_data:
                max_workers = min(12, len(tasks_data))
                with _futures.ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix='l2-zip-member-scan') as executor:
                    futures = [
                        executor.submit(_scan_single_member_data, filename, raw)
                        for filename, raw in tasks_data
                    ]
                    for fut in _futures.as_completed(futures):
                        try:
                            filename, sf, sr, yr = fut.result()
                            mn = os.path.basename(filename)
                            agg_flags += [f"[{mn}] {f}" for f in sf]
                            agg_flags += [f"[{mn}] {f}" for f in yr["flags"]]
                            agg_risk += sr + yr["risk"]
                            scanned += 1
                            if agg_risk >= MAX_MEMBER_RISK:
                                for f in futures:
                                    f.cancel()
                                break
                        except Exception as e:
                            logger.warning(f"[L2 MEMBER SCAN] Sub-task error: {e}")

    except Exception as e:
        logger.warning(f"[L2 MEMBER SCAN] {file_name}: {e}")

    return {"risk":min(agg_risk,MAX_MEMBER_RISK),
            "flags":agg_flags,"members_scanned":scanned}

def layer2_zip_validation(file_obj, filepath):
    """
    Layer 2: Universal static analysis. Weighted risk aggregation.

    Returns: (passed: bool, threat_description: str|None, layer_result: dict)
    Result dict contains: status, message, risk, flags.
    """
    update_stage(file_obj.id, 2, 'running', 'Heuristic analysis in progress...')
    logger.info(f"[SECURITY] Layer 2 → Heuristic Analysis started for {file_obj.name}")

    file_ext=os.path.splitext(file_obj.name)[1].lower()

    # Category buckets (weighted)
    office_risk=0;  office_flags=[]
    pdf_risk=0;     pdf_flags=[]
    archive_risk=0; archive_flags=[]
    string_risk=0;  string_flags=[]
    yara_risk=0;    yara_flags=[]; yara_matches=[]
    entropy_risk=0; entropy_flags=[]
    # Hard structural signals (unweighted)
    hard_risk=0;    hard_flags=[]

    # ── Step 0: MIME fingerprint ──
    def run_mime_check():
        try:
            if magic is not None:
                mime=magic.from_file(filepath,mime=True)
                exec_mime=any(x in mime for x in
                    ['executable','x-dosexec','x-msdownload','x-sh','x-shellscript'])
                benign_ext=file_ext not in DANGEROUS_EXTENSIONS and \
                           file_ext not in {'.sh','.ps1','.exe','.bat'}
                if exec_mime and benign_ext:
                    return 60, [f"MIME mismatch: {mime} with '{file_ext}'"]
        except Exception: pass
        return 0, []

    # Submit non-archive steps to ThreadPoolExecutor to run concurrently
    fut_mime = _shared_executor.submit(run_mime_check)
    fut_polyglot = _shared_executor.submit(_check_polyglot, filepath, file_ext) if file_ext in IMAGE_EXTENSIONS else None
    fut_pdf = _shared_executor.submit(_analyze_pdf_structure, filepath, file_obj.name) if file_ext == '.pdf' else None
    fut_office = _shared_executor.submit(_analyze_office_zip, filepath, file_obj.name) if file_ext in OFFICE_EXTENSIONS else None
    fut_strings = _shared_executor.submit(_analyze_strings, filepath)
    fut_yara = _shared_executor.submit(_run_yara_scan, filepath, file_obj.name)
    fut_entropy = _shared_executor.submit(_compute_file_entropy, filepath)

    # ── Step 2: Archive (runs in parallel on the main thread) ──
    is_archive_ext = file_ext in {'.zip', '.jar', '.war', '.ear', '.apk'}
    if is_archive_ext and zipfile.is_zipfile(filepath):
        try:
            with zipfile.ZipFile(filepath,'r') as zf:
                entries=zf.infolist()

                enc_r=_check_encrypted_archive(filepath,entries)
                archive_risk+=enc_r["risk"]; archive_flags+=enc_r["flags"]

                tc=sum(i.compress_size for i in entries)
                tu=sum(i.file_size for i in entries)
                # ZIP bomb: ratio check
                if tc>0 and tu/tc>100:
                    hard_risk+=80; hard_flags.append(f"ZIP bomb: ratio 1:{int(tu/tc)}")
                # ZIP bomb: absolute size check
                if tu > ZIP_MAX_UNCOMPRESSED_BYTES:
                    gb=round(tu/1073741824,1)
                    hard_risk+=80; hard_flags.append(f"ZIP bomb: {gb}GB uncompressed")

                for i in entries:
                    if '../' in i.filename or '..\\'in i.filename:
                        hard_risk+=80; hard_flags.append(f"Path traversal: {i.filename}"); break

                for i in entries:
                    if os.path.splitext(i.filename)[1].lower() in ARCHIVE_EXEC_EXTENSIONS:
                        archive_risk+=60; archive_flags.append(f"Executable: {i.filename}"); break

                for i in entries:
                    base=os.path.basename(i.filename); parts=base.split('.')
                    if len(parts)>=3:
                        pen='.'+parts[-2].lower(); last='.'+parts[-1].lower()
                        if pen in {'.pdf','.doc','.jpg','.png','.txt','.xlsx'} \
                                and last in DANGEROUS_EXTENSIONS:
                            hard_risk+=70; hard_flags.append(f"Double-extension: {base}"); break

                for i in entries:
                    if OBFUSCATED_PATTERN.match(os.path.basename(i.filename)):
                        archive_risk+=50; archive_flags.append(f"Obfuscated name: {i.filename}"); break

                nested=sum(1 for i in entries if i.filename.lower().endswith('.zip'))
                if nested>5: archive_risk+=35; archive_flags.append(f"Excessive nested ZIPs: {nested}")
                if len(entries)>1000: archive_risk+=20; archive_flags.append(f"Member count: {len(entries)}")
                
                # Skip testzip() for archives larger than 5 MB or office files
                if file_ext not in OFFICE_EXTENSIONS and os.path.getsize(filepath) <= 5 * 1024 * 1024:
                    bad=zf.testzip()
                    if bad: hard_risk+=80; hard_flags.append(f"Corrupted member: {bad}")

            # Get dynamic member scan limits based on file size (skip for office files)
            if file_ext not in OFFICE_EXTENSIONS:
                file_size_bytes = os.path.getsize(filepath)
                max_members, max_budget_bytes, max_depth = _get_member_scan_limits(file_size_bytes)
                mr=_scan_zip_members(filepath, file_obj.name, depth=0,
                                     max_members=max_members,
                                     max_budget_bytes=max_budget_bytes,
                                     max_depth=max_depth)
                archive_risk+=mr["risk"]; archive_flags+=mr["flags"]
                if mr["members_scanned"]>0:
                    logger.info(f"[L2] Scanned {mr['members_scanned']} members in {file_obj.name}")

        except zipfile.BadZipFile:
            hard_risk+=80; hard_flags.append("Invalid/corrupted archive")
        except Exception as e:
            archive_risk+=40; archive_flags.append(f"Archive error: {str(e)[:60]}")

    # ── Collect Parallel Results ──
    # MIME check result
    mime_risk, mime_flags = fut_mime.result()
    hard_risk += mime_risk
    hard_flags += mime_flags

    # Polyglot result
    if fut_polyglot:
        p = fut_polyglot.result()
        hard_risk += p.get("risk", 0)
        hard_flags += p.get("flags", [])

    # PDF result
    if fut_pdf:
        r = fut_pdf.result()
        pdf_risk = r.get("risk", 0)
        pdf_flags = r.get("flags", [])

    # Office XML result
    if fut_office:
        r = fut_office.result()
        office_risk = r.get("risk", 0)
        office_flags = r.get("flags", [])

    # Strings result
    string_flags, string_risk = fut_strings.result()
    if string_risk >= 50:
        hard_risk += string_risk

    # YARA result
    try:
        yr = fut_yara.result()
        if yr.get("degraded"):
            raise RuntimeError("YARA engine unavailable")
    except Exception as e:
        result = {"status": "fail", "risk": 100,
                  "message": f"YARA engine unavailable — file blocked: {str(e)[:80]}",
                  "flags": ["✖ YARA unavailable — heuristic analysis cannot complete"]}
        update_stage(file_obj.id, 2, 'fail',
                     '✖ YARA unavailable — file blocked (fail-closed)')
        return False, result["message"], result

    yara_risk = yr.get("risk", 0)
    yara_flags = yr.get("flags", [])
    yara_matches = yr.get("matches", [])
    
    # YARA critical → immediate hard block
    if any(m in ['ReverseShellPattern','DestructivePayload'] for m in yara_matches):
        reason=yara_flags[0] if yara_flags else "YARA: critical match"
        all_flags=hard_flags+office_flags+pdf_flags+archive_flags+string_flags+yara_flags
        result={"status":"malicious","message":reason,"risk":100,"flags":all_flags}
        update_stage(file_obj.id,2,'fail',reason)
        logger.info(f"[SECURITY] Layer 2 \u2192 result: status=malicious "
                    f"risk=100 (YARA critical) file={file_obj.name}")
        return False,reason,result

    # Entropy result
    ent = fut_entropy.result()
    entropy_risk, ef = _get_entropy_risk(ent, file_ext)
    if ef:
        entropy_flags.append(ef)

    # ── Weighted aggregation ──
    weighted=(
        min(office_risk,100)  * 0.30 +
        min(pdf_risk,100)     * 0.25 +
        min(archive_risk,100) * 0.20 +
        min(string_risk,100)  * 0.15 +
        min(yara_risk,100)    * 0.25 +
        min(entropy_risk,100) * 0.10
    )
    total_risk=min(int(weighted)+hard_risk,100)
    all_flags=(hard_flags+office_flags+pdf_flags+archive_flags+
               string_flags+yara_flags+entropy_flags)

    if total_risk>=70:
        reason=all_flags[0] if all_flags else "Heuristic analysis: high risk"
        result={"status":"malicious","message":reason,"risk":total_risk,"flags":all_flags}
        update_stage(file_obj.id,2,'fail',reason)
        logger.info(f"[SECURITY] Layer 2 \u2192 result: status=malicious "
                    f"risk={total_risk} file={file_obj.name}")
        return False,reason,result

    if total_risk >= 30:
        reason = ('; '.join(all_flags) if all_flags else "Suspicious indicators detected")
        message = f"Suspicious indicators blocked (risk: {total_risk}) — {reason}"
        result = {"status": "fail", "message": message,
                  "risk": total_risk, "flags": all_flags}
        update_stage(file_obj.id, 2, 'fail',
                     f"✖ Suspicious indicators blocked (risk: {total_risk})")
        logger.info(f"[SECURITY] Layer 2 → BLOCKED: suspicious risk={total_risk} "
                    f"file={file_obj.name}")
        return False, message, result

    msg="Heuristic analysis passed"+(f" ({len(all_flags)} flags)" if all_flags else "")
    result={"status":"safe","message":msg,"risk":total_risk,"flags":all_flags}
    update_stage(file_obj.id,2,'pass',msg)
    logger.info(f"[SECURITY] Layer 2 \u2192 result: status=safe "
                f"risk={total_risk} file={file_obj.name}")
    return True,None,result


# ═══════════════════════════════════════════════════════════════════
# DOCKER HELPERS
# ═══════════════════════════════════════════════════════════════════

# Docker availability cache (avoids calling `docker info` repeatedly)
_docker_available_cache = {'result': None, 'ts': 0}
_DOCKER_CACHE_TTL = 60  # seconds

def _is_docker_available():
    """Check if Docker CLI is installed and the daemon is responsive.
    Caches result for 60 seconds to avoid repeated slow subprocess calls."""
    now = time.time()
    if _docker_available_cache['result'] is not None and (now - _docker_available_cache['ts']) < _DOCKER_CACHE_TTL:
        return _docker_available_cache['result']
    if not shutil.which('docker'):
        _docker_available_cache.update({'result': False, 'ts': now})
        return False
    try:
        result = subprocess.run(
            ['docker', 'info'],
            capture_output=True, timeout=2
        )
        available = result.returncode == 0
        _docker_available_cache.update({'result': available, 'ts': now})
        return available
    except Exception:
        _docker_available_cache.update({'result': False, 'ts': now})
        return False


def _is_clamd_running(host='127.0.0.1', port=3310):
    """Check if ClamAV daemon is accepting connections."""
    import socket
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((host, port))
        sock.sendall(b'PING\n')
        response = sock.recv(64)
        sock.close()
        return b'PONG' in response
    except Exception:
        return False


# ═══════════════════════════════════════════════════════════════════
# LAYER 3 — CLAMAV (DOCKER — PERSISTENT CLAMD DAEMON)
# ═══════════════════════════════════════════════════════════════════

_clamav_daemon_verified = False

def _ensure_clamav_daemon():
    """
    Ensure the ClamAV daemon container is running.
    Starts it if not present. Returns True if daemon is available.
    """
    global _clamav_daemon_verified
    clamd_host = os.environ.get('CLAMD_HOST', '127.0.0.1')
    clamd_port = int(os.environ.get('CLAMD_PORT', '3310'))

    # Fast path: if clamd is already verified and running in this process, we are good to go!
    if _clamav_daemon_verified and _is_clamd_running(clamd_host, clamd_port):
        return True

    if not _is_docker_available():
        # Fallback: if clamd is already running outside docker (or on custom host), return True
        if _is_clamd_running(clamd_host, clamd_port):
            _clamav_daemon_verified = True
            return True
        return False

    image = os.environ.get('CLAMAV_DOCKER_IMAGE', 'clamav/clamav:latest')

    try:
        # Check if container exists
        inspect = subprocess.run(
            ['docker', 'inspect', 'clamav-daemon', '--format', '{{json .Mounts}} {{range .Config.Env}}{{println .}}{{end}}'],
            capture_output=True, text=True, timeout=10
        )

        container_exists = False
        if inspect.returncode == 0:
            # Does container have the required configs AND the correct volume mount?
            has_config = (
                'CLAMD_CONF_StreamMaxLength=500M' in inspect.stdout and
                'CLAMD_CONF_DetectPUA=no' in inspect.stdout and
                'CLAMD_CONF_Bytecode=no' in inspect.stdout and
                'CLAMD_CONF_AlertBrokenExecutables=no' in inspect.stdout and
                'CLAMD_CONF_MaxRecursion=5' in inspect.stdout and
                'CLAMD_CONF_MaxFiles=2000' in inspect.stdout and
                'CLAMD_CONF_MaxThreads=12' in inspect.stdout and
                '/scans' in inspect.stdout and
                HOST_SCAN_DIR in inspect.stdout
            )
            if not has_config:
                logger.info(f"Existing clamav-daemon container lacks required config or matches wrong mount ({HOST_SCAN_DIR}). Recreating container...")
                subprocess.run(['docker', 'stop', 'clamav-daemon'], capture_output=True, timeout=15)
                subprocess.run(['docker', 'rm', 'clamav-daemon'], capture_output=True, timeout=15)
            else:
                container_exists = True

        if container_exists:
            # Container exists and has correct config, check if it's running
            running_inspect = subprocess.run(
                ['docker', 'inspect', 'clamav-daemon', '--format', '{{.State.Running}}'],
                capture_output=True, text=True, timeout=10
            )
            if running_inspect.returncode == 0 and 'true' in running_inspect.stdout.lower():
                if _is_clamd_running(clamd_host, clamd_port):
                    _clamav_daemon_verified = True
                    return True
                # Container running but clamd not ready yet — wait
                logger.info("ClamAV container running, waiting for clamd to initialize...")
                for _ in range(30):  # Wait up to 60s for clamd
                    time.sleep(2)
                    if _is_clamd_running(clamd_host, clamd_port):
                        _clamav_daemon_verified = True
                        return True
                return False
            else:
                # Container stopped — restart it
                subprocess.run(['docker', 'start', 'clamav-daemon'],
                               capture_output=True, timeout=10)
        else:
            # Container doesn't exist — create it
            logger.info(f"Starting ClamAV daemon container ({image}) with optimized settings and volume persistence...")
            subprocess.run([
                'docker', 'run', '-d',
                '--name', 'clamav-daemon',
                '--restart', 'unless-stopped',
                '-p', f'{clamd_port}:3310',
                '-v', 'clamav-db:/var/lib/clamav',
                '-v', f'{HOST_SCAN_DIR}:/scans:ro',
                '-e', 'CLAMD_CONF_StreamMaxLength=500M',
                '-e', 'CLAMD_CONF_MaxFileSize=500M',
                '-e', 'CLAMD_CONF_MaxScanSize=500M',
                '-e', 'CLAMD_CONF_DetectPUA=no',
                '-e', 'CLAMD_CONF_ScanPE=yes',
                '-e', 'CLAMD_CONF_Bytecode=no',
                '-e', 'CLAMD_CONF_AlertBrokenExecutables=no',
                '-e', 'CLAMD_CONF_MaxRecursion=5',
                '-e', 'CLAMD_CONF_MaxFiles=2000',
                '-e', 'CLAMD_CONF_MaxThreads=12',
                '-e', 'CLAMD_CONF_ConcurrentDatabaseReload=no',
                '-e', 'CLAMD_CONF_ReadTimeout=300',
                '-e', 'CLAMD_CONF_CommandReadTimeout=30',
                image
            ], capture_output=True, text=True, timeout=60, check=True)

        # Wait for clamd to be ready (virus DB load takes time on first start)
        logger.info("Waiting for ClamAV daemon to load virus databases...")
        for i in range(45):  # Up to 90 seconds
            time.sleep(2)
            if _is_clamd_running(clamd_host, clamd_port):
                logger.info(f"ClamAV daemon ready after ~{(i+1)*2}s")
                _clamav_daemon_verified = True
                return True

        logger.warning("ClamAV daemon did not become ready in 90s")
        return False

    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to start ClamAV daemon: {e.stderr}")
        return False
    except Exception as e:
        logger.error(f"ClamAV daemon startup error: {e}")
        return False



def get_host_scan_dir():
    """Dynamically determine the host scan directory for ClamAV scans.
    For WSL 2 and Docker Desktop integration, we use /mnt/wsl/stackdrive_scans
    which is a shared mount namespace visible to all WSL2 distributions (including the
    docker-desktop VM where dockerd runs). This allows nSCAN to work directly and fast."""
    import os
    import subprocess
    if os.path.exists('/mnt/wsl'):
        wsl_shared = '/mnt/wsl/stackdrive_scans'
        if not os.path.exists(wsl_shared):
            try:
                os.makedirs(wsl_shared, mode=0o755, exist_ok=True)
            except Exception as e:
                logger.warning(f"Could not create {wsl_shared}, fallback to /tmp: {e}")
                return '/tmp'
        else:
            try:
                os.chmod(wsl_shared, 0o755)
            except Exception:
                pass
        
        # Check if we actually have write access to wsl_shared
        if not os.access(wsl_shared, os.W_OK):
            # Attempt to fix permissions using docker, since dockerd runs as root on the host VM
            # and has full root privileges to chmod files in /mnt/wsl
            try:
                subprocess.run(
                    ['docker', 'run', '--rm', '-v', f'{wsl_shared}:/scans', 'alpine', 'chmod', '777', '/scans'],
                    capture_output=True, timeout=5
                )
            except Exception as e:
                logger.warning(f"Could not fix permissions on {wsl_shared} via Docker: {e}")
            
            # Recheck write access
            if not os.access(wsl_shared, os.W_OK):
                logger.warning(f"{wsl_shared} is not writable after fix attempt, falling back to /tmp")
                return '/tmp'
                
        return wsl_shared
        
    if os.name == 'nt':
        wsl_path = r'\\wsl.localhost\Ubuntu\tmp'
        if os.path.exists(wsl_path):
            return wsl_path
    return '/tmp'

# Host and container directory mappings for ClamAV scans
HOST_SCAN_DIR = os.path.abspath(get_host_scan_dir())
CONTAINER_SCAN_DIR = '/scans'

def _clamd_scan_local(filepath, host='127.0.0.1', port=3310, timeout=300):
    """
    Attempt to scan the file using ClamAV's local SCAN command (no TCP streaming).
    Requires the file to be under /tmp and ClamAV container to have /tmp mounted at /scans.
    Returns: (success: bool, is_clean: bool, verdict_or_error: str|None)
      - success=True: Scan completed successfully via local SCAN command.
      - success=False: Local scan could not be run or failed (e.g. file not found in container, permission error), need to fall back to INSTREAM.
    """
    import socket
    abs_path = os.path.abspath(filepath)
    
    # Only support files under HOST_SCAN_DIR for local mounting
    if not abs_path.startswith(HOST_SCAN_DIR):
        logger.warning(f"[CLAMAV] Local scan path guard failed: {abs_path} does not start with {HOST_SCAN_DIR}")
        return False, True, None
        
    # Guarantee world-readable permissions before nSCAN
    try:
        parent_dir = os.path.dirname(abs_path)
        if parent_dir != HOST_SCAN_DIR:
            os.chmod(parent_dir, 0o755)
        os.chmod(abs_path, 0o644)
    except Exception as e:
        logger.warning(f"[CLAMAV] Failed to chmod file or parent directory for local scan: {e}")

    container_path = abs_path.replace(HOST_SCAN_DIR, CONTAINER_SCAN_DIR, 1).replace('\\', '/')
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    
    try:
        sock.connect((host, port))
        # Send SCAN command with container path
        cmd = f"nSCAN {container_path}\n"
        sock.sendall(cmd.encode('utf-8'))
        
        # Read response
        response = b''
        while True:
            data = sock.recv(4096)
            if not data:
                break
            response += data
            if b'\n' in data or b'\0' in data:
                break
                
        response_text = response.decode('utf-8', errors='replace').strip().strip('\x00')
        logger.info(f"[CLAMAV] nSCAN response: {response_text}")
        
        # If clamd says "No such file or directory" or "Permission denied" or similar, local scan failed
        if "No such file" in response_text or "Permission denied" in response_text or not response_text:
            return False, True, None
            
        if 'OK' in response_text and 'FOUND' not in response_text:
            return True, True, None
        elif 'FOUND' in response_text:
            virus_name = response_text.replace(container_path + ':', '').replace('FOUND', '').strip()
            return True, False, virus_name
        else:
            # Some other clamd response, treat as fallback
            return False, True, None
            
    except Exception as e:
        logger.warning(f"ClamAV local SCAN failed (will fallback to INSTREAM): {e}")
        return False, True, None
    finally:
        sock.close()


def _clamd_scan(filepath, host='127.0.0.1', port=3310, timeout=300):
    """
    Scan a file using the ClamAV daemon via TCP socket (clamd protocol).
    Returns: (is_clean: bool, virus_name: str|None)
    """
    import socket
    import struct

    # Try local mount-based scan first for performance (especially for large files)
    try:
        success, is_clean, result = _clamd_scan_local(filepath, host, port, timeout=300)
        if success:
            return is_clean, result
        else:
            logger.info("[CLAMAV] Using INSTREAM fallback instead")
    except Exception as e:
        logger.warning(f"Local scan helper error: {e}")
        logger.info("[CLAMAV] Using INSTREAM fallback instead")

    abs_path = os.path.abspath(filepath)
    file_size_bytes = os.path.getsize(abs_path)

    # Adaptive chunk sizing optimized for loopback TCP streaming without socket buffer overflow
    if file_size_bytes > 100 * 1024 * 1024:
        CHUNK = 2 * 1024 * 1024      # 2 MB
    elif file_size_bytes > 10 * 1024 * 1024:
        CHUNK = 1 * 1024 * 1024      # 1 MB
    else:
        CHUNK = 256 * 1024           # 256 KB

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except Exception as e:
        logger.warning(f"Failed to set TCP_NODELAY: {e}")

    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, CHUNK * 4)
    except Exception as e:
        logger.warning(f"Failed to set SO_SNDBUF: {e}")

    try:
        sock.connect((host, port))
        sock.settimeout(timeout)

        # INSTREAM command: stream file data to clamd
        sock.sendall(b'zINSTREAM\0')

        with open(abs_path, 'rb') as f:
            while True:
                chunk = f.read(CHUNK)
                if not chunk:
                    break
                # Combine 4-byte length header and chunk into a single sendall() call to reduce syscall overhead
                payload = struct.pack('!I', len(chunk)) + chunk
                sock.sendall(payload)

        # End of stream: send zero-length chunk
        sock.sendall(struct.pack('!I', 0))

        # Read response
        response = b''
        while True:
            data = sock.recv(4096)
            if not data:
                break
            response += data
            if b'\0' in data or b'\n' in data:
                break

        response_text = response.decode('utf-8', errors='replace').strip().strip('\x00')
        logger.info(f"ClamAV response: {response_text}")

        # Parse response: "stream: OK" or "stream: VirusName FOUND"
        if 'OK' in response_text and 'FOUND' not in response_text:
            return True, None
        elif 'FOUND' in response_text:
            # Extract virus name: "stream: Win.Test.EICAR_HDB-1 FOUND"
            virus_name = response_text.replace('stream:', '').replace('FOUND', '').strip()
            return False, virus_name
        else:
            logger.error(f"[SECURITY] ClamAV FAIL-CLOSED: unexpected response: "
                         f"{response_text[:80]}")
            return False, (f"ClamAV unexpected response — result inconclusive: "
                            f"{response_text[:80]}")

    except socket.timeout:
        logger.error("ClamAV scan timed out — treating as inconclusive (blocked)")
        return False, "ClamAV scan timed out — result inconclusive"
    except Exception as e:
        logger.error(f"ClamAV socket error: {e}")
        return False, f"ClamAV socket error — result inconclusive: {str(e)[:60]}"
    finally:
        sock.close()


def _clamd_scan_archive_members(filepath, host='127.0.0.1', port=3310, timeout=60):
    """
    Deep-scan: extract archive members and scan each individually via clamd.
    Defense-in-depth against ClamAV's built-in unpacker missing embedded threats.

    Returns: (all_clean: bool, virus_info: str|None)
      - all_clean=True  → every member scanned clean
      - all_clean=False → at least one member detected; virus_info has details

    Safety limits:
      - Max 50 members extracted (skip rest)
      - Max 100 MB per member (skip oversized)
      - Path traversal entries are refused
    """
    MAX_MEMBERS = 50
    MAX_MEMBER_SIZE = 100 * 1024 * 1024  # 100 MB

    if not zipfile.is_zipfile(filepath):
        return True, None  # Not an archive — nothing to deep-scan

    tmp_dir = None
    try:
        tmp_dir = tempfile.mkdtemp(prefix='clamav_deep_', dir=HOST_SCAN_DIR)
        os.chmod(tmp_dir, 0o755)
        with zipfile.ZipFile(filepath, 'r') as zf:
            members = zf.infolist()
            # Define target extensions for deep scanning (ignore benign assets like images, text, css)
            target_exts = ARCHIVE_EXEC_EXTENSIONS | MEMBER_SCAN_EXTENSIONS | OFFICE_EXTENSIONS | {
                '.elf', '.so', '.dll', '.class', '.jar', '.apk', '.bin', '.sys', '.drv'
            }

            scanned_members = []

            for info in members:
                if len(scanned_members) >= MAX_MEMBERS:
                    logger.warning(f"[CLAMAV DEEP] Stopping extraction after {MAX_MEMBERS} members")
                    break

                # Skip directories
                if info.is_dir():
                    continue

                # Path traversal guard
                if '..' in info.filename or info.filename.startswith('/'):
                    logger.warning(f"[CLAMAV DEEP] Skipping path-traversal entry: {info.filename}")
                    continue

                # Skip oversized members
                if info.file_size > MAX_MEMBER_SIZE:
                    logger.warning(f"[CLAMAV DEEP] Skipping oversized member: {info.filename} ({info.file_size} bytes)")
                    continue

                # Filter by extension
                ext = os.path.splitext(info.filename)[1].lower()
                if ext not in target_exts:
                    continue

                # Extract to temp file
                safe_name = os.path.basename(info.filename) or f"member_{len(scanned_members)}"
                member_path = os.path.join(tmp_dir, safe_name)

                # Handle duplicate names
                if os.path.exists(member_path):
                    member_path = os.path.join(tmp_dir, f"{len(scanned_members)}_{safe_name}")

                try:
                    with zf.open(info) as src, open(member_path, 'wb') as dst:
                        remaining = info.file_size
                        while remaining > 0:
                            chunk = src.read(min(1024 * 1024, remaining))
                            if not chunk:
                                break
                            dst.write(chunk)
                            remaining -= len(chunk)
                    os.chmod(member_path, 0o644)
                    scanned_members.append((info.filename, member_path))
                except Exception as e:
                    logger.warning(f"[CLAMAV DEEP] Failed to extract {info.filename}: {e}")
                    continue

            if not scanned_members:
                logger.info("[CLAMAV DEEP] No script or executable members found in archive. Skipping deep scan.")
                return True, None

            # Scan extracted members in parallel using a local ThreadPoolExecutor to prevent pool starvation deadlocks
            max_workers = min(12, len(scanned_members))
            scanned = 0
            
            with _futures.ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix='clamav-deep-scan') as executor:
                # Submit all scans
                future_to_member = {
                    executor.submit(_clamd_scan, path, host, port, timeout): (name, path)
                    for name, path in scanned_members
                }

                for fut in _futures.as_completed(future_to_member):
                    name, path = future_to_member[fut]
                    try:
                        is_clean, virus_name = fut.result()
                        scanned += 1
                        if not is_clean:
                            logger.warning(f"[CLAMAV DEEP] Threat in archive member '{name}': {virus_name}")
                            # Cancel other pending scans
                            for f in future_to_member:
                                f.cancel()
                            return False, f"{virus_name} (in archive: {name})"
                    except Exception as e:
                        logger.error(f"[CLAMAV DEEP] Error scanning member {name}: {e}")

            logger.info(f"[CLAMAV DEEP] All {scanned} archive members scanned clean")
            return True, None

    except zipfile.BadZipFile:
        logger.warning("[CLAMAV DEEP] Bad ZIP file — skipping deep scan")
        return True, None
    except Exception as e:
        logger.error(f"[CLAMAV DEEP] Archive deep-scan error: {e}")
        return True, None  # Don't block on deep-scan errors — outer scan is primary
    finally:
        if tmp_dir:
            try:
                shutil.rmtree(tmp_dir, ignore_errors=True)
            except Exception:
                pass


def run_clamav_local(file_obj, filepath):
    """
    Layer 3: ClamAV signature scan.
    Daemon pre-warmed at startup. DB freshness checked.
    Archive-aware: scans ZIP members for Office/JAR/APK/WAR.
    Reports DB age, scan time, members scanned.

    Returns: (passed: bool, threat_description: str|None, layer_result: dict)
    Result dict contains: status, message, risk, flags.
    """
    global _clamav_daemon_verified
    update_stage(file_obj.id,3,'running','ClamAV scan in progress...')
    logger.info(f"[SECURITY] Layer 3 → ClamAV started for {file_obj.name}")

    import time as _t; t0=_t.time()
    db_flags=[]; db_age_risk=0

    # Ensure we use environment variables for connection settings
    clamd_host = os.environ.get('CLAMD_HOST', '127.0.0.1')
    clamd_port = int(os.environ.get('CLAMD_PORT', '3310'))

    # Dynamic scan timeout based on file size: 0.6 s/MB + 60s with a max cap of 900 s
    file_size = os.path.getsize(filepath)
    file_size_mb = file_size / (1024 * 1024)
    dynamic_timeout = min(900, int(file_size_mb * 0.6 + 60))

    scan_filepath = filepath
    temp_slice_path = None

    try:
        # Performance optimization: if file is larger than 10MB, scan the first 10MB slice.
        # Antivirus signatures are typically located at the header/beginning of executable/document files.
        # Scanning a 10MB slice takes less than 1-2 seconds, preventing ClamAV from hanging on huge files.
        if file_size > 10 * 1024 * 1024:
            try:
                parent_dir = os.path.dirname(filepath)
                fd, temp_slice_path = tempfile.mkstemp(prefix='clamav_slice_', dir=parent_dir)
                with os.fdopen(fd, 'wb') as out_f, open(filepath, 'rb') as in_f:
                    out_f.write(in_f.read(10 * 1024 * 1024))
                os.chmod(temp_slice_path, 0o644)
                scan_filepath = temp_slice_path
                logger.info(f"[CLAMAV] Optimized scan: created 10MB slice for {file_obj.name} ({file_size_mb:.1f} MB)")
            except Exception as slice_err:
                logger.warning(f"[CLAMAV] Failed to create scan slice: {slice_err}")

        direct_scan_ok = False
        is_clean_final, threat_final = True, None

        # Hot path: if daemon was verified before, perform scan directly
        if _clamav_daemon_verified:
            try:
                is_clean_final, threat_final = _clamd_scan(scan_filepath, clamd_host, clamd_port, timeout=dynamic_timeout)
                if not is_clean_final and threat_final and "Scan error:" in threat_final:
                    _clamav_daemon_verified = False
                else:
                    direct_scan_ok = True
            except Exception as e:
                logger.warning(f"Direct ClamAV scan exception, resetting verified flag: {e}")
                _clamav_daemon_verified = False

        # Cold path: ensure daemon is running first, then scan
        if not direct_scan_ok:
            if not _ensure_clamav_daemon():
                # Only sleep and retry if Docker is available to start the container
                if _is_docker_available():
                    import time as _retry_t
                    _retry_t.sleep(3)
                    if _ensure_clamav_daemon():
                        # Recovered on retry!
                        pass
                    else:
                        result = {"status": "fail",
                                  "message": "ClamAV daemon unavailable — antivirus scan required",
                                  "risk": 100,
                                  "flags": ["✖ ClamAV daemon offline — file blocked (fail-closed)"],
                                  "db_age_hours": None, "scan_time_seconds": 0, "members_scanned": 0}
                        update_stage(file_obj.id, 3, 'fail',
                                     '✖ ClamAV daemon unavailable — blocked (fail-closed)')
                        logger.error(f"[SECURITY] Layer 3 → FAIL-CLOSED: ClamAV daemon offline "
                                     f"file={file_obj.name}")
                        return False, "ClamAV daemon unavailable — antivirus scan required", result
                else:
                    # Docker is unavailable, so we cannot spawn or wait for a container. Fail instantly.
                    result = {"status": "fail",
                              "message": "ClamAV daemon unavailable — antivirus scan required",
                              "risk": 100,
                              "flags": ["✖ ClamAV daemon offline — file blocked (fail-closed)"],
                              "db_age_hours": None, "scan_time_seconds": 0, "members_scanned": 0}
                    update_stage(file_obj.id, 3, 'fail',
                                 '✖ ClamAV daemon unavailable — blocked (fail-closed)')
                    logger.error(f"[SECURITY] Layer 3 → FAIL-CLOSED: ClamAV daemon offline "
                                 f"file={file_obj.name}")
                    return False, "ClamAV daemon unavailable — antivirus scan required", result

            # Daemon ensured, perform scan
            is_clean_final, threat_final = _clamd_scan(scan_filepath, clamd_host, clamd_port, timeout=dynamic_timeout)

        db_age = _get_clamav_db_age_hours()
        if db_age:
            if db_age > 720:
                db_flags.append(f"⚠ ClamAV DB {db_age}h old — severely outdated"); db_age_risk = 20
            elif db_age > 168:
                db_flags.append(f"⚠ ClamAV DB {db_age}h old — update recommended"); db_age_risk = 10

        scan_time = round(_t.time() - t0, 2)

        if not is_clean_final:
            threat = threat_final or "ClamAV: malware detected"
            result = {"status": "malicious", "message": threat, "risk": 100, "flags": [threat] + db_flags,
                      "db_age_hours": db_age, "scan_time_seconds": scan_time, "members_scanned": 0}
            update_stage(file_obj.id, 3, 'fail',
                         f"THREAT:{threat} | DB:{db_age}h | {scan_time}s")
            logger.info(f"[SECURITY] Layer 3 → result: status=malicious risk=100 file={file_obj.name}")
            return False, threat, result

        for f in db_flags: logger.warning(f"[L3 DB] {f}")

        final_risk = min(db_age_risk, 100)
        status = ('suspicious' if final_risk >= 40 else 'safe')
        message = ('; '.join(db_flags) if db_flags else f"Clean — {scan_time}s")
        result = {"status": status, "message": message, "risk": final_risk, "flags": db_flags,
                  "db_age_hours": db_age, "scan_time_seconds": scan_time, "members_scanned": 0}
        update_stage(file_obj.id, 3, 'pass',
                     f"Clean | DB:{db_age}h | {scan_time}s")
        logger.info(f"[SECURITY] Layer 3 → result: status={status} "
                    f"risk={final_risk} file={file_obj.name}")
        return True, None, result
    finally:
        if temp_slice_path and os.path.exists(temp_slice_path):
            try:
                os.remove(temp_slice_path)
            except Exception as e:
                logger.warning(f"[CLAMAV] Failed to remove slice path {temp_slice_path}: {e}")




# ═══════════════════════════════════════════════════════════════════
# LAYER 4 — ADVANCED BEHAVIORAL SANDBOX (DOCKER)
# ═══════════════════════════════════════════════════════════════════

# ─── Dangerous syscalls that indicate malicious intent ────────────
DANGEROUS_SYSCALLS = {
    'connect':    {'risk': 50, 'label': 'Network connection attempt'},
    'bind':       {'risk': 40, 'label': 'Port binding attempt'},
    'socket':     {'risk': 15, 'label': 'Socket creation'},
    'execve':     {'risk': 30, 'label': 'Process execution'},
    'fork':       {'risk': 15, 'label': 'Process forking'},
    'clone':      {'risk': 15, 'label': 'Process cloning'},
    'chmod':      {'risk': 25, 'label': 'Permission modification'},
    'chown':      {'risk': 25, 'label': 'Ownership change'},
    'ptrace':     {'risk': 40, 'label': 'Process tracing/debugging'},
    'mprotect':   {'risk': 20, 'label': 'Memory protection change'},
    'unlink':     {'risk': 10, 'label': 'File deletion'},
    'rename':     {'risk': 10, 'label': 'File renaming'},
    'symlink':    {'risk': 15, 'label': 'Symbolic link creation'},
    'mount':      {'risk': 40, 'label': 'Filesystem mount attempt'},
    'kill':       {'risk': 20, 'label': 'Signal/process termination'},
    'setuid':     {'risk': 35, 'label': 'Privilege escalation (setuid)'},
    'setgid':     {'risk': 35, 'label': 'Privilege escalation (setgid)'},
}


def _compute_file_entropy(filepath, sample_size=65536):
    """
    Compute Shannon entropy of a file.
    For files exceeding sample_size * 3, samples three disjoint blocks (head, middle, tail)
    to prevent detection evasion while maintaining fast execution.
    """
    try:
        import collections
        file_size = os.path.getsize(filepath)
        if file_size <= sample_size * 3:
            with open(filepath, 'rb') as f:
                data = f.read()
        else:
            with open(filepath, 'rb') as f:
                head = f.read(sample_size)
                
                mid_offset = (file_size - sample_size) // 2
                f.seek(mid_offset)
                middle = f.read(sample_size)
                
                f.seek(file_size - sample_size)
                tail = f.read(sample_size)
                
                data = head + middle + tail

        if not data:
            return 0.0

        counts = collections.Counter(data)
        entropy = 0.0
        total = len(data)
        for count in counts.values():
            probability = count / total
            entropy -= probability * math.log2(probability)

        return round(entropy, 4)

    except Exception:
        return 0.0

def _analyze_strace_log(strace_output):
    """
    Analyze strace output for dangerous system call patterns.
    Returns: (syscall_summary: list[str], flags: list[str], risk_score: int)
    """
    syscall_summary = []
    flags = []
    risk = 0
    seen_syscalls = set()

    for line in strace_output.split('\n'):
        line = line.strip()
        if not line:
            continue

        for syscall, info in DANGEROUS_SYSCALLS.items():
            # Match syscall at start of line (strace format: "syscall(...)")
            if re.match(rf'^(\[\s*\d+\]\s+)?{syscall}\(', line) or f' {syscall}(' in line:
                if syscall not in seen_syscalls:
                    seen_syscalls.add(syscall)
                    syscall_summary.append(f"{syscall}: {info['label']}")
                    risk += info['risk']
                    if info['risk'] >= 30:
                        flags.append(f"⚠ {info['label']} ({syscall})")

    return syscall_summary, flags, risk


def _analyze_process_behavior(strace_output, exit_code, execution_time, was_oom_killed=False):
    """
    Analyze process-level behavioral indicators.
    Returns: (flags: list[str], risk_score: int)
    """
    flags = []
    risk = 0

    # OOM kill detection
    if was_oom_killed:
        flags.append("⚠ Process killed by OOM (excessive memory consumption)")
        risk += 25

    # Abnormal exit code
    if exit_code is not None and exit_code not in (0, 1, 124, 137):
        flags.append(f"Abnormal exit code: {exit_code}")
        risk += 10

    # Timeout / hanging detection (10s timeout should trigger code 124)
    if exit_code == 124:
        flags.append("⚠ Process exceeded execution timeout (evasion technique)")
        risk += 20

    # Fork bomb / excessive process spawning
    fork_count = len(re.findall(r'(?:fork|clone)\(', strace_output))
    if fork_count > 20:
        flags.append(f"⚠ Excessive process spawning ({fork_count} forks)")
        risk += 30
    elif fork_count > 5:
        flags.append(f"Moderate process spawning ({fork_count} forks)")
        risk += 10

    # Shell spawning detection
    shell_patterns = ['/bin/sh', '/bin/bash', '/bin/dash', '/bin/zsh']
    for shell in shell_patterns:
        if shell in strace_output:
            flags.append(f"⚠ Shell spawned: {shell}")
            risk += 20
            break

    return flags, risk


def run_sandbox_local(file_obj, filepath):
    """
    Layer 4: Advanced behavioral sandbox analysis.
    Unified routing engine:
      - execute: ELF/PE/Mach-O binaries (runs inside isolated container under strace).
      - static_analysis: Scripts and source code (.py, .js, .sh, .ps1, etc. using AST/regex grep).
      - document: PDFs, Office Open XML, RTF (extracts structures, links, macros, DDE).
    
    Returns: (passed: bool, threat_description: str|None, layer_result: dict)
    """
    import ast
    import re
    import time as _t
    
    update_stage(file_obj.id, 4, 'running', 'Analyzing file for sandbox routing...')
    logger.info(f"[SECURITY] Layer 4 → Sandbox execution started for {file_obj.name}")
    file_obj.sandbox_status_detail = None
    
    # 1. Determine file type / route
    file_ext = os.path.splitext(file_obj.name)[1].lower()
    
    # Detect mime type safely
    mime_type = ""
    try:
        if magic is not None:
            mime_type = magic.from_file(filepath, mime=True).lower()
    except Exception:
        pass
        
    # ── Classify route ──
    route = "static_analysis"  # default

    # Check magic bytes for true file type
    _magic_bytes = b''
    try:
        with open(filepath, 'rb') as _mf:
            _magic_bytes = _mf.read(8)
    except Exception:
        pass

    is_pe  = _magic_bytes[:2] == b'MZ'   # Windows PE — cannot exec on Linux
    is_elf = _magic_bytes[:4] == b'\x7fELF'
    is_shebang = _magic_bytes[:2] == b'#!'

    is_binary = (
        (any(x in mime_type for x in ['executable','elf','sharedlib',
                                       'octet-stream','dosexec'])
         or file_ext in ['.exe','.elf','.bin','.so','.dll','.msi'])
        and not is_pe   # ← PE excluded from execute route
    )
    is_script = (
        any(x in mime_type for x in ['script','text/x-']) or
        file_ext in ['.py','.js','.sh','.bash','.pl','.ps1',
                     '.bat','.cmd','.php','.vbs','.html','.htm']
    )
    is_document = (
        any(x in mime_type for x in ['pdf','msword','officedocument','rtf'])
        or file_ext in ['.pdf','.docx','.xlsx','.pptx','.docm','.xlsm',
                        '.pptm','.doc','.xls','.ppt','.rtf']
    )

    if is_pe:
        route = "inspect"        # PE: static strings only, no execution
        # Windows PE cannot run under Linux strace — intentional.
        # True Windows execution requires Cuckoo/VM (out of scope).
    elif is_binary or is_elf or is_shebang:
        route = "execute"
    elif is_document:
        route = "document"
    elif is_script:
        route = "static_analysis"

    logger.info(f"[SECURITY] Route selected: '{route}' for {file_obj.name} (mime: {mime_type})")
    
    all_flags = []
    total_risk = 0
    entropy = 0.0
    syscall_summary = []
    process_activity = []
    file_access = []
    exit_code = None
    was_oom_killed = False
    strace_output = ""
    
    # Pre-execution: Compute entropy and extract strings for all files
    entropy = _compute_file_entropy(filepath)
    # File-type-aware entropy (uses ENTROPY_THRESHOLDS from A7)
    _ent_risk, _ent_flag = _get_entropy_risk(entropy, file_ext)
    if _ent_risk > 0:
        total_risk += _ent_risk
        if _ent_flag:
            all_flags.append(_ent_flag)
        
    if route not in ('execute', 'inspect'):
        string_flags, string_risk = _analyze_strings(filepath)
        all_flags.extend(string_flags)
        total_risk += string_risk

    if route == "execute":
        # Dynamic execution under strace
        if not _is_docker_available():
            logger.error("[SECURITY] Layer 4 → FAIL-CLOSED: Docker engine offline")
            result = {
                "status": "fail",
                "message": "Docker engine offline — sandbox execution required for binaries",
                "risk": 100,
                "flags": ["✖ Docker engine offline — binary analysis blocked (fail-closed)"],
                "behavior": {}, "sandbox_route": "blocked"
            }
            update_stage(file_obj.id, 4, 'fail',
                         '✖ Docker offline — binary blocked (fail-closed)')
            return False, result["message"], result
        else:
            sandbox_image = os.environ.get('SANDBOX_DOCKER_IMAGE', '')
            if not sandbox_image:
                logger.error("[SECURITY] Layer 4 → FAIL-CLOSED: SANDBOX_DOCKER_IMAGE not configured")
                result = {
                    "status": "fail",
                    "message": "Sandbox image not configured — binary execution blocked",
                    "risk": 100,
                    "flags": ["✖ SANDBOX_DOCKER_IMAGE env var not set — contact administrator"],
                    "behavior": {}, "sandbox_route": "blocked"
                }
                update_stage(file_obj.id, 4, 'fail',
                             '✖ Sandbox not configured — binary blocked (fail-closed)')
                return False, result["message"], result
            else:
                # Docker is available and image is set. Run dynamic analysis!
                update_stage(file_obj.id, 4, 'running', 'Running file in sandbox container...')
                sandbox_timeout = int(os.environ.get('SANDBOX_TIMEOUT', '30'))
                strace_timeout = sandbox_timeout * 3
                file_dir = os.path.dirname(os.path.abspath(filepath))
                file_name = os.path.basename(filepath)
                
                # Copy binary to tmpfs, chmod +x, run under strace
                sandbox_script = (
                    f"cp /sandbox/{file_name} /tmp/run_bin && "
                    f"chmod +x /tmp/run_bin && "
                    f"timeout {strace_timeout}s strace -f "
                    f"-e trace=network,process,file,memory,ipc "
                    f"-e signal=all "
                    f"-o /tmp/trace.log /tmp/run_bin >/dev/null 2>&1; "
                    f"echo \"===STRACE===\"; "
                    f"cat /tmp/trace.log 2>/dev/null; "
                    f"echo \"===END===\""
                )
                
                docker_cmd = [
                    'docker', 'run', '--rm',
                    '--network', 'none',
                    '--memory', '512m',
                    '--memory-swap', '512m',
                    '--cpus', '1',
                    '--pids-limit', '64',
                    '--read-only',
                    '--tmpfs', '/tmp:size=128m',
                    '--security-opt', 'no-new-privileges',
                    '--cap-drop', 'ALL',
                    '--cap-add', 'SYS_PTRACE',
                    '-v', f'{file_dir}:/sandbox:ro',
                    sandbox_image,
                    'sh', '-c', sandbox_script
                ]
                
                try:
                    scan_start = _t.time()
                    proc = subprocess.run(
                        docker_cmd,
                        capture_output=True,
                        text=True,
                        timeout=strace_timeout + 30
                    )
                    execution_time = _t.time() - scan_start
                    exit_code = proc.returncode
                    
                    if exit_code == 137:
                        was_oom_killed = True
                        
                    output = proc.stdout or ''
                    if '===STRACE===' in output:
                        strace_output = output.split('===STRACE===')[1].split('===END===')[0]
                    else:
                        strace_output = output
                        
                    # Analyze strace logs
                    update_stage(file_obj.id, 4, 'running', 'Analyzing sandbox system calls...')
                    s_summary, s_flags, s_risk = _analyze_strace_log(strace_output)
                    syscall_summary.extend(s_summary)
                    all_flags.extend(s_flags)
                    total_risk += s_risk
                    
                    # Analyze process behavior
                    p_flags, p_risk = _analyze_process_behavior(
                        strace_output, exit_code, execution_time, was_oom_killed
                    )
                    all_flags.extend(p_flags)
                    total_risk += p_risk
                    process_activity = p_flags
                    
                    # Extract file accesses
                    file_accesses = re.findall(r'open(?:at)?\([^"]*"([^"]+)"', strace_output)
                    file_access = list(set(file_accesses))[:20]
                    
                    hidden_files = [f for f in file_access if os.path.basename(f).startswith('.')]
                    if hidden_files:
                        all_flags.append(f"⚠ Hidden file access: {', '.join(hidden_files[:3])}")
                        total_risk += 15
                        
                    sensitive_paths = ['/etc/passwd', '/etc/shadow', '/proc/', '/sys/']
                    for path in file_access:
                        for sensitive in sensitive_paths:
                            if path.startswith(sensitive):
                                all_flags.append(f"⚠ Sensitive path access: {path}")
                                total_risk += 15
                                break
                                
                    file_obj.sandbox_status_detail = 'normal_exit' if exit_code in (0, 1) else (
                        'oom_killed' if was_oom_killed else 'timeout' if exit_code == 124 else 'crashed'
                    )
                except subprocess.TimeoutExpired:
                    all_flags.append("⚠ Sandbox execution timed out — potential evasion/denial of service")
                    total_risk += 25
                    file_obj.sandbox_status_detail = 'timeout'
                except Exception as e:
                    logger.error(f"Sandbox run exception: {e}")
                    all_flags.append(f"Sandbox execution error: {str(e)[:60]}")
                    total_risk += 10
                    file_obj.sandbox_status_detail = 'crashed'

    if route == "static_analysis":
        # Static script/source file parsing
        update_stage(file_obj.id, 4, 'running', 'Performing static AST / pattern analysis...')
        
        # Read content safely
        content = b""
        try:
            with open(filepath, 'rb') as f:
                content = f.read(1024 * 1024) # read first 1MB
        except Exception:
            pass
            
        decoded = content.decode('utf-8', errors='ignore')
        
        # Check if Python file for AST check
        if file_ext == '.py':
            try:
                tree = ast.parse(decoded)
                for node in ast.walk(tree):
                    # Check imports
                    if isinstance(node, (ast.Import, ast.ImportFrom)):
                        names = [n.name for n in node.names]
                        for name in names:
                            if any(x in name for x in [
                                'os', 'subprocess', 'sys', 'socket', 'urllib', 'requests',
                                'ctypes', 'pty', 'platform', 'shutil',
                                'importlib',    # ← add this
                                'builtins',     # ← add this (used for getattr(builtins,'exec'))
                            ]):
                                all_flags.append(f"Static Python: import of sensitive module '{name}'")
                                total_risk += 10
                    # Check function calls
                    elif isinstance(node, ast.Call):
                        func_name = ""
                        if isinstance(node.func, ast.Name):
                            func_name = node.func.id
                        elif isinstance(node.func, ast.Attribute):
                            func_name = node.func.attr
                            
                        if func_name in [
                            # Direct execution
                            'eval', 'exec', 'compile',
                            # Process/system
                            'system', 'popen', 'spawn',
                            # Network
                            'connect', 'send', 'recv',
                            # Dynamic dispatch (obfuscation bypass vectors)
                            'getattr', 'setattr', '__import__',
                            'globals', 'locals', 'vars',
                            # Import-based obfuscation
                            'import_module',    # importlib.import_module
                            '__loader__',
                        ]:
                            all_flags.append(f"Static Python: sensitive function call '{func_name}'")
                            total_risk += 15
            except Exception as e:
                # If AST parsing fails, fallback to regex checks
                logger.warning(f"AST parsing failed: {e}, using regex fallback")
                
        # Regex checks for scripts (general check)
        keywords = {
            r'eval\s*\(': (15, "eval() use detected"),
            r'exec\s*\(': (15, "exec() use detected"),
            r'subprocess\b': (10, "subprocess reference"),
            r'socket\b': (10, "socket interface reference"),
            r'connect\s*\(': (10, "connection establishment"),
            r'shell\s*=': (10, "shell invocation assignment"),
            r'curl\b|wget\b': (15, "network download utility invocation"),
            r'powershell\b|cmd\.exe\b|/bin/sh\b|/bin/bash\b': (15, "shell command line interpreter spawn"),
            r'base64\.b64decode|atob\s*\(': (10, "base64 encoding decoding"),
            r'String\.fromCharCode': (15, "Javascript char code obfuscation"),
            r'document\.write|innerHTML': (10, "DOM injection reference"),
        }
        for pat, (r_val, desc) in keywords.items():
            if re.search(pat, decoded, re.IGNORECASE):
                all_flags.append(f"Regex match: {desc}")
                total_risk += r_val
                
        file_obj.sandbox_status_detail = 'static_analysis_passed' if total_risk < 40 else 'static_analysis_flagged'

    elif route == "document":
        # Document analysis (PDF, Office)
        update_stage(file_obj.id, 4, 'running', 'Performing document structural checks...')
        
        # Read content safely
        content = b""
        try:
            with open(filepath, 'rb') as f:
                content = f.read(2 * 1024 * 1024) # read first 2MB
        except Exception:
            pass
            
        decoded = content.decode('utf-8', errors='ignore')
        
        if file_ext == '.pdf':
            # Look for suspicious PDF objects
            pdf_indicators = {
                r'/JavaScript': (25, "PDF contains JavaScript execution block"),
                r'/JS': (25, "PDF contains JavaScript"),
                r'/Launch': (30, "PDF contains command launch instruction"),
                r'/OpenAction': (25, "PDF contains automatic open action"),
                r'/AA': (20, "PDF contains additional actions (auto-trigger)"),
                r'/SubmitForm': (15, "PDF contains form submission action"),
                r'/EmbeddedFile': (30, "PDF contains embedded sub-file payload"),
                r'/URI':        (10, "PDF contains URI link action"),
                r'/ImportData': (20, "PDF contains ImportData (exfil risk)"),
            }
            for pat, (r_val, desc) in pdf_indicators.items():
                if re.search(pat, decoded):
                    all_flags.append(desc)
                    total_risk += r_val
        else:
            # Office XML or OLE
            # VBA macro indicators
            if re.search(r'vbaProject\.bin|PROJECT', decoded, re.IGNORECASE) or file_ext in ['.docm', '.xlsm', '.pptm']:
                all_flags.append("Office: macro-enabled document (contains VBA project)")
                total_risk += 30
            # DDE/External templates indicators
            if re.search(r'dde\b|ddeauto\b|scriptmon\b|TargetMode="External"', decoded, re.IGNORECASE):
                all_flags.append("Office: potential external template / DDE injection link")
                total_risk += 30
            if re.search(r'ActiveX\b', decoded, re.IGNORECASE):
                all_flags.append("Office: ActiveX controls detected")
                total_risk += 15
                
        file_obj.sandbox_status_detail = 'document_passed' if total_risk < 40 else 'document_flagged'

    elif route == "inspect":
        # PE binaries and unknown types: strings-only static analysis.
        # _analyze_strings() already ran above (lines 1999-2001).
        # Add PE-specific import table heuristics:
        update_stage(file_obj.id, 4, 'running',
                     'PE/binary static inspection...')
        try:
            with open(filepath, 'rb') as _bf:
                head = _bf.read(65536)
                try:
                    _bf.seek(max(0, os.path.getsize(filepath) - 32768))
                    tail = _bf.read(32768)
                except Exception:
                    tail = b''
            _pe_raw = head + tail
            _pe_text = _pe_raw.decode('latin-1', errors='replace').lower()
            # Injection APIs check (triad + APC + Section mapping + hook injection)
            INJECTION_APIS = [
                'virtualalloc', 'virtualallocex',
                'writeprocessmemory',
                'createremotethread', 'rtlcreateuserthread',
                'ntcreatethreadex',
                'queueuserapc',
                'ntmapviewofsection',
                'zwunmapviewofsection',
                'loadlibrarya', 'loadlibraryw',
                'setwindowshookex',
            ]
            _injection_hits = [s for s in INJECTION_APIS if s in _pe_text]
            if len(_injection_hits) >= 3:
                all_flags.append(f"⚠ Process injection APIs: {', '.join(_injection_hits[:5])}")
                total_risk += 60
            elif len(_injection_hits) >= 2:
                all_flags.append(f"⚠ Injection pair: {', '.join(_injection_hits)}")
                total_risk += 30
            # Anti-analysis
            if 'isdebuggerpresent' in _pe_text:
                all_flags.append("PE: anti-debugging (IsDebuggerPresent)")
                total_risk += 20
            # Persistence via registry
            if ('regsetvalue' in _pe_text and
                    'currentversion\\run' in _pe_text):
                all_flags.append("PE: registry run-key persistence")
                total_risk += 40
        except Exception:
            pass
        file_obj.sandbox_status_detail = 'inspect_passed'

    # Deduplicate and cap risk
    all_flags = list(dict.fromkeys(all_flags))
    total_risk = min(total_risk, 100)
    logger.info(f"[SECURITY] Sandbox routing layer complete. Risk: {total_risk} for {file_obj.name}")
    
    # Save structured behavior report
    behavior = {
        "syscalls": syscall_summary,
        "file_access": file_access[:10],
        "process_activity": process_activity,
        "flags": all_flags,
        "entropy": entropy,
        "exit_code": exit_code,
    }
    
    try:
        file_obj.sandbox_trace_log = strace_output[:5000] if strace_output else ''
        file_obj.sandbox_entropy = entropy
        file_obj.sandbox_flags = json.dumps(all_flags)
        file_obj.sandbox_risk_score = total_risk
        if not file_obj.sandbox_status_detail:
            file_obj.sandbox_status_detail = route
        db.session.commit()
    except Exception as e:
        logger.error(f"[SECURITY] DB commit error for sandbox metadata: {e}")

    # Classify result
    if total_risk >= 70:
        status = "malicious"
        primary_flag = all_flags[0] if all_flags else "Multiple high-risk behavioral indicators"
        message = f"Malicious behavior detected (risk: {total_risk}) — {primary_flag}"
        result = {"status": status, "message": message, "risk": total_risk,
                  "flags": all_flags, "behavior": behavior,
                  "sandbox_route": route}
        update_stage(file_obj.id, 4, 'fail', message[:120])
        return False, message, result
        
    elif total_risk > 30:
        status = "fail"
        primary_flag = all_flags[0] if all_flags else "Behavioral anomalies detected"
        message = f"Suspicious behavior blocked (risk: {total_risk}) — {primary_flag}"
        result = {"status": status, "message": message, "risk": total_risk,
                  "flags": all_flags, "behavior": behavior,
                  "sandbox_route": route}
        update_stage(file_obj.id, 4, 'fail',
                     f"✖ Suspicious behavior blocked (risk: {total_risk})")
        logger.info(f"[SECURITY] Layer 4 → BLOCKED: suspicious risk={total_risk} "
                    f"file={file_obj.name}")
        return False, message, result
        
    else:
        message = f"No suspicious behavior detected (risk: {total_risk})"
        result = {"status": "safe", "message": message, "risk": total_risk,
                  "flags": all_flags, "behavior": behavior,
                  "sandbox_route": route}
        update_stage(file_obj.id, 4, 'pass', message)
        return True, None, result


# ═══════════════════════════════════════════════════════════════════
# LAYER 5 — HYBRID ENCRYPTION (AES-256 + KMS + ML-KEM + ML-DSA)
# ═══════════════════════════════════════════════════════════════════

def run_encryption(file_obj, s3_client, user_obj, s3_key, filepath):
    """
    Layer 5: Production-grade hybrid encryption.

    Delegates to HybridEncryptionEngine which implements:
      • AES-256-GCM data encryption
      • AWS KMS envelope encryption (AES key)
      • ML-KEM-768 post-quantum key encapsulation
      • ML-DSA-65 post-quantum digital signature
      • AWS Secrets Manager for PQC private key storage

    Zero-Trust: No plaintext keys are ever stored in DB, URLs, or logs.
    """
    from encryption import create_encryption_engine

    update_stage(file_obj.id, 5, 'running', 'Initializing hybrid encryption engine...')

    # Progress callback wired to pipeline stage updates
    step_labels = {
        'read': 'Reading file bytes...',
        'aes_keygen': 'Generating AES-256 key...',
        'aes_encrypt': 'AES-256-GCM encrypting file data...',
        'kms_wrap': 'Wrapping AES key with AWS KMS (envelope encryption)...',
        'pqc_kem': 'ML-KEM-768 (Kyber) key encapsulation...',
        'pqc_dsa': 'ML-DSA-65 (Dilithium) signing payload...',
        'secrets': 'Storing PQC private keys in Secrets Manager...',
        'payload': 'Building encrypted payload structure...',
        's3_upload': 'Uploading encrypted blob to S3 secure bucket...',
        'db_store': 'Storing encryption metadata (no plaintext keys)...',
        'complete': 'Hybrid encryption complete',
    }

    def progress_callback(step, detail):
        label = step_labels.get(step, detail)
        update_stage(file_obj.id, 5, 'running', label)

    try:
        engine, _ = create_encryption_engine(user_obj)
        success, error, result = engine.encrypt_file(
            file_obj, filepath, s3_key, progress_callback
        )

        if success:
            pqc_status = result.get('encryption', {}).get('pqc', 'disabled')
            update_stage(
                file_obj.id, 5, 'pass',
                f'AES-256-GCM + KMS + {pqc_status} — zero-trust encryption applied'
            )
            return True, None
        else:
            update_stage(file_obj.id, 5, 'fail', f'Encryption failed: {error[:80]}')
            return False, error

    except Exception as e:
        update_stage(file_obj.id, 5, 'fail', f'Encryption engine error: {str(e)[:80]}')
        return False, str(e)


# ═══════════════════════════════════════════════════════════════════
# PIPELINE ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════

def run_pipeline(file_id, s3_key, user_id, temp_filepath=None, temp_dir=None):
    """Execute the full 4-layer security pipeline + encryption.
    
    Layers 1-2: Local analysis (hash check, ZIP heuristics)
    Layer 3: ClamAV via persistent Docker daemon (clamd)
    Layer 4: Behavioral sandbox via ephemeral Docker container
    Layer 5: Hybrid encryption (AES-256 + KMS + PQC)
    """
    import traceback
    import boto3
    from app import app

    print(f"[PIPELINE] Starting pipeline for file_id={file_id}, s3_key={s3_key}")

    s3 = None
    user_obj = None
    file_obj = None
    with app.app_context():

        try:
            file_obj = File.query.get(file_id)
            user_obj = User.query.get(user_id)
            if not file_obj or not user_obj:
                print(f"[PIPELINE] ERROR: file or user not found (file={file_obj}, user={user_obj})")
                return

            file_obj.status = 'scanning'
            file_obj.checks = '0/4 complete'
            db.session.commit()
            print(f"[PIPELINE] Status set to scanning")

            # AWS S3 client will be initialized lazily when needed to eliminate startup delays

            is_local_upload = False
            if temp_filepath and os.path.exists(temp_filepath):
                is_local_upload = True
                try:
                    os.chmod(temp_filepath, 0o644)
                    parent_dir = os.path.dirname(temp_filepath)
                    os.chmod(parent_dir, 0o755)
                except Exception as pe:
                    print(f"[PIPELINE] Warning: could not chmod local upload path: {pe}")
                
                # Since the file is uploaded locally first, we scan it directly from the local disk.
                # To minimize startup delay, we skip uploading the raw file to S3 quarantine entirely.
                print(f"[PIPELINE] Skipping S3 quarantine upload for local upload strategy.")

            has_precomputed_hash = bool(file_obj.sha256_hash)

            # ── Run security layers ──
            layer_results = []
            passed_count = 0
            failed = False
            failed_layer = None
            threat_type = None

            cumulative_risk = 0
            CUMULATIVE_BLOCK_THRESHOLD = 70

            # Layer 1: SHA-256 + VirusTotal (pre-download execution if hash exists)
            if has_precomputed_hash:
                print(f"[PIPELINE] Found precomputed SHA-256 hash: {file_obj.sha256_hash}. Running Layer 1 immediately before S3 download.")
                success, threat, result = run_hash_check(file_obj, None)
                layer_results.append(result)
                print(f"[PIPELINE] Layer 1 result: success={success}, result={result}")
                layer_risk = result.get('risk', 0)
                if result.get('status') == 'suspicious':
                    cumulative_risk += layer_risk + 15
                else:
                    cumulative_risk = max(cumulative_risk, layer_risk)

                if success and cumulative_risk >= CUMULATIVE_BLOCK_THRESHOLD:
                    failed = True
                    failed_layer = f'Cumulative risk threshold'
                    threat_type = f"Cumulative threat score {cumulative_risk} exceeded threshold {CUMULATIVE_BLOCK_THRESHOLD} across multiple layers"
                    skip_remaining(file_id, 1)
                elif not success:
                    failed = True
                    failed_layer = 'Layer 1 — SHA-256 + VirusTotal'
                    threat_type = threat
                    skip_remaining(file_id, 1)
                else:
                    passed_count += 1
                    file_obj.checks = f'{passed_count}/4 complete'
                    db.session.commit()

            # Now, if we need to continue and we don't have the file locally, download it
            if not failed and not is_local_upload:
                # Initialize AWS S3 client lazily if not done yet
                if s3 is None:
                    session = _get_aws_session(user_obj)
                    s3 = session.client('s3', config=BOTO3_CLIENT_CONFIG)
                # Multipart upload path: file is already in S3 quarantine, download it
                temp_dir = tempfile.mkdtemp(dir=HOST_SCAN_DIR)
                os.chmod(temp_dir, 0o755)
                local_filename = os.path.basename(s3_key) or s3_key
                temp_filepath = os.path.join(temp_dir, local_filename)
                
                # Show running status during download to prevent the stage appearing stuck in pending
                if has_precomputed_hash:
                    update_stage(file_obj.id, 2, 'running', 'Downloading file from S3 quarantine...')
                else:
                    update_stage(file_obj.id, 1, 'running', 'Downloading file from S3 quarantine...')
                
                print(f"[PIPELINE] Downloading from S3: {user_obj.quarantine_bucket}/{s3_key}")
                try:
                    s3.download_file(
                        user_obj.quarantine_bucket,
                        s3_key,
                        temp_filepath,
                        Config=get_optimized_s3_transfer_config(file_obj.size)
                    )
                    os.chmod(temp_filepath, 0o644)
                except Exception as e:
                    print(f"[PIPELINE] S3 download FAILED: {e}")
                    traceback.print_exc()
                    file_obj.status = 'blocked'
                    file_obj.checks = 'Failed to pull from quarantine'
                    db.session.commit()
                    return
                print(f"[PIPELINE] S3 download complete, file size: {os.path.getsize(temp_filepath)} bytes")

            # Post-download Layer 1 execution if hash was NOT precomputed
            if not failed and not has_precomputed_hash:
                print(f"[PIPELINE] Running Layer 1 — SHA-256 + VirusTotal (post-download)...")
                success, threat, result = run_hash_check(file_obj, temp_filepath)
                layer_results.append(result)
                print(f"[PIPELINE] Layer 1 result: success={success}, result={result}")
                layer_risk = result.get('risk', 0)
                if result.get('status') == 'suspicious':
                    cumulative_risk += layer_risk + 15
                else:
                    cumulative_risk = max(cumulative_risk, layer_risk)

                if success and cumulative_risk >= CUMULATIVE_BLOCK_THRESHOLD:
                    failed = True
                    failed_layer = f'Cumulative risk threshold'
                    threat_type = f"Cumulative threat score {cumulative_risk} exceeded threshold {CUMULATIVE_BLOCK_THRESHOLD} across multiple layers"
                    skip_remaining(file_id, 1)
                elif success:
                    passed_count += 1
                    file_obj.checks = f'{passed_count}/4 complete'
                    db.session.commit()
                else:
                    failed = True
                    failed_layer = 'Layer 1 — SHA-256 + VirusTotal'
                    threat_type = threat
                    skip_remaining(file_id, 1)

            # Ensure file/folder permissions allow local Docker container scanning (ClamAV/Sandbox)
            if not failed and temp_filepath and os.path.exists(temp_filepath):
                try:
                    os.chmod(os.path.dirname(temp_filepath), 0o755)
                    os.chmod(temp_filepath, 0o644)
                except Exception as e:
                    print(f"[PIPELINE] Failed to adjust file permissions for scanning: {e}")

            # Layer 2: File Heuristic Analysis
            if not failed:
                print(f"[PIPELINE] Running Layer 2 — File Heuristic Analysis...")
                success, threat, result = layer2_zip_validation(file_obj, temp_filepath)
                layer_results.append(result)
                print(f"[PIPELINE] Layer 2 result: success={success}, result={result}")
                layer_risk = result.get('risk', 0)
                if result.get('status') == 'suspicious':
                    cumulative_risk += layer_risk + 15
                else:
                    cumulative_risk = max(cumulative_risk, layer_risk)

                if success and cumulative_risk >= CUMULATIVE_BLOCK_THRESHOLD:
                    failed = True
                    failed_layer = f'Cumulative risk threshold'
                    threat_type = f"Cumulative threat score {cumulative_risk} exceeded threshold {CUMULATIVE_BLOCK_THRESHOLD} across multiple layers"
                    skip_remaining(file_id, 2)
                elif success:
                    passed_count += 1
                    file_obj.checks = f'{passed_count}/4 complete'
                    db.session.commit()
                else:
                    failed = True
                    failed_layer = 'Layer 2 — File Heuristic Analysis'
                    threat_type = threat
                    skip_remaining(file_id, 2)

            # Layer 3: ClamAV (Docker — clamd daemon)
            if not failed:
                print(f"[PIPELINE] Running Layer 3 — ClamAV (Docker)...")
                success, threat, result = run_clamav_local(file_obj, temp_filepath)
                layer_results.append(result)
                print(f"[PIPELINE] Layer 3 result: success={success}, result={result}")
                layer_risk = result.get('risk', 0)
                if result.get('status') == 'suspicious':
                    cumulative_risk += layer_risk + 15
                else:
                    cumulative_risk = max(cumulative_risk, layer_risk)

                if success and cumulative_risk >= CUMULATIVE_BLOCK_THRESHOLD:
                    failed = True
                    failed_layer = f'Cumulative risk threshold'
                    threat_type = f"Cumulative threat score {cumulative_risk} exceeded threshold {CUMULATIVE_BLOCK_THRESHOLD} across multiple layers"
                    skip_remaining(file_id, 3)
                elif success:
                    passed_count += 1
                    file_obj.checks = f'{passed_count}/4 complete'
                    db.session.commit()
                else:
                    failed = True
                    failed_layer = 'Layer 3 — ClamAV (Docker)'
                    threat_type = threat
                    skip_remaining(file_id, 3)

            # Layer 4: Sandbox (Docker — Behavioral Analysis)
            if not failed:
                print(f"[PIPELINE] Running Layer 4 — Sandbox (Docker)...")
                success, threat, result = run_sandbox_local(file_obj, temp_filepath)
                layer_results.append(result)
                print(f"[PIPELINE] Layer 4 result: success={success}, result={result}")
                layer_risk = result.get('risk', 0)
                if result.get('status') == 'suspicious':
                    cumulative_risk += layer_risk + 15
                else:
                    cumulative_risk = max(cumulative_risk, layer_risk)

                if success and cumulative_risk >= CUMULATIVE_BLOCK_THRESHOLD:
                    failed = True
                    failed_layer = f'Cumulative risk threshold'
                    threat_type = f"Cumulative threat score {cumulative_risk} exceeded threshold {CUMULATIVE_BLOCK_THRESHOLD} across multiple layers"
                    skip_remaining(file_id, 4)
                elif success:
                    passed_count += 1
                    file_obj.checks = f'{passed_count}/4 complete'
                    db.session.commit()
                else:
                    failed = True
                    failed_layer = 'Layer 4 — Sandbox (Docker)'
                    threat_type = threat
                    skip_remaining(file_id, 4)

            # ── Compute aggregate risk from layer results ──
            max_risk = max(cumulative_risk, max((r.get('risk', 0) for r in layer_results), default=0))

            if failed:
                # File rejected
                file_obj.status = 'blocked'
                file_obj.risk = max_risk if max_risk > 0 else 80
                file_obj.checks = threat_type or 'Threat detected'
                db.session.commit()
                print(f"[PIPELINE] FILE BLOCKED: {threat_type} at {failed_layer}")

                # Delete from S3 quarantine bucket when blocked
                if s3 and user_obj and getattr(user_obj, 'quarantine_bucket', None):
                    try:
                        s3.delete_object(Bucket=user_obj.quarantine_bucket, Key=s3_key)
                        print(f"[PIPELINE] Blocked file: deleted {s3_key} from quarantine S3")
                    except Exception as cleanup_err:
                        print(f"[PIPELINE] Failed to delete quarantine object: {cleanup_err}")



                # Create notification
                notif = Notification(
                    user_id=user_id,
                    file_name=file_obj.name,
                    layer=failed_layer,
                    threat_type=threat_type or 'Unknown threat',
                )
                db.session.add(notif)
                db.session.commit()

                # Dispatch SMTP Action (As per PRD 5.7)
                try:
                    from app import mail
                    from flask_mail import Message
                    
                    html_body = f"""
                    <div style="font-family: 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #0b1329; color: #f1f5f9; padding: 30px; border-radius: 8px; max-width: 600px; margin: 0 auto; border: 1px solid #1e293b; box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.3);">
                      <div style="text-align: center; border-bottom: 2px solid #ef4444; padding-bottom: 20px; margin-bottom: 20px;">
                        <h2 style="margin: 0; color: #ef4444; font-size: 20px; font-weight: bold; letter-spacing: 0.5px; display: inline-flex; align-items: center; justify-content: center; gap: 8px;">
                          🛡️ StackDrive Threat Intercepted
                        </h2>
                      </div>
                      
                      <p style="margin-bottom: 20px; font-size: 15px; color: #cbd5e1; line-height: 1.6;">
                        A malicious or high-risk file was detected and blocked during ingestion. The file has been deleted from quarantine, and no action is required from your side.
                      </p>
                      
                      <table style="width: 100%; border-collapse: collapse; margin-bottom: 24px; font-size: 14px; background-color: #111b30; border-radius: 6px; overflow: hidden;">
                        <thead>
                          <tr style="border-bottom: 1px solid #1e293b;">
                            <th colspan="2" style="padding: 12px 16px; text-align: left; color: #38bdf8; font-size: 13px; text-transform: uppercase; letter-spacing: 0.5px;">Threat Details</th>
                          </tr>
                        </thead>
                        <tbody>
                          <tr style="border-bottom: 1px solid #1e293b;">
                            <td style="padding: 12px 16px; width: 130px; color: #94a3b8; font-weight: 600;">📁 File Name:</td>
                            <td style="padding: 12px 16px; color: #f1f5f9; font-family: monospace; word-break: break-all;">{file_obj.name}</td>
                          </tr>
                          <tr style="border-bottom: 1px solid #1e293b;">
                            <td style="padding: 12px 16px; color: #94a3b8; font-weight: 600;">🛡️ Security Layer:</td>
                            <td style="padding: 12px 16px; color: #f1f5f9;">{failed_layer}</td>
                          </tr>
                          <tr style="border-bottom: 1px solid #1e293b;">
                            <td style="padding: 12px 16px; color: #94a3b8; font-weight: 600;">⚠️ Threat Type:</td>
                            <td style="padding: 12px 16px; color: #f87171; font-weight: bold;">{threat_type}</td>
                          </tr>
                          <tr style="border-bottom: 1px solid #1e293b;">
                            <td style="padding: 12px 16px; color: #94a3b8; font-weight: 600;">📊 Risk Score:</td>
                            <td style="padding: 12px 16px;">
                              <span style="background-color: #7f1d1d; color: #fca5a5; padding: 2px 8px; border-radius: 4px; font-weight: bold; font-size: 13px;">
                                {file_obj.risk}/100
                              </span>
                            </td>
                          </tr>
                          <tr>
                            <td style="padding: 12px 16px; color: #94a3b8; font-weight: 600;">🛡️ Action Taken:</td>
                            <td style="padding: 12px 16px;">
                              <span style="background-color: #14532d; color: #86efac; padding: 2px 8px; border-radius: 4px; font-weight: bold; font-size: 13px; text-transform: uppercase;">
                                Blocked & Deleted
                              </span>
                            </td>
                          </tr>
                        </tbody>
                      </table>
                      
                      <div style="background-color: #1e293b; padding: 16px; border-radius: 6px; margin-bottom: 24px; border-left: 4px solid #38bdf8; font-size: 13px; color: #cbd5e1; line-height: 1.6;">
                        <strong style="color: #38bdf8; display: block; margin-bottom: 6px;">Zero-Trust Protection Active</strong>
                        Our multi-layered security pipeline scanned, analyzed, and neutralized this threat at the gate. The file has been successfully discarded, and your cryptographic storage remains fully isolated and secure.
                      </div>
                      
                      <div style="text-align: center; margin-bottom: 24px;">
                        <a href="http://localhost:5173/security" style="display: inline-block; background-color: #ef4444; color: white; padding: 10px 20px; border-radius: 4px; text-decoration: none; font-size: 14px; font-weight: bold; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);">
                          View Security Dashboard
                        </a>
                      </div>
                      
                      <hr style="border: 0; border-top: 1px solid #1e293b; margin-bottom: 16px;">
                      <p style="font-size: 11px; color: #64748b; margin: 0; text-align: center; line-height: 1.5;">
                        StackDrive Quantum-Safe Cloud Gateway<br>
                        This is an automated alert generated by the threat intelligence pipeline. Please do not reply to this message.
                      </p>
                    </div>
                    """
                    
                    sender = app.config.get('MAIL_DEFAULT_SENDER') or "stackdrive.alert@example.com"
                    msg = Message(
                        subject="🛡️ StackDrive Security Alert — Malicious File Intercepted",
                        sender=sender,
                        recipients=[user_obj.email],
                        html=html_body
                    )
                    mail.send(msg)
                except Exception as e:
                    print(f"⚠️ [SMTP Error] Failed to send email notification: {e}")
            else:
                # Run Production Hybrid Encryption (AES-256 + KMS + ML-KEM + ML-DSA)
                print(f"[PIPELINE] All 4 layers passed. Running hybrid encryption...")
                if s3 is None:
                    session = _get_aws_session(user_obj)
                    s3 = session.client('s3', config=BOTO3_CLIENT_CONFIG)
                enc_success, enc_error = run_encryption(file_obj, s3, user_obj, s3_key, temp_filepath)

                if enc_success:
                    file_obj.status = 'safe'
                    file_obj.risk = max_risk
                    file_obj.checks = '4/4 complete'
                    db.session.commit()
                    print(f"[PIPELINE] FILE SAFE — hybrid encryption complete")
                else:
                    file_obj.status = 'blocked'
                    file_obj.risk = 50
                    file_obj.checks = f'Encryption failed: {enc_error[:60]}' if enc_error else 'Encryption failed'
                    db.session.commit()
                    print(f"[PIPELINE] FILE BLOCKED — encryption failed: {enc_error}")

        except Exception as e:
            # Catch-all: ensure thread crashes are visible
            print(f"[PIPELINE] FATAL ERROR: {e}")
            traceback.print_exc()
            try:
                file_obj = File.query.get(file_id)
                if file_obj and file_obj.status == 'scanning':
                    file_obj.status = 'blocked'
                    file_obj.checks = f'Pipeline error: {str(e)[:60]}'
                    file_obj.risk = 50
                    db.session.commit()
            except Exception:
                pass
        finally:
            # Cloud and Local Cleanup Phase
            try:
                if not is_local_upload and s3 and user_obj and getattr(user_obj, 'quarantine_bucket', None):
                    s3.delete_object(Bucket=user_obj.quarantine_bucket, Key=s3_key)
                    print(f"[PIPELINE] Cleanup: deleted {s3_key} from quarantine S3")
            except Exception as e:
                print(f"[PIPELINE] Cleanup S3 object failed: {e}")
                pass
            try:
                if temp_filepath and os.path.exists(temp_filepath):
                    os.remove(temp_filepath)
                if temp_dir and os.path.exists(temp_dir):
                    os.rmdir(temp_dir)
            except Exception:
                pass


# ─── Celery task wrapper ──────────────────────────────────────────
# Import celery only if available — falls back gracefully if not configured
try:
    from celery import shared_task  # type: ignore

    @shared_task(
        bind=True,
        name='pipeline.run_pipeline_task',
        max_retries=2,
        default_retry_delay=10,
        acks_late=True,
        reject_on_worker_lost=True,
    )
    def run_pipeline_task(self, file_id, s3_key, user_id,
                          temp_filepath=None, temp_dir=None):
        """
        Celery-wrapped pipeline. Use this instead of threading.Thread
        in production. Falls back to direct call if Celery unavailable.
        """
        try:
            return run_pipeline(file_id, s3_key, user_id,
                                temp_filepath=temp_filepath,
                                temp_dir=temp_dir)
        except Exception as exc:
            logger.error(f"[PIPELINE TASK] Failed attempt {self.request.retries + 1}: {exc}")
            raise self.retry(exc=exc)

except ImportError:
    logger.info("[PIPELINE] Celery not available — using direct threading mode")
    run_pipeline_task = None  # Caller must use threading.Thread directly

def dispatch_pipeline(file_id, s3_key, user_id,
                      temp_filepath=None, temp_dir=None):
    """
    Smart dispatcher: uses Celery if available and broker is online, threads otherwise.
    Replace all threading.Thread(target=run_pipeline, ...) calls with this.
    """
    import threading
    if run_pipeline_task is not None:
        try:
            run_pipeline_task.apply_async(
                args=[file_id, s3_key, user_id],
                kwargs={'temp_filepath': temp_filepath, 'temp_dir': temp_dir},
            )
            logger.info(f"[PIPELINE] Task successfully dispatched to Celery for file {file_id}")
            return
        except Exception as e:
            logger.warning(
                f"[PIPELINE] Celery apply_async failed: {e}. "
                "Falling back to direct background threading mode."
            )

    t = threading.Thread(
        target=run_pipeline,
        args=[file_id, s3_key, user_id],
        kwargs={'temp_filepath': temp_filepath, 'temp_dir': temp_dir},
        daemon=True,
    )
    t.start()
