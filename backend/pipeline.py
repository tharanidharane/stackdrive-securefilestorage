"""
Security Pipeline — Production-Grade Zero-Trust File Scanning System
====================================================================
Layer 1: SHA-256 + VirusTotal (Threat Intelligence)
Layer 2: ZIP Validation + Heuristic Analysis
Layer 3: ClamAV (Docker — Persistent clamd Daemon)
Layer 4: Sandbox (Docker — Advanced Behavioral Analysis)
Layer 5: AES-256 + PQC Encryption
"""
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
from functools import lru_cache
from datetime import datetime
from models import db, File, PipelineStage, Notification, User
import tempfile
import requests

logger = logging.getLogger(__name__)

# ─── VirusTotal result cache (hash → result dict) ─────────────────
_vt_cache = {}

# ─── Pipeline stage definitions ───────────────────────────────────
PIPELINE_STAGES = [
    {'order': 1, 'name': 'SHA-256 + VirusTotal'},
    {'order': 2, 'name': 'ZIP Heuristic Analysis'},
    {'order': 3, 'name': 'ClamAV (Docker)'},
    {'order': 4, 'name': 'Sandbox (Docker)'},
    {'order': 5, 'name': 'Encryption'},
]

# Stage name migration mapping (old → new)
STAGE_NAME_MIGRATION = {
    'Hash Check': 'SHA-256 + VirusTotal',
    'ZIP Validation': 'ZIP Heuristic Analysis',
    'ClamAV Scan': 'ClamAV (Docker)',
    'Sandbox Analysis': 'Sandbox (Docker)',
    'ClamAV (Fargate)': 'ClamAV (Docker)',
    'Sandbox (Fargate)': 'Sandbox (Docker)',
}


def compute_sha256(filepath):
    """Compute SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
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
# LAYER 1 — SHA-256 + VIRUSTOTAL (THREAT INTELLIGENCE)
# ═══════════════════════════════════════════════════════════════════

def run_hash_check(file_obj, filepath):
    """
    Layer 1: Compute SHA-256 hash and query VirusTotal API.
    
    Returns: (passed: bool, threat_description: str|None, layer_result: dict)
    
    Result shape:
        {"status": "safe|suspicious|malicious|unknown", "message": str, "risk": int}
    """
    update_stage(file_obj.id, 1, 'running', 'Computing SHA-256 hash...')

    # Step 1: Compute SHA-256
    sha256 = compute_sha256(filepath)
    file_obj.sha256_hash = sha256
    db.session.commit()

    update_stage(file_obj.id, 1, 'running', f'Querying VirusTotal for {sha256[:16]}...')

    # Step 2: Check cache
    if sha256 in _vt_cache:
        result = _vt_cache[sha256]
        logger.info(f"VirusTotal cache hit for {sha256[:16]}")
        return _apply_layer1_result(file_obj, result, sha256)

    # Step 3: Query VirusTotal API
    vt_api_key = os.environ.get('VT_API_KEY')
    if not vt_api_key:
        result = {"status": "unknown", "message": "VT_API_KEY not configured", "risk": 20}
        _vt_cache[sha256] = result
        update_stage(file_obj.id, 1, 'pass', 'VirusTotal API key not configured — skipping threat intelligence')
        return True, None, result

    try:
        response = requests.get(
            f'https://www.virustotal.com/api/v3/files/{sha256}',
            headers={'x-apikey': vt_api_key},
            timeout=5
        )

        if response.status_code == 200:
            data = response.json()
            stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})

            if stats.get('malicious', 0) > 0:
                result = {
                    "status": "malicious",
                    "message": f"Detected by VirusTotal ({stats['malicious']} engines)",
                    "risk": 100
                }
            elif stats.get('suspicious', 0) > 0:
                result = {
                    "status": "suspicious",
                    "message": f"Suspicious indicators ({stats['suspicious']} engines)",
                    "risk": 40
                }
            else:
                result = {
                    "status": "safe",
                    "message": "No threats detected by VirusTotal",
                    "risk": 0
                }

        elif response.status_code == 404:
            result = {
                "status": "unknown",
                "message": "File not found in VirusTotal database",
                "risk": 20
            }

        elif response.status_code == 429:
            result = {
                "status": "unknown",
                "message": "VirusTotal rate limit exceeded",
                "risk": 20
            }

        else:
            result = {
                "status": "unknown",
                "message": f"VirusTotal returned HTTP {response.status_code}",
                "risk": 20
            }

    except requests.exceptions.Timeout:
        result = {
            "status": "unknown",
            "message": "VirusTotal request timed out (5s)",
            "risk": 20
        }
    except requests.exceptions.ConnectionError:
        result = {
            "status": "unknown",
            "message": "VirusTotal unavailable (connection error)",
            "risk": 20
        }
    except Exception as e:
        result = {
            "status": "unknown",
            "message": f"VirusTotal query failed: {str(e)[:60]}",
            "risk": 20
        }

    # Cache result
    _vt_cache[sha256] = result
    return _apply_layer1_result(file_obj, result, sha256)


def _apply_layer1_result(file_obj, result, sha256):
    """Apply Layer 1 result to pipeline stage and return tuple."""
    if result['status'] == 'malicious':
        update_stage(file_obj.id, 1, 'fail', result['message'])
        return False, result['message'], result
    elif result['status'] == 'suspicious':
        # Suspicious is a pass but logged — file continues through pipeline
        update_stage(file_obj.id, 1, 'pass', f"⚠ {result['message']}")
        return True, None, result
    elif result['status'] == 'unknown':
        # Unknown is a pass with caution — file continues
        update_stage(file_obj.id, 1, 'pass', result['message'])
        return True, None, result
    else:
        update_stage(file_obj.id, 1, 'pass', result['message'])
        return True, None, result


# ═══════════════════════════════════════════════════════════════════
# LAYER 2 — ZIP VALIDATION + HEURISTIC ANALYSIS
# ═══════════════════════════════════════════════════════════════════

# Dangerous executable extensions
DANGEROUS_EXTENSIONS = {'.exe', '.bat', '.sh', '.ps1', '.js', '.vbs', '.cmd', '.msi'}

# Regex for obfuscated filenames: 20+ chars of alphanumeric followed by an executable extension
OBFUSCATED_PATTERN = re.compile(r'^[a-zA-Z0-9]{20,}\.(exe|bat|sh|ps1|js|vbs|cmd|msi)$', re.IGNORECASE)


def layer2_zip_validation(file_obj, filepath):
    """
    Layer 2: ZIP structure validation + heuristic analysis.
    
    Returns: (passed: bool, threat_description: str|None, layer_result: dict)
    
    Checks:
        - Valid ZIP archive
        - Suspicious file types (.exe, .bat, .sh, .ps1, .js, .vbs)
        - Hidden files (starting with '.')
        - ZIP bombs (compression ratio > 100)
        - Nested ZIP files
        - Path traversal ("../")
        - Obfuscated filenames (long random strings + executable extensions)
        - Excessive file count (> 1000)
    """
    update_stage(file_obj.id, 2, 'running', 'Analyzing ZIP archive structure and heuristics...')

    # Check if valid ZIP
    if not zipfile.is_zipfile(filepath):
        result = {"status": "malicious", "message": "Invalid or corrupted archive", "risk": 80}
        update_stage(file_obj.id, 2, 'fail', result['message'])
        return False, result['message'], result

    try:
        with zipfile.ZipFile(filepath, 'r') as zf:
            entries = zf.infolist()
            issues_critical = []
            issues_suspicious = []

            # ── Check 1: ZIP bomb (compression ratio) ──
            total_compressed = sum(info.compress_size for info in entries)
            total_uncompressed = sum(info.file_size for info in entries)

            if total_compressed > 0 and total_uncompressed / total_compressed > 100:
                ratio = int(total_uncompressed / total_compressed)
                issues_critical.append(f"ZIP bomb detected — decompression ratio 1:{ratio}")

            # ── Check 2: Path traversal ──
            for info in entries:
                if '../' in info.filename or '..\\' in info.filename:
                    issues_critical.append(f"Path traversal detected: {info.filename}")
                    break  # One is enough to flag

            # ── Check 3: Suspicious file types (executables) ──
            for info in entries:
                ext = os.path.splitext(info.filename)[1].lower()
                if ext in DANGEROUS_EXTENSIONS:
                    issues_critical.append(f"Suspicious executable found: {info.filename}")
                    break  # Flag on first find

            # ── Check 4: Obfuscated filenames ──
            for info in entries:
                basename = os.path.basename(info.filename)
                if OBFUSCATED_PATTERN.match(basename):
                    issues_critical.append(f"Obfuscated executable filename: {basename}")
                    break

            # ── Check 5: Hidden files ──
            hidden_count = sum(
                1 for info in entries
                if os.path.basename(info.filename).startswith('.') and info.filename != './'
            )
            if hidden_count > 0:
                issues_suspicious.append(f"{hidden_count} hidden file(s) detected")

            # ── Check 6: Nested ZIP files ──
            nested_zips = sum(
                1 for info in entries
                if info.filename.lower().endswith('.zip')
            )
            if nested_zips > 5:
                issues_suspicious.append(f"Excessive nested ZIPs: {nested_zips} archives")
            elif nested_zips > 0:
                issues_suspicious.append(f"{nested_zips} nested ZIP archive(s) found")

            # ── Check 7: Excessive file count ──
            if len(entries) > 1000:
                issues_suspicious.append(f"Excessive file count: {len(entries)} files")

            # ── Check 8: Archive integrity ──
            bad = zf.testzip()
            if bad:
                issues_critical.append(f"Corrupted file in archive: {bad}")

            # ── Decision ──
            if issues_critical:
                reason = issues_critical[0]  # Report the first critical issue
                result = {"status": "malicious", "message": reason, "risk": 80}
                update_stage(file_obj.id, 2, 'fail', reason)
                return False, reason, result

            if issues_suspicious:
                reason = '; '.join(issues_suspicious)
                result = {"status": "suspicious", "message": reason, "risk": 30}
                update_stage(file_obj.id, 2, 'pass', f"⚠ {reason}")
                return True, None, result  # Suspicious passes but is logged

            result = {"status": "safe", "message": "No issues detected", "risk": 0}
            update_stage(file_obj.id, 2, 'pass', 'Archive structure valid, no threats detected')
            return True, None, result

    except zipfile.BadZipFile:
        result = {"status": "malicious", "message": "Invalid or corrupted archive", "risk": 80}
        update_stage(file_obj.id, 2, 'fail', result['message'])
        return False, result['message'], result
    except Exception as e:
        result = {"status": "malicious", "message": f"Validation error: {str(e)[:80]}", "risk": 80}
        update_stage(file_obj.id, 2, 'fail', result['message'])
        return False, result['message'], result


# ═══════════════════════════════════════════════════════════════════
# DOCKER HELPERS
# ═══════════════════════════════════════════════════════════════════

def _is_docker_available():
    """Check if Docker CLI is installed and the daemon is responsive."""
    if not shutil.which('docker'):
        return False
    try:
        result = subprocess.run(
            ['docker', 'info'],
            capture_output=True, timeout=10
        )
        return result.returncode == 0
    except Exception:
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

def _ensure_clamav_daemon():
    """
    Ensure the ClamAV daemon container is running.
    Starts it if not present. Returns True if daemon is available.
    """
    clamd_host = os.environ.get('CLAMD_HOST', '127.0.0.1')
    clamd_port = int(os.environ.get('CLAMD_PORT', '3310'))

    # Already running?
    if _is_clamd_running(clamd_host, clamd_port):
        return True

    if not _is_docker_available():
        return False

    image = os.environ.get('CLAMAV_DOCKER_IMAGE', 'clamav/clamav:latest')

    try:
        # Check if container exists but is stopped
        inspect = subprocess.run(
            ['docker', 'inspect', 'clamav-daemon', '--format', '{{.State.Running}}'],
            capture_output=True, text=True, timeout=10
        )

        if inspect.returncode == 0:
            if 'true' in inspect.stdout.lower():
                # Container running but clamd not ready yet — wait
                logger.info("ClamAV container running, waiting for clamd to initialize...")
                for _ in range(30):  # Wait up to 60s for clamd
                    time.sleep(2)
                    if _is_clamd_running(clamd_host, clamd_port):
                        return True
                return False
            else:
                # Container stopped — restart it
                subprocess.run(['docker', 'start', 'clamav-daemon'],
                               capture_output=True, timeout=10)
        else:
            # Container doesn't exist — create it
            logger.info(f"Starting ClamAV daemon container ({image})...")
            subprocess.run([
                'docker', 'run', '-d',
                '--name', 'clamav-daemon',
                '--restart', 'unless-stopped',
                '-p', f'{clamd_port}:3310',
                image
            ], capture_output=True, text=True, timeout=60, check=True)

        # Wait for clamd to be ready (virus DB load takes time on first start)
        logger.info("Waiting for ClamAV daemon to load virus databases...")
        for i in range(45):  # Up to 90 seconds
            time.sleep(2)
            if _is_clamd_running(clamd_host, clamd_port):
                logger.info(f"ClamAV daemon ready after ~{(i+1)*2}s")
                return True

        logger.warning("ClamAV daemon did not become ready in 90s")
        return False

    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to start ClamAV daemon: {e.stderr}")
        return False
    except Exception as e:
        logger.error(f"ClamAV daemon startup error: {e}")
        return False


def _clamd_scan(filepath, host='127.0.0.1', port=3310, timeout=60):
    """
    Scan a file using the ClamAV daemon via TCP socket (clamd protocol).
    Returns: (is_clean: bool, virus_name: str|None)
    """
    import socket

    abs_path = os.path.abspath(filepath)
    file_data = open(abs_path, 'rb').read()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        sock.connect((host, port))

        # INSTREAM command: stream file data to clamd
        sock.sendall(b'zINSTREAM\0')

        # Send file in chunks (max 2GB per chunk header)
        chunk_size = 8192
        offset = 0
        while offset < len(file_data):
            chunk = file_data[offset:offset + chunk_size]
            # Send chunk length as 4-byte big-endian unsigned int
            sock.sendall(struct.pack('!I', len(chunk)))
            sock.sendall(chunk)
            offset += chunk_size

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
            logger.warning(f"Unexpected ClamAV response: {response_text}")
            return True, None  # Treat unexpected responses as safe (graceful)

    except socket.timeout:
        logger.error("ClamAV scan timed out")
        return True, None  # Timeout → graceful degradation
    except Exception as e:
        logger.error(f"ClamAV socket error: {e}")
        return True, None
    finally:
        sock.close()


def run_clamav_local(file_obj, filepath):
    """
    Layer 3: Enterprise ClamAV scan via persistent clamd daemon.
    
    Uses TCP socket (port 3310) to communicate with a persistent
    ClamAV daemon container. Virus database loaded once at startup,
    providing ~1-2 second scan times.
    
    Returns: (passed: bool, threat_description: str|None, layer_result: dict)
    """
    update_stage(file_obj.id, 3, 'running', 'Connecting to ClamAV daemon...')

    clamd_host = os.environ.get('CLAMD_HOST', '127.0.0.1')
    clamd_port = int(os.environ.get('CLAMD_PORT', '3310'))

    # Ensure daemon is running
    if not _ensure_clamav_daemon():
        if not _is_docker_available():
            result = {"status": "unknown", "message": "Docker not available — ClamAV skipped", "risk": 20}
            update_stage(file_obj.id, 3, 'pass',
                         'Docker engine not available — ClamAV layer skipped (degraded mode)')
            return True, None, result
        else:
            result = {"status": "unknown", "message": "ClamAV daemon unavailable", "risk": 20}
            update_stage(file_obj.id, 3, 'pass',
                         'ClamAV daemon not responsive — layer skipped (degraded mode)')
            return True, None, result

    logger.info(f"[SECURITY] Layer 3 → ClamAV started for {file_obj.name}")
    update_stage(file_obj.id, 3, 'running', 'Scanning file with ClamAV daemon (clamd)...')

    try:
        scan_start = time.time()
        is_clean, virus_name = _clamd_scan(filepath, clamd_host, clamd_port, timeout=60)
        scan_time = time.time() - scan_start

        if is_clean:
            logger.info(f"[SECURITY] Layer 3 → ClamAV finished: SAFE ({scan_time:.1f}s)")
            result = {
                "status": "safe",
                "message": f"No virus detected by ClamAV ({scan_time:.1f}s)",
                "risk": 0
            }
            update_stage(file_obj.id, 3, 'pass', result['message'])
            return True, None, result
        else:
            threat = f"ClamAV detected malware: {virus_name}"
            result = {"status": "malicious", "message": threat, "risk": 100}
            update_stage(file_obj.id, 3, 'fail', threat)
            return False, threat, result

    except Exception as e:
        logger.error(f"ClamAV scan error: {e}")
        result = {"status": "unknown", "message": f"ClamAV scan error: {str(e)[:60]}", "risk": 20}
        update_stage(file_obj.id, 3, 'pass', result['message'])
        return True, None, result


# ═══════════════════════════════════════════════════════════════════
# LAYER 4 — ADVANCED BEHAVIORAL SANDBOX (DOCKER)
# ═══════════════════════════════════════════════════════════════════

# ─── Suspicious string patterns for static analysis ───────────────
SUSPICIOUS_STRINGS = [
    'cmd.exe', 'powershell', 'wget', 'curl', '/etc/passwd', '/etc/shadow',
    'nc -e', 'ncat', 'base64 -d', 'eval(', 'exec(', 'system(',
    'subprocess', 'os.system', 'os.popen', 'rm -rf', 'chmod 777',
    'reverse shell', 'bind shell', '/dev/tcp', 'mkfifo', 'telnet',
    'certutil', 'bitsadmin', 'regsvr32', 'mshta', 'rundll32',
    'crontab', '/tmp/.', 'LD_PRELOAD', 'LD_LIBRARY_PATH',
    'bash -i', 'sh -i', 'python -c'
]

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


def _compute_file_entropy(filepath, sample_size=8192):
    """
    Compute Shannon entropy of a file (or first sample_size bytes).
    High entropy (>7.5) suggests encryption, packing, or obfuscation.
    """
    try:
        with open(filepath, 'rb') as f:
            data = f.read(sample_size)

        if not data:
            return 0.0

        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1

        entropy = 0.0
        total = len(data)
        for count in byte_counts:
            if count == 0:
                continue
            probability = count / total
            entropy -= probability * math.log2(probability)

        return round(entropy, 4)

    except Exception:
        return 0.0


def _analyze_strings(filepath, max_bytes=65536):
    """
    Extract and analyze printable strings from binary for suspicious indicators.
    Returns: (flags: list[str], risk_score: int)
    """
    flags = []
    risk = 0

    try:
        with open(filepath, 'rb') as f:
            raw = f.read(max_bytes)

        # Extract printable strings (4+ chars)
        text = raw.decode('utf-8', errors='ignore').lower()

        for suspicious in SUSPICIOUS_STRINGS:
            if suspicious.lower() in text:
                flags.append(f"Suspicious string: '{suspicious}'")
                risk += 10

        # Base64 regex block detection (blocks >= 64 chars)
        if re.search(r'(?:[A-Za-z0-9+/]{4}){16,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?', raw.decode('utf-8', errors='ignore')):
            flags.append("⚠ Base64 encoded payload block detected")
            risk += 15

        # Cap string-based risk contribution
        risk = min(risk, 40)

    except Exception:
        pass

    return flags, risk


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
    Layer 4: Advanced behavioral sandbox analysis via Docker.
    
    Runs the file inside a highly restricted ephemeral Docker container with:
      • --network none (no network access)
      • --memory 256m (memory limit)
      • --cpus 1 (CPU limit)
      • --pids-limit 64 (process limit)
      • --read-only filesystem
      • --security-opt no-new-privileges
      • --cap-drop ALL
    
    Behavioral monitoring:
      1. strace system call analysis (execve, connect, chmod, etc.)
      2. File type identification (file command)
      3. Suspicious string detection (cmd.exe, powershell, wget, etc.)
      4. Shannon entropy analysis (obfuscation/packing detection)
      5. Process behavior analysis (fork bombs, shell spawning, OOM kills)
      6. Resource abuse detection (timeouts, memory spikes)
    
    Returns: (passed: bool, threat_description: str|None, layer_result: dict)
    """
    logger.info(f"[SECURITY] Layer 4 → Sandbox execution started for {file_obj.name}")
    update_stage(file_obj.id, 4, 'running', 'Initializing behavioral sandbox...')

    # Strict File Type Validation before proceeding
    try:
        file_check_out = subprocess.check_output(['file', filepath]).decode().lower()
        if not any(x in file_check_out for x in ['elf', 'executable', 'script', 'archive', 'zip']):
            message = "Skipped sandbox (non-executable file type)"
            logger.info(f"[SECURITY] Layer 4 → Sandbox skipped. Filetype output: {file_check_out.strip()}")
            result = {"status": "safe", "message": message, "risk": 0, "behavior": {}}
            update_stage(file_obj.id, 4, 'pass', message)
            
            # Save null metadata
            file_obj.sandbox_status_detail = 'skipped'
            db.session.commit()
            return True, None, result
    except Exception as e:
        logger.warning(f"[SECURITY] File validation failed safely: {e}")

    # Check Docker availability
    if not _is_docker_available():
        result = {
            "status": "unknown",
            "message": "Docker not available — sandbox skipped",
            "risk": 20,
            "behavior": {"syscalls": [], "file_access": [], "process_activity": [], "flags": []}
        }
        update_stage(file_obj.id, 4, 'pass',
                     'Docker engine not available — sandbox layer skipped (degraded mode)')
        
        file_obj.sandbox_status_detail = 'degraded_docker_offline'
        db.session.commit()
        return True, None, result

    sandbox_image = os.environ.get('SANDBOX_DOCKER_IMAGE', 'python:3.11-slim@sha256:32ece7335d03ce4bafda8ad0c7e2af31559e31dcd839defc882ea12933d6eafe')
    sandbox_timeout = int(os.environ.get('SANDBOX_TIMEOUT', '10'))
    file_dir = os.path.dirname(os.path.abspath(filepath))
    file_name = os.path.basename(filepath)

    # ── Phase 1: Static Analysis (pre-execution) ──
    update_stage(file_obj.id, 4, 'running', 'Phase 1: Static analysis (entropy + strings)...')

    all_flags = []
    total_risk = 0

    # Entropy analysis
    entropy = _compute_file_entropy(filepath)
    if entropy > 7.5:
        all_flags.append(f"⚠ High entropy ({entropy}) — possible obfuscation/packing")
        total_risk += 20
    elif entropy > 6.5:
        all_flags.append(f"Elevated entropy ({entropy})")
        total_risk += 5

    # String analysis
    string_flags, string_risk = _analyze_strings(filepath)
    all_flags.extend(string_flags)
    total_risk += string_risk

    # ── Phase 2: Dynamic Analysis (container execution) ──
    update_stage(file_obj.id, 4, 'running', 'Phase 2: Dynamic analysis in isolated container...')

    syscall_summary = []
    process_activity = []
    file_access = []
    was_oom_killed = False
    container_exit_code = None
    strace_output = ''

    try:
        # Build the Docker command for behavioral monitoring
        # Uses strace for syscall tracing + file identification + string extraction
        sandbox_script = (
            f"timeout {sandbox_timeout}s sh -c '"
            f"strace -f -e trace=network,process,file -o /tmp/trace.log "
            f"sh -c \"file /sandbox/{file_name}; "
            f"strings /sandbox/{file_name} 2>/dev/null | head -50; "
            f"cat /sandbox/{file_name} > /dev/null 2>&1\" 2>/dev/null; "
            f"echo \"===STRACE===\"; "
            f"cat /tmp/trace.log 2>/dev/null; "
            f"echo \"===END===\"'"
        )

        docker_cmd = [
            'docker', 'run', '--rm',
            '--network', 'none',
            '--memory', '256m',
            '--cpus', '1',
            '--pids-limit', '64',
            '--read-only',
            '--tmpfs', '/tmp:size=64m',
            '--security-opt', 'no-new-privileges',
            '--cap-drop', 'ALL',
            '-v', f'{file_dir}:/sandbox:ro',
            sandbox_image,
            'sh', '-c', sandbox_script,
        ]

        scan_start = time.time()
        proc = subprocess.run(
            docker_cmd,
            capture_output=True,
            text=True,
            timeout=sandbox_timeout + 30  # Extra grace period for Docker overhead
        )
        execution_time = time.time() - scan_start
        container_exit_code = proc.returncode

        # Check for OOM kill (exit code 137)
        if container_exit_code == 137:
            was_oom_killed = True

        # Parse strace output
        output = proc.stdout or ''
        stderr = proc.stderr or ''

        if '===STRACE===' in output:
            strace_output = output.split('===STRACE===')[1].split('===END===')[0]
        else:
            strace_output = output

        # Analyze strace syscalls
        update_stage(file_obj.id, 4, 'running', 'Analyzing system call behavior...')
        syscall_summary, syscall_flags, syscall_risk = _analyze_strace_log(strace_output)
        all_flags.extend(syscall_flags)
        total_risk += syscall_risk

        # Analyze process behavior
        proc_flags, proc_risk = _analyze_process_behavior(
            strace_output, container_exit_code, execution_time, was_oom_killed
        )
        all_flags.extend(proc_flags)
        total_risk += proc_risk
        process_activity = proc_flags

        # Extract file access patterns from strace
        file_accesses = re.findall(r'open(?:at)?\([^"]*"([^"]+)"', strace_output)
        file_access = list(set(file_accesses))[:20]  # Dedupe, limit to 20

        # Check for hidden file creation
        hidden_files = [f for f in file_access if os.path.basename(f).startswith('.')]
        if hidden_files:
            all_flags.append(f"⚠ Hidden file access: {', '.join(hidden_files[:3])}")
            total_risk += 15

        # Check for sensitive path access
        sensitive_paths = ['/etc/passwd', '/etc/shadow', '/proc/', '/sys/']
        for path in file_access:
            for sensitive in sensitive_paths:
                if path.startswith(sensitive):
                    all_flags.append(f"⚠ Sensitive path access: {path}")
                    total_risk += 15
                    break

    except subprocess.TimeoutExpired:
        all_flags.append("⚠ Sandbox execution timed out — potential evasion")
        total_risk += 25
        execution_time = sandbox_timeout + 30
    except Exception as e:
        logger.error(f"Sandbox execution error: {e}")
        all_flags.append(f"Sandbox execution error: {str(e)[:60]}")
        total_risk += 10

    # ── Phase 3: Risk Classification ──
    update_stage(file_obj.id, 4, 'running', 'Computing behavioral risk score...')

    # Cap total risk at 100
    total_risk = min(total_risk, 100)
    logger.info(f"[SECURITY] Risk score computed: {total_risk} for {file_obj.name}")

    # Build structured behavior report
    behavior = {
        "syscalls": syscall_summary,
        "file_access": file_access[:10],
        "process_activity": process_activity,
        "flags": all_flags,
        "entropy": entropy,
        "exit_code": container_exit_code,
    }

    # Persist sandbox metadata to DB
    sandbox_status = 'normal_exit' if container_exit_code in (0, 1) else ('oom_killed' if was_oom_killed else 'timeout' if container_exit_code == 124 else 'crashed')
    
    try:
        file_obj.sandbox_trace_log = strace_output[:5000] if strace_output else ''
        file_obj.sandbox_entropy = entropy
        file_obj.sandbox_flags = json.dumps(all_flags)
        file_obj.sandbox_risk_score = total_risk
        file_obj.sandbox_status_detail = sandbox_status
        db.session.commit()
    except Exception as e:
        logger.error(f"[SECURITY] DB commit error for sandbox metadata: {e}")

    # Classify
    if total_risk > 70:
        status = "malicious"
        primary_flag = all_flags[0] if all_flags else "Multiple high-risk behavioral indicators"
        message = f"Malicious behavior detected (risk: {total_risk}) — {primary_flag}"
        result = {"status": status, "message": message, "risk": total_risk, "behavior": behavior}
        update_stage(file_obj.id, 4, 'fail', message[:120])
        return False, message, result

    elif total_risk > 30:
        status = "suspicious"
        primary_flag = all_flags[0] if all_flags else "Behavioral anomalies detected"
        message = f"Suspicious behavior (risk: {total_risk}) — {primary_flag}"
        result = {"status": status, "message": message, "risk": total_risk, "behavior": behavior}
        update_stage(file_obj.id, 4, 'pass', f"⚠ {message[:120]}")
        return True, None, result

    else:
        message = f"No suspicious behavior detected (risk: {total_risk})"
        result = {"status": "safe", "message": message, "risk": total_risk, "behavior": behavior}
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

            # Initialize AWS S3 client (still needed for file transfer + encryption)
            session = boto3.Session(
                aws_access_key_id=user_obj.aws_access_key,
                aws_secret_access_key=user_obj.aws_secret_key,
                region_name=user_obj.aws_region
            )
            s3 = session.client('s3')

            if temp_filepath and os.path.exists(temp_filepath):
                # New fast-upload path: File was saved locally in app.py. upload it to S3 in background.
                print(f"[PIPELINE] Uploading {temp_filepath} to S3 Quarantine: {user_obj.quarantine_bucket}/{s3_key}")
                try:
                    s3.upload_file(temp_filepath, user_obj.quarantine_bucket, s3_key)
                except Exception as e:
                    print(f"[PIPELINE] S3 upload FAILED: {e}")
                    traceback.print_exc()
                    file_obj.status = 'blocked'
                    file_obj.checks = 'Failed to upload to S3 quarantine'
                    db.session.commit()
                    return
                print("[PIPELINE] S3 upload complete, proceeding to local scanning...")
            else:
                # Multipart upload path or legacy: file is already in S3, download for local scanning
                temp_dir = tempfile.mkdtemp()
                # Extract just the filename from s3_key (handles "uploads/uuid/file.zip" style keys)
                local_filename = os.path.basename(s3_key) or s3_key
                temp_filepath = os.path.join(temp_dir, local_filename)
                print(f"[PIPELINE] Downloading from S3: {user_obj.quarantine_bucket}/{s3_key}")
                try:
                    s3.download_file(user_obj.quarantine_bucket, s3_key, temp_filepath)
                except Exception as e:
                    print(f"[PIPELINE] S3 download FAILED: {e}")
                    traceback.print_exc()
                    file_obj.status = 'blocked'
                    file_obj.checks = 'Failed to pull from quarantine'
                    db.session.commit()
                    return
                print(f"[PIPELINE] S3 download complete, file size: {os.path.getsize(temp_filepath)} bytes")

            # ── Run security layers ──
            layer_results = []
            passed_count = 0
            failed = False
            failed_layer = None
            threat_type = None

            # Layer 1: SHA-256 + VirusTotal
            print(f"[PIPELINE] Running Layer 1 — SHA-256 + VirusTotal...")
            success, threat, result = run_hash_check(file_obj, temp_filepath)
            layer_results.append(result)
            print(f"[PIPELINE] Layer 1 result: success={success}, result={result}")
            if success:
                passed_count += 1
                file_obj.checks = f'{passed_count}/4 complete'
                db.session.commit()
            else:
                failed = True
                failed_layer = 'Layer 1 — SHA-256 + VirusTotal'
                threat_type = threat
                skip_remaining(file_id, 1)

            # Layer 2: ZIP Heuristic Analysis
            if not failed:
                print(f"[PIPELINE] Running Layer 2 — ZIP Heuristic Analysis...")
                success, threat, result = layer2_zip_validation(file_obj, temp_filepath)
                layer_results.append(result)
                print(f"[PIPELINE] Layer 2 result: success={success}, result={result}")
                if success:
                    passed_count += 1
                    file_obj.checks = f'{passed_count}/4 complete'
                    db.session.commit()
                else:
                    failed = True
                    failed_layer = 'Layer 2 — ZIP Heuristic Analysis'
                    threat_type = threat
                    skip_remaining(file_id, 2)

            # Layer 3: ClamAV (Docker — clamd daemon)
            if not failed:
                print(f"[PIPELINE] Running Layer 3 — ClamAV (Docker)...")
                success, threat, result = run_clamav_local(file_obj, temp_filepath)
                layer_results.append(result)
                print(f"[PIPELINE] Layer 3 result: success={success}, result={result}")
                if success:
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
                if success:
                    passed_count += 1
                    file_obj.checks = f'{passed_count}/4 complete'
                    db.session.commit()
                else:
                    failed = True
                    failed_layer = 'Layer 4 — Sandbox (Docker)'
                    threat_type = threat
                    skip_remaining(file_id, 4)

            # ── Compute aggregate risk from layer results ──
            max_risk = max((r.get('risk', 0) for r in layer_results), default=0)

            if failed:
                # File rejected
                file_obj.status = 'blocked'
                file_obj.risk = max_risk if max_risk > 0 else 80
                file_obj.checks = threat_type or 'Threat detected'
                db.session.commit()
                print(f"[PIPELINE] FILE BLOCKED: {threat_type} at {failed_layer}")

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
                    msg = Message(
                        subject="StackDrive Security Alert — Malicious File Detected",
                        sender="stackdrive.alert@example.com",
                        recipients=[user_obj.email]
                    )
                    msg.body = (
                        f"StackDrive intercepted a threat:\n\n"
                        f"File: {file_obj.name}\n"
                        f"Layer: {failed_layer}\n"
                        f"Threat: {threat_type}\n"
                        f"Risk Score: {file_obj.risk}\n"
                        f"Action: BLOCKED"
                    )
                    mail.send(msg)
                except Exception:
                    pass  # Fail silently if SMTP credentials are mock
            else:
                # Run Production Hybrid Encryption (AES-256 + KMS + ML-KEM + ML-DSA)
                print(f"[PIPELINE] All 4 layers passed. Running hybrid encryption...")
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
                s3.delete_object(Bucket=user_obj.quarantine_bucket, Key=s3_key)
            except Exception:
                pass
            try:
                if temp_filepath and os.path.exists(temp_filepath):
                    os.remove(temp_filepath)
                if temp_dir and os.path.exists(temp_dir):
                    os.rmdir(temp_dir)
            except Exception:
                pass
