"""
StackDrive AI Security Copilot — Intelligence Engine
=====================================================
Provides context-aware responses about user files, threats,
and security concepts. Works standalone (no API key needed)
and optionally integrates with Gemini for richer answers.
"""
import os
import re
import json
import requests as req
from datetime import datetime
from models import db, File, PipelineStage, Notification, User


# ── Conversation History (per user, in-memory) ─────────────────
_conversation_history = {}  # { user_id: [ {role, parts}, ... ] }

def clear_conversation_history(user_id):
    """Call this when user logs out or clicks 'New Chat'."""
    _conversation_history.pop(user_id, None)


# ── File Lookup ─────────────────────────────────────────────────

def _find_file_by_name(user_id, name_query):
    """Fuzzy-match a file by name from user's uploads."""
    # Clean query
    q = name_query.strip().strip('"\'[]')
    if not q:
        return None
    # Exact match first (most recent)
    f = File.query.filter_by(user_id=user_id, name=q).order_by(File.uploaded_at.desc()).first()
    if f:
        return f
    # Partial match (case-insensitive)
    results = File.query.filter(
        File.user_id == user_id,
        File.name.ilike(f'%{q}%')
    ).order_by(File.uploaded_at.desc()).all()
    return results[0] if results else None


def _find_file_by_reference(user_id, message):
    """
    Advanced NLU file resolver. Handles casual references like:
    'that exe', 'my pdf', 'the zip file', 'last file', 'first one',
    'the blocked file', 'the safe one', 'it', 'this file'
    """
    msg = message.lower()

    # 1. Try explicit filename extraction first
    filename = _extract_filename(message)
    if filename:
        f = _find_file_by_name(user_id, filename)
        if f:
            return f

    # 2. Extension-based casual references ("that exe", "my pdf", "the zip")
    ext_map = {
        'exe': '.exe', 'pdf': '.pdf', 'zip': '.zip', 'doc': '.doc',
        'docx': '.docx', 'xlsx': '.xlsx', 'pptx': '.pptx', 'csv': '.csv',
        'txt': '.txt', 'py': '.py', 'js': '.js', 'sh': '.sh', 'bat': '.bat',
        'png': '.png', 'jpg': '.jpg', 'jpeg': '.jpeg', 'gif': '.gif',
        'mp4': '.mp4', 'rar': '.rar', '7z': '.7z', 'tar': '.tar',
        'html': '.html', 'css': '.css', 'json': '.json', 'xml': '.xml',
        'dll': '.dll', 'so': '.so', 'bin': '.bin', 'elf': '.elf',
        'docm': '.docm', 'xlsm': '.xlsm', 'pptm': '.pptm', 'rtf': '.rtf',
        'md': '.md', 'iso': '.iso', 'apk': '.apk', 'msi': '.msi',
        'gz': '.gz', 'deb': '.deb', 'rpm': '.rpm', 'wav': '.wav', 'mp3': '.mp3',
    }
    for keyword, ext in ext_map.items():
        if re.search(rf'\b{keyword}\b', msg):
            f = File.query.filter(
                File.user_id == user_id,
                File.name.ilike(f'%{ext}')
            ).order_by(File.uploaded_at.desc()).first()
            if f:
                return f

    # 3. Status-based references ("the blocked file", "safe one", "failed file")
    status_keywords = {
        'blocked': 'blocked', 'rejected': 'blocked', 'failed': 'blocked',
        'malicious': 'blocked', 'dangerous': 'blocked', 'threat': 'blocked',
        'safe': 'safe', 'clean': 'safe', 'passed': 'safe', 'verified': 'safe',
        'scanning': 'scanning', 'pending': 'quarantine',
    }
    for keyword, status in status_keywords.items():
        if keyword in msg:
            f = File.query.filter_by(user_id=user_id, status=status)\
                .order_by(File.uploaded_at.desc()).first()
            if f:
                return f

    # 4. Recency references ("last file", "latest", "recent", "just uploaded", "it", "this")
    if any(k in msg for k in ['last', 'latest', 'recent', 'just uploaded',
                               'my file', 'the file', 'this file', 'that file',
                               ' it ', 'is it']):
        return File.query.filter_by(user_id=user_id)\
            .order_by(File.uploaded_at.desc()).first()

    return None


def _get_stages(file_id):
    """Get pipeline stages for a file."""
    return PipelineStage.query.filter_by(file_id=file_id)\
        .order_by(PipelineStage.stage_order).all()


def _format_size(size_bytes):
    if not size_bytes:
        return "unknown"
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes/1024:.1f} KB"
    elif size_bytes < 1024**3:
        return f"{size_bytes/(1024*1024):.1f} MB"
    return f"{size_bytes/(1024**3):.1f} GB"


# ── Intent Detection ───────────────────────────────────────────

def _extract_filename(message):
    """Extract a filename from the user's message."""
    patterns = [
        # "for [filename]"
        r'for\s+\[?([^\]]+?\.[a-zA-Z0-9]{1,10})\]?(?:\s|$|\?)',
        # "explain what filename.ext is" / "what is filename.ext"
        r'(?:explain\s+what|what\s+is|what\'s)\s+["\']?([a-zA-Z0-9_\-\.\(\)\s]+\.[a-zA-Z0-9]{1,10})\b',
        # "explain/about/check filename.ext"
        r'(?:explain|about|check|find|search|show|details?\s+of|tell\s+me\s+about)\s+["\']?([a-zA-Z0-9_\-\.\(\)\s]+\.[a-zA-Z0-9]{1,10})\b',
        # "why was filename.ext blocked"
        r'why\s+(?:was|is|did|got)\s+["\']?([a-zA-Z0-9_\-\.\(\)\s]+\.[a-zA-Z0-9]{1,10})\b',
        # filename.ext blocked/safe/etc
        r'([a-zA-Z0-9_\-\.\(\)]+\.[a-zA-Z0-9]{1,10})\s+(?:blocked|safe|detected|failed|file|dangerous)',
        # "filename.ext" (quoted)
        r'"([^"]+\.[a-zA-Z0-9]+)"',
        # Catch-all: any word with a known file extension anywhere in the message
        r'([a-zA-Z0-9_\-\.\(\)\s]+\.(?:zip|exe|pdf|py|js|sh|bat|doc|docx|docm|xlsx|xlsm|csv|txt|png|jpg|jpeg|gif|md|html|css|json|xml|rar|7z|tar|gz|dll|so|bin|elf|pptx|pptm|rtf|mp4|mp3|wav|iso|apk|msi|deb|rpm))\b',
    ]
    for pat in patterns:
        m = re.search(pat, message, re.IGNORECASE)
        if m:
            return m.group(1).strip()
    return None


def _detect_intent(message):
    """Classify user intent from their message with NLU-grade matching."""
    msg = message.lower().strip()

    # Greetings and casual openers
    if re.match(r'^(hi|hey|hello|yo|sup|hola|greetings|good morning|good evening|good afternoon)\b', msg):
        return 'greeting'
    if re.match(r'^(thanks|thank you|thx|ty|cheers|appreciate|cool|nice|got it|ok thanks)\b', msg):
        return 'thanks'
    if re.match(r'^(help|what can you do|commands|menu|options)\b', msg):
        return 'help'

    if any(k in msg for k in ['report', 'generate report', 'pdf report', 'export', 'incident report', 'soc report']):
        return 'report'
    if any(k in msg for k in ['compare', 'vs', 'versus', 'difference between', 'most dangerous', 'rank', 'ranking',
                               'which file', 'worst file', 'riskiest']):
        return 'compare_files'
    if any(k in msg for k in ['timeline', 'attack timeline', 'sequence', 'what happened step', 'walk me through',
                               'step by step', 'what happened']):
        return 'timeline'
    if any(k in msg for k in ['why was', 'why did', 'why is', 'why got', 'blocked', 'failed', 'detected', 'caught',
                               'rejected', 'not allowed', 'stopped', 'quarantine']):
        return 'why_blocked'
    if any(k in msg for k in ['how dangerous', 'risk', 'how risky', 'threat level', 'severity', 'how bad',
                               'is it dangerous', 'should i worry', 'concern']):
        return 'risk_assess'
    if any(k in msg for k in ['what should i do', 'recommend', 'suggestion', 'next step', 'advice',
                               'what now', 'what next', 'action']):
        return 'recommend'
    if any(k in msg for k in ['explain', 'what is this file', 'tell me about', 'is it safe', 'is it ok',
                               'is my file safe', 'is my file ok', 'details of', 'analyze', 'scan result',
                               'did it pass', 'is it clean', 'any issues', 'any problem',
                               'what about', 'show me', 'check']):
        return 'explain_file'
    if any(k in msg for k in ['find', 'search', 'locate', 'where is']):
        return 'search_file'
    if any(k in msg for k in ['dashboard', 'summary', 'how many', 'overview', 'stats', 'status',
                               'all files', 'my files', 'total files', 'file count']):
        return 'dashboard'
    if any(k in msg for k in ['what is stackdrive', 'about stackdrive', 'how does stackdrive',
                               'tell me about stackdrive', 'what is this app', 'what is this platform']):
        return 'about'
    if any(k in msg for k in ['entropy', 'clamav', 'sandbox', 'virustotal', 'heuristic', 'ml-kem',
                               'kyber', 'quantum', 'aes', 'kms', 'reverse shell', 'malware',
                               'what is a', 'what does', 'how does', 'yara', 'strace', 'ml-dsa',
                               'dilithium', 'hkdf', 'zero trust', 'zero-trust', 'dlp', 'watermark',
                               'zip bomb', 'polyglot', 'path traversal']):
        return 'security_concept'

    # If message contains a filename, try to explain it
    if _extract_filename(message):
        return 'explain_file'

    return 'general'


# ── Response Generators ────────────────────────────────────────

def _compare_files(user_id):
    """Compare all files by risk score."""
    files = File.query.filter_by(user_id=user_id)\
        .order_by(File.risk.desc()).limit(5).all()
    if not files:
        return "You have no files to compare."
    lines = ["📊 **Files Ranked by Risk Score**", ""]
    for i, f in enumerate(files, 1):
        emoji = "🔴" if (f.risk or 0) > 70 else "🟠" if (f.risk or 0) > 40 else "🟢"
        lines.append(f"{i}. {emoji} **{f.name}** — Risk: {f.risk or 0}/100 | Status: {f.status.upper()}")
    lines.append("")
    most = files[0]
    if (most.risk or 0) > 70:
        lines.append(f"⚠ **{most.name}** is your highest-risk file. Consider reviewing or removing it.")
    else:
        lines.append("✅ No files are in the critical risk zone.")
    return "\n".join(lines)


def _recommend(user_id):
    """Post-scan recommendations based on user's files."""
    safe = File.query.filter_by(user_id=user_id, status='safe').count()
    blocked = File.query.filter_by(user_id=user_id, status='blocked').count()
    total = File.query.filter_by(user_id=user_id).count()
    if total == 0:
        return "You haven't uploaded any files yet. Upload a file to get started!"
    lines = ["🧭 **Recommended Next Steps**", ""]
    if blocked > 0:
        lines.append(f"1. ⚠ You have **{blocked} blocked file(s)**. Review why they were blocked using *\"Why was [filename] blocked?\"*")
        lines.append("2. 🔍 Treat the original source of blocked files as potentially compromised.")
        lines.append("3. 🛡 Run a local antivirus scan on the device that prepared those files.")
    if safe > 0:
        lines.append(f"{'4' if blocked else '1'}. ✅ Your **{safe} safe file(s)** are encrypted and stored securely.")
        lines.append(f"{'5' if blocked else '2'}. 🔗 Use StackDrive's secure sharing — never send raw S3 URLs.")
    if total > 5:
        lines.append(f"{'6' if blocked else '3'}. 📊 Use *\"Compare my files\"* to see which files have the highest risk.")
    return "\n".join(lines)


def _explain_file(file_obj, stages):
    """Generate a plain-English explanation of a file's scan results."""
    status_emoji = {'safe': '✅', 'blocked': '🚫', 'scanning': '🔄', 'quarantine': '⏳'}
    emoji = status_emoji.get(file_obj.status, '❓')

    lines = [f"{emoji} **{file_obj.name}** ({file_obj.size_display})"]
    lines.append(f"Uploaded: {file_obj.uploaded_at.strftime('%d %b %Y, %I:%M %p') if file_obj.uploaded_at else 'unknown'}")
    lines.append(f"Status: **{file_obj.status.upper()}**")
    lines.append(f"Risk Score: **{file_obj.risk or 0}/100**")

    if file_obj.sha256_hash:
        lines.append(f"SHA-256: `{file_obj.sha256_hash[:16]}...`")

    lines.append("")
    lines.append("**Pipeline Results:**")
    for s in stages:
        icon = '✅' if s.status == 'pass' else '❌' if s.status == 'fail' else '⏭' if s.status == 'skipped' else '🔄'
        lines.append(f"{icon} Layer {s.stage_order} ({s.name}): {s.detail}")

    # Sandbox details
    if file_obj.sandbox_status_detail and file_obj.sandbox_status_detail != 'skipped':
        lines.append("")
        lines.append("**Sandbox Analysis:**")
        lines.append(f"• Entropy: {file_obj.sandbox_entropy or 'N/A'}" +
                     (" ⚠ (high — possible obfuscation)" if (file_obj.sandbox_entropy or 0) > 7.5 else ""))
        lines.append(f"• Exit condition: {file_obj.sandbox_status_detail}")
        if file_obj.sandbox_flags:
            try:
                flags = json.loads(file_obj.sandbox_flags)
                if flags:
                    lines.append("• Behavioral flags:")
                    for flag in flags[:8]:
                        lines.append(f"  → {flag}")
            except:
                pass

    if file_obj.status == 'safe':
        lines.append("")
        lines.append("This file passed all security layers and is **encrypted with AES-256 + Post-Quantum Cryptography** in your AWS S3 bucket.")
    elif file_obj.status == 'blocked':
        lines.append("")
        lines.append("⚠ This file was **blocked and deleted** from quarantine. Your storage was not affected.")

    return "\n".join(lines)


def _why_blocked(file_obj, stages):
    """Explain why a file was blocked in plain English."""
    if file_obj.status != 'blocked':
        return f"**{file_obj.name}** was not blocked — its current status is **{file_obj.status.upper()}**."

    failed_stage = next((s for s in stages if s.status == 'fail'), None)
    lines = [f"🚫 **{file_obj.name}** was blocked by **{failed_stage.name if failed_stage else 'the security pipeline'}**."]
    lines.append("")

    if failed_stage:
        lines.append(f"**Detection Layer:** Layer {failed_stage.stage_order} — {failed_stage.name}")
        lines.append(f"**Finding:** {failed_stage.detail}")
        lines.append("")

    lines.append("**What this means in plain English:**")

    checks = (file_obj.checks or '').lower()
    # Translate technical findings
    explanations = {
        'virustotal': "Multiple antivirus engines flagged this file as malicious based on known threat signatures.",
        'execve': "The file tried to execute other programs — this is how malware runs hidden commands.",
        'connect': "The file attempted to make network connections, possibly to contact a remote attacker's server (reverse shell).",
        'fork': "The file tried to spawn multiple hidden processes, which is a common evasion technique.",
        'entropy': "The file's contents appear encrypted or compressed to hide malicious code (obfuscation).",
        'reverse': "The file exhibited reverse-shell behavior — attempting to give remote control to an attacker.",
        'powershell': "The file contains obfuscated PowerShell commands, commonly used by malware.",
        'shell': "The file attempted to spawn a system shell (e.g. /bin/sh), which is suspicious for non-executable files.",
        'clamav': "The file matches a known malware signature in the ClamAV antivirus database.",
        'heuristic': "File structure analysis detected suspicious patterns like hidden executables or path traversal attempts.",
        'timeout': "The file caused the sandbox to timeout, which is an evasion technique used by malware.",
        'oom': "The file consumed excessive memory in the sandbox, indicating possible resource-abuse malware.",
        'cumulative': "Multiple security layers found suspicious indicators that collectively exceeded the threat threshold.",
    }

    found_any = False
    for keyword, explanation in explanations.items():
        if keyword in checks or (file_obj.sandbox_flags and keyword in (file_obj.sandbox_flags or '').lower()):
            lines.append(f"• {explanation}")
            found_any = True

    if not found_any:
        lines.append(f"• The file triggered the detection: **{file_obj.checks}**")

    lines.append("")
    lines.append(f"**Risk Score:** {file_obj.risk or 0}/100")
    lines.append("**Action taken:** File permanently deleted from quarantine. Your AWS storage was never affected.")

    return "\n".join(lines)


def _risk_assessment(file_obj, stages):
    """Provide an AI-style risk assessment."""
    risk = file_obj.risk or 0
    level = "LOW" if risk < 30 else "MEDIUM" if risk < 60 else "HIGH" if risk < 85 else "CRITICAL"
    color = "🟢" if risk < 30 else "🟡" if risk < 60 else "🟠" if risk < 85 else "🔴"

    lines = [f"{color} **Risk Assessment for {file_obj.name}**"]
    lines.append(f"**Threat Level: {level}** ({risk}/100)")
    lines.append("")

    indicators = []
    if file_obj.sandbox_entropy and file_obj.sandbox_entropy > 7.0:
        indicators.append(f"⚠ High entropy payload ({file_obj.sandbox_entropy})")
    if file_obj.sandbox_flags:
        try:
            flags = json.loads(file_obj.sandbox_flags)
            for flag in flags[:5]:
                indicators.append(f"⚠ {flag}")
        except:
            pass

    for s in stages:
        if s.status == 'fail':
            indicators.append(f"❌ Failed: {s.name} — {s.detail}")

    if indicators:
        lines.append("**Risk Indicators:**")
        for ind in indicators:
            lines.append(f"• {ind}")
    else:
        lines.append("No significant risk indicators detected.")

    lines.append("")
    lines.append("**Why this risk score?**")

    if risk < 30:
        lines.append(f"A score of {risk}/100 is LOW. The file passed all scan layers without triggering meaningful threat signatures. The small score contribution typically comes from minor flags like elevated entropy or uncommon file structure — not actual malicious behavior.")
    elif risk < 60:
        lines.append(f"A score of {risk}/100 is MEDIUM. The file passed most layers but exhibited traits common in potentially unwanted software — such as high entropy, unusual process behavior, or structural anomalies. It's not confirmed malware, but warrants caution.")
    elif risk < 85:
        lines.append(f"A score of {risk}/100 is HIGH. Multiple security layers flagged this file. It either matched known threat signatures, exhibited suspicious runtime behavior, or had characteristics typical of obfuscated malware.")
    else:
        lines.append(f"A score of {risk}/100 is CRITICAL. The file definitively matched malware signatures or actively exhibited malicious behavior (reverse shell, process injection, etc.) in the sandbox.")

    # Per-indicator explanations
    if file_obj.sandbox_entropy and file_obj.sandbox_entropy > 7.0:
        lines.append(f"\n• **High entropy ({file_obj.sandbox_entropy:.2f})** contributes to the risk score because files with very random data often hide malicious code through encryption or packing. A score above 7.2 triggers a risk penalty.")

    for s in stages:
        if s.status == 'fail':
            lines.append(f"\n• **Layer {s.stage_order} failure ({s.name})** is the primary risk driver. When a scan layer fails, StackDrive applies a significant score penalty because a failed layer means a detected threat or scan interruption.")

    return "\n".join(lines)


def _generate_report(file_obj, stages, user_email):
    """Generate a rich, structured security report."""
    now = datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')
    risk = file_obj.risk or 0
    level = "LOW" if risk < 30 else "MEDIUM" if risk < 60 else "HIGH" if risk < 85 else "CRITICAL"
    verdict = "✅ CLEAN — Safe to use" if file_obj.status == 'safe' else "🚫 MALICIOUS — Permanently blocked"

    lines = [
        f"# 🛡️ StackDrive Security Report",
        f"**File:** {file_obj.name}  |  **Generated:** {now}  |  **Requested by:** {user_email}",
        "",
        "---",
        "",
        "## 📋 Executive Summary",
        f"- **Verdict:** {verdict}",
        f"- **Risk Score:** {risk}/100 ({level})",
        f"- **File Size:** {file_obj.size_display}",
        f"- **Upload Time:** {file_obj.uploaded_at.strftime('%d %b %Y, %I:%M %p UTC') if file_obj.uploaded_at else 'N/A'}",
        "",
        "## 🔍 File Identity",
        f"- **Original Filename:** {file_obj.name}",
        f"- **File Size:** {file_obj.size_display}",
        f"- **SHA-256 Hash:** `{file_obj.sha256_hash or 'Not computed'}`",
        f"- **Storage Path:** {'Encrypted in AWS S3' if file_obj.status == 'safe' else 'Deleted from quarantine'}",
        f"- **Encryption:** {'AES-256-GCM + ML-KEM-768 + ML-DSA-65' if file_obj.status == 'safe' else 'N/A — file not stored'}",
        "",
        "## 🔬 4-Layer Security Pipeline Results",
    ]

    for s in stages:
        icon = '✅ PASS' if s.status == 'pass' else '❌ FAIL' if s.status == 'fail' else '⏭ SKIPPED'
        lines.append(f"### Layer {s.stage_order}: {s.name}")
        lines.append(f"- **Result:** {icon}")
        lines.append(f"- **Detail:** {s.detail}")
        if s.started_at and s.completed_at:
            duration = (s.completed_at - s.started_at).total_seconds()
            lines.append(f"- **Scan Duration:** {duration:.1f} seconds")
        lines.append("")

    lines.append("## 🧪 Sandbox Behavioral Analysis")
    if file_obj.sandbox_status_detail and file_obj.sandbox_status_detail != 'skipped':
        entropy_warning = " ⚠ HIGH — Possible obfuscation/packing" if (file_obj.sandbox_entropy or 0) > 7.5 else " (Normal)"
        lines.append(f"- **File Entropy:** {file_obj.sandbox_entropy or 'N/A'}/8.0{entropy_warning}")
        lines.append(f"- **Sandbox Exit:** {file_obj.sandbox_status_detail}")
        lines.append(f"- **Heuristic Risk Score:** {file_obj.sandbox_risk_score or 0}/100")
        if file_obj.sandbox_flags:
            try:
                flags = json.loads(file_obj.sandbox_flags)
                if flags:
                    lines.append("- **Behavioral Flags Detected:**")
                    for flag in flags:
                        lines.append(f"  - ⚠ {flag}")
            except:
                pass
    else:
        lines.append("- Sandbox analysis was **skipped** for this file type.")
    lines.append("")

    lines.append("## ⚖️ Threat Assessment & Recommendations")
    if file_obj.status == 'blocked':
        failed = next((s for s in stages if s.status == 'fail'), None)
        lines.append(f"- **Classification:** MALICIOUS")
        lines.append(f"- **Detection Layer:** {failed.name if failed else 'Unknown'}")
        lines.append(f"- **Threat Description:** {file_obj.checks or 'Suspicious activity detected'}")
        lines.append("- **Action Taken:** File permanently deleted from quarantine. Your AWS S3 storage was never affected.")
        lines.append("")
        lines.append("**Recommendations:**")
        lines.append("1. Do NOT re-upload this file or variants of it.")
        lines.append("2. Treat the original source (email, download link, USB) as compromised.")
        lines.append("3. If this file came from a colleague, notify them — their machine may be infected.")
        lines.append("4. Run a local antivirus scan on the device that prepared this file.")
    else:
        lines.append("- **Classification:** CLEAN")
        lines.append("- **All 4 security layers passed with no threats detected.**")
        lines.append("- File is encrypted at rest with AES-256-GCM + Post-Quantum Cryptography (ML-KEM-768).")
        lines.append("- Stored securely in your private AWS S3 bucket.")
        lines.append("")
        lines.append("**Recommendations:**")
        lines.append("1. File is safe to download and use.")
        lines.append("2. Share using StackDrive's secure link feature — never send raw S3 URLs.")

    lines += [
        "", "---",
        "## 🔐 Cryptographic Integrity",
        f"- **Encryption Standard:** AES-256-GCM (symmetric) + ML-KEM-768 (post-quantum KEM)",
        f"- **Digital Signature:** ML-DSA-65 (post-quantum signature scheme)",
        f"- **Key Management:** AWS KMS (keys never stored in plaintext)",
        f"- **Encryption Version:** v{file_obj.encryption_version or 2}",
        "", "---",
        f"*This report was auto-generated by StackDrive Bot on {now}.*",
        "*StackDrive — Zero-Trust Secure Cloud File Ingestion Gateway*"
    ]

    return "\n".join(lines)


def _threat_timeline(file_obj, stages):
    """Generate a threat/event timeline."""
    lines = [f"📅 **Event Timeline — {file_obj.name}**", ""]
    time_str = file_obj.uploaded_at.strftime('%H:%M:%S') if file_obj.uploaded_at else '—'
    lines.append(f"1️⃣ `{time_str}` — File uploaded to quarantine ({file_obj.size_display})")
    for s in stages:
        icon = '✅' if s.status == 'pass' else '❌' if s.status == 'fail' else '⏭' if s.status == 'skipped' else '🔄'
        num = ['2️⃣','3️⃣','4️⃣','5️⃣','6️⃣'][s.stage_order - 1] if s.stage_order <= 5 else f"{s.stage_order+1}."
        t = s.completed_at.strftime('%H:%M:%S') if s.completed_at else '—'
        lines.append(f"{num} `{t}` — {icon} {s.name}: {s.detail[:80]}")
    if file_obj.status == 'blocked':
        lines.append(f"7️⃣ File **BLOCKED** and deleted from quarantine")
    elif file_obj.status == 'safe':
        lines.append(f"7️⃣ File **ENCRYPTED** (AES-256 + PQC) → stored in S3")
    return "\n".join(lines)


def _dashboard_summary(user_id):
    """Generate a dashboard summary."""
    safe = File.query.filter_by(user_id=user_id, status='safe').count()
    blocked = File.query.filter_by(user_id=user_id, status='blocked').count()
    scanning = File.query.filter_by(user_id=user_id, status='scanning').count()
    total = File.query.filter_by(user_id=user_id).count()
    notifs = Notification.query.filter_by(user_id=user_id)\
        .order_by(Notification.detected_at.desc()).limit(5).all()

    lines = ["📊 **Your StackDrive Dashboard**", ""]
    lines.append(f"• **Total files:** {total}")
    lines.append(f"• ✅ **Safe:** {safe}")
    lines.append(f"• 🚫 **Blocked:** {blocked}")
    lines.append(f"• 🔄 **Scanning:** {scanning}")
    if total > 0:
        lines.append(f"• Pass rate: **{round(safe/total*100,1)}%**")
    if notifs:
        lines.append("")
        lines.append("**Recent Threats:**")
        for n in notifs:
            lines.append(f"• **{n.file_name}** — {n.threat_type} (caught by {n.layer})")
    elif blocked == 0:
        lines.append("\n✅ All clear — no threats detected!")
    return "\n".join(lines)


def _security_concept(message):
    """Answer common security questions."""
    msg = message.lower()
    concepts = {
        'entropy': (
            "**Entropy** measures how random a file's contents are (0-8 scale).\n\n"
            "• Normal files (documents, images): 4-6\n"
            "• Compressed files (ZIP, GZIP): 7.0-7.8\n"
            "• Encrypted/packed malware: 7.5-8.0\n\n"
            "In StackDrive's sandbox, entropy > 7.5 is flagged as suspicious because "
            "attackers encrypt their payloads to evade antivirus scanners."
        ),
        'clamav': (
            "**ClamAV** is an open-source antivirus engine used in StackDrive's Layer 3.\n\n"
            "It runs inside an isolated Docker container and scans files against a database of "
            "known malware signatures. When a file matches a signature, ClamAV reports the "
            "malware family name (e.g., `Win.Trojan.Agent`)."
        ),
        'sandbox': (
            "**Behavioral Sandbox** (Layer 4) runs files inside a locked-down Docker container with:\n\n"
            "• No network access\n• 512MB memory limit\n• Read-only filesystem\n• All capabilities dropped\n\n"
            "It uses `strace` to monitor system calls (execve, connect, fork) and detects "
            "malicious behaviors like reverse shells, privilege escalation, and data exfiltration."
        ),
        'strace': (
            "**strace** is a Linux diagnostic tool that intercepts every system call a program makes.\n\n"
            "StackDrive uses it in the Layer 4 sandbox to trace dangerous calls like `execve` (run programs), "
            "`connect` (network access), `fork` (spawn processes), and `open` (file access). "
            "Think of it as a CCTV camera recording every action a program takes at the OS level."
        ),
        'reverse shell': (
            "A **reverse shell** is when malware connects back to an attacker's server and provides "
            "them with a command shell on your machine.\n\n"
            "StackDrive's sandbox detects this by watching for `connect()` system calls to external "
            "IPs combined with `execve('/bin/sh')` — the classic reverse shell pattern."
        ),
        'ml-kem': (
            "**ML-KEM-768** (formerly Kyber) is a NIST-standardized post-quantum key encapsulation mechanism.\n\n"
            "It protects encryption keys against future quantum computer attacks. StackDrive combines "
            "it with AES-256-GCM and AWS KMS using HKDF key derivation for hybrid encryption that's "
            "secure against both classical and quantum threats."
        ),
        'ml-dsa': (
            "**ML-DSA-65** (formerly Dilithium) is a NIST-standardized post-quantum digital signature algorithm.\n\n"
            "StackDrive uses it to sign encrypted file payloads. During decryption, the signature is "
            "verified to prove the file hasn't been tampered with — even by someone with access to the storage. "
            "It's like a quantum-proof wax seal on a letter."
        ),
        'dilithium': None,  # redirects to ml-dsa
        'kyber': None,  # redirects to ml-kem
        'quantum': None,  # redirects to ml-kem
        'hkdf': (
            "**HKDF** (HMAC-based Key Derivation Function) is used by StackDrive to combine two key sources "
            "into one strong AES-256 encryption key.\n\n"
            "It mixes the AWS KMS data key with the ML-KEM-768 shared secret using SHA-256, producing "
            "a hybrid key that requires both classical KMS and post-quantum components to reconstruct. "
            "This ensures that breaking one algorithm alone isn't enough."
        ),
        'virustotal': (
            "**VirusTotal** (Layer 1) checks your file's SHA-256 hash against 70+ antivirus engines.\n\n"
            "If any engines flag the hash, StackDrive reports how many detected it and the malware name. "
            "A file flagged by 5+ engines is automatically blocked."
        ),
        'heuristic': (
            "**Heuristic Analysis** (Layer 2) examines file structure for suspicious patterns:\n\n"
            "• Hidden executables inside archives\n• Path traversal attacks (../)\n"
            "• Obfuscated filenames and double extensions\n• Zip bombs (extreme compression ratios)\n"
            "• Polyglot file detection\n• Suspicious MIME type mismatches\n• Custom YARA rule matching"
        ),
        'yara': (
            "**YARA rules** are pattern-matching rules used in StackDrive's Layer 2 to detect malware.\n\n"
            "They work like search warrants — each rule defines specific byte patterns, strings, or "
            "conditions that indicate malicious behavior. StackDrive ships custom rules for detecting "
            "obfuscated scripts, embedded executables, and persistence mechanisms."
        ),
        'zip bomb': (
            "A **ZIP bomb** is a malicious archive designed to crash scanners by expanding to enormous sizes.\n\n"
            "A tiny 42KB file can decompress to over 4.5 petabytes. StackDrive detects these in Layer 2 "
            "by checking the compression ratio (blocked if > 100:1) and the absolute uncompressed size "
            "(blocked if > 2GB)."
        ),
        'polyglot': (
            "A **polyglot file** is a file that's valid in two or more formats simultaneously — "
            "like a file that's both a valid PDF and a valid ZIP.\n\n"
            "Attackers use this to sneak malware past scanners that only check the file extension. "
            "StackDrive's Layer 2 detects polyglots by comparing magic bytes against the declared MIME type."
        ),
        'path traversal': (
            "**Path traversal** is an attack where archive entries contain `../` sequences to escape "
            "the extraction directory and overwrite system files.\n\n"
            "For example, a ZIP file might contain `../../../etc/passwd`. StackDrive's Layer 2 "
            "blocks any archive entry with path traversal patterns before extraction."
        ),
        'zero trust': (
            "**Zero-trust** means StackDrive never assumes a file is safe based on who uploaded it.\n\n"
            "Every file — regardless of source — goes through all 4 security layers. If any scanning "
            "engine is offline, the file is blocked (fail-closed). No plaintext encryption keys are ever "
            "stored in the database, logs, or URLs. Trust is verified, never assumed."
        ),
        'zero-trust': None,  # redirects to zero trust
        'dlp': (
            "**Data Loss Prevention (DLP)** in StackDrive includes real-time watermarking.\n\n"
            "When a file is downloaded via a share link, PDFs get a diagonal watermark stamped with "
            "the downloader's email address, and text files get an appended ownership marker. "
            "This traces any leaked files back to the person who downloaded them."
        ),
        'watermark': None,  # redirects to dlp
        'aes': (
            "**AES-256-GCM** is the symmetric encryption algorithm StackDrive uses.\n\n"
            "It provides both confidentiality (encryption) and integrity (authentication tag). "
            "The 256-bit key is generated by AWS KMS and never stored in plaintext — "
            "this is the zero-trust architecture."
        ),
        'kms': (
            "**AWS KMS** (Key Management Service) generates and protects StackDrive's encryption keys.\n\n"
            "When a file is encrypted, KMS generates a unique data encryption key (DEK). The plaintext DEK "
            "encrypts the file, then KMS encrypts the DEK itself (envelope encryption). The plaintext DEK "
            "is immediately wiped from memory — only the encrypted version is stored in the database."
        ),
        'malware': (
            "**Malware** is any software intentionally designed to cause damage — viruses, trojans, "
            "ransomware, worms, spyware, and more.\n\n"
            "StackDrive's 4-layer pipeline catches malware through hash reputation (Layer 1), "
            "structural analysis (Layer 2), signature matching (Layer 3), and runtime behavior monitoring "
            "(Layer 4). Files that exhibit malicious behavior are blocked and permanently deleted."
        ),
    }
    for key, answer in concepts.items():
        if key in msg:
            if answer is None:
                # Redirect to related concept
                for k2, a2 in concepts.items():
                    if a2 and k2 in msg:
                        return a2
                return concepts.get('ml-kem', '')
            return answer

    if 'what is stackdrive' in msg or 'about stackdrive' in msg:
        return (
            "**StackDrive** is a zero-trust, AI-powered secure cloud file storage platform.\n\n"
            "Every uploaded file goes through a 4-layer security pipeline:\n"
            "1. **SHA-256 + VirusTotal** — threat intelligence\n"
            "2. **File Heuristic Analysis** — structural analysis\n"
            "3. **ClamAV** — antivirus scan in Docker\n"
            "4. **Behavioral Sandbox** — runtime analysis in isolated container\n\n"
            "Safe files are encrypted with **AES-256 + ML-KEM-768 + ML-DSA-65** and stored in AWS S3."
        )
    return None


def _about_stackdrive():
    return _security_concept('what is stackdrive')


# ── Main Copilot Handler ──────────────────────────────────────

def handle_copilot_message(user_id, user_message, selected_file_id=None):
    """
    Main copilot handler. Detects intent, looks up files, generates response.
    Uses advanced NLU file resolution for casual references and selected files.
    Returns: reply string
    """
    intent = _detect_intent(user_message)
    filename = _extract_filename(user_message)

    # Get user for email
    user_obj = User.query.get(user_id)
    user_email = user_obj.email if user_obj else 'unknown'

    # ── Greeting / Thanks / Help (no file lookup needed) ──
    if intent == 'greeting':
        total = File.query.filter_by(user_id=user_id).count()
        blocked = File.query.filter_by(user_id=user_id, status='blocked').count()
        if total == 0:
            return "Hey! 👋 I'm **StackDrive Bot**, your AI security analyst. Upload a file and I'll walk you through every scan result, risk score, and threat detected."
        elif blocked > 0:
            return f"Hey! 👋 You have **{total} files** uploaded, with **{blocked} blocked threat(s)**. Ask me about any file — try *\"why was it blocked?\"* or *\"dashboard summary\"*."
        else:
            return f"Hey! 👋 You have **{total} files** uploaded, all clear so far. Ask me anything — try *\"is my file safe?\"*, *\"compare my files\"*, or *\"what is entropy?\"*."

    if intent == 'thanks':
        return "You're welcome! 🛡️ I'm here whenever you need a scan breakdown, risk assessment, or security explanation. Just ask!"

    if intent == 'help':
        return (
            "I'm your **StackDrive Bot**. Here's what I can do:\n\n"
            "🔍 **\"Explain [filename]\"** — full scan breakdown\n"
            "🚫 **\"Why was [filename] blocked?\"** — threat explanation\n"
            "⚠ **\"How dangerous is [filename]?\"** — risk assessment\n"
            "📋 **\"Generate report for [filename]\"** — security report\n"
            "📅 **\"Show timeline for [filename]\"** — event sequence\n"
            "📊 **\"Dashboard summary\"** — your account overview\n"
            "🏆 **\"Compare my files\"** — rank files by risk\n"
            "🧭 **\"What should I do next?\"** — recommendations\n"
            "🧠 **\"What is entropy?\"** — security concepts\n\n"
            "You can also say things like *\"is that exe safe?\"*, *\"what about the blocked file?\"*, "
            "or *\"tell me about my last upload\"* — I understand casual references!"
        )

    # ── Non-file intents ──
    if intent == 'dashboard':
        return _dashboard_summary(user_id)

    if intent == 'compare_files':
        return _compare_files(user_id)

    if intent == 'recommend':
        return _recommend(user_id)

    if intent == 'security_concept' or intent == 'about':
        answer = _security_concept(user_message)
        if answer:
            return answer

    # ── File-related intents — use advanced NLU resolver ──
    file_obj = None
    stages = []
    found_via_selected = False

    # Step 1: Try explicit filename match
    if filename:
        file_obj = _find_file_by_name(user_id, filename)

    # Step 2: If user has a file selected in the UI, ALWAYS prefer it when no explicit filename was mentioned
    if not file_obj and selected_file_id:
        file_obj = File.query.filter_by(user_id=user_id, id=selected_file_id).first()
        if file_obj:
            # Only override if the message doesn't explicitly mention a DIFFERENT file by name
            stages = _get_stages(file_obj.id)
            found_via_selected = True

    # Step 3: Try NLU reference matching ("that exe", "the blocked file", etc.)
    if not file_obj:
        file_obj = _find_file_by_reference(user_id, user_message)

    if file_obj and not stages:
        stages = _get_stages(file_obj.id)

    if intent in ('explain_file', 'search_file', 'why_blocked', 'risk_assess', 'report', 'timeline'):
        if not file_obj:
            if filename:
                return f"I couldn't find a file matching **\"{filename}\"** in your account. Try a partial name or ask *\"dashboard summary\"* to see all your files."
            
            # Prioritize selected file ID if user has selected one in the dropdown
            if selected_file_id:
                file_obj = File.query.filter_by(user_id=user_id, id=selected_file_id).first()
                if file_obj:
                    stages = _get_stages(file_obj.id)
                    found_via_selected = True
            
            # Last resort: most recent file
            if not file_obj:
                file_obj = File.query.filter_by(user_id=user_id)\
                    .order_by(File.uploaded_at.desc()).first()
                if file_obj:
                    stages = _get_stages(file_obj.id)
                    prefix = f"(Answering about your most recent file: **{file_obj.name}**)\n\n"
                else:
                    return "You haven't uploaded any files yet. Upload a file first, then ask me about it!"
        else:
            prefix = ""

        if found_via_selected and file_obj:
            prefix = f"(Answering about your currently selected file: **{file_obj.name}**)\n\n"

        if intent == 'explain_file' or intent == 'search_file':
            return prefix + _explain_file(file_obj, stages)
        elif intent == 'why_blocked':
            return prefix + _why_blocked(file_obj, stages)
        elif intent == 'risk_assess':
            return prefix + _risk_assessment(file_obj, stages)
        elif intent == 'report':
            return prefix + _generate_report(file_obj, stages, user_email)
        elif intent == 'timeline':
            return prefix + _threat_timeline(file_obj, stages)

    # ── General fallback — attempt file-based answer before showing help ──
    if file_obj:
        return _explain_file(file_obj, stages)

    # Final fallback: help menu
    total = File.query.filter_by(user_id=user_id).count()
    if total > 0:
        return (
            "I'm not sure what you mean, but I'm here to help! Try:\n\n"
            "• *\"Is my file safe?\"* — scan results for your latest upload\n"
            "• *\"Why was it blocked?\"* — threat explanation\n"
            "• *\"Dashboard summary\"* — overview of all your files\n"
            "• *\"What is entropy?\"* — security concept explanation\n\n"
            "You can refer to files casually — *\"that exe\"*, *\"the blocked file\"*, or just the filename."
        )
    return (
        "Hey! 👋 I'm **StackDrive Bot**, your AI security analyst.\n\n"
        "Upload a file to get started — I'll explain every scan result, "
        "flag threats, and answer any security questions you have."
    )


# ── Gemini Integration ────────────────────────────────────────

def _build_file_context(user_id, selected_file_id=None):
    """Build real file context for Gemini."""
    parts = []
    
    # 1. Selected file context (active UI selection)
    if selected_file_id:
        f = File.query.filter_by(user_id=user_id, id=selected_file_id).first()
        if f:
            stages = _get_stages(f.id)
            stage_info = "; ".join([
                f"Layer {s.stage_order} ({s.name}): {s.status} — {s.detail}" for s in stages
            ])
            sandbox = ""
            if f.sandbox_status_detail:
                sandbox = (f"\n  sandbox_entropy: {f.sandbox_entropy}"
                           f"\n  sandbox_flags: {f.sandbox_flags or '[]'}"
                           f"\n  sandbox_risk_score: {f.sandbox_risk_score}")
            parts.append("[CURRENTLY_SELECTED_FILE]")
            parts.append(
                f"file_name: {f.name}\nsize: {f.size_display}\nstatus: {f.status}"
                f"\nrisk: {f.risk}\nsha256: {f.sha256_hash or 'N/A'}"
                f"\npipeline: {stage_info}{sandbox}"
            )
            parts.append("[/CURRENTLY_SELECTED_FILE]\n")
    files = File.query.filter_by(user_id=user_id)\
        .order_by(File.uploaded_at.desc()).limit(10).all()
    if files:
        parts.append("[USER_FILES_CONTEXT]")
        for f in files:
            stages = _get_stages(f.id)
            stage_info = "; ".join([
                f"Layer {s.stage_order} ({s.name}): {s.status} — {s.detail}" for s in stages
            ])
            sandbox = ""
            if f.sandbox_status_detail:
                sandbox = (f"\n  sandbox_entropy: {f.sandbox_entropy}"
                          f"\n  sandbox_flags: {f.sandbox_flags or '[]'}"
                          f"\n  sandbox_risk_score: {f.sandbox_risk_score}")
            parts.append(
                f"\nfile_name: {f.name}\nsize: {f.size_display}\nstatus: {f.status}"
                f"\nrisk: {f.risk}\nsha256: {f.sha256_hash or 'N/A'}"
                f"\npipeline: {stage_info}{sandbox}\n---"
            )
        parts.append("[/USER_FILES_CONTEXT]")

    safe = File.query.filter_by(user_id=user_id, status='safe').count()
    blocked = File.query.filter_by(user_id=user_id, status='blocked').count()
    total = File.query.filter_by(user_id=user_id).count()
    parts.append(f"\n[DASHBOARD] total:{total} safe:{safe} blocked:{blocked} [/DASHBOARD]")
    return "\n".join(parts)


def call_gemini(user_id, user_message, system_prompt, selected_file_id=None):
    """Call Gemini API with conversation history and full context. Returns reply or None."""
    api_key = os.environ.get('GEMINI_API_KEY', '').strip()
    if not api_key:
        return None
    try:
        context = _build_file_context(user_id, selected_file_id)
        system_with_context = f"{system_prompt}\n\n{context}"

        # Build conversation history
        history = _conversation_history.get(user_id, [])

        # Add new user message to history
        history.append({"role": "user", "parts": [{"text": user_message}]})
        _conversation_history[user_id] = history[-20:]  # update immediately to avoid losing context

        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={api_key}"
        resp = req.post(url, json={
            "system_instruction": {"parts": [{"text": system_with_context}]},
            "contents": history[-10:],  # last 10 turns only
            "generationConfig": {
                "temperature": 0.4,
                "maxOutputTokens": 1500,
                "topP": 0.90
            },
            "safetySettings": [
                {"category": c, "threshold": "BLOCK_NONE"} for c in [
                    "HARM_CATEGORY_HARASSMENT", "HARM_CATEGORY_HATE_SPEECH",
                    "HARM_CATEGORY_SEXUALLY_EXPLICIT", "HARM_CATEGORY_DANGEROUS_CONTENT"
                ]
            ]
        }, timeout=30)

        if resp.status_code == 200:
            candidates = resp.json().get('candidates', [])
            if candidates:
                parts = candidates[0].get('content', {}).get('parts', [])
                reply_text = parts[0].get('text', '') if parts else None
                if reply_text:
                    # Save assistant reply to history
                    history.append({"role": "model", "parts": [{"text": reply_text}]})
                    _conversation_history[user_id] = history[-20:]  # cap at 20 turns total
                    return reply_text
    except Exception as e:
        print(f"[COPILOT] Gemini error: {e}")
    return None

