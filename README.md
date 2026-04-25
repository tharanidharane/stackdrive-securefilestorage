# 2026-AI-Driven-Secure-Cloud-File-Upload-System-with-Quantum-Resistant-Encryption-Support
### https://idea.unisys.com/D8755

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Web-0ea5e9?style=for-the-badge" alt="Platform" />
  <img src="https://img.shields.io/badge/Backend-Python%203.12-306998?style=for-the-badge&logo=python&logoColor=white" alt="Python" />
  <img src="https://img.shields.io/badge/Frontend-React%2019-61dafb?style=for-the-badge&logo=react&logoColor=black" alt="React" />
  <img src="https://img.shields.io/badge/Encryption-AES--256--GCM-22c55e?style=for-the-badge" alt="AES-256" />
  <img src="https://img.shields.io/badge/PQC-ML--KEM--768%20%2B%20ML--DSA--65-a855f7?style=for-the-badge" alt="PQC" />
  <img src="https://img.shields.io/badge/Cloud-AWS-ff9900?style=for-the-badge&logo=amazonaws&logoColor=white" alt="AWS" />
</p>

# 🛡️ StackDrive — Secure Cloud File Ingestion Gateway

> **Zero-Trust file security platform with AI-driven threat detection, multi-layer scanning, and post-quantum cryptographic protection.**

StackDrive is an enterprise-grade web application that enforces a strict **zero-trust security model** for cloud file uploads. Every incoming file is automatically quarantined, scanned through a **5-layer automated defense pipeline**, and — only upon passing all checks — encrypted with **hybrid post-quantum cryptography** before being promoted to secure cloud storage. No file is ever trusted by default.

---

## Table of Contents

- [Problem Statement](#-problem-statement)
- [Core Architecture](#-core-architecture)
- [Security Pipeline — Deep Dive](#-security-pipeline--deep-dive)
- [Hybrid Encryption Engine](#-hybrid-encryption-engine)
- [Technology Stack](#-technology-stack)
- [Project Structure](#-project-structure)
- [Getting Started](#-getting-started)
- [Environment Configuration](#-environment-configuration)
- [API Reference](#-api-reference)
- [Frontend Features](#-frontend-features)
- [Security Design Principles](#-security-design-principles)

---

## 🎯 Problem Statement

Traditional cloud storage solutions accept and store files **without real-time deep inspection**, leaving organizations vulnerable to:

- **Malware propagation** through seemingly benign file uploads
- **Zero-day exploits** embedded in obfuscated archives
- **ZIP bombs** designed to exhaust server resources
- **Data exfiltration payloads** with encoded reverse shells
- **Quantum computing threats** to current encryption standards (RSA, ECC)

StackDrive addresses all of these by implementing an **automated, multi-layered security gateway** that inspects, analyzes, and cryptographically protects every file — before it ever touches permanent storage.

---

## 🏗 Core Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        CLIENT (React 19 + Vite)                        │
│   Login/Signup ─► Dashboard ─► Upload ─► File History ─► Security      │
│                    3D Quantum Lock Auth Scene (Three.js)                │
└────────────────────────────────┬────────────────────────────────────────┘
                                 │  REST API (JWT Auth)
                                 ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                     BACKEND (Flask + Python 3.12)                       │
│                                                                         │
│  ┌─────────────┐  ┌──────────────────────────────────────────────────┐  │
│  │  Auth Layer  │  │        SECURITY PIPELINE (5 Layers)             │  │
│  │  (JWT+bcrypt)│  │                                                  │  │
│  └──────┬───────┘  │  L1: SHA-256 + VirusTotal Threat Intelligence   │  │
│         │          │  L2: ZIP Heuristic Analysis (8 static checks)   │  │
│         ▼          │  L3: ClamAV (Docker — persistent clamd daemon)  │  │
│  ┌─────────────┐   │  L4: Sandbox (Docker — behavioral analysis)     │  │
│  │  SQLite DB   │  │  L5: Hybrid Encryption (AES-256 + KMS + PQC)   │  │
│  │  (Users,     │  └──────────────────────────────────────────────────┘  │
│  │   Files,     │                        │                               │
│  │   Pipeline,  │                        ▼                               │
│  │   Notifs)    │  ┌──────────────────────────────────────────────────┐  │
│  └──────────────┘  │            AWS INFRASTRUCTURE                    │  │
│                    │  S3 (Quarantine + Secure buckets)                │  │
│                    │  KMS (Envelope encryption + SSE)                 │  │
│                    │  IAM/STS (Scoped sessions)                       │  │
│                    │  Secrets Manager (PQC private keys)              │  │
│                    └──────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
```

### Data Flow

1. **Upload** — User uploads a `.zip` file via presigned multipart upload directly to the S3 **quarantine bucket**.
2. **Quarantine** — The file is isolated; no downstream system can access it until the pipeline completes.
3. **Pipeline Execution** — Layers 1–4 run sequentially in a background thread. Each layer produces a pass/fail verdict and a risk score.
4. **Cumulative Risk Scoring** — Risk scores are aggregated across layers. If the cumulative score exceeds the configurable threshold (default: 70), the file is **blocked** regardless of individual layer results.
5. **Encryption** — Files that pass all layers are encrypted with hybrid AES-256-GCM + AWS KMS + ML-KEM-768/ML-DSA-65 and promoted to the **secure bucket**.
6. **Notification** — Blocked files trigger real-time in-app notifications and automated SMTP email alerts.
7. **Cleanup** — The quarantine copy is deleted after processing, ensuring no raw files persist.

---

## 🔬 Security Pipeline — Deep Dive

### Layer 1: SHA-256 Hash + VirusTotal Threat Intelligence

| Aspect | Detail |
|:---|:---|
| **Purpose** | Cross-reference uploaded file hashes against 70+ antivirus engines |
| **Implementation** | SHA-256 hash computed locally → queried against VirusTotal REST API v3 |
| **Caching** | Redis-backed with configurable TTL (default 6h); in-memory fallback for dev |
| **Verdicts** | `safe` (0 detections), `suspicious` (flagged by ≥1 engine), `malicious` (confirmed by ≥1 engine), `unknown` (not in VT database) |
| **Graceful Degradation** | Continues pipeline if API key missing, rate-limited, or VT unreachable |

### Layer 2: ZIP Heuristic Analysis (8 Static Checks)

All uploads are validated against eight independent heuristic checks:

| # | Check | Risk |
|:--|:------|:-----|
| 1 | **ZIP bomb detection** — Decompression ratio > 100:1 | Critical |
| 2 | **Path traversal** — `../` sequences in entry names | Critical |
| 3 | **Dangerous executables** — `.exe`, `.bat`, `.sh`, `.ps1`, `.js`, `.vbs`, `.cmd`, `.msi` | Critical |
| 4 | **Obfuscated filenames** — 20+ char random strings with executable extensions | Critical |
| 5 | **Hidden files** — Entries starting with `.` | Suspicious |
| 6 | **Nested archives** — Recursive ZIP files (>5 = suspicious) | Suspicious |
| 7 | **Excessive file count** — Archives with >1000 entries | Suspicious |
| 8 | **Archive integrity** — CRC/structure corruption via `testzip()` | Critical |

*Critical issues immediately block the file. Suspicious issues increment the cumulative risk score.*

### Layer 3: ClamAV Antivirus (Docker — Persistent Daemon)

| Aspect | Detail |
|:---|:---|
| **Architecture** | Persistent `clamav/clamav` Docker container running the `clamd` daemon on TCP port 3310 |
| **Protocol** | Raw TCP socket using the `INSTREAM` clamd protocol (binary chunk streaming) |
| **Two-Phase Scanning** | Phase 1: Stream entire file to clamd. Phase 2: Extract and individually scan each archive member (defense-in-depth against unpacker evasion) |
| **Safety Limits** | Max 50 members extracted, max 100MB per member, path traversal entries refused |
| **Startup** | Auto-starts container if not running; waits up to 90s for virus DB load |
| **Graceful Degradation** | If Docker unavailable, layer is skipped with a risk penalty (degraded mode) |

### Layer 4: Behavioral Sandbox (Docker — Ephemeral Containers)

The most advanced layer — executes files inside a **highly restricted ephemeral Docker container** with:

**Container Security Constraints:**
- `--network none` — Zero network access
- `--memory 256m` — Hard memory limit
- `--cpus 1` — CPU throttling
- `--pids-limit 64` — Process count limit
- `--read-only` — Immutable filesystem
- `--security-opt no-new-privileges` — Privilege escalation prevention
- `--cap-drop ALL` — All Linux capabilities dropped

**Behavioral Analysis Modules:**

| Module | Mechanism |
|:---|:---|
| **Syscall Analysis** | `strace` captures all system calls; 17 dangerous syscalls monitored (connect, bind, execve, chmod, ptrace, setuid, etc.) with individual risk weights |
| **String Analysis** | Scans binary for 35+ suspicious patterns (reverse shell commands, base64 payloads, privilege escalation strings) |
| **Entropy Analysis** | Shannon entropy computation; high entropy (>7.5) indicates encryption, packing, or obfuscation |
| **Process Behavior** | Detects fork bombs, shell spawning, OOM kills, timeout evasion, abnormal exit codes |
| **File Type Validation** | MIME type verification against expected `.zip` format (blocks disguised executables) |

**Risk Scoring:** Each module contributes a weighted risk score normalized to 0–100. The final sandbox verdict applies cumulative scoring against the pipeline threshold.

---

## 🔐 Hybrid Encryption Engine

StackDrive implements a **production-grade, zero-trust hybrid encryption architecture** combining classical and post-quantum cryptographic primitives:

```
┌───────────────────────────────────────────────────────────────┐
│                    ENCRYPTION FLOW (v2)                        │
│                                                               │
│  Raw File ──► AES-256-GCM ──► Encrypted Blob                 │
│                    │                                          │
│                    ├── AES Key ──► KMS Envelope Encrypt       │
│                    │                                          │
│                    ├── ML-KEM-768 (Kyber) Key Encapsulation   │
│                    │       └── HKDF(KMS_DEK ∥ PQC_SS)         │
│                    │             └── Hybrid AES Key            │
│                    │                                          │
│                    └── ML-DSA-65 (Dilithium) Digital Signature │
│                          └── Signs(nonce ∥ CT ∥ tag ∥ binding)│
│                                                               │
│  Binary Payload Layout:                                       │
│  [MAGIC 5B][HDR_LEN 4B][JSON HDR][KEM_CT][NONCE][CT][TAG][SIG]│
└───────────────────────────────────────────────────────────────┘
```

### Cryptographic Primitives

| Layer | Algorithm | Purpose |
|:------|:----------|:--------|
| **Symmetric Encryption** | AES-256-GCM | File data encryption with authenticated encryption (chunked 1MB streaming) |
| **Key Management** | AWS KMS `GenerateDataKey` | Envelope encryption — AES data encryption key (DEK) never stored in plaintext |
| **Post-Quantum KEM** | ML-KEM-768 (NIST FIPS 203 / Kyber) | Quantum-resistant key encapsulation; shared secret combined with KMS DEK via HKDF |
| **Post-Quantum Signature** | ML-DSA-65 (NIST FIPS 204 / Dilithium) | Quantum-resistant digital signature over the entire encrypted payload |
| **Key Derivation** | HKDF-SHA-256 | Derives the final AES key from `KMS_DEK ∥ PQC_shared_secret` with file-scoped context |
| **Hybrid Binding** | HMAC-SHA-256 | `SHA-256(AES_key ∥ PQC_SS)` — cryptographic proof that both classical and PQC paths contributed to key material |

### Zero-Trust Key Storage Rules

| Key Material | Storage Location | Access Control |
|:-------------|:-----------------|:---------------|
| AES-256 DEK (plaintext) | **Never stored** — wiped from memory after encryption | `del aes_key` in Python |
| AES-256 DEK (encrypted) | SQLite — `kms_encrypted_key` binary blob | KMS decrypt with encryption context required |
| PQC Private Keys (Kyber + Dilithium) | AWS Secrets Manager | Per-file secret with ARN reference |
| PQC Public Keys + Ciphertexts | SQLite — non-sensitive metadata | Read-only after creation |
| Encrypted File Blob | S3 Secure Bucket with SSE-KMS | Server-side encryption at rest |

---

## 🛠 Technology Stack

### Backend

| Component | Technology | Version |
|:----------|:-----------|:--------|
| API Framework | Flask | 3.1.0 |
| Database ORM | Flask-SQLAlchemy | 3.1.1 |
| Authentication | Flask-JWT-Extended + bcrypt | 4.7.1 |
| Email Alerts | Flask-Mail (SMTP) | 0.10.0 |
| AWS SDK | Boto3 (S3, KMS, IAM, STS, Secrets Manager) | 1.36.14 |
| Cryptography | PyCryptodome (AES-256-GCM, HKDF) | 3.21.0 |
| Post-Quantum | liboqs-python (ML-KEM-768, ML-DSA-65) | Source build |
| Threat Intel | VirusTotal API v3 | REST |
| Antivirus | ClamAV (Docker clamd daemon) | Latest |
| Sandbox | Docker Engine (ephemeral containers) | — |
| Task Queue | Celery (optional, auto-detected) | — |
| Caching | Redis (optional, VT cache) | — |

### Frontend

| Component | Technology | Version |
|:----------|:-----------|:--------|
| Framework | React | 19.2.4 |
| Build Tool | Vite | 8.0.4 |
| Routing | React Router DOM | 7.14.0 |
| 3D Graphics | Three.js (Quantum Lock auth scene) | 0.184.0 |
| Icons | Lucide React | 1.8.0 |
| Styling | Vanilla CSS (custom design system) | — |

---

## 📁 Project Structure

```
stackdrive/
├── backend/
│   ├── app.py                  # Flask API — routes for auth, upload, files, dashboard, notifications
│   ├── pipeline.py             # 5-layer security pipeline (1,600+ lines) — hash, ZIP, ClamAV, sandbox, encryption
│   ├── encryption.py           # Hybrid encryption engine — AES-256 + KMS + ML-KEM + ML-DSA
│   ├── models.py               # SQLAlchemy models — User, File (with PQC metadata), PipelineStage, Notification
│   ├── config.py               # App configuration — DB path resolution (WSL-aware), JWT, upload limits
│   ├── Dockerfile.sandbox      # Custom sandbox Docker image with diagnostic tools
│   ├── requirements.txt        # Python dependencies (11 packages + PQC source build instructions)
│   ├── .env.example            # Environment variable template (VT key, PQC toggle, Docker images)
│   └── e2e_master.py           # End-to-end test suite for the full security pipeline
│
├── src/
│   ├── App.jsx                 # Root component — routing, auth state, session management
│   ├── main.jsx                # Entry point
│   ├── index.css               # Global design system (CSS custom properties, responsive layout)
│   ├── components/
│   │   ├── EncryptionScene.jsx  # 3D WebGL padlock scene (Three.js) — login/logout animations
│   │   ├── UploadZone.jsx       # Drag-and-drop upload with presigned multipart S3 upload
│   │   ├── PipelinePanel.jsx    # Real-time pipeline progress visualization
│   │   ├── FileTable.jsx        # File listing with status badges
│   │   ├── NotificationPanel.jsx# Threat notification feed
│   │   ├── Header.jsx           # Top navigation bar
│   │   ├── Sidebar.jsx          # Collapsible sidebar navigation
│   │   ├── StatCard.jsx         # Animated metric cards with count-up effect
│   │   ├── StatusBadge.jsx      # Color-coded status indicators
│   │   ├── Modal.jsx            # Reusable modal dialog
│   │   └── Toast.jsx            # Toast notification system
│   ├── pages/
│   │   ├── Dashboard.jsx        # Security posture overview with live metrics
│   │   ├── UploadPage.jsx       # File upload with real-time pipeline tracking
│   │   ├── FileHistory.jsx      # Complete file audit trail with search/filter
│   │   ├── SecurityPage.jsx     # Pipeline analytics — layer stats, recent threats
│   │   ├── SettingsPage.jsx     # AWS account connection, profile management
│   │   ├── LoginPage.jsx        # Authentication with 3D quantum lock scene
│   │   ├── SignupPage.jsx       # Registration with animated auth scene
│   │   └── LogoutPage.jsx       # Cinematic logout with reverse lock animation
│   ├── services/
│   │   └── api.js               # Centralized HTTP client — JWT interceptor, error handling, all API methods
│   └── hooks/
│       ├── useCountUp.js        # Animated counter hook for dashboard metrics
│       └── usePipelineSimulation.js # Pipeline stage simulation for UI preview
│
├── public/                      # Static assets
├── index.html                   # HTML entry point
├── package.json                 # Frontend dependencies
├── vite.config.js               # Vite build configuration
├── eslint.config.js             # ESLint rules
└── .gitignore                   # Comprehensive ignore rules (env, db, storage, venv, node_modules)
```

---

## 🚀 Getting Started

### Prerequisites

| Requirement | Minimum Version | Purpose |
|:------------|:----------------|:--------|
| **Node.js** | v18+ | Frontend build and dev server |
| **Python** | 3.11+ | Backend API runtime |
| **Docker** | Latest (daemon running) | ClamAV antivirus + sandbox behavioral analysis |
| **AWS Account** | IAM user with S3, KMS, STS, Secrets Manager permissions | Cloud storage and key management |

### 1. Clone the Repository

```bash
git clone https://github.com/tharanidharane/stackdrive-securefilestorage.git
cd stackdrive-securefilestorage
```

### 2. Backend Setup

```bash
cd backend

# Create and activate virtual environment
python -m venv venv

# Windows
.\venv\Scripts\activate

# macOS / Linux
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

#### Post-Quantum Cryptography (Optional)

ML-KEM-768 and ML-DSA-65 require `liboqs-python`, which must be compiled from source:

```bash
# Requires: Linux/WSL, CMake, GCC or Clang
git clone --depth=1 https://github.com/open-quantum-safe/liboqs-python
cd liboqs-python && pip install .
```

Enable PQC in your `.env`:
```
PQC_ENABLED=true
```

> **Note:** When `PQC_ENABLED=false`, the system uses AES-256-GCM + AWS KMS envelope encryption — still production-grade, but without quantum resistance.

#### Configure Environment Variables

```bash
# Copy the template
cp .env.example .env

# Edit with your values
# Required: VT_API_KEY (from https://www.virustotal.com)
# Optional: PQC_ENABLED, CLAMD_HOST, SANDBOX_DOCKER_IMAGE
```

#### Start the Backend Server

```bash
python app.py
# Server starts at http://localhost:5000
```

### 3. Frontend Setup

In a **separate terminal** from the project root:

```bash
# Install dependencies
npm install

# Start the Vite development server
npm run dev
# Frontend available at http://localhost:5173
```

### 4. Connect AWS (In-App)

After logging in, navigate to **Settings → AWS Configuration** and provide:

- AWS Access Key ID
- AWS Secret Access Key
- Region (default: `ap-south-1`)

StackDrive will automatically provision:
- Quarantine S3 bucket (public access blocked)
- Secure S3 bucket (SSE-KMS encrypted)
- KMS Customer Managed Key with alias
- CORS configuration for browser-direct uploads

---

## ⚙️ Environment Configuration

| Variable | Required | Default | Description |
|:---------|:---------|:--------|:------------|
| `VT_API_KEY` | Recommended | — | VirusTotal API key for Layer 1 threat intelligence |
| `PQC_ENABLED` | No | `false` | Enable post-quantum cryptography (ML-KEM-768 + ML-DSA-65) |
| `SECRET_KEY` | Production | `stackdrive-secret-key-*` | Flask secret key (change in production) |
| `JWT_SECRET_KEY` | Production | `jwt-super-secret-key-*` | JWT signing key (change in production) |
| `CLAMAV_DOCKER_IMAGE` | No | `clamav/clamav:latest` | ClamAV Docker image (SHA-256 pinning supported) |
| `CLAMD_HOST` | No | `127.0.0.1` | ClamAV daemon hostname |
| `CLAMD_PORT` | No | `3310` | ClamAV daemon port |
| `SANDBOX_DOCKER_IMAGE` | No | `python:3.11-slim` | Sandbox base image (SHA-256 pinning supported) |
| `SANDBOX_TIMEOUT` | No | `10` | Sandbox execution timeout in seconds |
| `REDIS_URL` | No | — | Redis connection URL for VirusTotal result caching |
| `DATABASE_URL` | No | `sqlite:///stackdrive.db` | Database URI override |
| `MAIL_SERVER` | No | `smtp.gmail.com` | SMTP server for threat email alerts |
| `MAIL_PORT` | No | `587` | SMTP port |
| `MAIL_USERNAME` | No | — | SMTP username |
| `MAIL_PASSWORD` | No | — | SMTP password |

---

## 📡 API Reference

### Authentication

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `POST` | `/api/auth/signup` | Register new account (email + password) |
| `POST` | `/api/auth/login` | Authenticate and receive JWT token |
| `GET` | `/api/auth/me` | Get current user profile (JWT required) |

### AWS Management

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `POST` | `/api/aws/connect` | Provision AWS infrastructure (S3 + KMS + IAM) |
| `GET` | `/api/aws/status` | Check AWS connection status |
| `POST` | `/api/aws/disconnect` | Disconnect AWS account |

### File Operations

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `POST` | `/api/upload/initiate` | Initiate presigned multipart upload (10MB chunks) |
| `POST` | `/api/upload/complete` | Finalize upload and trigger security pipeline |
| `POST` | `/api/upload/abort` | Abort incomplete multipart upload |
| `POST` | `/api/upload` | Legacy single-file upload (fallback) |
| `GET` | `/api/files` | List all files with optional status filter |
| `GET` | `/api/files/:id` | Get file details and pipeline stages |
| `GET` | `/api/files/:id/download` | Download decrypted file (safe files only) |
| `DELETE` | `/api/files/:id` | Delete file from S3 + cleanup PQC secrets |

### Pipeline & Analytics

| Method | Endpoint | Description |
|:-------|:---------|:------------|
| `GET` | `/api/pipeline/:id` | Real-time pipeline stage status for a file |
| `GET` | `/api/dashboard/metrics` | Dashboard metrics (safe/blocked/scanning/quarantine counts) |
| `GET` | `/api/security/stats` | Security analytics (pass rates, layer stats, recent threats) |
| `GET` | `/api/notifications` | Threat notifications with unread count |
| `POST` | `/api/notifications/read` | Mark all notifications as read |

---

## 🖥 Frontend Features

- **3D Quantum Lock Authentication** — Interactive WebGL padlock scene (Three.js) with cinematic unlock/lock animations on login/logout, orbital rings, data nodes, and 240 quantum particles with mouse parallax
- **Real-Time Security Dashboard** — Live metrics with animated count-up cards showing files safe, threats blocked, active scans, and quarantine queue
- **Drag-and-Drop Upload** — Browser-direct S3 multipart upload via presigned URLs with chunk-level progress tracking
- **Live Pipeline Visualization** — Stage-by-stage progress display as each security layer executes
- **File History & Audit Trail** — Complete upload history with status badges (quarantine → scanning → safe/blocked), SHA-256 hashes, risk scores, and sandbox analysis details
- **Security Analytics Page** — Layer-by-layer pass/fail statistics, recent threat log, scan pass rate metrics
- **AWS Configuration Portal** — One-click AWS infrastructure provisioning from the settings page
- **Automated Email Alerts** — SMTP-based notifications dispatched when threats are detected
- **Responsive Design** — Collapsible sidebar, mobile-friendly layout, dark theme with glassmorphism effects

---

## 🔒 Security Design Principles

1. **Zero Trust** — No file is trusted by default. All uploads are quarantined and must pass all scanning layers before promotion.
2. **Defense in Depth** — Five independent security layers, each capable of catching threats the others might miss.
3. **Cumulative Risk Scoring** — Individual layer risk scores are aggregated. Even if no single layer fails, a high cumulative score triggers blocking.
4. **Graceful Degradation** — If Docker is unavailable or VirusTotal is unreachable, affected layers are skipped with appropriate risk penalties rather than crashing.
5. **Zero Plaintext Keys** — AES encryption keys are never stored in plaintext. They exist only in memory during the encryption/decryption operation and are immediately wiped.
6. **Post-Quantum Readiness** — NIST-standardized ML-KEM-768 and ML-DSA-65 algorithms protect against future quantum computing threats to the key exchange and signature verification.
7. **Ephemeral Sandbox Isolation** — Behavioral analysis containers have no network, limited resources, dropped capabilities, and are destroyed after each scan.
8. **Least Privilege** — AWS sessions use STS role assumption with scoped permissions where possible. Stored credential fallback logs deprecation warnings.

---

<p align="center">
  <strong>StackDrive</strong> — Because your data shouldn't be trusted until it's verified.
</p>
