# 2026-AI-Driven-Secure-Cloud-File-Upload-System-with-Quantum-Resistant-Encryption-Support
**Platform:** Python | React | AES-256 | PQC | AWS

---

# 🛡️ StackDrive — Secure Cloud File Ingestion Gateway
> Zero-Trust file security platform with AI-driven threat detection, multi-layer scanning, and post-quantum cryptographic protection.

StackDrive is an enterprise-grade web application that enforces a strict zero-trust security model for cloud file uploads. Every incoming file is automatically quarantined, scanned through a 5-layer automated defense pipeline, and — only upon passing all checks — encrypted with hybrid post-quantum cryptography before being promoted to secure cloud storage. No file is ever trusted by default.

---

## 📋 Table of Contents
1. [Problem Statement](#-problem-statement)
2. [Core Architecture](#-core-architecture)
3. [Security Pipeline — Deep Dive](#-security-pipeline--deep-dive)
4. [Hybrid Encryption Engine](#-hybrid-encryption-engine)
5. [Technology Stack](#-technology-stack)
6. [Project Structure](#-project-structure)
7. [Getting Started](#-getting-started)
8. [Environment Configuration](#-environment-configuration)
9. [API Reference](#-api-reference)
10. [Frontend Features](#-frontend-features)
11. [Security Design Principles](#-security-design-principles)

---

## 🎯 Problem Statement
Traditional cloud storage solutions accept and store files without real-time deep inspection, leaving organizations vulnerable to:
*   **Malware propagation** through seemingly benign file uploads.
*   **Zero-day exploits** embedded in obfuscated archives and PDFs.
*   **ZIP bombs** designed to exhaust server disk space and memory.
*   **Data exfiltration payloads** containing encoded reverse shells or hidden PE/ELF binaries.
*   **Quantum computing threats** targeting current public-key encryption standards (RSA, ECC).

StackDrive addresses all of these by implementing an automated, multi-layered security gateway that inspects, analyzes, and cryptographically protects every file — *before* it ever touches permanent storage.

---

## 🏗 Core Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        CLIENT (React 19 + Vite)                         │
│   Login/Signup ─► Dashboard ─► Upload ─► File History ─► Security       │
│                    3D Quantum Lock Auth Scene (Three.js)                │
└────────────────────────────────┬────────────────────────────────────────┘
                                 │  REST API (JWT Auth)
                                 ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                     BACKEND (Flask + Python 3.12)                       │
│                                                                         │
│  ┌──────────────┐  ┌─────────────────────────────────────────────────┐  │
│  │  Auth Layer  │  │        SECURITY PIPELINE (5 Layers)             │  │
│  │  (JWT+bcrypt)│  │                                                 │  │
│  └──────┬───────┘  │  L1: Multi-Source Threat Intelligence           │  │
│         │          │  L2: Universal Static Analysis (YARA + ZIP)     │  │
│         ▼          │  L3: ClamAV (Docker — persistent daemon)        │  │
│  ┌──────────────┐  │  L4: Sandbox (Docker — behavioral analysis)     │  │
│  │  SQLite DB   │  │  L5: Hybrid Encryption (AES-256 + KMS + PQC)    │  │
│  │  (Users,     │  └─────────────────────────────────────────────────┘  │
│  │   Files,     │                        │                              │
│  │   Pipeline,  │                        ▼                              │
│  │   Sharing)   │  ┌──────────────────────────────────────────────────┐ │
│  └──────────────┘  │            AWS INFRASTRUCTURE                    │ │
│                    │  S3 (Quarantine + Secure buckets)                │ │
│                    │  KMS (Envelope encryption + SSE)                 │ │
│                    │  IAM/STS (Scoped Role sessions)                  │ │
│                    │  Secrets Manager (PQC private keys)              │ │
│                    └──────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
```

### Data Flow
1.  **Upload:** User uploads files via presigned multipart uploads directly to the isolated S3 quarantine bucket in chunks.
2.  **Quarantine:** The file remains completely isolated. Access is restricted until the entire pipeline executes successfully.
3.  **Pipeline Execution:** Layers 1–4 run sequentially in background worker threads. Each layer generates a pass/fail verdict and a risk score.
4.  **Cumulative Risk Scoring:** Risk scores are aggregated across layers. If the cumulative score exceeds the threshold (70), the file is blocked.
5.  **Encryption (Layer 5):** Files passing all layers are encrypted with hybrid AES-256-GCM + AWS KMS + ML-KEM-768/ML-DSA-65 and promoted to the secure bucket.
6.  **Notification:** Blocked files trigger real-time in-app notifications and automated SMTP email alerts to the owner.
7.  **Cleanup:** The raw quarantine copy is immediately deleted after processing, ensuring no raw threat persistence.

---

## 🔬 Security Pipeline — Deep Dive

### Layer 1: Multi-Source Threat Intelligence
*   **Purpose:** Cross-reference file hashes against global threat intelligence feeds.
*   **Feeds Queried:** VirusTotal API v3 (70+ AV engines), MalwareBazaar, AlienVault OTX, URLHaus, ThreatFox, and CIRCL (NSRL known-good lookup).
*   **Caching Strategy:** Single connection pool Redis cache with TTL (6h), falling back to an auto-evicting TTL-aware in-memory cache.
*   **Circuit Protection:** Unified `ApiGuard` implementing token-bucket rate limiting and circuit breakers per API client to prevent requests on failure states.
*   **Degraded Mode:** If APIs are unreachable or keyless fallback fails, the layer yields a default risk penalty (15) and continues.

### Layer 2: Universal Static Analysis
Inspects files using a multi-threaded parallel static checking suite:
1.  **ZIP Bomb Detection:** Prevents decompression ratio exploits (>100:1) and limits absolute uncompressed size (2GB).
2.  **Path Traversal Guard:** Detects and blocks entries containing `../` or `..\`.
3.  **YARA Rules engine:** Scans payload using structured custom rules (reverse shells, auto-exec macros, destructive bash commands, LOLBaS abuse).
4.  **Office Open XML Analyzer:** Scans Office formats for VBA/XLM macro binaries, remote template injection URLs, and ActiveX dependencies.
5.  **PDF Structure Analyzer:** Scans byte-level offsets for `/JavaScript`, `/OpenAction`, `/Launch`, `/EmbeddedFile`, and `/XFA` forms.
6.  **Double-Extension & Obfuscated Filename Checks:** Captures executable extensions disguised with secondary file extensions.
7.  **Polyglot Inspection:** Prevents image files containing hidden ZIP, PE, or ELF headers.
8.  **Shannon Entropy:** Detects packed binaries, encryptors, and obfuscated shellcodes.

### Layer 3: ClamAV Antivirus (Docker Daemon)
*   **Architecture:** Persistent `clamav/clamav:latest` Docker container running the daemon on TCP port 3310.
*   **Protocol:** High-speed socket connection using the `zINSTREAM` clamd protocol.
*   **Two-Phase Scanning:** Streams the entire archive, then extracts up to 50 members (max 100MB per file) and performs independent checks on code components (defense-in-depth against obfuscated zip contents).
*   **Degraded Mode:** Auto-recovers container on startup; falls back to an informational warning if Docker is stopped.

### Layer 4: Behavioral Sandbox (Docker)
Spawns ephemeral, resource-constrained container instances to analyze file execution heuristics:
*   **Sandbox Isolation Constraints:**
    *   `--network none` — Zero external socket connections.
    *   `--memory 256m` — Limits memory utilization (DoS protection).
    *   `--cpus 1` — Throttled CPU cycles.
    *   `--pids-limit 64` — Fork bomb prevention.
    *   `--read-only` — Immutable sandbox filesystem.
    *   `--security-opt no-new-privileges` — Dropped capability set.
*   **Diagnostic Modules:**
    *   *Syscall Analysis:* Captures system calls via `strace` (connect, bind, execve, ptrace, chmod, setuid, clone, etc.) with custom threat weights.
    *   *Process & Time limits:* Detects execution timeouts (evasion) and abnormal exit codes.

---

## 🔐 Hybrid Encryption Engine

```
┌─────────────────────────────────────────────────────────────────┐
│                    ENCRYPTION FLOW (v2)                         │
│                                                                 │
│  Raw File ──► AES-256-GCM ──► Encrypted Blob                    │
│                    │                                            │
│                    ├── AES Key ──► KMS Envelope Encrypt         │
│                    │                                            │
│                    ├── ML-KEM-768 (Kyber) Key Encapsulation     │
│                    │       └── HKDF(KMS_DEK ∥ PQC_SS)           │
│                    │             └── Hybrid AES Key             │
│                    │                                            │
│                    └── ML-DSA-65 (Dilithium) Digital Signature  │ 
│                          └── Signs(nonce ∥ CT ∥ tag ∥ binding)   │
│                                                                 │
│  Binary Payload Layout:                                         │
│  [MAGIC 5B][HDR_LEN 4B][JSON HDR][KEM_CT][NONCE][CT][TAG][SIG]  │
└─────────────────────────────────────────────────────────────────┘
```

### Cryptographic Abstraction
*   **Classical Layer:** AES-256-GCM authenticated symmetric encryption.
*   **Key Wrapping:** AWS KMS Customer Managed Keys generate a unique Data Encryption Key (DEK) for each file with user-scoped encryption context.
*   **Post-Quantum KEM:** NIST FIPS 203 standardized **ML-KEM-768** (Kyber). Generates a quantum-resistant shared secret combined with the KMS DEK using HKDF-SHA-256.
*   **Post-Quantum Signature:** NIST FIPS 204 standardized **ML-DSA-65** (Dilithium). Validates authenticity and binding integrity of the encapsulated packet.
*   **Hybrid Binding Verification:** HMAC-SHA-256 proof ensures both KMS and PQC layers contributed cryptographically to the decryption key material.

### Zero-Trust Key Storage Rules
*   **Plaintext Keys:** Kept in memory only during cryptographic operations, immediately wiped (`del` statement).
*   **Encrypted DEK:** Stored in the SQLite metadata table (`kms_encrypted_key`).
*   **PQC Private Keys:** Provisioned per-file and written to **AWS Secrets Manager** with restrictive access policies.
*   **Encrypted Payloads:** Uploaded directly to the target secure S3 bucket with KMS Server-Side Encryption (SSE-KMS) enabled.

---

## 🛠 Technology Stack

### Backend
| Component | Technology | Version / Source |
| :--- | :--- | :--- |
| **API Framework** | Flask | 3.1.0 |
| **Database ORM** | Flask-SQLAlchemy | 3.1.1 |
| **Authentication** | Flask-JWT-Extended + Bcrypt | 4.7.1 / 4.3.0 |
| **Email Service** | Flask-Mail (SMTP wrapper) | 0.10.0 |
| **Cloud SDK** | Boto3 (S3, KMS, Secrets Manager, STS) | 1.36.14 |
| **Cryptography** | PyCryptodome (AES-GCM, HKDF) | 3.21.0 |
| **PQC Library** | `liboqs-python` (ML-KEM, ML-DSA) | Compiled from Source |
| **Security scanning** | Yara-Python / PyClamd | 4.x / 0.4.0 |
| **Database** | SQLite | 3.x |

### Frontend
| Component | Technology | Version |
| :--- | :--- | :--- |
| **Core Library** | React | 19.2.4 |
| **Build System** | Vite | 8.0.4 |
| **Routing** | React Router DOM | 7.14.0 |
| **3D Animations** | Three.js (WebGL rendering) | 0.184.0 |
| **Icons Library** | Lucide React | 1.8.0 |
| **Styling** | Vanilla CSS (Custom Responsive design) | — |

---

## 📁 Project Structure

```
stackdrive/
├── backend/
│   ├── app.py                      # Flask API — Auth, upload orchestrator, sharing, copilot, dashboard endpoints
│   ├── pipeline.py                 # 5-layer scanning pipeline — VT intelligence, ZIP, ClamAV, Sandbox, YARA
│   ├── encryption.py               # Hybrid PQC cryptosystem — AES-256 + KMS + ML-KEM + ML-DSA
│   ├── models.py                   # SQLAlchemy tables — User, File, PipelineStage, SharedFile, ShareAuditLog
│   ├── config.py                   # App configurations — WSL-detection, DB paths, JWT rules, limits
│   ├── Dockerfile.sandbox          # Custom sandbox container filesystem
│   └── requirements.txt            # Python backend dependencies
│
├── src/
│   ├── App.jsx                     # Application router and session wrapper
│   ├── main.jsx                    # Client runtime entrypoint
│   ├── index.css                   # Custom global styling and CSS variables
│   │
│   ├── components/
│   │   ├── AICopilot.css           # Chat styling sheet
│   │   ├── AICopilot.jsx           # AI Copilot user interface (Gemini API)
│   │   ├── CustomSelect.jsx        # Custom drop-down inputs
│   │   ├── EncryptionScene.jsx     # Three.js 3D Padlock background visual
│   │   ├── FileTable.jsx           # Responsive list representation
│   │   ├── Header.jsx              # Navigation header
│   │   ├── Modal.jsx               # Floating modal overlay
│   │   ├── NotificationPanel.jsx   # Live alerts dashboard drawer
│   │   ├── PipelinePanel.jsx       # Real-time pipeline scanner step progress
│   │   ├── Sidebar.jsx             # Left Collapsible side-navigation
│   │   ├── StatCard.jsx            # Animated statistics blocks
│   │   ├── StatusBadge.jsx         # Scanner state display
│   │   ├── Toast.jsx               # System confirmation toast
│   │   └── UploadZone.jsx          # Presigned multipart S3 dropzone
│   │
│   ├── pages/
│   │   ├── Dashboard.jsx           # Main stats and summary dashboard
│   │   ├── UploadPage.jsx          # Drag-and-drop workspace with logs
│   │   ├── FileHistory.jsx         # Full logs panel and sharing creation
│   │   ├── SecurityPage.jsx        # Pipeline pass rates and scan history
│   │   ├── SettingsPage.jsx        # AWS connections and user configuration
│   │   ├── LoginPage.jsx           # Login interface with 3D Lock
│   │   ├── SignupPage.jsx          # Registration form with 3D Lock
│   │   ├── ShareLanding.jsx        # File download page for shared links
│   │   ├── SharedFiles.jsx         # Active share links manager (revoke/extend)
│   │   └── LogoutPage.jsx          # Logout page with locking visual
│   │
│   ├── services/
│   │   └── api.js                  # Axios-equivalent REST API client with JWT interceptors
│   ├── data/
│   │   └── mockData.js             # Local analytics statistics mocks
│   └── hooks/
│       ├── useCountUp.js           # Metric numeric count-up hook
│       └── usePipelineSimulation.js # Offline pipeline preview mockup hook
│
├── public/                         # Public SVGs, icons, and logos
├── vite.config.js                  # Vite compiler configurations
└── eslint.config.js                # Code linting rules
```

---

## 🚀 Getting Started

### Prerequisites
*   **Node.js:** `v18` or higher
*   **Python:** `3.11` or higher
*   **Docker Desktop:** Daemon active for sandbox and antivirus scanning layers.
*   **AWS Credentials:** Scoped access keys with permissions for S3, KMS, and Secrets Manager.

### 1. Clone the Repository
```bash
git clone https://github.com/UnisysUIP/2026-AI-Driven-Secure-Cloud-File-Upload-System-with-Quantum-Resistant-Encryption-Support.git
cd 2026-AI-Driven-Secure-Cloud-File-Upload-System-with-Quantum-Resistant-Encryption-Support
```

### 2. Backend Installation & Setup
```bash
cd backend
python -m venv venv

# Windows (Command Prompt / PowerShell)
.\venv\Scripts\activate

# macOS / Linux
source venv/bin/activate

# Install requirements
pip install -r requirements.txt
```

#### Post-Quantum Cryptography Compilation (Optional)
ML-KEM and ML-DSA dependencies require `liboqs-python` compiled from source:
```bash
# Requires CMake and GCC/Clang on WSL/Linux
git clone --depth=1 https://github.com/open-quantum-safe/liboqs-python.git
cd liboqs-python
pip install .
```
Enable the algorithm suite in your `.env`:
```env
PQC_ENABLED=true
```

#### Run the Flask Server
```bash
python app.py
# Server initializes on http://localhost:5000
```

### 3. Frontend Installation & Setup
In a new terminal window at the root of the project folder:
```bash
# Install npm components
npm install

# Start Vite dev server
npm run dev
# Dashboard launches on http://localhost:5173
```

### 4. Direct Cloud Integration
1. Log in to your StackDrive account dashboard.
2. Navigate to **Settings** -> **AWS Configuration**.
3. Input your `AWS Access Key ID`, `AWS Secret Access Key`, and `Region`.
4. Click **Connect AWS**. StackDrive will automatically provision:
   * A quarantine S3 bucket (public access blocked).
   * A secure S3 bucket (SSE-KMS default).
   * An AWS KMS Customer Managed key with alias `stackdrive-key-<id>`.
   * Dynamic CORS permissions for S3 multipart uploads.

---

## ⚙️ Environment Configuration

| Variable | Required | Default | Purpose |
| :--- | :--- | :--- | :--- |
| `VT_API_KEY` | Recommended | — | VirusTotal threat intelligence queries |
| `OTX_API_KEY`| No | — | AlienVault OTX intelligence checks |
| `PQC_ENABLED`| No | `false` | Enable/Disable ML-KEM and ML-DSA |
| `SECRET_KEY` | Production | `stackdrive-secret-...` | Flask Session secret key |
| `JWT_SECRET_KEY` | Production | `jwt-super-...` | JWT encoding signing key |
| `CLAMAV_DOCKER_IMAGE`| No | `clamav/clamav:latest` | AV daemon container image |
| `CLAMD_HOST` | No | `127.0.0.1` | Target address of antivirus socket |
| `CLAMD_PORT` | No | `3310` | Port of antivirus daemon |
| `SANDBOX_TIMEOUT`| No | `10` | Execution time limit in sandbox |
| `REDIS_URL` | No | — | Redis cache endpoint for hash lookup caching |
| `DATABASE_URL`| No | `sqlite:///stackdrive.db` | Overwrites default SQLite directory path |
| `MAIL_SERVER` | No | `smtp.gmail.com` | Alert SMTP email target |
| `MAIL_PORT` | No | `587` | Outgoing mail server TLS port |
| `MAIL_USERNAME`| No | — | SMTP authentication user name |
| `MAIL_PASSWORD`| No | — | SMTP authentication password |

---

## 📡 API Reference

### Authentication
*   `POST /api/auth/signup` — Registers email + password. Returns JWT token.
*   `POST /api/auth/login` — Authenticates login credentials. Returns JWT token.
*   `GET /api/auth/me` — Gets profile details for the authenticated user.

### AWS Provisioner
*   `POST /api/aws/connect` — Ephemerally connects and provisions AWS components.
*   `GET /api/aws/status` — Retrieves cloud connection settings.
*   `POST /api/aws/disconnect` — Clears connected AWS parameters from metadata.

### File Ingestion & Pipeline
*   `POST /api/upload/initiate` — Starts S3 multipart upload session, returns presigned part URLs.
*   `POST /api/upload/complete` — Concludes S3 multipart upload and queues background scanning.
*   `POST /api/upload/abort` — Cancels multipart upload and deletes S3 temp chunks.
*   `POST /api/upload` — Single-request file upload backup.
*   `GET /api/files` — Returns list of user files (filter by `status` available).
*   `GET /api/files/:id` — Details of file and individual pipeline stage results.
*   `GET /api/files/:id/download` — Decrypts and streams target file (verified safe files only).
*   `DELETE /api/files/:id` — Deletes S3 binaries, Secrets Manager private keys, and DB metadata.
*   `GET /api/pipeline/:id` — Returns real-time scanner updates.

### Secure Sharing (v2 Engine)
*   `POST /api/files/:id/share` — Generates link with optional password, download limits, and expiry.
*   `GET /api/share/:token/info` — Retrieves file sharing status (without downloading).
*   `GET /api/share/:token` — Decrypts and downloads shared file.
*   `POST /api/share/:token/download` — Decrypts and downloads shared file (supports email watermarking).
*   `GET /api/shares` — Lists all sharing links created by the user.
*   `POST /api/shares/:id/revoke` — Revokes sharing link immediately.
*   `POST /api/shares/:id/extend` — Extends link expiration by a specified number of hours.
*   `GET /api/shares/:id/audit` — Retrieves download audit log trail (IP, timestamps, events).

### AI Copilot & Reporting
*   `POST /api/copilot/chat` — Submits message to the security copilot (Gemini API with fallback).
*   `GET /api/copilot/report_data/:file_id` — Generates a comprehensive security report for a file.
*   `DELETE /api/copilot/history` — Clears conversation history for the current user session.

### Analytics & Alerts
*   `GET /api/dashboard/metrics` — Dashboard counts (safe, blocked, scanning, quarantine).
*   `GET /api/security/stats` — Detailed analytics, threat log, and layer pass rates.
*   `GET /api/notifications` — Notification list for threat detections.
*   `POST /api/notifications/read` — Marks all threat alerts as read.

---

## 🖥 Frontend Features
*   **3D Padlock Authentication Scene:** Powered by `Three.js` (WebGL). Renders an interactive WebGL padlock scene on authentication pages with responsive orbital ring nodes and mouse-parallax particles.
*   **Real-time scanning monitors:** Live tracker visualizing pipeline stage transitions in real-time as background scans complete.
*   **S3 direct multipart upload zone:** Drag-and-drop file interface connecting directly to S3 bucket chunk streams.
*   **Security Posture Analytics:** Interactive graphs depicting layer pass-rates, security metrics, and chronological threat logs.
*   **V2 Sharing Panel:** Create password-protected download interfaces, extend timelines, track download logs, and inject email watermarks into PDFs and text files on download.
*   **AI Security Copilot Chatbot:** Built-in floating chat drawer using Gemini API. Provides contextual security analysis and compiles printable PDF threat report downloads.

---

## 🔒 Security Design Principles
*   **Zero-Trust Ingestion:** Every file is locked within quarantine. No download or decryption is possible until all layers pass.
*   **Defense in Depth:** Structured 5-layer pipeline ensuring heuristic, static signature, network intel, and behavioral analysis cover all vector fronts.
*   **Weighted Risk Thresholding:** If the cumulative score exceeds 70 across any indicators, the file is automatically blocked.
*   **Zero-Plaintext Footprint:** DEK keys are never logged, stored in plaintext, or passed through S3 metadata parameters.
*   **Post-Quantum Resilience:** ML-KEM-768 key encapsulation and ML-DSA-65 signatures protect the encrypted storage from potential quantum decryption harvesting.
*   **Isolated Sandboxing:** Behavioral testing runs in memory-limited, network-disabled, dropped-privilege Docker environments.
*   **Comprehensive Sharing Audit Trail:** Tracks all successful, expired, blocked, or failed password entries with IP log records to prevent link enumeration.

---
*StackDrive: Because your data shouldn't be trusted until it's verified.*
