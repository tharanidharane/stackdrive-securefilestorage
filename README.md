# 🛡️ StackDrive

<br/>

> **Secure Cloud File Ingestion Gateway**
> *AI-Driven Secure Upload with Quantum-Resistant Encryption*

StackDrive is a next-generation web-based secure cloud file ingestion gateway designed for zero-trust environments. By implementing a multi-layer automated security pipeline and post-quantum cryptography, StackDrive ensures complete data integrity and confidentiality *before* any file touches your permanent cloud storage.

---

## 🚀 Key Features

*   **Zero-Trust Architecture**
    No file is automatically trusted. All uploads are initially confined to an isolated quarantine AWS S3 bucket.
*   **4-Layer Defense Pipeline**
    *   *Hash Compilation*: Matches uploaded files against known malware signatures.
    *   *ZIP Validation*: Prevents recursive ZIP bombs and malicious hidden executables.
    *   *Antivirus Engine*: Powered by ClamAV for widespread threat neutralization.
    *   *Zero-Day Sandbox*: Isolated Docker-based execution to analyze behavioral heuristics.
*   **Quantum-Safe Protocol**
    Fully encrypts validated files using robust AES-256 paired with AWS KMS key management, wrapped in the NIST-standardized Post-Quantum Cryptography algorithms (ML-KEM/Kyber & ML-DSA/Dilithium).
*   **Real-Time Threat Notifications**
    Instant SMTP-based automated email alerts dynamically dispatch when security triggers are tripped.

## 🏗️ System Architecture

*   **Frontend**: A sleek, responsive dashboard built strictly on **React.js** powered by **Vite** and styled with **Tailwind CSS**.
*   **Backend**: A high-efficiency **Python (Flask)** REST API orchestrating the file ingestion, security, and AWS resource routing.
*   **Infrastructure**: Deeply integrated AWS workflows (**S3, IAM, KMS, STS**) abstract away complex credentials, granting purely secure, user-managed ephemeral sessions.

## 🛠️ Technology Stack

| Pillar | Core Services |
| :--- | :--- |
| **Frontend** | React 19, Vite, Tailwind CSS |
| **Backend** | Python 3.12, Flask, JWT Auth, SQLite |
| **Crypto & Security** | AES-256, PyCryptodome, `liboqs` (PQC), ClamAV |
| **Cloud Architecture** | AWS S3, AWS KMS, AWS IAM |
| **Test & Container** | Docker (for Sandbox execution) |

## 📦 Setting Up the Gateway Locally

### Prerequisites
*   Node.js (`v18` or newer)
*   Python (`3.11` or newer)
*   Docker (Daemon must be running for advanced sandbox behavior tests)
*   Valid AWS Identity with CLI provisioning.

### 1. Backend Server Setup
Start by getting the Python environment operational.

```bash
cd backend
python -m venv venv
# On Windows:
.\venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

# Install the Python dependencies
pip install -r requirements.txt
```

> **Note**: Custom algorithms like ML-KEM/ML-DSA might require compiling `liboqs-python` via source or a tailored binary due to post-quantum nature requirements.

Start the API:
```bash
python app.py
```

### 2. Frontend Dashboard Setup
In a new terminal window inside the root `stackdrive` directory:

```bash
# Install NPM packages
npm install

# Start the Vite development server
npm run dev
```

Navigate to `http://localhost:5173` to access the dashboard!
---
*StackDrive: Because your data shouldn't be trusted until it's verified.*
