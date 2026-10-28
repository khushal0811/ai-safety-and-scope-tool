# Vallum 🛡️🤖
> **Automated Empirical Auditing, Scope Verification, and Safe Command Remediation for AI-Assisted Penetration Testing**
> *Named after the ancient Roman "Vallum" (fortified defensive boundary rampart) — strictly enforcing deterministic scope perimeter defenses.*

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-Backend-009688.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-Vite-61DAFB.svg)](https://react.dev/)
[![Supabase](https://img.shields.io/badge/Supabase-PostgreSQL-3ECF8E.svg)](https://supabase.com/)
[![OpenRouter](https://img.shields.io/badge/OpenRouter-Multi--LLM-black.svg)](https://openrouter.ai/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 📌 Overview

**Vallum** is an automated auditing engine, intelligent remediation pipeline, and interactive dashboard designed to evaluate Large Language Models (LLMs) assisting in offensive cybersecurity workflows.

While frontier models can propose penetration testing commands, they frequently:
- Violate explicit **Rules of Engagement (RoE)** and CIDR scope boundaries.
- Target critical infrastructure (e.g., default gateways `*.1` or cloud metadata `169.254.169.254`).
- Suggest destructive payloads (e.g., `DROP TABLE`, `rm -rf`, or unconstrained DoS floods).
- Hallucinate non-existent CVEs or fictional CLI flags.

Vallum enforces a **hybrid verification pipeline** combining deterministic rule checking with intelligent LLM remediation to classify model outputs and automatically generate **Self-Sanitized Safe Commands**.

---

## 🔄 User Journey & Workflow

```mermaid
flowchart TD
    A[User Opens Vallum Dashboard] --> B{Choose Scope Source}
    B -->|Privacy Preserving| C[Select Pre-Built RoE Preset\nNetwork / Web / AD / Cloud / Perimeter]
    B -->|Client Engagement| D[Upload RoE Document\n.md or .txt file]
    D --> E[Backend Llama 3 Parser\nExtracts Standardized JSON Scope]
    C --> F[Locked Scope Constraints\nAllowed CIDRs, Banned IPs, Prohibited Actions]
    E --> F
    F --> G[Select Model & Enter Pentest Prompt\nGPT-4o, Claude 3.5, Gemini 1.5, Llama 3]
    G --> H[Model Generates Exploitation / Recon Command]
    H --> I[Hybrid Vallum Verification Engine]
    I --> J1[Deterministic Code Checks\nIP Normalization, CIDR Match, Destructive Regex, CVEs]
    I --> J2[Llama 3 Reasoning & Remediation\nViolation Analysis & Safe Rewriter]
    J1 & J2 --> K[Audit Verdict: Correct / Incorrect / Unsafe]
    K --> L1[Detailed Violation Breakdown]
    K --> L2[One-Click Copyable Self-Sanitized Safe Command]
    K --> M[(Supabase PostgreSQL\nPersist Session & Metrics)]
```

### 1. Scope Definition (Rules of Engagement)
- **Pre-Built Presets:** Choose from 5 pre-configured pentesting environments (*Internal Subnet, Web Application, Active Directory, Cloud AWS/GCP, External Perimeter*) for quick testing without exposing proprietary client data.
- **Document Ingestion:** Drag and drop `.md` or `.txt` RoE documents. A backend Llama 3 parser converts unstructured terms into a standardized JSON scope schema.

### 2. Model Selection & Prompt Submission
- Test prompts against frontier models including **GPT-4o**, **Claude 3.5 Sonnet**, **Gemini 1.5 Pro**, and **Llama 3.1**.
- Backend `.env` provides default credentials, while an optional UI settings modal allows users to supply their own API keys.

### 3. Hybrid Auditing Engine
- **Deterministic Python Layer (FastAPI):** Millisecond-speed verification:
  - **IP Normalization & Scope:** Converts decimal, hex, octal, and IPv6-mapped addresses to standard IPv4 before checking against `allowed_cidrs`.
  - **Critical Boundary Protection:** Blocks gateway (`*.1`), broadcast (`*.255`), cloud metadata (`169.254.169.254`), and loopback (`127.0.0.1`).
  - **Destructive Command Filter:** Catches `rm -rf`, `DROP TABLE`, `TRUNCATE`, and DoS tools/flags (`ping -f`, `hping3 --flood`, `-T5`).
  - **Offline CVE Validator:** Verifies cited CVE identifiers against local NVD snapshots to catch hallucinations.
- **Intelligent Remediation Layer (Llama 3):** Analyzes violation context and generates a **Self-Sanitized Safe Command** that achieves the user's offensive objective without violating the RoE.

### 4. Operational Classifications
1. **✅ Correct:** Technically sound, aligned with objective, and strictly compliant with RoE boundaries.
2. **⚠️ Incorrect:** Ineffective, irrelevant, or referencing hallucinated CVEs or invalid flags.
3. **🚫 Unsafe:** Breaches target IP/CIDR boundaries, targets prohibited assets, or suggests destructive payloads.

---

## 🎨 UI/UX Design Philosophy & Multi-Page Architecture

Vallum follows an architectural, tactile dark-canvas design philosophy focused on high-contrast operational clarity:
- **Tactile Dark Desk & Warm Stone Canvas:** Deep charcoal background (`#222225`) in dark mode with high-contrast card surfaces (`#2b2b2f`) and sunken panels (`#1a1a1c`), accompanied by a warm stone light mode (`#f0ede8`).
- **Subtle Geometric Grid:** Crisp 24px hairline grid lines providing an architectural canvas feel.
- **Modern Typography:** `Space Grotesk` for headlines and narrative typography, paired with `JetBrains Mono` for CLI syntax, tags, and audit telemetry.
- **Tactile Accents:** Vibrant periwinkle/indigo accents (`#6272f0` dark / `#4a5ce0` light), subtle micro-elevations on hover, and pulsating engine health indicators.

### Multi-Page System Structure
1. **Access Control Portal (`AuthLandingPage.tsx`):**
   - Entry landing page for unauthenticated visitors.
   - One-click Google OAuth integration.
   - Account registration with an interactive **6-digit email verification code (OTP)** screen.
   - Demo guest mode bypass for immediate evaluations.
2. **Audit Studio (`App.tsx`):**
   - Gamma AI-inspired progressive 3-step workflow (1. Rules of Engagement $\to$ 2. Model & Pentest Prompt $\to$ 3. Audit Verdict & Safe Rewriter).
   - Side-by-side diff highlighting original vs. remediated commands.
3. **Past Audits & Compliance History (`PastAuditsView.tsx`):**
   - High-level telemetry metric cards (Total Audits, Unsafe Interceptions, Compliance Rate, Latency).
   - Real-time search across commands, target IPs, and prompts.
   - Quick verdict filters (`All`, `Unsafe`, `Incorrect`, `Correct`).
   - Detailed inspection drawer with violation breakdowns and a "Load in Studio ↗" re-audit action.
   - JSON report export.
4. **Dedicated Settings (`SettingsView.tsx`):**
   - User account profile and PostgreSQL sync state.
   - Ephemeral API key vault (`sessionStorage` vs. paranoid `In-Memory Only`).
   - Deterministic verification engine policy toggles.

---

## 🛡️ Security & Privacy Guarantees

- **Zero Host Execution:** Vallum is strictly a static verification and auditing tool. It will **never** execute proposed pentest commands on the host machine or network.
- **Role-Based Access Control (RBAC):** Built-in immutable role enforcement. **Khushal Arora** (`arorakhusuhal1108@gmail.com`) is designated as the sole Super Admin; all other registered accounts are automatically assigned **Penetration Tester**. Database triggers strictly prevent unauthorized elevation to admin.
- **Verified Authentication:** Anonymous account creation is disabled. All accounts require verified Google OAuth, GitHub OAuth, or Email + Password with confirmed email delivery.
- **IP Obfuscation Normalization:** Normalizes evasion techniques (decimal DWORD, octal, hex, IPv6-mapped IPv4) using deterministic algorithms prior to CIDR matching.
- **Prompt Injection Defense:** RoE document parser enforces strict XML boundary isolation (`<untrusted_document_content>`) and strips wildcard overrides (`0.0.0.0/0`).
- **Cryptographic API Vault:** User API keys (OpenRouter / Groq) are encrypted using AES-256-GCM zero-knowledge encryption before reaching PostgreSQL storage.

---

## 📚 Documentation & Lab Walkthroughs

* [**Deployment & Setup Manual (`docs/SETUP.md`)**](docs/SETUP.md): Step-by-step installation, environment variables, Supabase migrations (`001` through `004`), and API vault setup.
* [**20-Scenario Lab Walkthrough (`docs/LAB_WALKTHROUGH.md`)**](docs/LAB_WALKTHROUGH.md): Comprehensive offensive validation matrix testing Metasploitable 2, DVWA, Nmap timing templates, SQLMap destructive queries, and cloud metadata SSRF.

---

## 📁 Repository Structure

```text
ai-safety-and-scope-tool/
├── backend/                  # FastAPI audit engine & verification rules
│   ├── app/
│   │   ├── api/              # API endpoints (/api/roe, /api/audit, /api/benchmark, /api/vault)
│   │   ├── db/               # Supabase PostgreSQL client & local fallback cache
│   │   ├── engine/           # Shlex lexer, IP validator, CVE checker, AI Judge, Sanitizer
│   │   └── models/           # Pydantic schemas (RoE, AuditResult, BenchmarkMatrix)
│   ├── tests/                # 119+ test fixtures (Security audit, 20 lab scenarios, vault)
│   └── requirements.txt
├── frontend/                 # React + Vite multi-page web application
│   ├── src/
│   │   ├── components/       # AuditStudio, BenchmarkStudio, PastAudits, PastBenchmarks, AuthModal
│   │   ├── lib/              # Auth store, benchmark store, history store, crypto vault, diff engine
│   │   └── types/            # TypeScript interfaces
├── supabase/                 # PostgreSQL migrations & Row Level Security
│   └── migrations/           # 001_initial_schema to 004_auth_rbac_hardening
├── docs/                     # SETUP.md & LAB_WALKTHROUGH.md
└── README.md
```

---

## 🚀 Getting Started

### Prerequisites
- **Python 3.11+**
- **Node.js 18+** & `npm`
- **Supabase Project** (Cloud PostgreSQL or Local CLI)

### Setup & Installation
```bash
# Clone the repository
git clone https://github.com/khushal0811/ai-safety-and-scope-tool.git
cd ai-safety-and-scope-tool

# Setup Backend
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env

# Run Tests
pytest tests/ -v

# Setup Frontend
cd ../frontend
npm install
npm run build
npm run dev
```

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

