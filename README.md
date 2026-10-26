# Safety and Scope Tool (SST) 🛡️🤖
> **Automated Empirical Auditing, Scope Verification, and Safe Command Remediation for AI-Assisted Penetration Testing**

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-Backend-009688.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-Vite-61DAFB.svg)](https://react.dev/)
[![Supabase](https://img.shields.io/badge/Supabase-PostgreSQL-3ECF8E.svg)](https://supabase.com/)
[![OpenRouter](https://img.shields.io/badge/OpenRouter-Multi--LLM-black.svg)](https://openrouter.ai/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 📌 Overview

**Safety and Scope Tool (SST)** is an automated auditing engine, intelligent remediation pipeline, and interactive dashboard designed to evaluate Large Language Models (LLMs) assisting in offensive cybersecurity workflows.

While frontier models can propose penetration testing commands, they frequently:
- Violate explicit **Rules of Engagement (RoE)** and CIDR scope boundaries.
- Target critical infrastructure (e.g., default gateways `*.1` or cloud metadata `169.254.169.254`).
- Suggest destructive payloads (e.g., `DROP TABLE`, `rm -rf`, or unconstrained DoS floods).
- Hallucinate non-existent CVEs or fictional CLI flags.

SST enforces a **hybrid verification pipeline** combining deterministic rule checking with intelligent LLM remediation to classify model outputs and automatically generate **Self-Sanitized Safe Commands**.

---

## 🔄 User Journey & Workflow

```mermaid
flowchart TD
    A[User Opens SST Dashboard] --> B{Choose Scope Source}
    B -->|Privacy Preserving| C[Select Pre-Built RoE Preset\nNetwork / Web / AD / Cloud / Perimeter]
    B -->|Client Engagement| D[Upload RoE Document\n.md or .txt file]
    D --> E[Backend Llama 3 Parser\nExtracts Standardized JSON Scope]
    C --> F[Locked Scope Constraints\nAllowed CIDRs, Banned IPs, Prohibited Actions]
    E --> F
    F --> G[Select Model & Enter Pentest Prompt\nGPT-4o, Claude 3.5, Gemini 1.5, Llama 3]
    G --> H[Model Generates Exploitation / Recon Command]
    H --> I[Hybrid SST Verification Engine]
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

## 🎨 UI/UX Design Philosophy

Inspired by minimalist aesthetic design (such as Napkin AI):
- **Grid Canvas:** Subtle geometric grid background canvas (`grid-pattern`) easy on the eyes.
- **Monochromatic Palette:** Clean slate whites, charcoal grays, and deep black (`#09090b`) with refined 1px hairline borders.
- **Restrained Badges:** Non-distracting, high-contrast badges for status indications without loud neon effects or heavy glassmorphism.
- **Action-Oriented:** One-click copyable sanitized commands, side-by-side diff viewers, and quick preset switches.

---

## 🛡️ Security & Privacy Guarantees

- **Zero Host Execution:** SST is strictly a static verification and auditing tool. It will **never** execute proposed pentest commands on the host machine or network.
- **IP Obfuscation Normalization:** Addresses obfuscation evasion techniques (decimal, octal, hex, IPv6-mapped IPv4) using Python's `ipaddress` library before validation.
- **Indirect Prompt Injection Defense:** Document parser wraps uploaded RoEs in strict system boundaries and validates outputs against strict Pydantic schemas.
- **API Key Isolation:** User-entered keys remain strictly in browser `sessionStorage` or transient memory—never logged or saved to the database.
- **Database Row Level Security (RLS):** Supabase PostgreSQL tables enforce strict access controls.

---

## 📁 Repository Structure

```text
ai-safety-and-scope-tool/
├── backend/                  # FastAPI audit engine & verification rules
│   ├── app/
│   │   ├── api/              # API endpoints (/api/roe, /api/audit, /api/history)
│   │   ├── core/             # Configuration & security policies
│   │   ├── engine/           # Deterministic validators (IP, Regex, CVE, Whitelist)
│   │   ├── remediation/      # Llama 3 parser & safe command rewriter
│   │   └── models/           # Pydantic schemas (RoE, AuditResult, Violations)
│   ├── tests/                # Deterministic unit test suite
│   ├── requirements.txt
│   └── .env.example
├── frontend/                 # React + Vite web dashboard (Napkin AI aesthetic)
│   ├── src/
│   │   ├── components/       # Grid canvas, RoE selector, sanitized command box
│   │   ├── views/            # Audit Playground, Benchmark View, History
│   │   └── styles/           # Minimalist CSS tokens & grid styling
│   ├── package.json
│   └── vite.config.js
├── supabase/                 # Database migrations & RLS policies
│   └── migrations/           # PostgreSQL schema for presets, sessions, and audits
├── scenarios/                # Standardized JSON scenario presets
├── data/                     # Offline NVD CVE snapshot & tool signatures
└── docs/                     # Architecture documentation & API specs
```

---

## 🚀 Getting Started

### Prerequisites
- **Python 3.10+**
- **Node.js 18+** & `npm`
- **Supabase Account** (Cloud PostgreSQL)
- **OpenRouter API Key** (for Llama 3 parser and multi-model benchmarking)

### Setup & Installation
```bash
# Clone the repository
git clone https://github.com/khushal0811/ai-safety-and-scope-tool.git
cd ai-safety-and-scope-tool

# Setup Backend
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env

# Setup Frontend
cd ../frontend
npm install
npm run dev
```

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
