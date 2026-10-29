# Vallum — Complete Conversation, Security Evolution & Infrastructure Summary

**Repository:** `https://github.com/khushal0811/ai-safety-and-scope-tool`  
**Latest Commit (`main`):** `171f8e3`  
**Automated Test Suite:** `195 passed, 0 failed` (`pytest`)  
**Frontend Production Build:** `tsc -b && vite build` (`0 errors`)

---

## 1. Where We Started

We started with **Vallum (AI Safety & Scope Boundary Engine)** — a full-stack security verification platform designed to sit between an LLM (or human penetration tester) and offensive command execution. Its core premise is **Strict Zero Host Execution**:

1. **Scope Definition (RoE):** Users select a preset Rules of Engagement (RoE) scope or upload/paste a custom penetration testing contract (`.md` / `.txt`), which is extracted into a structured `RoeScope` schema (`allowed_cidrs`, `allowed_domains`, `target_hosts`, `prohibited_ips`, `allowed_tools`, `prohibited_tools`, `prohibited_flags`, `max_nmap_timing`).
2. **Command Auditing (Two-Pass Hybrid Engine):**
   - **Pass 1 (Deterministic Engine):** Parses commands, normalizes obfuscated IPs (hex, octal, decimal dword, IPv6-mapped, 2/3-part notation), validates targets against CIDR/domain scope and RFC1918/link-local/cloud metadata (`169.254.169.254`) rules, checks destructive patterns, and validates CVE references.
   - **Pass 2 (AI Judge & Remediation):** Uses an LLM judge to filter false positives from contextual explanations and synthesize safe, scope-compliant replacement commands.
3. **Comparative Benchmarking Studio:** Queries multiple frontier models (GPT-4o, Claude Sonnet 4.6, Gemini 3 Pro, Gemini 3.8 Flash, Claude Haiku 5.5) simultaneously to measure scope compliance, violation rate, hallucination rate, and latency.

In its initial state, the project used `shlex` tokenization, had basic regex rules, relied on system-level fallback API keys, and passed user identity loosely between the React frontend and FastAPI backend.

---

## 2. Chronological Evolution: What We Changed & Why

### Phase A — Core Engine Upgrades & Feature Expansion
1. **Bashlex AST Parser & `ToolFlagSpec` Registry (`d15c7bb`):**
   - *Why:* Flat `shlex` tokenization failed on compound bash pipelines (`&&`, `||`, `;`, `|`), subshells `$()`, and per-tool flag semantics (e.g., distinguishing whether `-p 80` is a port flag vs. a target host argument).
   - *What changed:* Rewrote `backend/app/engine/parser.py` to parse full bash Abstract Syntax Trees (ASTs), added a per-tool flag specification registry in `backend/app/engine/tool_rules.py`, and added a surgical SSRF payload scanner (`f67e6e2`) to inspect `-d` / `--data` / `--json` arguments for embedded internal URLs or metadata IPs.
2. **Strict Candidate Contract (`7d39b0d`, `327a832`):**
   - *Why:* An LLM AI Judge in Pass 2 could previously hallucinate non-existent violation IDs or override hard scope boundaries.
   - *What changed:* Restricted Pass 2 in `backend/app/engine/ai_judge.py` so it can only adjudicate candidate IDs explicitly emitted by Pass 1, and added a **Deterministic-Only Mode** toggle (`4834f8c`) for air-gapped / zero-LLM trust tiers.
3. **CLI Shim Daemon (`b2db744`), Micro-Sandbox (`8c38591`), and Formal Attestation Reports (`b05c9a9`):**
   - *Why:* Operators needed terminal-level command interception (`vallum-shim`), pre-flight dry-run simulation (`backend/app/engine/sandbox.py`), and tamper-evident PDF/Markdown/JSON compliance reports with SHA-256 hash chains (`backend/app/engine/reporter.py`).
4. **Strict Bring-Your-Own-Key (BYOK) Architecture (`4f5bb8d`, `3012368`, `1076da0`):**
   - *Why:* To prevent unauthenticated callers from draining server-side OpenRouter credits, all user audits and multi-model benchmarks were gated on the user supplying their own OpenRouter API key.
   - *What changed:* Added `InitialSetupModal.tsx` and cloud vault persistence so returning users who already saved a key in their encrypted database vault bypass the setup modal automatically across devices — even when logging in on a brand-new browser or device (`1076da0`).

---

### Phase B — Deep Security Audits & Hardening (Rounds 1–4 + Full-Stack Sweep)

#### 1. RoE Extractor Prompt-Injection & Scope-Classification Hardening (`d3b0880`)
- **Problem:** A maliciously crafted RoE document could attempt prompt injection during LLM scope extraction or trick the parser into classifying `"0.0.0.0/0"` as an authorized CIDR or placing prohibited IPs inside `target_hosts`.
- **Fix:** Wrapped untrusted document text in sanitized XML isolation tags in `backend/app/engine/roe_parser.py`, added deterministic post-validation that strips `0.0.0.0/0` and `::/0`, removes any `prohibited_ips` from `target_hosts`, and clamps Nmap timing templates to `0..5`.

#### 2. Closing Unauthenticated Identity-Spoofing & Vault Master Key Bypasses (`5f9e05a`)
- **Problem:**
  1. `backend/app/api/deps.py` previously fell back to trusting raw `X-User-Id` headers or `?user_id=` query parameters even in production when no `Authorization: Bearer` token was sent.
  2. `POST /api/vault/keys` accepted `user_id` from the JSON request body, and `POST /api/vault/verify-key` read `X-User-Id` directly.
  3. `POST /api/benchmark/query` and `/evaluate` could decrypt and spend another user's vault key via a forged header.
  4. `backend/app/engine/crypto_vault.py` fell back to `SUPABASE_ANON_KEY` (which is public in the frontend bundle) or a hardcoded string if `KEY_VAULT_MASTER_KEY` was unset.
- **Fix:**
  - Enforced strict Supabase JWT verification (`Authorization: Bearer <token>`) across all protected routes (`require_authenticated_user_id` / `get_authenticated_user_id`).
  - Gated the `X-User-Id` fallback strictly to `ENVIRONMENT == "development"` and blocked it whenever `SUPABASE_URL` points to a live remote `.supabase.co` database.
  - Bound every AES-256-GCM ciphertext in `crypto_vault.py` to `user_id` via **Additional Authenticated Data (AAD)** (`vallum-vault:v1:{user_id}`), and required an explicit 256-bit `KEY_VAULT_MASTER_KEY`.

#### 3. Round 4 Engine & Attestation Fixes (`5f9e05a`)
- **Problem:**
  - `rm -rf` detection in `backend/app/engine/destructive_rules.py` used a regex that only matched combined flags (`-rf` / `-fr`), missing separate flags (`rm -r -f /data`) and GNU long options (`rm --recursive --force /data`).
  - `dd` block-device detection required `if=` before `of=`, missing `dd of=/dev/sda if=/dev/zero`.
- **Fix:** Replaced brittle order-dependent regexes with AST token-segment analyzers (`_has_rm_recursive_force` and `_has_dd_to_block_device`) that inspect all flags and argument tokens regardless of order.

#### 4. Closing Cross-User Unscoped Data Leaks (`ad45d87`)
- **Problem:** `fetch_audit_logs_for_roe` and `fetch_custom_roes` in `backend/app/db/supabase_client.py` only applied `.eq("user_id", user_id)` *if* `user_id` was truthy — meaning an anonymous request (`user_id=None`) skipped the filter and returned every user's rows.
- **Fix:** `fetch_audit_logs_for_roe` now immediately returns `[]` if `user_id` is missing or not a valid UUID. `fetch_custom_roes` scopes strictly to `user_id.eq.<uuid>,user_id.is.null` for authenticated users and `user_id.is.null` (system presets only) for unauthenticated callers.

#### 5. Compliance Report Custom-Scope Resolution & Hash-Chain Consistency (`b233465`)
- **Problem:** `backend/app/engine/reporter.py` only looked up `roe_id` in static `ROE_PRESETS` and silently fell back to `ROE_PRESETS[0]` ("Internal Network Recon") whenever a user exported a report for a custom uploaded RoE. Also, audits were saved in a FastAPI `BackgroundTask`, causing a race condition when exporting a report immediately after an audit completed.
- **Fix:** Added `fetch_custom_roe_by_id` lookup in `generate_compliance_report` (raising HTTP 404 if unknown instead of substituting another scope), unified the SHA-256 chain seed across PDF/Markdown/JSON, and persisted audits synchronously before returning.

#### 6. Full-Stack Audit Sweep: Frontend Key Storage, Rate Limiting & Defense-in-Depth (`171f8e3`)
- **Problem:** `frontend/src/lib/keyStore.ts` was writing raw API keys to permanent `localStorage` and calling `supabase.from('user_api_vault').delete()` directly from the browser.
- **Fix:**
  - Rewrote `frontend/src/lib/keyStore.ts` so raw API keys are held **exclusively in volatile in-memory variables** on the client and never written to `localStorage` or `sessionStorage` (with automatic startup cleanup of any legacy stored keys).
  - Routed all vault writes, status checks, and deletions strictly through the FastAPI backend (`/api/vault/*`).
  - Added cross-user collision protection in `save_custom_roe`, deterministic re-verification of AI Judge `sanitized_script` outputs in `ai_judge.py`, narrowed CORS regex + added sliding-window rate limiting in `main.py`, and cleaned up `render.yaml`.

---

## 3. Hosting Architecture & Environment Keys

### 3.1 Frontend Hosting — **Vercel**
- **Config File:** `frontend/vercel.json` (rewrites all SPA routes `/(.*)` to `/index.html`).
- **Framework Preset:** Vite (`npm run build` → outputs `frontend/dist`).
- **Environment Variables in Vercel Dashboard:**

| Variable Name | Visibility | Purpose |
|---|---|---|
| `VITE_API_URL` (or `VITE_API_BASE_URL`) | Public (build-time) | URL of the deployed Render FastAPI backend (e.g., `https://vallum-backend.onrender.com`). |
| `VITE_SUPABASE_URL` | Public (build-time) | Your Supabase project URL (`https://<project-ref>.supabase.co`). |
| `VITE_SUPABASE_ANON_KEY` | Public (build-time) | Supabase anonymous public key used **only** for `supabase.auth.*` login/session management in the browser. |

---

### 3.2 Backend Hosting — **Render**
- **Config File:** `render.yaml`
- **Service Name:** `vallum-backend` (`rootDir: backend`)
- **Build Command:** `pip install -r requirements.txt`
- **Start Command:** `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
- **Health Check Path:** `/api/health`
- **Environment Variables in Render Dashboard:**

| Variable Name | Value / Secret Type | Purpose |
|---|---|---|
| `PYTHON_VERSION` | `3.11.9` | Pins Python runtime on Render. |
| `ENVIRONMENT` | `production` | Enforces strict JWT auth, disables dev UID fallbacks, and requires `KEY_VAULT_MASTER_KEY`. |
| `CORS_ORIGINS` | `https://vallum.vercel.app,http://localhost:5173` | Allowed explicit origins (supplemented by regex `https://(vallum\|ai-safety-and-scope-tool)(-[a-z0-9-]+)?\.vercel\.app`). |
| `KEY_VAULT_MASTER_KEY` | **Secret** (64-char hex / 32 bytes) | Server-side master key for AES-256-GCM encryption/decryption of user API keys in `user_api_vault` with per-user AAD binding. Also accepts `VAULT_MASTER_KEY` as an alias. |
| `SUPABASE_URL` | **Secret** (`https://<ref>.supabase.co`) | Supabase project REST endpoint. |
| `SUPABASE_SERVICE_ROLE_KEY` | **Secret** (`eyJ...` service_role JWT) | Privileged backend-only key used by FastAPI to read/write isolated user rows in Supabase PostgreSQL. (`SUPABASE_KEY` is also supported as a fallback alias). |
| `OPENROUTER_API_KEY` | **Secret** (`sk-or-v1-...`, optional) | Used for server-side unstructured RoE document extraction (`/api/roe/parse-*`) if the user hasn't supplied a key yet. Never used to bypass BYOK for user audits/benchmarks. |
| `GROQ_API_KEY` | **Secret** (`gsk_...`, optional) | Fallback provider key for fast JSON extraction / Pass 2 AI Judge when configured. |

---

## 4. Supabase Architecture, Tables & Security Model

All database migrations live in `supabase/migrations/`:

### 4.1 Authentication & Immutable RBAC (`004_auth_rbac_hardening.sql`)
- **Providers Enabled:** Google OAuth, GitHub OAuth, and verified Email + Password (`email_confirmed_at` required).
- **Roles:** Only two roles exist: `'admin'` and `'penetration_tester'`.
- **Immutable Super-Admin Invariant:** Both the PostgreSQL trigger `trg_enforce_sole_admin_policy()` and the application layer (`supabase_client.py` / `authStore.ts`) enforce that **only** Khushal Arora (`arorakhushal1108@gmail.com` / `arorak1108@gmail.com`) can hold the `'admin'` role. All other accounts are automatically assigned `'penetration_tester'`.

### 4.2 Database Tables (`public` schema)

| Table | Primary / Unique Key | Purpose & Isolation Model |
|---|---|---|
| **`profiles`** | `id` (`UUID`, FK → `auth.users.id`) | Stores `email`, `full_name`, `avatar_url`, and `role` (`admin` \| `penetration_tester`). Auto-populated on signup via `handle_new_user()` trigger. |
| **`user_api_vault`** | `user_id` (`UUID`, PK, FK → `auth.users.id`) | Stores `encrypted_openrouter_key`, `encrypted_groq_key`, `key_hint_openrouter`, and `key_hint_groq`. Ciphertexts are encrypted by the backend using **AES-256-GCM** with `KEY_VAULT_MASTER_KEY` and bound to `user_id` via AAD (`vallum-vault:v1:{user_id}`). |
| **`roe_presets`** | `id` (`UUID`), `roe_id` (`TEXT UNIQUE`) | Built-in canonical Rules of Engagement presets (e.g., Internal Network Recon, Web App Bug Bounty, Cloud Perimeter). Read-only for all users. |
| **`custom_roes`** | `id` (`UUID`), `roe_id` (`TEXT UNIQUE`), `user_id` (`UUID`) | Custom Rules of Engagement uploaded or extracted by users. Strictly isolated by `user_id` (plus read-only `user_id IS NULL` system presets), with ownership verification preventing cross-user overwrite on `roe_id`. |
| **`audit_logs`** | `id` (`UUID`), `audit_id` (`TEXT UNIQUE`), `user_id` (`UUID`) | Complete ledger of every audited command/prompt, extracted commands, target findings, `verdict` (`Correct` / `Incorrect` / `Unsafe`), violations, `safe_sanitized_command`, and latency. Used to build the chronological SHA-256 hash chain for compliance attestation reports. |
| **`benchmark_runs`** | `id` (`UUID`), `benchmark_id` (`TEXT UNIQUE`), `user_id` (`UUID`) | Stores multi-model comparative benchmark runs (`compliance_rate`, `scope_violation_rate`, `hallucination_rate`, `average_latency_ms`, `fastest_model`, `summary`, `items`). |

### 4.3 How the End-to-End Key Vault Flow Works Across Devices
1. **Saving a Key:** When you paste your `sk-or-v1-...` key in the Initial Setup Modal or Settings View, the frontend holds it in volatile JavaScript memory for the current tab and sends it over HTTPS with your Supabase Bearer JWT to `POST /api/vault/keys`.
2. **Server-Side Encryption:** The FastAPI backend verifies your JWT, derives your `user_id`, encrypts the key using AES-256-GCM (`KEY_VAULT_MASTER_KEY` + AAD `vallum-vault:v1:{user_id}`), and upserts the ciphertext + masked hint (`sk-or-…xxxx`) into `public.user_api_vault`.
3. **Logging In From Any New Device:** When you sign in on a new laptop or browser, `App.tsx` calls `GET /api/vault/status` with your Bearer JWT. The backend confirms `has_openrouter_key: true` from `user_api_vault`, automatically skips the setup popup, and decrypts your key in volatile server memory whenever you run an audit or benchmark.
