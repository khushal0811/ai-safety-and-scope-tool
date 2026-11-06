# Calibration Expansion & Live Benchmark Validation — Plan

Status: executed locally; results recorded below; awaiting commit and merge
Date: 2026-11-06
Owner: Khushal Arora
Repository: `ai-safety-and-scope-tool`
Related: `docs/BENCHMARK_COUNCIL_PLAN.md`, `docs/CALIBRATION_AUDIT_OVERRIDE.json`, `docs/BENCHMARK_LIVE_VALIDATION.json`

---

## 1. Scope

Two workstreams, plus a parked list of everything else that is still open.

1. Expand the audit AI-override calibration from the 13-case seed to a 60-case
   labeled set, then tune only if the bars are missed.
2. Run a full live benchmark validation: five models, three repeats, using the
   hybrid audit engine, and verify the metrics, persistence, and latency.

No code behavior changes are planned in this workstream unless calibration
misses the quality bars (in which case the change is a prompt-version bump plus
a re-run, not a new scoring rule).

---

## 2. Current state

- 13-case seed: `backend/scripts/calibration_cases.json`.
- Harness: `backend/scripts/calibrate_audit_override.py`.
- Report: `docs/CALIBRATION_AUDIT_OVERRIDE.json`.
- Seed results: 100% agreement, 0% safe false-positive rate, all unsafe cases
  preserved, refusal handled.
- Benchmark code: hybrid engine, 3 repeats, p50/p95, pass@k, consistency,
  leaderboard, auth, quota. Unit-tested, not yet live-validated.
- Branch `feat/hybrid-override-benchmark` is committed locally and not pushed.
- Migrations `013` and `014` are applied in Supabase.

---

## 3. Workstream A — expand calibration to 60 cases

### 3.1 Case composition (60)

| Group | Count | Examples |
|---|---:|---|
| Safe / clean | 20 | Authorized nmap/smbclient/curl across all five presets; awkward shell (`for`, pipes, redirections); local wordlists and config files; dynamic value bound to an authorized target. |
| Unsafe / critical | 20 | Prohibited gateway/broadcast, out-of-scope IP, banned tool, destructive payload, cloud metadata, sudo, package install, interactive/reverse shell, piped shell. |
| Warning / incorrect | 8 | Unresolved dynamic target, non-allowlisted tool, timing above max, unverifiable or invented CVE. |
| Refusal / mixed | 6 | Plain refusal, refusal with a safe alternative, mixed refusal plus commands, empty output. |
| Edge cases | 6 | Obfuscated IP (hex, octal, decimal, IPv6-mapped), prompt-injection text inside the model output, filename that looks like a domain, authorized-domain usage, encoded payload, over-long response. |

Every preset must be represented: `NET-001`, `WEB-002`, `AD-003`,
`CLOUD-004`, `EXT-005`.

### 3.2 Labeling rules

Each case records:

- `expected_verdict`: the human verdict.
- `label`: safe / unsafe / warning / refusal / edge.
- `note`: why the label is what it is.
- Optional `expected_pass1_behavior`: `correct`, `false_positive_warning`, or
  `false_positive_critical`. The critical false-positive class is constructed
  from known engine false-positive shapes (shell syntax, local operator,
  flag value) and must be checked once to confirm Pass 1 really flags it.

### 3.3 Quality bars (same as the benchmark plan)

- Verdict agreement >= 90%.
- Safe-output false-positive rate <= 5%.
- Critical false negatives: 0 on the labeled set.
- Stability: two temperature-0 runs agree on >= 90% of cases.
- The run must fit a reasonable budget (see section 5).

### 3.4 Execution steps

1. Author the 47 new cases in `backend/scripts/calibration_cases.json`.
2. Run the harness against the real judge:

   ```bash
   cd backend
   ./.venv/bin/python scripts/calibrate_audit_override.py \
       --report ../docs/CALIBRATION_AUDIT_OVERRIDE.json
   ```

3. Review misses. If a miss is a prompt problem, bump the prompt version
   (`audit-judge-v4`), document the change, and re-run.
4. Commit the updated cases and report.

### 3.5 Estimated cost and time

- Roughly 60-90 judge calls (some critical cases add a second pass).
- DeepSeek Flash pricing keeps this inexpensive; the cost report from
  `ai_judge_usage` will record it.
- Human time is in writing the labels, which is the real work.

---

## 4. Workstream B — full live benchmark validation

### 4.1 Prerequisites

- Branch pushed, PR merged, and backend deployed (so migrations `013`/`014` are
  live). Local validation is possible but production is the target.
- A working OpenRouter key for the target models (user key), plus the backend
  system key for judging.
- Daily quota headroom for at least one full run.

### 4.2 Validation matrix

| Item | Value |
|---|---|
| Models | All five canonical frontier models |
| Repeats | 3 |
| Scenarios | Two: External/Web recon and SMB recon (one run each) |
| Target calls | 15 per scenario; 30 total |
| Judge calls | 1-2 per model run; roughly 15-30 per scenario |
| Persistence | One `benchmark_runs` row per scenario with summary/items JSONB |

### 4.3 Checks

- All five models return results for all three repeats; errors and refusals are
  excluded from scoring but still visible.
- Verdicts flow through the hybrid engine only; no deterministic-only path.
- `summary` has correctness, safety, p50/p95, pass@k, consistency, leaderboard,
  per-scenario, and cost fields.
- Leaderboard zero-correctness cap holds (max 40).
- Persistence: row exists, history endpoint returns it, items include per-run
  audits and override logs.
- Latency: p95 run time within the UI abort window (180 s); if it exceeds it,
  reduce fan-out or investigate OpenRouter latency, do not silently drop
  repeats.
- Quota: a second run within the same day does not bypass the limit.

### 4.4 Optional helper

Add `backend/scripts/validate_benchmark_live.py` to run the route logic
directly (or against a local server), print the comparison table, and write a
JSON validation report to `docs/`. The script is a harness, not product code.

### 4.5 Abort criteria

- Sustained provider rate limits or timeouts: stop, record, and re-run later
  with fewer models or staggered repeats.
- Wrong verdicts that indicate a judge regression: stop and return to
  Workstream A before continuing.

---

## 5. Budget and safety

- Real provider calls spend credits. Cap the calibration run and each
  validation run; log usage from `ai_judge_usage`;
  keep a per-run budget note.
- No command execution at any point; everything remains static analysis.
- Do not run these unattended.

---

## 6. Execution order and checkpoints

1. Confirm this plan.
2. Push/merge the current branch and deploy (owner go required).
3. Workstream A: author 60 cases, run, tune if needed, commit report.
4. Workstream B: run the two live validations, commit the report.
5. Update `AGENT_INDEX.md` with the results.
6. Decide whether the prompt version needs bumping and whether the 13-case
   report should be replaced by the 60-case report.

Checkpoints where I stop and report: after the 60-case authoring, after the
first calibration run, after each live benchmark scenario.

---

## 7. Parked work (later, by owner priority)

Platform:

- Vault-robustness PR: distinct "key unreadable — re-save your key" status.
- Policy-tier discussion: `nc`, `bash -c`, whitelist breadth.
- `PROJECT_TRACKER.md` unfinished items: benchmark summary table / charts /
  side-by-side (verify which are stale), Phase 6 hardening tests (30+
  obfuscated IP variants, RoE prompt-injection payloads, frontend XSS,
  zero-host-execution verification), 20 lab scenarios, setup guide, Swagger
  docs, final summary and video.
- Cost price configuration (`BENCHMARK_*_PER_MILLION_USD`), Render quota value.
- Optional deep-review council.
- Frontend display of the new benchmark metrics (currently API/JSON only).

Gateway (`scopewire`):

- M0 traffic-capture spike and repository scaffolding when requested.
- Engine vendoring and identity/policy planes per the brief.
- Egress containment remains v2-deferred.

---

## 8. Decisions needed from the owner

1. Confirm the 60-case composition and group counts.
2. Confirm running the live benchmark validation after merge against production
   (preferred) or locally first.
3. Confirm the per-run budget cap and the daily quota value for the validation
   week.
4. Confirm whether the 60-case calibration report should replace
   `docs/CALIBRATION_AUDIT_OVERRIDE.json` or be stored alongside it.

---

## 9. Execution results (2026-11-06)

Workstream A — calibration:

- 60 cases, all five presets, groups: 21 safe, 19 unsafe, 8 warning, 5 refusal
  plus 1 mixed, 6 edge.
- Final run: agreement 100%, safe false-positive rate 0%, unsafe preserved
  100%, refusals handled 5/5.
- Report: `docs/CALIBRATION_AUDIT_OVERRIDE.json`.

Workstream B — live benchmark validation (local, real providers):

- Scenario SMB: five models, three repeats, wall 80.42 s, persisted.
- Scenario Web: five models, three repeats, wall 92.24 s, persisted.
- All checks passed: five models, three repeats each, hybrid-only, within the
  180 s UI window, persistence verified.
- Report: `docs/BENCHMARK_LIVE_VALIDATION.json`.

Issues found and fixed during execution:

- A SCOPE-category warning was forcing `Unsafe`; now only CRITICAL scope
  findings do.
- Banned tools with an `.exe`/script suffix (for example `mimikatz.exe`) did not
  match the prohibited-tool list; tool names are now normalized.
- Nested and hex-encoded URLs inside a curl query were not scanned; the
  embedded-payload scanner now finds nested schemes and normalizes hex hosts.
- Sequential judging pushed runs past the UI window; judge calls now run with a
  bounded concurrency semaphore (`BENCHMARK_MAX_CONCURRENT_JUDGES`, default 6).
- Judge JSON parsing now repairs fences, surrounding prose, and control
  characters; the one-retry repair path remains.
- Verdict overrides must agree with the confirmed findings; escalation without a
  critical finding is rejected.

Budget: not tracked per owner decision.
