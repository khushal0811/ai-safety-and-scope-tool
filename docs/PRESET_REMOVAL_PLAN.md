# Preset Removal Plan — Custom-Only Scope Definition

Status: implemented and tested; migration 015 pending owner application after deploy
Date: 2026-11-06
Owner: Khushal Arora

## 1. Goal

Remove the pre-built RoE preset feature. A scope can only be defined by:

- pasting RoE text, or
- uploading a `.md` / `.txt` document,

parsed through the existing extraction pipeline and stored as a custom RoE.
No preset selector, no preset endpoint, no preset table in production.

## 2. Scope

Affected surfaces:

- Audit Studio scope step (preset tab and preset list removed).
- Benchmark Studio scope selection (no preset dropdown; uses the active custom
  scope).
- Sandbox dry-run and compliance reports (resolve custom RoEs only).
- Backend `/api/roe/presets` endpoint and `app/data/presets.py`.
- Supabase `roe_presets` table (dropped by migration 015 after deploy).
- CLI shim (explicit scope file required; no default preset and no preset list).
- Tests (test-only scope fixtures replace production presets).
- Docs/ledger references.

## 3. Locked decisions

1. One scope source: parsed custom RoEs (`custom_roes` table). The frontend
   already has text + file parsing; it becomes the only path.
2. The preset endpoint and table are removed, not deprecated.
3. Benchmarks run against the active custom scope. No per-benchmark preset
   switcher.
4. A run without a parsed scope is blocked with a clear message.
5. History restore: add `GET /api/roe/custom/{roe_id}`; if the saved custom RoE
   is unavailable, the audit/benchmark cannot restore that scope and the user
   must define it again.
6. The CLI requires `--roe <file>` (`.md`, `.txt`, or `.json`). `vallum roe
   list` shows the configured file instead of presets. No default scope.
7. Tests keep equivalent scopes in a test-only module; production code has no
   preset data.
8. Migration order: deploy code first, then apply migration 015.

## 4. Affected files

Backend:

- Delete `backend/app/data/presets.py`; update `backend/app/data/__init__.py`.
- `backend/app/api/routes_roe.py`: remove `/presets`; add
  `GET /api/roe/custom/{roe_id}`.
- `backend/app/api/routes_audit.py`: the deterministic endpoint resolves the
  custom RoE or returns 404/422; no preset fallback.
- `backend/app/api/routes_sandbox.py`: custom-only resolution.
- `backend/app/engine/roe_integrity.py`: `resolve_roe_scope` uses custom RoEs.
- `backend/app/engine/reporter.py`: custom-only resolution, clearer error.
- `backend/app/engine/verifier.py`: `evaluate_deterministic_command` requires a
  resolved `roe`; no preset import.
- `backend/app/db/supabase_client.py`: remove `fetch_roe_presets`; connectivity
  probe uses another table; update `fetch_custom_roes` docs.
- `backend/app/db/__init__.py`: drop the removed export.
- `backend/app/cli/shim.py`: explicit scope file only.

Frontend:

- Delete `frontend/src/data/presets.ts`.
- `frontend/src/components/RoeSelector.tsx`: remove segmented control, preset
  list, and preset props; text/upload only.
- `frontend/src/App.tsx`: remove `roeMode`, `presetId`, `DEFAULT_ROE`,
  preset-based history restore, and the benchmark preset dropdown; require a
  parsed custom scope.
- `frontend/src/components/BenchmarkStudioView.tsx`: remove `allRoes` /
  `onSelectRoe`; show a “define a scope first” state.
- `frontend/src/services/auditService.ts`: remove `fetchRoePresets`; remove the
  `ROE-PRESET-NET-001` sandbox fallback; add `fetchCustomRoeById`.
- `frontend/src/data/models.ts`: comment cleanup only.

Database:

- `supabase/migrations/015_drop_roe_presets.sql`: `DROP TABLE IF EXISTS
  public.roe_presets CASCADE;`

Tests:

- New `backend/tests/scopes.py` with the five equivalent test scopes and a
  `get_test_scope(id)` helper.
- Update `conftest.py` and the eight test files that import `ROE_PRESETS`.
- Remove preset-endpoint tests; add tests: `/api/roe/presets` is gone, custom
  parse still works, deterministic endpoint rejects a missing scope, history
  restore endpoint returns a saved custom RoE.

Docs:

- README, SETUP, conversation summary, AGENT_INDEX, PROJECT_TRACKER: remove
  preset references, document the custom-only flow and migration 015.

## 5. Phases

1. Backend removals + test scopes; backend tests green.
2. Frontend custom-only scope flow; benchmark scope handling; build green.
3. CLI explicit-scope flow.
4. Migration 015 + docs.
5. Full tests, local smoke (parse text file, audit, benchmark scope), commit,
   push, PR, merge.
6. Production verification; owner applies migration 015 after deploy.

## 6. Acceptance

- Audit Studio: no preset UI anywhere; audit cannot run without a parsed scope.
- Benchmark Studio: no preset dropdown; cannot run without a parsed scope.
- `GET /api/roe/presets` returns 404; no production import of
  `app.data.presets`.
- CLI without `--roe` errors clearly; with a scope file it works.
- Backend suite + frontend build green; local smoke passes.
- Migration 015 applied after deploy; `roe_presets` gone.

## 7. Risks and mitigations

| Risk | Mitigation |
|---|---|
| Tests depend heavily on preset fixtures | Test-only scope module with the same values; mechanical import update. |
| Users lose quick-start scopes | Text/file parsing already exists; error messages point to it. |
| Benchmark history references preset roe_ids | History still renders; scope restore shows a clear “scope not found” path. |
| CLI default scope removed | Explicit error with usage; `--roe <file>` documented. |
| Drop table before code deploy | Migration applied only after deploy; table becomes unused first. |

## 8. Out of scope

- Changing the RoE parser/extractor.
- Reworking benchmark scenarios (prompts stay; only scope selection changes).
- Any other feature work.

## 9. Execution results (2026-11-06)

- Backend: preset module, endpoint, and all production references removed;
  336 tests passing with test-only scope fixtures.
- Frontend: custom text/upload is the only scope path; benchmark uses the
  active custom scope with a "define scope first" state; build green.
- CLI: explicit `--roe <file>` required; preset listing replaced with the
  configured scope file; report command requires a saved custom RoE id.
- Local smoke: `/api/roe/presets` returns 404; deterministic audit without a
  scope returns 422; with a full custom scope returns 200.
- Migration `015_drop_roe_presets.sql` is written and must be applied **after**
  the code deploy (dropping the table while old code still runs would break it).
