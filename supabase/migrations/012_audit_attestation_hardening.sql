-- 012_audit_attestation_hardening.sql
-- Bind each audit to the canonical RoE actually used and make the ledger
-- append-only for clients. The backend service role writes signed records;
-- anon/authenticated sessions may only read their own rows (AUDIT_005 High 5).

-- 1. Per-record scope binding and server-signed chain metadata.
ALTER TABLE public.audit_logs
    ADD COLUMN IF NOT EXISTS roe_hash TEXT,
    ADD COLUMN IF NOT EXISTS roe_snapshot JSONB,
    ADD COLUMN IF NOT EXISTS chain_index BIGINT,
    ADD COLUMN IF NOT EXISTS prev_hash TEXT,
    ADD COLUMN IF NOT EXISTS chain_hash TEXT,
    ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;

-- One ordered chain per (user, RoE). A gap or duplicate is detectable.
CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_logs_user_roe_chain
    ON public.audit_logs(user_id, roe_id, chain_index)
    WHERE chain_index IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_audit_logs_deleted_at
    ON public.audit_logs(deleted_at);

-- 2. Fabrication: remove every client INSERT path. Only the service role
--    (which bypasses RLS) may append audit records.
DROP POLICY IF EXISTS "Users can insert their own audit logs" ON public.audit_logs;
DROP POLICY IF EXISTS "Anyone or service can insert audit logs" ON public.audit_logs;
DROP POLICY IF EXISTS "Users can insert audit logs" ON public.audit_logs;

-- 3. Selective omission: no client DELETE or UPDATE path. Deletion is a
--    backend-written soft-delete tombstone that remains in the signed chain.
DROP POLICY IF EXISTS "Users can delete their own audit logs" ON public.audit_logs;
DROP POLICY IF EXISTS "Users can delete audit logs" ON public.audit_logs;
DROP POLICY IF EXISTS "Users can update their own audit logs" ON public.audit_logs;
DROP POLICY IF EXISTS "Users can update audit logs" ON public.audit_logs;

REVOKE INSERT, UPDATE, DELETE ON public.audit_logs FROM anon, authenticated;

-- 4. Metrics exclude soft-deleted history from the live dashboard, while the
--    attestation report still includes every tombstone in the chain.
CREATE OR REPLACE FUNCTION public.audit_metrics(p_user_id UUID)
RETURNS TABLE(total BIGINT, unsafe BIGINT, correct BIGINT, incorrect BIGINT, pass_rate BIGINT, avg_latency_ms BIGINT)
LANGUAGE sql STABLE
SET search_path = public, pg_temp
AS $$
    SELECT
        COUNT(*)::BIGINT,
        COUNT(*) FILTER (WHERE verdict = 'Unsafe')::BIGINT,
        COUNT(*) FILTER (WHERE verdict = 'Correct')::BIGINT,
        COUNT(*) FILTER (WHERE verdict = 'Incorrect')::BIGINT,
        ROUND(100.0 * COUNT(*) FILTER (WHERE verdict = 'Correct') / NULLIF(COUNT(*), 0))::BIGINT,
        ROUND(AVG(execution_time_ms))::BIGINT
    FROM public.audit_logs
    WHERE user_id = p_user_id AND deleted_at IS NULL;
$$;

REVOKE ALL ON FUNCTION public.audit_metrics(UUID) FROM PUBLIC, anon, authenticated;

-- Review note: existing rows created before this migration have NULL
-- roe_hash/chain_hash. They are treated as un-attestable legacy rows by the
-- report engine; they are not silently re-signed or included in a new report.
