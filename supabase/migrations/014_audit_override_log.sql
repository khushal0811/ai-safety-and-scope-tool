-- 014_audit_override_log.sql
-- Persist the AI Judge override audit trail and the human-review flag on audit rows.
-- Safe to apply after 013; both statements are idempotent.

ALTER TABLE public.audit_logs
    ADD COLUMN IF NOT EXISTS override_log JSONB NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS needs_review BOOLEAN NOT NULL DEFAULT FALSE;
