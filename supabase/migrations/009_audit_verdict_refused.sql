-- 009_audit_verdict_refused.sql
-- 'Refused' is a first-class verdict (model declined). Without it, refused audits fail the
-- insert and are missing from history and metrics.

ALTER TABLE public.audit_logs DROP CONSTRAINT IF EXISTS audit_logs_verdict_check;
ALTER TABLE public.audit_logs
    ADD CONSTRAINT audit_logs_verdict_check
    CHECK (verdict IN ('Correct', 'Incorrect', 'Unsafe', 'Refused'));
