-- 005_security_hardening.sql
-- Forward-only hardening migration. Earlier migrations are left as applied.

-- 1. Deleting a user must delete their rows, not orphan them into a globally readable state.
--    (Previously ON DELETE SET NULL turned a deleted user's audit logs into user_id IS NULL rows.)
ALTER TABLE public.audit_logs DROP CONSTRAINT IF EXISTS audit_logs_user_id_fkey;
ALTER TABLE public.audit_logs
    ADD CONSTRAINT audit_logs_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES auth.users(id) ON DELETE CASCADE;

-- 2. SELECT policies: a row is visible only to its owner. Rows with user_id IS NULL
--    (guest rows) are no longer readable by any anon/authenticated client.
DROP POLICY IF EXISTS "Users can view their own audit logs or guest logs" ON public.audit_logs;
CREATE POLICY "Users can view their own audit logs"
    ON public.audit_logs FOR SELECT
    USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "Users can view their own custom RoEs or public scopes" ON public.custom_roes;
CREATE POLICY "Users can view their own custom RoEs"
    ON public.custom_roes FOR SELECT
    USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "Users can view their own benchmark runs" ON public.benchmark_runs;
CREATE POLICY "Users can view their own benchmark runs"
    ON public.benchmark_runs FOR SELECT
    USING (auth.uid() = user_id);

-- Review note: existing rows with user_id IS NULL (guest rows) are not deleted here.
-- They are unreachable through RLS after this migration; remove them deliberately after review:
--   DELETE FROM public.audit_logs WHERE user_id IS NULL;
