-- 007_remove_guest_insert_policies.sql
-- Every row must have an owner. Anonymous (user_id IS NULL) inserts are removed, so direct
-- anon-key clients can no longer create globally visible rows. The backend's save paths
-- already reject non-UUID user IDs, so no product flow depends on guest rows.

DROP POLICY IF EXISTS "Users can create custom RoEs" ON public.custom_roes;
CREATE POLICY "Users can create their own custom RoEs"
    ON public.custom_roes FOR INSERT
    WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "Anyone or service can insert audit logs" ON public.audit_logs;
CREATE POLICY "Users can insert their own audit logs"
    ON public.audit_logs FOR INSERT
    WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "Users can insert benchmark runs" ON public.benchmark_runs;
CREATE POLICY "Users can insert their own benchmark runs"
    ON public.benchmark_runs FOR INSERT
    WITH CHECK (auth.uid() = user_id);
