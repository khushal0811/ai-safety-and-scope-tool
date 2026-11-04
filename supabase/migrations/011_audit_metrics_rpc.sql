-- 011_audit_metrics_rpc.sql
-- Server-side aggregation for the metrics endpoint, so a heavy user no longer streams every
-- audit row into the API process.

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
    WHERE user_id = p_user_id;
$$;

-- Only the service role (the backend) may call this; it is not exposed to anon/authenticated clients.
REVOKE ALL ON FUNCTION public.audit_metrics(UUID) FROM PUBLIC, anon, authenticated;
