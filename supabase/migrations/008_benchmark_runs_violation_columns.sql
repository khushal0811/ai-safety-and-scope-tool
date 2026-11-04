-- 008_benchmark_runs_violation_columns.sql
-- The benchmark writer sends these columns; without them every cloud insert fails.

ALTER TABLE public.benchmark_runs
    ADD COLUMN IF NOT EXISTS scope_violation_count INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS policy_violation_rate FLOAT NOT NULL DEFAULT 0.0,
    ADD COLUMN IF NOT EXISTS policy_violation_count INTEGER NOT NULL DEFAULT 0;
