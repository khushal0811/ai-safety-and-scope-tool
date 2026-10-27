-- ==============================================================================
-- Vallum (AI Safety & Scope Tool) — Benchmark Runs Migration (003_benchmark_runs.sql)
-- Target: Supabase PostgreSQL
-- Enforces Row Level Security (RLS) across public.benchmark_runs with service-role bypass.
-- ==============================================================================

CREATE TABLE IF NOT EXISTS public.benchmark_runs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    benchmark_id TEXT UNIQUE NOT NULL,
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    roe_id TEXT NOT NULL,
    scenario_title TEXT DEFAULT 'Custom Benchmark' NOT NULL,
    prompt TEXT NOT NULL,
    total_models INTEGER NOT NULL DEFAULT 0,
    compliance_rate FLOAT NOT NULL DEFAULT 0.0,
    scope_violation_rate FLOAT NOT NULL DEFAULT 0.0,
    hallucination_rate FLOAT NOT NULL DEFAULT 0.0,
    average_latency_ms FLOAT NOT NULL DEFAULT 0.0,
    fastest_model TEXT,
    summary JSONB NOT NULL DEFAULT '{}'::jsonb,
    items JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ DEFAULT TIMEZONE('utc'::text, NOW()) NOT NULL
);

-- Indexes for rapid telemetry queries and metrics calculation
CREATE INDEX IF NOT EXISTS idx_benchmark_runs_user_id ON public.benchmark_runs(user_id);
CREATE INDEX IF NOT EXISTS idx_benchmark_runs_created_at ON public.benchmark_runs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_benchmark_runs_roe_id ON public.benchmark_runs(roe_id);

-- Row Level Security (RLS) Policies
ALTER TABLE public.benchmark_runs ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Users can view their own benchmark runs" ON public.benchmark_runs;
CREATE POLICY "Users can view their own benchmark runs"
    ON public.benchmark_runs FOR SELECT
    USING (auth.uid() = user_id OR user_id IS NULL);

DROP POLICY IF EXISTS "Users can insert benchmark runs" ON public.benchmark_runs;
CREATE POLICY "Users can insert benchmark runs"
    ON public.benchmark_runs FOR INSERT
    WITH CHECK (auth.uid() = user_id OR user_id IS NULL);

DROP POLICY IF EXISTS "Users can delete their own benchmark runs" ON public.benchmark_runs;
CREATE POLICY "Users can delete their own benchmark runs"
    ON public.benchmark_runs FOR DELETE
    USING (auth.uid() = user_id);
