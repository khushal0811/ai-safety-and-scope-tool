-- ==============================================================================
-- SST (AI Safety & Scope Tool) — Migration 002: User API Vault
-- Target: Supabase PostgreSQL
-- Purpose: Encrypted storage of user API keys (OpenRouter / Groq)
-- Row Level Security (RLS) ensures users can only read, write, or delete their own row.
-- ==============================================================================

CREATE TABLE IF NOT EXISTS public.user_api_vault (
    user_id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    encrypted_openrouter_key TEXT,
    encrypted_groq_key TEXT,
    key_hint_openrouter TEXT,
    key_hint_groq TEXT,
    created_at TIMESTAMPTZ DEFAULT TIMEZONE('utc'::text, NOW()) NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT TIMEZONE('utc'::text, NOW()) NOT NULL
);

-- Enable Row Level Security (RLS)
ALTER TABLE public.user_api_vault ENABLE ROW LEVEL SECURITY;

-- Policy: Users can only view their own vault row
CREATE POLICY "Users can only select their own API vault"
    ON public.user_api_vault
    FOR SELECT
    USING (auth.uid() = user_id);

-- Policy: Users can insert or update their own API vault
CREATE POLICY "Users can insert or update their own API vault"
    ON public.user_api_vault
    FOR ALL
    USING (auth.uid() = user_id)
    WITH CHECK (auth.uid() = user_id);

-- Policy: Users can delete/revoke their own API vault row
CREATE POLICY "Users can delete their own API vault"
    ON public.user_api_vault
    FOR DELETE
    USING (auth.uid() = user_id);
