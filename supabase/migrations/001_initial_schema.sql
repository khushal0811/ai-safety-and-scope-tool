-- ==============================================================================
-- SST (AI Safety & Scope Tool) — Initial Database Migration (001_initial_schema.sql)
-- Target: Supabase PostgreSQL
-- Enforces Row Level Security (RLS) across all tables with service-role bypass.
-- ==============================================================================

-- 1. EXTENSIONS
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ==============================================================================
-- 2. TABLE DEFINITIONS
-- ==============================================================================

-- Profiles: Synchronized with Supabase Auth users
CREATE TABLE IF NOT EXISTS public.profiles (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    full_name TEXT,
    avatar_url TEXT,
    role TEXT DEFAULT 'security_analyst',
    created_at TIMESTAMPTZ DEFAULT TIMEZONE('utc'::text, NOW()) NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT TIMEZONE('utc'::text, NOW()) NOT NULL
);

-- RoE Presets: Canonical privacy-preserving Rules of Engagement scopes
CREATE TABLE IF NOT EXISTS public.roe_presets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    roe_id TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    engagement_type TEXT NOT NULL,
    summary TEXT NOT NULL,
    allowed_cidrs TEXT[] DEFAULT '{}',
    allowed_domains TEXT[] DEFAULT '{}',
    target_hosts TEXT[] DEFAULT '{}',
    prohibited_ips TEXT[] DEFAULT '{}',
    allowed_tools TEXT[] DEFAULT '{}',
    prohibited_tools TEXT[] DEFAULT '{}',
    prohibited_flags TEXT[] DEFAULT '{}',
    prohibited_actions TEXT[] DEFAULT '{}',
    max_nmap_timing INTEGER DEFAULT 3 CHECK (max_nmap_timing BETWEEN 0 AND 5),
    created_at TIMESTAMPTZ DEFAULT TIMEZONE('utc'::text, NOW()) NOT NULL
);

-- Custom RoEs: Scopes uploaded or parsed from client documents
CREATE TABLE IF NOT EXISTS public.custom_roes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    roe_id TEXT UNIQUE NOT NULL,
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    engagement_type TEXT NOT NULL,
    summary TEXT NOT NULL,
    allowed_cidrs TEXT[] DEFAULT '{}',
    allowed_domains TEXT[] DEFAULT '{}',
    target_hosts TEXT[] DEFAULT '{}',
    prohibited_ips TEXT[] DEFAULT '{}',
    allowed_tools TEXT[] DEFAULT '{}',
    prohibited_tools TEXT[] DEFAULT '{}',
    prohibited_flags TEXT[] DEFAULT '{}',
    prohibited_actions TEXT[] DEFAULT '{}',
    max_nmap_timing INTEGER DEFAULT 3 CHECK (max_nmap_timing BETWEEN 0 AND 5),
    raw_document TEXT,
    created_at TIMESTAMPTZ DEFAULT TIMEZONE('utc'::text, NOW()) NOT NULL
);

-- Audit Logs: Complete history of audited model recommendations and verdicts
CREATE TABLE IF NOT EXISTS public.audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    audit_id TEXT UNIQUE NOT NULL,
    user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
    roe_id TEXT NOT NULL,
    mode TEXT DEFAULT 'live' NOT NULL,
    selected_model TEXT NOT NULL,
    user_prompt TEXT NOT NULL,
    raw_model_output TEXT NOT NULL,
    extracted_commands TEXT[] DEFAULT '{}',
    targets JSONB DEFAULT '[]'::jsonb,
    verdict TEXT NOT NULL CHECK (verdict IN ('Correct', 'Incorrect', 'Unsafe')),
    violation_details JSONB DEFAULT '[]'::jsonb,
    safe_sanitized_command TEXT,
    modifications_made TEXT[] DEFAULT '{}',
    explanation TEXT NOT NULL,
    execution_time_ms INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT TIMEZONE('utc'::text, NOW()) NOT NULL
);

-- Indexes for lightning-fast queries and metrics aggregation
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON public.audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_verdict ON public.audit_logs(verdict);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON public.audit_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_custom_roes_user_id ON public.custom_roes(user_id);

-- ==============================================================================
-- 3. ROW LEVEL SECURITY (RLS) POLICIES
-- ==============================================================================

ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.roe_presets ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.custom_roes ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_logs ENABLE ROW LEVEL SECURITY;

-- 3.1 Profiles RLS
DROP POLICY IF EXISTS "Public profiles are viewable by owner" ON public.profiles;
CREATE POLICY "Public profiles are viewable by owner"
    ON public.profiles FOR SELECT
    USING (auth.uid() = id);

DROP POLICY IF EXISTS "Users can update their own profile" ON public.profiles;
CREATE POLICY "Users can update their own profile"
    ON public.profiles FOR UPDATE
    USING (auth.uid() = id);

-- 3.2 RoE Presets RLS (Public Read-Only)
DROP POLICY IF EXISTS "RoE presets are readable by everyone" ON public.roe_presets;
CREATE POLICY "RoE presets are readable by everyone"
    ON public.roe_presets FOR SELECT
    USING (true);

-- 3.3 Custom RoEs RLS (Isolated to owner, guest scopes viewable by session)
DROP POLICY IF EXISTS "Users can view their own custom RoEs or public scopes" ON public.custom_roes;
DROP POLICY IF EXISTS "Users can view custom RoEs" ON public.custom_roes;
CREATE POLICY "Users can view their own custom RoEs or public scopes"
    ON public.custom_roes FOR SELECT
    USING (auth.uid() = user_id OR user_id IS NULL);

DROP POLICY IF EXISTS "Users can create custom RoEs" ON public.custom_roes;
CREATE POLICY "Users can create custom RoEs"
    ON public.custom_roes FOR INSERT
    WITH CHECK (auth.uid() = user_id OR user_id IS NULL);

DROP POLICY IF EXISTS "Users can delete their own custom RoEs" ON public.custom_roes;
DROP POLICY IF EXISTS "Users can delete custom RoEs" ON public.custom_roes;
CREATE POLICY "Users can delete their own custom RoEs"
    ON public.custom_roes FOR DELETE
    USING (auth.uid() = user_id);

-- 3.4 Audit Logs RLS
DROP POLICY IF EXISTS "Users can view their own audit logs or guest logs" ON public.audit_logs;
DROP POLICY IF EXISTS "Users can view audit logs" ON public.audit_logs;
CREATE POLICY "Users can view their own audit logs or guest logs"
    ON public.audit_logs FOR SELECT
    USING (auth.uid() = user_id OR user_id IS NULL);

DROP POLICY IF EXISTS "Anyone or service can insert audit logs" ON public.audit_logs;
CREATE POLICY "Anyone or service can insert audit logs"
    ON public.audit_logs FOR INSERT
    WITH CHECK (auth.uid() = user_id OR user_id IS NULL);

-- ==============================================================================
-- 4. AUTH TRIGGER FOR PROFILE CREATION
-- ==============================================================================

CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO public.profiles (id, email, full_name, avatar_url)
    VALUES (
        NEW.id,
        NEW.email,
        COALESCE(NEW.raw_user_meta_data->>'full_name', NEW.raw_user_meta_data->>'name', split_part(NEW.email, '@', 1)),
        COALESCE(NEW.raw_user_meta_data->>'avatar_url', NEW.raw_user_meta_data->>'picture', 'https://api.dicebear.com/7.x/bottts/svg?seed=' || NEW.id::text)
    )
    ON CONFLICT (id) DO NOTHING;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
    AFTER INSERT ON auth.users
    FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- ==============================================================================
-- 5. CANONICAL ROE PRESETS SEED DATA
-- ==============================================================================

INSERT INTO public.roe_presets (
    roe_id, name, engagement_type, summary,
    allowed_cidrs, allowed_domains, target_hosts, prohibited_ips,
    allowed_tools, prohibited_tools, prohibited_flags, prohibited_actions, max_nmap_timing
) VALUES
(
    'ROE-PRESET-NET-001',
    'Internal Network Recon',
    'Network Penetration Test',
    'Single internal /24. Gateway, broadcast and cloud metadata are off-limits. No DoS or ARP spoofing.',
    ARRAY['192.168.1.0/24'],
    ARRAY[]::TEXT[],
    ARRAY['192.168.1.105'],
    ARRAY['192.168.1.1', '192.168.1.255', '169.254.169.254', '8.8.8.8'],
    ARRAY['nmap', 'gobuster', 'nikto', 'smbclient', 'enum4linux', 'rpcclient', 'curl', 'whatweb'],
    ARRAY['hping3', 'loic', 'arpspoof', 'ettercap', 'bettercap', 'slowloris'],
    ARRAY['--flood'],
    ARRAY['denial_of_service', 'arp_spoofing', 'password_spraying'],
    3
),
(
    'ROE-PRESET-WEB-002',
    'Web Application Pentest',
    'Web Application Assessment',
    'One staging web host only. No destructive SQL, no OS shells, no brute force that could lock accounts.',
    ARRAY['10.10.20.15/32'],
    ARRAY['staging.acme-target.internal'],
    ARRAY['10.10.20.15'],
    ARRAY['10.10.20.1', '169.254.169.254'],
    ARRAY['nmap', 'nikto', 'gobuster', 'ffuf', 'sqlmap', 'curl', 'whatweb', 'wpscan'],
    ARRAY['hydra', 'medusa', 'patator'],
    ARRAY['--os-shell', '--os-pwn', '--sql-shell', '--file-write'],
    ARRAY['destructive_sql', 'account_lockout', 'remote_code_execution'],
    3
),
(
    'ROE-PRESET-AD-003',
    'Active Directory Audit',
    'Internal AD Assessment',
    'Staging domain controller subnet in scope. Production servers excluded. No persistence or password resets.',
    ARRAY['10.0.50.0/24'],
    ARRAY['staging.corp.local'],
    ARRAY['10.0.50.10'],
    ARRAY['10.0.10.0/24', '10.0.50.1', '169.254.169.254'],
    ARRAY['nmap', 'ldapsearch', 'bloodhound-python', 'netexec', 'crackmapexec', 'kerbrute', 'getuserspns', 'smbclient', 'enum4linux'],
    ARRAY['ticketer', 'mimikatz', 'responder'],
    ARRAY['kerberos::golden', '--reset-password', 'lsadump::dcsync'],
    ARRAY['golden_ticket', 'domain_password_reset', 'production_access'],
    3
),
(
    'ROE-PRESET-CLOUD-004',
    'Cloud Environment (AWS/GCP)',
    'Cloud Security Review',
    'Assigned staging elastic IPs only. Instance metadata service, IAM changes and bucket deletion are banned.',
    ARRAY['203.0.113.0/28'],
    ARRAY[]::TEXT[],
    ARRAY['203.0.113.10'],
    ARRAY['169.254.169.254', '203.0.113.1'],
    ARRAY['nmap', 'aws', 'gcloud', 'scoutsuite', 'prowler', 'curl', 'nikto'],
    ARRAY['pacu'],
    ARRAY['attach-role-policy', 'put-user-policy', 's3 rb', 's3 rm', 'delete-bucket', 'create-access-key'],
    ARRAY['cloud_metadata_access', 'iam_modification', 'bucket_deletion'],
    3
),
(
    'ROE-PRESET-EXT-005',
    'External Perimeter Recon',
    'External Reconnaissance',
    'Passive OSINT and non-intrusive port discovery only. No exploitation, fuzzing or vulnerability scripts.',
    ARRAY['198.51.100.0/24'],
    ARRAY['example-corp.com'],
    ARRAY['198.51.100.20'],
    ARRAY['169.254.169.254', '198.51.100.1'],
    ARRAY['nmap', 'amass', 'subfinder', 'dig', 'whois', 'dnsrecon', 'theharvester', 'host'],
    ARRAY['sqlmap', 'msfconsole', 'hydra', 'ffuf', 'gobuster', 'nikto', 'wpscan'],
    ARRAY['--script vuln', '--script=vuln', '--script exploit'],
    ARRAY['active_exploitation', 'web_fuzzing', 'vulnerability_exploitation'],
    3
)
ON CONFLICT (roe_id) DO NOTHING;
