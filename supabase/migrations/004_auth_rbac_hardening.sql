-- ==============================================================================
-- Vallum (AI Safety & Scope Tool) — Migration 004: Auth Hardening, RBAC & Account Purge
-- Target: Supabase PostgreSQL
-- Enforces:
-- 1. Purge of all dummy/test/mock accounts.
-- 2. Strict Role-Based Access Control (RBAC): 'admin' and 'penetration_tester'.
-- 3. Immutable Sole Admin: Khushal Arora (arorakhusuhal1108@gmail.com) is the ONLY Admin.
--    No other user can ever be granted or elevate to the admin role.
-- ==============================================================================

-- 1. PURGE DUMMY AND SETUP TEST ACCOUNTS
DELETE FROM public.audit_logs 
WHERE user_id IN (
    SELECT id FROM auth.users 
    WHERE email ILIKE '%@pentest.local' 
       OR email ILIKE 'demo@%' 
       OR email ILIKE 'test@%' 
       OR email ILIKE 'dummy@%'
       OR email ILIKE 'guest@%'
);

DELETE FROM public.benchmark_runs 
WHERE user_id IN (
    SELECT id FROM auth.users 
    WHERE email ILIKE '%@pentest.local' 
       OR email ILIKE 'demo@%' 
       OR email ILIKE 'test@%' 
       OR email ILIKE 'dummy@%'
       OR email ILIKE 'guest@%'
);

DELETE FROM public.custom_roes 
WHERE user_id IN (
    SELECT id FROM auth.users 
    WHERE email ILIKE '%@pentest.local' 
       OR email ILIKE 'demo@%' 
       OR email ILIKE 'test@%' 
       OR email ILIKE 'dummy@%'
       OR email ILIKE 'guest@%'
);

DELETE FROM public.user_api_vault 
WHERE user_id IN (
    SELECT id FROM auth.users 
    WHERE email ILIKE '%@pentest.local' 
       OR email ILIKE 'demo@%' 
       OR email ILIKE 'test@%' 
       OR email ILIKE 'dummy@%'
       OR email ILIKE 'guest@%'
);

DELETE FROM public.profiles 
WHERE email ILIKE '%@pentest.local' 
   OR email ILIKE 'demo@%' 
   OR email ILIKE 'test@%' 
   OR email ILIKE 'dummy@%'
   OR email ILIKE 'guest@%';

DELETE FROM auth.users 
WHERE email ILIKE '%@pentest.local' 
   OR email ILIKE 'demo@%' 
   OR email ILIKE 'test@%' 
   OR email ILIKE 'dummy@%'
   OR email ILIKE 'guest@%';

-- 2. RBAC SCHEMA RECONFIGURATION
ALTER TABLE public.profiles 
    ALTER COLUMN role SET DEFAULT 'penetration_tester';

-- Normalize any existing profiles
UPDATE public.profiles 
SET role = 'penetration_tester'
WHERE LOWER(email) != 'arorakhusuhal1108@gmail.com';

-- Ensure Khushal Arora is the designated Admin
UPDATE public.profiles 
SET role = 'admin' 
WHERE LOWER(email) = 'arorakhusuhal1108@gmail.com';

-- Add check constraint for valid roles
ALTER TABLE public.profiles 
    DROP CONSTRAINT IF EXISTS check_valid_role;

ALTER TABLE public.profiles 
    ADD CONSTRAINT check_valid_role 
    CHECK (role IN ('admin', 'penetration_tester'));

-- 3. IMMUTABLE SOLE-ADMIN POLICY TRIGGER
-- Rejects any role update to 'admin' for any email other than arorakhusuhal1108@gmail.com
CREATE OR REPLACE FUNCTION public.enforce_sole_admin_policy()
RETURNS TRIGGER AS $$
BEGIN
    IF LOWER(NEW.email) = 'arorakhusuhal1108@gmail.com' THEN
        NEW.role := 'admin';
    ELSE
        IF NEW.role = 'admin' THEN
            RAISE EXCEPTION 'RBAC Security Violation: Only arorakhusuhal1108@gmail.com is authorized for the admin role.';
        END IF;
        NEW.role := 'penetration_tester';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

DROP TRIGGER IF EXISTS trg_enforce_sole_admin_policy ON public.profiles;
CREATE TRIGGER trg_enforce_sole_admin_policy
    BEFORE INSERT OR UPDATE ON public.profiles
    FOR EACH ROW
    EXECUTE FUNCTION public.enforce_sole_admin_policy();

-- 4. NEW USER REGISTRATION HOOK
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER AS $$
DECLARE
    assigned_role TEXT;
BEGIN
    IF LOWER(NEW.email) = 'arorakhusuhal1108@gmail.com' THEN
        assigned_role := 'admin';
    ELSE
        assigned_role := 'penetration_tester';
    END IF;

    INSERT INTO public.profiles (id, email, full_name, avatar_url, role)
    VALUES (
        NEW.id,
        NEW.email,
        COALESCE(NEW.raw_user_meta_data->>'full_name', NEW.raw_user_meta_data->>'name', split_part(NEW.email, '@', 1)),
        COALESCE(NEW.raw_user_meta_data->>'avatar_url', NEW.raw_user_meta_data->>'picture', 'https://api.dicebear.com/7.x/bottts/svg?seed=' || NEW.id::text),
        assigned_role
    )
    ON CONFLICT (id) DO UPDATE SET
        email = EXCLUDED.email,
        full_name = COALESCE(EXCLUDED.full_name, public.profiles.full_name),
        avatar_url = COALESCE(EXCLUDED.avatar_url, public.profiles.avatar_url),
        role = assigned_role,
        updated_at = NOW();

    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
