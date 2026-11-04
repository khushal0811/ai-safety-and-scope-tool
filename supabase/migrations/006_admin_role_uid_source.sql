-- 006_admin_role_uid_source.sql
-- Forward-only. Moves the admin role source from a user-editable email column to an
-- immutable auth UID table, removes the mistyped admin address, and makes the profile
-- email immutable for its owner.

-- 1. Role source of truth: auth.users UIDs, managed only by the database owner / service role.
CREATE TABLE IF NOT EXISTS public.admin_users (
    user_id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE
);
ALTER TABLE public.admin_users ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.admin_users FROM anon, authenticated;

-- Seed the designated admin(s) by UID, using the two correct addresses only.
-- (The 'khusuhal' typo address from 004 is intentionally not carried forward.)
INSERT INTO public.admin_users (user_id)
SELECT id FROM auth.users
WHERE LOWER(email) IN ('arorakhushal1108@gmail.com', 'arorak1108@gmail.com')
ON CONFLICT (user_id) DO NOTHING;

-- 2. Profile email is identity data: the owner may not change it.
CREATE OR REPLACE FUNCTION public.prevent_profile_email_change()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.email IS DISTINCT FROM OLD.email AND auth.uid() = OLD.id THEN
        RAISE EXCEPTION 'Profile email is immutable.';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

DROP TRIGGER IF EXISTS trg_prevent_profile_email_change ON public.profiles;
CREATE TRIGGER trg_prevent_profile_email_change
    BEFORE UPDATE ON public.profiles
    FOR EACH ROW
    EXECUTE FUNCTION public.prevent_profile_email_change();

-- 3. Role is derived from admin_users, never from the profile's own (mutable) email or role.
CREATE OR REPLACE FUNCTION public.enforce_sole_admin_policy()
RETURNS TRIGGER AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM public.admin_users WHERE user_id = NEW.id) THEN
        NEW.role := 'admin';
    ELSE
        NEW.role := 'penetration_tester';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 4. New-user hook: same insert as before, role derived from the UID table.
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER AS $$
DECLARE
    assigned_role TEXT;
BEGIN
    IF EXISTS (SELECT 1 FROM public.admin_users WHERE user_id = NEW.id) THEN
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

-- 5. Re-derive existing profile roles from the UID table.
UPDATE public.profiles p
SET role = CASE WHEN EXISTS (SELECT 1 FROM public.admin_users a WHERE a.user_id = p.id)
                THEN 'admin' ELSE 'penetration_tester' END;
