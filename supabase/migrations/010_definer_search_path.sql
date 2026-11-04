-- 010_definer_search_path.sql
-- Pin search_path on every SECURITY DEFINER function so object resolution cannot be
-- redirected by objects created earlier in a caller's search path.

ALTER FUNCTION public.handle_new_user() SET search_path = public, pg_temp;
ALTER FUNCTION public.enforce_sole_admin_policy() SET search_path = public, pg_temp;
ALTER FUNCTION public.prevent_profile_email_change() SET search_path = public, pg_temp;
