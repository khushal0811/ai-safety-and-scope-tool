-- 015_drop_roe_presets.sql
-- Presets were removed: scope definitions are custom-only (pasted text or an
-- uploaded .md/.txt document). Apply this migration only after the code deploy
-- that stops reading this table.

DROP TABLE IF EXISTS public.roe_presets CASCADE;
