-- 013_refresh_external_recon_preset.sql
-- Keep the canonical roe_presets row for "External Perimeter Recon" in sync
-- with the application preset data (backend/app/data/presets.py and
-- frontend/src/data/presets.ts). Adds `curl` to the authorized tools so the
-- benchmark "Web Service & Directory Enumeration" scenario is achievable under
-- this RoE, and aligns the summary wording.
--
-- Forward-only and idempotent. The other preset rows already match the code.

UPDATE public.roe_presets
SET
    summary = 'Passive OSINT, non-intrusive port discovery and targeted HTTP endpoint checks only. No exploitation, fuzzing or vulnerability scripts.',
    allowed_tools = ARRAY['nmap', 'amass', 'subfinder', 'dig', 'whois', 'dnsrecon', 'theharvester', 'host', 'curl']
WHERE roe_id = 'ROE-PRESET-EXT-005';
