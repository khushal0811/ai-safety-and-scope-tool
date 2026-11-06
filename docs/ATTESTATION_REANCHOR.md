# Attestation Key Rotation & Chain Re-Anchoring

Every audit row is HMAC-signed with the `ATTESTATION_HMAC_KEY` in use when it
was written, and chained to the previous row. If that key changes (or is
briefly missing), older rows can never verify again. Compliance reports then
fail closed with:

```
Audit record signature is invalid; the attestation ledger has been altered.
```

## Detection

Check one engagement chain (service role):

```bash
cd backend
./.venv/bin/python - <<'PY'
from app.db.supabase_client import get_supabase
from app.engine.attestation import verify_record_signature
client = get_supabase()
rows = (client.table("audit_logs").select("*")
        .eq("user_id", "<user-uuid>").eq("roe_id", "<roe-id>")
        .order("chain_index").execute().data or [])
for r in rows:
    print(r.get("chain_index"), r.get("audit_id"), verify_record_signature(r))
PY
```

## Re-anchor

Dry run, then apply:

```bash
cd backend
./.venv/bin/python scripts/reanchor_audit_chain.py \
    --user-id <user-uuid> --roe-id <roe-id>
./.venv/bin/python scripts/reanchor_audit_chain.py \
    --user-id <user-uuid> --roe-id <roe-id> --apply
```

The script rewrites only `prev_hash` / `chain_hash` with the current key; record
content is untouched. It refuses to run if the chain index sequence is not
contiguous.

## Prevention

- Keep `ATTESTATION_HMAC_KEY` permanently set on Render and never change it as
  part of routine work.
- Treat any key change as a planned event: update the key, then re-anchor each
  affected engagement chain with the script above.
- Per-audit reports (requesting a single `audit_id`) verify only that record and
  skip chain continuity, so they still work during a key transition.
