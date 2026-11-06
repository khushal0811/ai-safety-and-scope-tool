"""Re-anchor one audit chain after an attestation key rotation.

Each audit row is HMAC-signed with the ATTESTATION_HMAC_KEY in use when it was
written. If that key changed (or was briefly missing), older rows can never
verify again and every compliance report for that engagement fails closed with
"the attestation ledger has been altered".

This owner-authorized maintenance script rewrites only the chain metadata
(prev_hash / chain_hash) for one (user_id, roe_id) chain using the current key.
Record content is not touched. Run without --apply for a dry run.

Usage (from backend/):
    ./.venv/bin/python scripts/reanchor_audit_chain.py \
        --user-id <uuid> --roe-id <roe_id>
    ./.venv/bin/python scripts/reanchor_audit_chain.py \
        --user-id <uuid> --roe-id <roe_id> --apply
"""

import argparse
import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.db.supabase_client import get_supabase  # noqa: E402
from app.engine.attestation import (  # noqa: E402
    compute_record_signature,
    genesis_hash,
    verify_record_signature,
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Re-anchor one audit chain with the current attestation key")
    parser.add_argument("--user-id", required=True, help="Audit owner UUID")
    parser.add_argument("--roe-id", required=True, help="Engagement RoE id")
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Write the re-anchored hashes. Default is a dry run.",
    )
    args = parser.parse_args()

    client = get_supabase()
    if client is None:
        raise SystemExit("No Supabase client configured.")

    rows = (
        client.table("audit_logs")
        .select("*")
        .eq("user_id", args.user_id)
        .eq("roe_id", args.roe_id)
        .order("chain_index", desc=False)
        .execute()
        .data
        or []
    )
    if not rows:
        raise SystemExit("No audit records found for that user/roe.")

    indexes = [int(r.get("chain_index") or 0) for r in rows]
    if indexes != list(range(1, len(rows) + 1)):
        raise SystemExit(f"Chain index sequence is not contiguous: {indexes}. Refusing to re-anchor.")

    prev = genesis_hash(args.roe_id)
    updates = []
    print(f"{'chain':<6} {'audit_id':<18} {'before':<8} {'after':<8}")
    for row in rows:
        record = dict(row)
        record["prev_hash"] = prev
        new_hash = compute_record_signature(record)
        record["chain_hash"] = new_hash
        after_ok = verify_record_signature(record)
        print(
            f"{record.get('chain_index'):<6} {record.get('audit_id'):<18} "
            f"{str(verify_record_signature(row)):<8} {str(after_ok):<8}"
        )
        updates.append((record.get("id"), prev, new_hash))
        prev = new_hash

    if not args.apply:
        print("\nDry run only. Re-run with --apply to write the re-anchored chain.")
        return

    for row_id, prev_hash, chain_hash in updates:
        (
            client.table("audit_logs")
            .update({"prev_hash": prev_hash, "chain_hash": chain_hash})
            .eq("id", row_id)
            .execute()
        )

    # Verify from a fresh read.
    verified = (
        client.table("audit_logs")
        .select("*")
        .eq("user_id", args.user_id)
        .eq("roe_id", args.roe_id)
        .order("chain_index", desc=False)
        .execute()
        .data
        or []
    )
    all_ok = all(verify_record_signature(r) for r in verified)
    print(f"\nApplied. Re-anchored rows: {len(updates)} | all verify: {all_ok}")
    if not all_ok:
        raise SystemExit("Verification after re-anchor failed; inspect the chain.")


if __name__ == "__main__":
    main()
