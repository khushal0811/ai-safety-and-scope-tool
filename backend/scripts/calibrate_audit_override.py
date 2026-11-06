"""Live calibration for the audit AI Judge override path.

Runs the real hybrid engine (Pass 1 + AI Judge with full override) against the
labeled cases in ``scripts/calibration_cases.json`` and reports agreement and
false-positive / false-negative rates.

Usage (from backend/):
    ./.venv/bin/python scripts/calibrate_audit_override.py
    ./.venv/bin/python scripts/calibrate_audit_override.py --limit 6
    ./.venv/bin/python scripts/calibrate_audit_override.py --report ../docs/CALIBRATION_AUDIT_OVERRIDE.json
"""

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

# Make the backend package importable when the script is run directly.
BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.data.presets import get_roe_preset_by_id  # noqa: E402
from app.engine.verifier import evaluate_audit, evaluate_audit_async  # noqa: E402
from app.models.audit import AuditRequest  # noqa: E402


CASES_PATH = Path(__file__).resolve().parent / "calibration_cases.json"


async def run_case(case: Dict[str, Any]) -> Dict[str, Any]:
    roe = get_roe_preset_by_id(case["roe_id"])
    if roe is None:
        raise SystemExit(f"Unknown RoE preset: {case['roe_id']}")

    request = AuditRequest(
        roe=roe,
        model_id="calibration-runner",
        user_prompt=case.get("user_prompt", "Calibration case"),
        model_output=case["model_output"],
    )

    pass1 = evaluate_audit(request)
    final = await evaluate_audit_async(request)

    return {
        "id": case["id"],
        "label": case.get("label", "unknown"),
        "expected": case["expected_verdict"],
        "pass1": pass1.verdict.value,
        "final": final.verdict.value,
        "match": final.verdict.value == case["expected_verdict"],
        "trust_tier": final.trust_tier,
        "overrides": len(final.override_log),
        "needs_review": final.needs_review,
        "usage": final.ai_judge_usage,
        "safe_sanitized_command": final.safe_sanitized_command,
    }


def summarize(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    safe = [r for r in rows if r["label"] == "safe"]
    unsafe = [r for r in rows if r["label"] == "unsafe"]
    return {
        "cases": len(rows),
        "agreement": round(sum(1 for r in rows if r["match"]) / len(rows), 3) if rows else 0.0,
        "safe_false_positive_rate": round(
            sum(1 for r in safe if r["final"] != "Correct") / len(safe), 3
        ) if safe else 0.0,
        "safe_false_positives_corrected_by_ai": sum(
            1 for r in safe if r["pass1"] != "Correct" and r["final"] == "Correct"
        ),
        "unsafe_preserved": round(
            sum(1 for r in unsafe if r["final"] == "Unsafe") / len(unsafe), 3
        ) if unsafe else 0.0,
        "refusals_handled": sum(
            1 for r in rows if r["label"] == "refusal" and r["final"] == "Refused"
        ),
    }


async def main_async(cases: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for case in cases:
        row = await run_case(case)
        rows.append(row)
        print(
            f"{row['id']:<28} expected={row['expected']:<9} "
            f"pass1={row['pass1']:<9} final={row['final']:<9} match={row['match']}"
        )
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description="Live audit override calibration")
    parser.add_argument("--limit", type=int, default=0, help="Run only the first N cases")
    parser.add_argument("--report", type=str, default="", help="Write the JSON report to this path")
    args = parser.parse_args()

    cases = json.loads(CASES_PATH.read_text(encoding="utf-8"))
    if args.limit and args.limit > 0:
        cases = cases[: args.limit]

    rows = asyncio.run(main_async(cases))
    summary = summarize(rows)

    print("\nSummary:")
    print(json.dumps(summary, indent=2))

    if args.report:
        report = {"summary": summary, "results": rows}
        Path(args.report).write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"\nReport written to {args.report}")


if __name__ == "__main__":
    main()
