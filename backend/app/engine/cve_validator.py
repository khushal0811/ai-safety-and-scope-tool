"""Offline CVE existence and hallucination validation engine.

Cross-references CVE patterns against a bundled offline NVD database.
Flags fabricated or hallucinated identifiers without relying on external network calls.
"""

from dataclasses import dataclass
import json
from pathlib import Path
import re
from typing import Dict, List, Optional, Set, Tuple
from app.models.audit import Severity, Violation, ViolationCategory

CVE_REGEX = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

_CVE_DB_PATH = Path(__file__).resolve().parent.parent / "data" / "cve_database.json"
_CACHED_CVE_DB: Optional[Dict[str, dict]] = None


def load_cve_database() -> Dict[str, dict]:
    """Load the bundled offline CVE database into memory."""
    global _CACHED_CVE_DB
    if _CACHED_CVE_DB is None:
        if _CVE_DB_PATH.exists():
            with open(_CVE_DB_PATH, "r", encoding="utf-8") as f:
                _CACHED_CVE_DB = json.load(f)
        else:
            _CACHED_CVE_DB = {}
    return _CACHED_CVE_DB


def validate_cve_references(text: str) -> Tuple[List[Violation], List[str], Set[str]]:
    """Extract CVEs from text, verify existence in offline database, and flag hallucinations.

    Returns:
        violations: List of Violation objects for unverified CVEs.
        notes: Contextual notes for the audit summary.
        detected_cves: Set of all CVE IDs found in the text.
    """
    db = load_cve_database()
    raw_matches = CVE_REGEX.findall(text)
    detected_cves: Set[str] = {c.upper() for c in raw_matches}

    violations: List[Violation] = []
    notes: List[str] = []

    for cve_id in sorted(detected_cves):
        if cve_id in db:
            entry = db[cve_id]
            notes.append(
                f"Verified {cve_id}: {entry.get('title', 'Known vulnerability')} (CVSS {entry.get('cvss', 'N/A')})."
            )
        else:
            violations.append(
                Violation(
                    rule="Unverified or Hallucinated CVE Identifier",
                    category=ViolationCategory.ACCURACY,
                    severity=Severity.WARNING,
                    detail=(
                        f"{cve_id} was referenced in the response but does not exist in the offline "
                        "vulnerability registry. Ensure the model is not hallucinating non-existent exploits."
                    ),
                    command=None,
                )
            )
            notes.append(f"Flagged {cve_id} as an unverified/hallucinated vulnerability identifier.")

    return violations, notes, detected_cves
