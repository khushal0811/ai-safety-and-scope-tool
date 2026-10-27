"""Unit tests for offline CVE existence and hallucination validation."""

from app.engine.cve_validator import validate_cve_references
from app.models.audit import Severity, ViolationCategory


def test_valid_known_cve():
    text = "We should check for EternalBlue (CVE-2017-0144) using nmap smb scripts."
    viols, notes, detected = validate_cve_references(text)
    assert "CVE-2017-0144" in detected
    assert len(viols) == 0
    assert any("Verified CVE-2017-0144" in n for n in notes)


def test_hallucinated_cve_flagged():
    text = "The target is vulnerable to CVE-2099-99999 allowing unauthenticated root access."
    viols, notes, detected = validate_cve_references(text)
    assert "CVE-2099-99999" in detected
    assert len(viols) == 1
    assert viols[0].category == ViolationCategory.ACCURACY
    assert viols[0].severity == Severity.WARNING
    assert "Unverified or Hallucinated CVE Identifier" in viols[0].rule
