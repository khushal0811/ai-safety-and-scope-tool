"""Unit tests for unstructured RoE document parser and prompt injection mitigation."""

import pytest
from app.engine.roe_parser import (
    deterministic_roe_post_validation,
    fallback_regex_roe_extractor,
    sanitize_raw_document,
)


def test_sanitize_raw_document_null_byte():
    with pytest.raises(ValueError, match="null bytes"):
        sanitize_raw_document("malicious\x00content")


def test_sanitize_raw_document_oversized():
    huge = "a" * (501 * 1024)
    with pytest.raises(ValueError, match="exceeds maximum file limit"):
        sanitize_raw_document(huge)


def test_deterministic_post_validation_blocks_wildcard_cidr():
    adversarial_payload = {
        "name": "Attacker Injected Scope",
        "allowed_cidrs": ["0.0.0.0/0", "192.168.1.0/24"],
        "prohibited_ips": [],
        "max_nmap_timing": 10,  # exceeds allowed
    }
    roe = deterministic_roe_post_validation(adversarial_payload)
    # 0.0.0.0/0 MUST be discarded
    assert "0.0.0.0/0" not in roe.allowed_cidrs
    assert "192.168.1.0/24" in roe.allowed_cidrs
    # Metadata MUST be enforced
    assert "169.254.169.254" in roe.prohibited_ips
    # Timing template MUST be clamped <= 5
    assert roe.max_nmap_timing <= 5


def test_fallback_regex_roe_extractor():
    text = """# Rules of Engagement
Testing subnet: 10.0.50.0/24
Target host: 10.0.50.15
Excluded host: 10.0.50.1
"""
    roe = fallback_regex_roe_extractor(text, "test.md")
    assert "10.0.50.0/24" in roe.allowed_cidrs
    assert "10.0.50.15" in roe.target_hosts
    assert "169.254.169.254" in roe.prohibited_ips


def test_deterministic_post_validation_prohibited_overrides_target_hosts():
    """Verify that any IP in prohibited_ips is stripped from target_hosts (Apex Financial scenario)."""
    payload = {
        "name": "Apex Financial Infrastructure Engagement",
        "allowed_cidrs": ["10.0.10.0/24"],
        "target_hosts": ["10.0.10.1", "8.8.8.8", "1.1.1.1", "10.0.10.50"],
        "prohibited_ips": ["10.0.10.1", "10.0.10.255", "8.8.8.8", "1.1.1.1"],
    }
    roe = deterministic_roe_post_validation(payload)
    # Prohibited hosts must be stripped from target_hosts
    assert "10.0.10.1" not in roe.target_hosts
    assert "8.8.8.8" not in roe.target_hosts
    assert "1.1.1.1" not in roe.target_hosts
    # Authorized host remains
    assert "10.0.10.50" in roe.target_hosts
    # Prohibited IPs are fully present
    assert "10.0.10.1" in roe.prohibited_ips
    assert "10.0.10.255" in roe.prohibited_ips
    assert "8.8.8.8" in roe.prohibited_ips
    assert "1.1.1.1" in roe.prohibited_ips
    assert "169.254.169.254" in roe.prohibited_ips



# AUDIT_005 Low: IPv6 authorized subnets need a family-specific minimum prefix

def test_deterministic_post_validation_rejects_broad_ipv6_subnets():
    payload = {
        "name": "IPv6 Scope",
        "allowed_cidrs": [
            "2000::/8",
            "::/8",
            "2001:db8::/32",
            "2001:db8:1::/48",
            "10.0.0.0/8",
            "10.1.0.0/16",
        ],
    }
    roe = deterministic_roe_post_validation(payload)
    assert "2000::/8" not in roe.allowed_cidrs
    assert "::/8" not in roe.allowed_cidrs
    assert "2001:db8::/32" not in roe.allowed_cidrs
    assert "2001:db8:1::/48" in roe.allowed_cidrs
    assert "10.0.0.0/8" in roe.allowed_cidrs
    assert "10.1.0.0/16" in roe.allowed_cidrs


def test_roe_scope_model_rejects_broad_ipv6_subnet():
    from pydantic import ValidationError
    from app.models.roe import RoeScope

    with pytest.raises(ValidationError, match="too broad"):
        RoeScope(
            roe_id="ROE-IPV6-BROAD",
            name="Broad IPv6",
            engagement_type="Network",
            allowed_cidrs=["2000::/8"],
        )

    scope = RoeScope(
        roe_id="ROE-IPV6-OK",
        name="Scoped IPv6",
        engagement_type="Network",
        allowed_cidrs=["2001:db8:1::/48"],
    )
    assert scope.allowed_cidrs == ["2001:db8:1::/48"]
