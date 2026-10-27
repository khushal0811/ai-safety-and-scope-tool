"""Unit tests for IP obfuscation normalization and Scope/CIDR validation."""

import pytest
from app.engine.ip_validator import normalize_ip_candidate, ScopeValidator
from app.models.audit import TargetKind, TargetStatus
from app.models.roe import RoeScope


def test_ip_normalization_standard_dot_decimal():
    norm = normalize_ip_candidate("192.168.1.105")
    assert norm.is_valid is True
    assert norm.canonical == "192.168.1.105"
    assert norm.kind == TargetKind.IP
    assert norm.is_obfuscated is False


def test_ip_normalization_hex_dword():
    # 0x7f000001 == 127.0.0.1
    norm = normalize_ip_candidate("0x7f000001")
    assert norm.is_valid is True
    assert norm.canonical == "127.0.0.1"
    assert norm.is_obfuscated is True
    assert norm.format_type == "hex_dword"


def test_ip_normalization_dotted_hex():
    norm = normalize_ip_candidate("0x7f.0.0.1")
    assert norm.is_valid is True
    assert norm.canonical == "127.0.0.1"
    assert norm.is_obfuscated is True


def test_ip_normalization_dotted_octal():
    # 0177 == 127 in octal
    norm = normalize_ip_candidate("0177.0.0.1")
    assert norm.is_valid is True
    assert norm.canonical == "127.0.0.1"
    assert norm.is_obfuscated is True


def test_ip_normalization_decimal_dword():
    # 2130706433 == 127.0.0.1
    norm = normalize_ip_candidate("2130706433")
    assert norm.is_valid is True
    assert norm.canonical == "127.0.0.1"
    assert norm.is_obfuscated is True


def test_ip_normalization_ipv6_mapped_ipv4():
    norm = normalize_ip_candidate("::ffff:192.168.1.105")
    assert norm.is_valid is True
    assert norm.canonical == "192.168.1.105"
    assert norm.is_obfuscated is True
    assert norm.format_type == "ipv6_mapped_ipv4"


def test_ip_normalization_cidr():
    norm = normalize_ip_candidate("192.168.1.0/24")
    assert norm.is_valid is True
    assert norm.canonical == "192.168.1.0/24"
    assert norm.kind == TargetKind.CIDR


def test_ip_normalization_domain():
    norm = normalize_ip_candidate("staging.acme-target.internal")
    assert norm.is_valid is True
    assert norm.canonical == "staging.acme-target.internal"
    assert norm.kind == TargetKind.DOMAIN


def test_scope_validator_in_scope(network_recon_roe: RoeScope):
    validator = ScopeValidator(network_recon_roe)
    target = normalize_ip_candidate("192.168.1.105")
    finding = validator.classify_target(target)
    assert finding.status == TargetStatus.IN_SCOPE
    assert finding.normalized == "192.168.1.105"


def test_scope_validator_out_of_scope(network_recon_roe: RoeScope):
    validator = ScopeValidator(network_recon_roe)
    target = normalize_ip_candidate("10.10.10.50")
    finding = validator.classify_target(target)
    assert finding.status == TargetStatus.OUT_OF_SCOPE


def test_scope_validator_prohibited_gateway(network_recon_roe: RoeScope):
    validator = ScopeValidator(network_recon_roe)
    target = normalize_ip_candidate("192.168.1.1")
    finding = validator.classify_target(target)
    assert finding.status == TargetStatus.PROHIBITED


def test_scope_validator_prohibited_broadcast(network_recon_roe: RoeScope):
    validator = ScopeValidator(network_recon_roe)
    target = normalize_ip_candidate("192.168.1.255")
    finding = validator.classify_target(target)
    assert finding.status == TargetStatus.PROHIBITED


def test_scope_validator_prohibited_cloud_metadata(network_recon_roe: RoeScope):
    validator = ScopeValidator(network_recon_roe)
    target = normalize_ip_candidate("169.254.169.254")
    finding = validator.classify_target(target)
    assert finding.status == TargetStatus.PROHIBITED


def test_scope_validator_prohibited_public_dns(network_recon_roe: RoeScope):
    validator = ScopeValidator(network_recon_roe)
    target = normalize_ip_candidate("8.8.8.8")
    finding = validator.classify_target(target)
    assert finding.status == TargetStatus.PROHIBITED


def test_scope_validator_obfuscated_evasion_caught(network_recon_roe: RoeScope):
    validator = ScopeValidator(network_recon_roe)
    # 0x7f000001 (127.0.0.1) loopback
    target = normalize_ip_candidate("0x7f000001")
    finding = validator.classify_target(target)
    assert finding.obfuscated is True
    assert finding.status == TargetStatus.PROHIBITED
