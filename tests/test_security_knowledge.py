import pytest

from ai_cyber_os.dataset_profiles import TARGET_DATASETS
from ai_cyber_os.security_knowledge import (
    extract_family_identifiers,
    normalize_family_record,
    supported_families,
    validate_family_record,
)


def test_all_thirteen_dataset_families_have_explicit_contracts():
    assert supported_families() == TARGET_DATASETS
    assert len(supported_families()) == 13


@pytest.mark.parametrize(
    ("family", "record", "expected_type", "expected_value"),
    [
        ("nvd_cve", {"cve": {"id": "CVE-2026-1234"}, "description": "example"}, "cve", "CVE-2026-1234"),
        ("cisa_kev", {"cveID": "CVE-2026-1234"}, "cve", "CVE-2026-1234"),
        ("epss", {"cve": "CVE-2026-1234", "epss": 0.2}, "cve", "CVE-2026-1234"),
        ("cwe", {"ID": "CWE-79", "Name": "XSS"}, "cwe", "CWE-79"),
        ("cpe", {"cpeName": "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"}, "cpe", "CPE:2.3:A:VENDOR:PRODUCT:1.0:*:*:*:*:*:*:*"),
        ("cvss", {"cve_id": "CVE-2026-1234", "vectorString": "CVSS:3.1/AV:N/AC:L"}, "cve", "CVE-2026-1234"),
        ("mitre_attack", {"external_id": "T1059", "name": "Command and Scripting Interpreter"}, "attack", "T1059"),
        ("capec", {"id": "CAPEC-66", "name": "SQL Injection"}, "capec", "CAPEC-66"),
        ("d3fend", {"id": "D3FEND-DA"}, "d3fend", "D3FEND-DA"),
        ("sigma", {"id": "123e4567-e89b-12d3-a456-426614174000", "title": "Example rule"}, "sigma", "123E4567-E89B-12D3-A456-426614174000"),
        ("suricata_rules", {"sid": 2026001, "content": "alert tcp"}, "suricata_sid", "2026001"),
        ("zeek_intel", {"indicator": "bad.example", "description": "fixture"}, "indicator", "bad.example"),
        ("mbc", {"id": "B0001", "name": "Example behavior"}, "mbc", "B0001"),
    ],
)
def test_family_specific_identifier_extraction(family, record, expected_type, expected_value):
    identifiers = extract_family_identifiers(family, record)
    assert {"type": expected_type, "value": expected_value} in identifiers


def test_normalized_envelope_preserves_provenance_and_hashes_content():
    row = normalize_family_record(
        "nvd_cve",
        {
            "cve": {"id": "CVE-2026-9999"},
            "description": "fixture evidence",
            "source": "local fixture",
            "source_uri": "fixture://nvd",
            "license": "operator supplied",
            "version": "test-v1",
            "validation_status": "unverified",
        },
    )
    assert row["record_id"] == "CVE-2026-9999"
    assert row["content"] == "fixture evidence"
    assert len(row["content_sha256"]) == 64
    assert row["source_uri"] == "fixture://nvd"
    assert row["validation_status"] == "unverified"
    assert row["identifiers"] == [{"type": "cve", "value": "CVE-2026-9999"}]


def test_unknown_family_and_missing_identity_fail_closed():
    with pytest.raises(ValueError, match="unsupported security knowledge family"):
        validate_family_record("unknown", {"id": "X"})
    with pytest.raises(ValueError, match="no recognizable family identifier"):
        validate_family_record("nvd_cve", {"title": "missing identifier"})
