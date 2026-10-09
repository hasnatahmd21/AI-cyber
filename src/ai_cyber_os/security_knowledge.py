"""Family-aware normalized contracts for the 13 AI-CYBER security knowledge sources.

This module validates the shape of records supplied by an operator. It does not
claim that a source is authentic, current, licensed, or externally verified.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any

FAMILY_FIELDS: dict[str, dict[str, Any]] = {
    "nvd_cve": {"id_fields": ("cve.id", "cve_id", "id"), "patterns": (("cve", r"\bCVE-\d{4}-\d{4,}\b"),)},
    "cisa_kev": {"id_fields": ("cveID", "cve_id", "id"), "patterns": (("cve", r"\bCVE-\d{4}-\d{4,}\b"),)},
    "epss": {"id_fields": ("cve", "cve_id", "id"), "patterns": (("cve", r"\bCVE-\d{4}-\d{4,}\b"),)},
    "cwe": {"id_fields": ("ID", "cwe_id", "id"), "patterns": (("cwe", r"\bCWE-?\d+\b"),)},
    "cpe": {"id_fields": ("cpeName", "cpe23Uri", "cpe", "id"), "patterns": (("cpe", r"\bcpe:2\.3:\S+"),)},
    "cvss": {"id_fields": ("cve_id", "cve", "id"), "patterns": (("cve", r"\bCVE-\d{4}-\d{4,}\b"), ("cvss_vector", r"\bCVSS:3\.[01]/\S+|\bCVSS:4\.0/\S+"))},
    "mitre_attack": {"id_fields": ("external_id", "attack_id", "id"), "patterns": (("attack", r"\b(?:T\d{4}(?:\.\d{3})?|G\d{4}|S\d{4}|M\d{4})\b"),)},
    "capec": {"id_fields": ("id", "capec_id", "external_id"), "patterns": (("capec", r"\bCAPEC-?\d+\b"),)},
    "d3fend": {"id_fields": ("id", "d3fend_id", "external_id"), "patterns": (("d3fend", r"\bD3FEND-[A-Z0-9]+\b"),)},
    "sigma": {"id_fields": ("id", "rule_id", "uuid"), "patterns": (("sigma", r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b"),)},
    "suricata_rules": {"id_fields": ("sid", "id", "rule_id"), "patterns": (("suricata_sid", r"\bsid\s*:\s*(\d+)\s*;?"),)},
    "zeek_intel": {"id_fields": ("indicator", "value", "id", "indicator_value"), "patterns": (("indicator", r""),)},
    "mbc": {"id_fields": ("id", "mbc_id", "external_id"), "patterns": (("mbc", r"\b[BCF]\d{4}\b"),)},
}

IDENTIFIER_ALIASES: dict[str, tuple[str, ...]] = {
    "cve": ("cve", "cve_id", "cveID"),
    "cwe": ("cwe", "cwe_id"),
    "attack": ("attack_id", "technique_id", "external_id"),
    "capec": ("capec_id",),
    "d3fend": ("d3fend_id",),
    "cpe": {"id_fields": ("cpeName", "cpe23Uri", "cpe", "id"), "patterns": (("cpe", r"\bcpe:2\.3:\S+"),)},
    "suricata_sid": ("sid",),
}


def supported_families() -> tuple[str, ...]:
    """Return the supported family names in stable, deterministic order."""
    return tuple(FAMILY_FIELDS)


def _path_value(raw: dict[str, Any], path: str) -> Any:
    value: Any = raw
    for part in path.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def _string(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    return str(value).strip()


def extract_family_identifiers(dataset: str, raw: dict[str, Any]) -> list[dict[str, str]]:
    """Extract identifiers explicitly present in one supported family's record."""
    family = dataset.strip().lower()
    if family not in FAMILY_FIELDS:
        raise ValueError(f"unsupported security knowledge family: {dataset}")
    serialized = json.dumps(raw, ensure_ascii=False, sort_keys=True, default=str)
    found: set[tuple[str, str]] = set()
    for kind, pattern in FAMILY_FIELDS[family]["patterns"]:
        if not pattern:
            continue
        for match in re.findall(pattern, serialized, flags=re.IGNORECASE):
            value = match if isinstance(match, str) else match[0]
            found.add((kind, value.upper()))
    # Preserve explicit identity fields even where source formats vary.
    for field in FAMILY_FIELDS[family]["id_fields"]:
        value = _string(_path_value(raw, field))
        if not value:
            continue
        if field == "cve.id" or re.fullmatch(r"CVE-\d{4}-\d{4,}", value, re.I):
            found.add(("cve", value.upper()))
        elif family == "cwe":
            match = re.search(r"CWE-?\d+", value, re.I)
            if match:
                found.add(("cwe", match.group(0).upper().replace("CWE", "CWE-") if not match.group(0).upper().startswith("CWE-") else match.group(0).upper()))
        elif family == "cpe" and value.lower().startswith("cpe:2.3:"):
            found.add(("cpe", value))
        elif family == "mitre_attack" and re.fullmatch(r"(?:T\d{4}(?:\.\d{3})?|G\d{4}|S\d{4}|M\d{4})", value, re.I):
            found.add(("attack", value.upper()))
        elif family == "capec" and re.fullmatch(r"CAPEC-?\d+", value, re.I):
            found.add(("capec", value.upper().replace("CAPEC", "CAPEC-").replace("CAPEC--", "CAPEC-")))
        elif family == "d3fend" and re.fullmatch(r"D3FEND-?[A-Z0-9]+", value, re.I):
            found.add(("d3fend", value.upper().replace("D3FEND", "D3FEND-").replace("D3FEND--", "D3FEND-")))
        elif family == "suricata_rules" and value.isdigit():
            found.add(("suricata_sid", value))
        elif family == "sigma" and re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F-]{27}", value):
            found.add(("sigma", value.lower()))
        elif family == "zeek_intel":
            found.add(("indicator", value))
        elif family == "mbc" and re.fullmatch(r"[BCF]\d{4}", value, re.I):
            found.add(("mbc", value.upper()))
    return [{"type": kind, "value": value} for kind, value in sorted(found)]


def validate_family_record(dataset: str, raw: dict[str, Any]) -> None:
    """Validate the minimal record contract without implying source verification."""
    family = dataset.strip().lower()
    if family not in FAMILY_FIELDS:
        raise ValueError(f"unsupported security knowledge family: {dataset}")
    if not isinstance(raw, dict):
        raise ValueError("security knowledge record must be an object")
    if not any(_string(raw.get(key)) for key in ("content", "text", "description", "title", "name")) and not raw:
        raise ValueError("security knowledge record must not be empty")
    if not extract_family_identifiers(family, raw):
        raise ValueError(f"{family} record has no recognizable family identifier")


def normalize_family_record(dataset: str, raw: dict[str, Any]) -> dict[str, Any]:
    """Return a stable, JSON-serializable envelope around source evidence."""
    validate_family_record(dataset, raw)
    family = dataset.strip().lower()
    identifiers = extract_family_identifiers(family, raw)
    canonical_id = identifiers[0]["value"]
    evidence = _string(raw.get("content") or raw.get("text") or raw.get("description") or raw)
    if not evidence:
        raise ValueError("security knowledge record content is empty")
    return {
        "dataset": family,
        "record_id": _string(raw.get("id")) or canonical_id,
        "family_identifier": canonical_id,
        "identifiers": identifiers,
        "title": _string(raw.get("title") or raw.get("name") or raw.get("id")),
        "content": evidence,
        "content_sha256": hashlib.sha256(evidence.encode("utf-8")).hexdigest(),
        "source": _string(raw.get("source")),
        "source_uri": _string(raw.get("source_uri")),
        "license": _string(raw.get("license")),
        "version": _string(raw.get("version")),
        "validation_status": _string(raw.get("validation_status") or "unverified"),
        "raw": raw,
    }
