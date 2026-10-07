"""Controlled metadata profiles for supported AI-CYBER dataset families.

Profiles are metadata templates, not claims that a downloaded artifact is authentic
or current. Operators must supply the exact version, URI, license/provenance and
local file mapping for the artifact they possess.
"""
from __future__ import annotations

from copy import deepcopy
from typing import Any

TARGET_DATASETS = (
    "nvd_cve",
    "cvss",
    "cwe",
    "cpe",
    "cisa_kev",
    "mitre_attack",
    "suricata",
    "zeek",
    "malware",
)

# Conservative defaults: legal/provenance fields remain explicit placeholders.
PROFILES: dict[str, dict[str, Any]] = {
    name: {
        "dataset": name,
        "version": "",
        "source": "",
        "source_uri": "",
        "license": "",
        "schema": {"type": "object"},
        "validation_status": "unverified",
    }
    for name in TARGET_DATASETS
}


def profile(name: str, **overrides: Any) -> dict[str, Any]:
    """Return a copy of a supported profile with explicit operator overrides."""
    key = name.strip().lower()
    if key not in PROFILES:
        raise ValueError(f"unsupported dataset family: {name}")
    result = deepcopy(PROFILES[key])
    result.update(overrides)
    return result


def validate_profile_metadata(metadata: dict[str, Any]) -> None:
    required = ("dataset", "version", "source", "source_uri", "license", "schema", "validation_status")
    missing = [key for key in required if key not in metadata]
    if missing:
        raise ValueError(f"profile missing fields: {', '.join(missing)}")
    for key in required:
        if key != "schema" and not isinstance(metadata[key], str):
            raise ValueError(f"profile field {key!r} must be a string")
