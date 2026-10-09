"""Deterministic cross-dataset security identifier relationship extraction.

This module extracts explicit identifiers from evidence text. Co-occurrence is
stored as a candidate relationship, not asserted to prove causation or equivalence.
"""
from __future__ import annotations

import re

PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("cve", re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)),
    ("cwe", re.compile(r"\bCWE-?\d+\b", re.I)),
    ("attack", re.compile(r"\b(?:T\d{4}(?:\.\d{3})?|G\d{4}|S\d{4}|M\d{4})\b", re.I)),
    ("cpe", re.compile(r"\bcpe:2\.3:[A-Za-z0-9*._:-]+", re.I)),
    ("capec", re.compile(r"\bCAPEC-?\d+\b", re.I)),
    ("d3fend", re.compile(r"\bD3FEND-?[A-Z0-9]+\b", re.I)),
    ("mbc", re.compile(r"\b[BCF]\d{4}\b", re.I)),
    ("sigma", re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b", re.I)),
    ("suricata_sid", re.compile(r"\bsid\s*:\s*(\d+)\s*;?", re.I)),
)


def extract_security_relations(text: str, *, record_id: str = "") -> list[tuple[str, str]]:
    """Extract sorted unique typed IDs; never infer a relation from unsupported text."""
    found: set[tuple[str, str]] = set()
    haystack = f"{record_id} {text}"
    for relation_type, pattern in PATTERNS:
        for value in pattern.findall(haystack):
            canonical = value.upper()
            if relation_type == "cwe" and canonical.startswith("CWE") and not canonical.startswith("CWE-"):
                canonical = "CWE-" + canonical[3:]
            elif relation_type == "capec":
                canonical = "CAPEC-" + canonical[5:].lstrip("-")
            elif relation_type == "d3fend":
                canonical = "D3FEND-" + canonical[6:].lstrip("-")
            elif relation_type == "cpe":
                canonical = canonical.upper()
            found.add((relation_type, canonical))
    # The dataset pipeline also uses synthetic CVE-like IDs in deterministic fixtures.
    match = re.search(r"(?i)\bCVE-\d{4}-[A-Z0-9][A-Z0-9._-]*\b", haystack)
    if match:
        found.add(("cve", match.group(0).upper()))
    return sorted(found)
