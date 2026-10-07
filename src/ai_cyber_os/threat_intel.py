"""Canonical parsers for common cyber-threat intelligence source formats.

These parsers are offline: they consume files already downloaded by the operator.
They never claim that an upstream source is authentic or current. Provenance and
validation state come from the dataset manifest and are preserved in records.
"""
from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Iterable

from .knowledge import _normalize


def _walk(value: Any) -> Iterable[Any]:
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk(child)


def parse_nvd(path: str | Path, *, dataset: str = "cve", source: str = "NVD",
              version: str = "", source_uri: str = "", license: str = "",
              validation_status: str = "unverified") -> list[dict[str, Any]]:
    """Parse NVD CVE JSON 1.x/2.x records into the common evidence contract."""
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    items = raw.get("vulnerabilities", raw.get("CVE_Items", [])) if isinstance(raw, dict) else raw
    if not isinstance(items, list):
        raise ValueError("NVD file does not contain a vulnerability list")
    out = []
    for item in items:
        cve = item.get("cve", item) if isinstance(item, dict) else {}
        if not isinstance(cve, dict):
            continue
        cve_id = cve.get("id") or cve.get("CVE_data_meta", {}).get("ID")
        if not cve_id:
            continue
        descriptions = cve.get("descriptions", [])
        desc = next((x.get("value") for x in descriptions if x.get("lang") == "en"), None)
        if desc is None:
            desc = next((x.get("value") for x in descriptions if isinstance(x, dict)), "")
        content = {
            "id": cve_id,
            "description": desc or "",
            "source_identifier": cve.get("sourceIdentifier"),
            "published": cve.get("published"),
            "last_modified": cve.get("lastModified"),
            "references": cve.get("references", []),
            "metrics": cve.get("metrics", {}),
            "weaknesses": cve.get("weaknesses", []),
            "configurations": cve.get("configurations", []),
        }
        out.append(_normalize(content, dataset=dataset, source=source, version=version,
                              source_uri=source_uri, license=license,
                              validation_status=validation_status))
    return out


def parse_cisa_kev(path: str | Path, *, dataset: str = "cisa-kev",
                   source: str = "CISA KEV", version: str = "",
                   source_uri: str = "", license: str = "",
                   validation_status: str = "unverified") -> list[dict[str, Any]]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    rows = raw.get("vulnerabilities", []) if isinstance(raw, dict) else raw
    if not isinstance(rows, list):
        raise ValueError("CISA KEV file does not contain vulnerabilities")
    return [
        _normalize(row, dataset=dataset, source=source, version=version,
                   source_uri=source_uri, license=license,
                   validation_status=validation_status)
        for row in rows if isinstance(row, dict)
    ]


def parse_attack_stix(path: str | Path, *, dataset: str = "mitre-attack",
                      source: str = "MITRE ATT&CK", version: str = "",
                      source_uri: str = "", license: str = "",
                      validation_status: str = "unverified") -> list[dict[str, Any]]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    objects = raw.get("objects", []) if isinstance(raw, dict) else raw
    if not isinstance(objects, list):
        raise ValueError("ATT&CK STIX file does not contain objects")
    out = []
    for obj in objects:
        if not isinstance(obj, dict) or obj.get("type") not in {"attack-pattern", "malware", "tool", "intrusion-set"}:
            continue
        content = {
            "id": obj.get("external_references", [{}])[0].get("external_id") if obj.get("external_references") else obj.get("id"),
            "stix_id": obj.get("id"),
            "type": obj.get("type"),
            "name": obj.get("name"),
            "description": obj.get("description", ""),
            "modified": obj.get("modified"),
            "external_references": obj.get("external_references", []),
            "kill_chain_phases": obj.get("kill_chain_phases", []),
        }
        out.append(_normalize(content, dataset=dataset, source=source, version=version,
                              source_uri=source_uri, license=license,
                              validation_status=validation_status))
    return out


def parse_cwe_xml(path: str | Path, *, dataset: str = "cwe",
                  source: str = "MITRE CWE", version: str = "",
                  source_uri: str = "", license: str = "",
                  validation_status: str = "unverified") -> list[dict[str, Any]]:
    root = ET.parse(path).getroot()
    out = []
    for elem in root.iter():
        tag = elem.tag.rsplit("}", 1)[-1]
        if tag != "Weakness":
            continue
        wid = elem.attrib.get("ID")
        name = elem.attrib.get("Name", "")
        if not wid:
            continue
        desc = ""
        for child in elem.iter():
            if child.tag.rsplit("}", 1)[-1] == "Description" and child.text:
                desc = " ".join(child.itertext()).strip()
                break
        out.append(_normalize({"id": f"CWE-{wid}", "name": name, "description": desc},
                              dataset=dataset, source=source, version=version,
                              source_uri=source_uri, license=license,
                              validation_status=validation_status))
    return out


PARSERS = {
    "nvd": parse_nvd,
    "cisa-kev": parse_cisa_kev,
    "attack-stix": parse_attack_stix,
    "cwe-xml": parse_cwe_xml,
}
