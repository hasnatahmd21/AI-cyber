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
        content["content"] = json.dumps(content, ensure_ascii=False, sort_keys=True, default=str)
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
        _normalize({**row, "id": row.get("id") or row.get("cveID")}, dataset=dataset,
                   source=source, version=version, source_uri=source_uri,
                   license=license, validation_status=validation_status)
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
        content["content"] = json.dumps(content, ensure_ascii=False, sort_keys=True, default=str)
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



def parse_cpe(path: str | Path, *, dataset: str = "cpe",
              source: str = "NVD CPE Dictionary", version: str = "",
              source_uri: str = "", license: str = "",
              validation_status: str = "unverified") -> list[dict[str, Any]]:
    """Parse common NVD CPE JSON/XML exports into evidence records."""
    p = Path(path)
    raw = json.loads(p.read_text(encoding="utf-8")) if p.suffix.lower() == ".json" else None
    candidates: list[Any] = []
    if isinstance(raw, dict):
        candidates = raw.get("matches", raw.get("products", raw.get("cpes", [])))
    elif isinstance(raw, list):
        candidates = raw
    if candidates:
        out = []
        for item in candidates:
            if not isinstance(item, dict):
                continue
            name = item.get("cpe23Uri") or item.get("cpeName") or item.get("name")
            if isinstance(name, list) and name:
                first = name[0]
                name = first.get("cpe23Uri") if isinstance(first, dict) else first
            if not name:
                continue
            out.append(_normalize({"id": str(name), "name": str(name), "data": item},
                                  dataset=dataset, source=source, version=version,
                                  source_uri=source_uri, license=license,
                                  validation_status=validation_status))
        return out
    root = ET.parse(p).getroot()
    out = []
    for elem in root.iter():
        tag = elem.tag.rsplit("}", 1)[-1]
        if tag not in {"cpe23-item", "cpe-item"}:
            continue
        name = elem.attrib.get("name")
        if not name:
            continue
        out.append(_normalize({"id": name, "name": name},
                              dataset=dataset, source=source, version=version,
                              source_uri=source_uri, license=license,
                              validation_status=validation_status))
    return out

PARSERS = {
    "nvd": parse_nvd,
    "cisa-kev": parse_cisa_kev,
    "attack-stix": parse_attack_stix,
    "cwe-xml": parse_cwe_xml,
    "cpe": parse_cpe,
}

def ingest_parsed(records: Iterable[dict[str, Any]], *, db_path: str | Path) -> dict[str, int]:
    """Persist parser output using the same evidence contract as normal ingestion."""
    from .knowledge import _extract_relations
    db = __import__("sqlite3").connect(str(db_path))
    db.row_factory = __import__("sqlite3").Row
    # Initialize the store schema without introducing a second schema.
    from .knowledge import open_store
    db.close()
    db = open_store(db_path)
    inserted = updated = duplicates = 0
    try:
        for record in records:
            old = db.execute(
                "SELECT record_id, dataset, content_sha256 FROM knowledge_records WHERE record_id=?",
                (record["record_id"],),
            ).fetchone()
            if old and old["content_sha256"] == record["content_sha256"] and old["dataset"] == record["dataset"]:
                duplicates += 1
                continue
            if old and old["dataset"] != record["dataset"]:
                base_id = record["record_id"]
                metadata = json.loads(record["metadata_json"])
                metadata["external_id"] = base_id
                record["metadata_json"] = json.dumps(
                    metadata, ensure_ascii=False, sort_keys=True, default=str
                )
                record["record_id"] = f"{record['dataset']}:{base_id}"
                old = db.execute(
                    "SELECT record_id, dataset, content_sha256 FROM knowledge_records WHERE record_id=?",
                    (record["record_id"],),
                ).fetchone()
                if old and old["content_sha256"] == record["content_sha256"]:
                    duplicates += 1
                    continue
            if old:
                updated += 1
                db.execute("DELETE FROM knowledge_fts WHERE record_id=?", (record["record_id"],))
            else:
                inserted += 1
            db.execute(
                """INSERT OR REPLACE INTO knowledge_records
                (record_id,dataset,source,source_uri,license,version,validation_status,title,content,
                 content_sha256,metadata_json,schema_version,ingested_at)
                VALUES (:record_id,:dataset,:source,:source_uri,:license,:version,:validation_status,
                        :title,:content,:content_sha256,:metadata_json,:schema_version,:ingested_at)""",
                record,
            )
            db.execute("DELETE FROM knowledge_relations WHERE record_id=?", (record["record_id"],))
            for relation_type, target_id in _extract_relations(
                f'{record["record_id"]} {record["title"]} {record["content"]}'
            ):
                db.execute(
                    "INSERT OR IGNORE INTO knowledge_relations(record_id,relation_type,target_id) VALUES (?,?,?)",
                    (record["record_id"], relation_type, target_id),
                )
            db.execute(
                "INSERT INTO knowledge_fts(record_id,dataset,title,content) VALUES (?,?,?,?)",
                (record["record_id"], record["dataset"], record["title"], record["content"]),
            )
            from .knowledge import _index_chunks
            _index_chunks(db, record)
        db.commit()
    finally:
        db.close()
    return {"records": inserted + updated + duplicates, "inserted": inserted,
            "updated": updated, "duplicates": duplicates}


def ingest_source(kind: str, path: str | Path, *, db_path: str | Path,
                  dataset: str | None = None, source: str | None = None,
                  version: str = "", source_uri: str = "", license: str = "",
                  validation_status: str = "unverified") -> dict[str, Any]:
    if kind not in PARSERS:
        raise ValueError(f"unsupported threat-intel source: {kind}")
    parser = PARSERS[kind]
    records = parser(
        path,
        dataset=dataset or {"nvd": "cve", "cisa-kev": "cisa-kev",
                             "attack-stix": "mitre-attack", "cwe-xml": "cwe", "cpe": "cpe"}[kind],
        source=source or {"nvd": "NVD", "cisa-kev": "CISA KEV",
                          "attack-stix": "MITRE ATT&CK", "cwe-xml": "MITRE CWE", "cpe": "NVD CPE Dictionary"}[kind],
        version=version, source_uri=source_uri, license=license,
        validation_status=validation_status,
    )
    result = ingest_parsed(records, db_path=db_path)
    result.update({"success": True, "source_type": kind, "path": str(path)})
    return result
