"""Canonical parsers for common cyber-threat intelligence source formats.

These parsers are offline: they consume files already downloaded by the operator.
They never claim that an upstream source is authentic or current. Provenance and
validation state come from the dataset manifest and are preserved in records.
"""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import re
import tarfile
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
    raw = _read_json(path)
    items = raw.get("vulnerabilities", raw.get("CVE_Items", [])) if isinstance(raw, dict) else raw
    if not isinstance(items, list):
        raise ValueError("NVD file does not contain a vulnerability list")
    declared_total = raw.get("totalResults") if isinstance(raw, dict) else None
    if declared_total is not None and declared_total != len(items):
        raise ValueError(
            f"NVD feed totalResults={declared_total} but contains {len(items)} vulnerability records"
        )
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
    raw = _read_json(path)
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
    raw = _read_json(path)
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
    raw = _read_json(p) if p.suffix.lower() == ".json" else None
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


def _read_json(path: str | Path) -> Any:
    """Read JSON/JSON.GZ while rejecting unresolved Git LFS pointer files."""
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(p)

    # Inspect raw bytes first: an unresolved pointer can have a .json/.gz name
    # and must never be treated as a valid dataset even if it looks like text.
    with p.open("rb") as handle:
        prefix = handle.read(512).lstrip()
    if prefix.startswith(b"version https://git-lfs.github.com/spec/v1") or (
        prefix.startswith(b"oid sha256:") and b"size " in prefix
    ):
        raise ValueError(
            f"Git LFS pointer detected instead of dataset content: {p}. "
            "Restore the LFS object and verify its original SHA-256 and size before parsing."
        )

    try:
        if p.name.lower().endswith(".json.gz") or p.suffix.lower() == ".gz":
            with gzip.open(p, "rt", encoding="utf-8") as handle:
                return json.load(handle)
        with p.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except (json.JSONDecodeError, UnicodeDecodeError, OSError) as exc:
        raise ValueError(f"invalid JSON dataset at {p}: {exc}") from exc


def _jsonld_scalar(value: Any) -> str:
    """Extract a useful scalar from a JSON-LD value without discarding the raw node."""
    if isinstance(value, dict):
        for key in ("@value", "@id", "value", "label"):
            if value.get(key) is not None:
                return _jsonld_scalar(value[key])
        return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    if isinstance(value, list):
        return "; ".join(part for part in (_jsonld_scalar(item) for item in value) if part)
    return "" if value is None else str(value)


def _jsonld_field(node: dict[str, Any], names: tuple[str, ...]) -> str:
    for name in names:
        if name in node:
            value = _jsonld_scalar(node[name]).strip()
            if value:
                return value
    for key, value in node.items():
        key_lower = key.lower()
        if any(key_lower.endswith(suffix) for suffix in names if ":" not in suffix):
            scalar = _jsonld_scalar(value).strip()
            if scalar:
                return scalar
    return ""


def parse_d3fend_jsonld(path: str | Path, *, dataset: str = "mitre-d3fend",
                        source: str = "MITRE D3FEND", version: str = "",
                        source_uri: str = "", license: str = "",
                        validation_status: str = "unverified") -> list[dict[str, Any]]:
    """Parse D3FEND JSON-LD as its individual @graph nodes, not one JSON document."""
    raw = _read_json(path)
    nodes = raw.get("@graph") if isinstance(raw, dict) else None
    if not isinstance(nodes, list):
        raise ValueError("D3FEND JSON-LD must contain an @graph list")
    out: list[dict[str, Any]] = []
    for node in nodes:
        if not isinstance(node, dict):
            continue
        node_id = node.get("@id") or node.get("id")
        if not node_id:
            # A graph node without a URI is malformed; do not create a fabricated ID.
            continue
        label = _jsonld_field(node, ("rdfs:label", "skos:prefLabel", "label", "http://www.w3.org/2000/01/rdf-schema#label"))
        description = _jsonld_field(node, ("description", "definition", "comment"))
        payload = {
            "id": str(node_id),
            "name": label or str(node_id),
            "description": description,
            "type": node.get("@type", ""),
            "content": json.dumps(node, ensure_ascii=False, sort_keys=True, default=str),
        }
        out.append(_normalize(payload, dataset=dataset, source=source, version=version,
                              source_uri=source_uri, license=license,
                              validation_status=validation_status))
    return out


def parse_mbc_stix(path: str | Path, *, dataset: str = "mitre-mbc",
                   source: str = "MITRE Malware Behavior Catalog", version: str = "",
                   source_uri: str = "", license: str = "",
                   validation_status: str = "unverified") -> list[dict[str, Any]]:
    """Parse actual STIX objects in one bundle, a directory, or a repository tarball.

    Bundle-file count and contained STIX-object count are intentionally different.
    Tar archives are streamed by member; they are never extracted to disk.
    """
    root = Path(path)
    if not root.exists():
        raise FileNotFoundError(root)

    archive_input = root.is_file() and (
        root.name.lower().endswith(".tar.gz") or root.suffix.lower() in {".tar", ".tgz"}
    )
    if root.is_dir():
        files = sorted(p for p in root.rglob("*.json") if p.is_file())
    elif root.is_file() and not archive_input:
        files = [root]
    else:
        files = []

    out: list[dict[str, Any]] = []
    seen_objects: dict[str, str] = {}

    def append_document(raw: Any, bundle_file: str) -> None:
        if isinstance(raw, dict) and isinstance(raw.get("objects"), list):
            objects = raw["objects"]
        elif isinstance(raw, list):
            objects = raw
        elif isinstance(raw, dict) and raw.get("type") and raw.get("id") and raw.get("type") != "bundle":
            objects = [raw]
        else:
            # Catalog manifests and metadata JSON files are not STIX objects.
            return

        for obj in objects:
            if not isinstance(obj, dict) or not obj.get("type") or not obj.get("id"):
                continue
            object_text = json.dumps(obj, ensure_ascii=False, sort_keys=True, default=str)
            stix_id = str(obj["id"])
            previous = seen_objects.get(stix_id)
            if previous is not None:
                if previous != object_text:
                    raise ValueError(
                        f"Conflicting STIX payloads share ID {stix_id!r}; "
                        "refusing to silently discard a different object version."
                    )
                # MBC's source archive includes the catalog bundle and per-object
                # JSON files. Count each distinct STIX ID once, while the readiness
                # report records bundle-file count separately.
                continue
            seen_objects[stix_id] = object_text
            record = {
                "id": str(obj["id"]),
                "stix_id": str(obj["id"]),
                "type": str(obj["type"]),
                "name": obj.get("name") or str(obj["id"]),
                "description": obj.get("description", ""),
                "bundle_file": bundle_file,
                "content": object_text,
            }
            out.append(_normalize(record, dataset=dataset, source=source, version=version,
                                  source_uri=source_uri, license=license,
                                  validation_status=validation_status))

    for file_path in files:
        raw = _read_json(file_path)
        try:
            bundle_file = str(file_path.relative_to(root)) if root.is_dir() else file_path.name
        except ValueError:
            bundle_file = file_path.name
        append_document(raw, bundle_file)

    if archive_input:
        with tarfile.open(root, "r:*") as archive:
            for member in sorted(archive.getmembers(), key=lambda entry: entry.name):
                if not member.isfile() or Path(member.name).suffix.lower() != ".json":
                    continue
                handle = archive.extractfile(member)
                if handle is None:
                    continue
                raw_bytes = handle.read()
                if raw_bytes.lstrip().startswith(b"version https://git-lfs.github.com/spec/v1"):
                    raise ValueError(
                        f"Git LFS pointer detected inside MBC archive member {member.name}"
                    )
                try:
                    raw = json.loads(raw_bytes.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise ValueError(f"Invalid JSON in MBC archive member {member.name}: {exc}") from exc
                append_document(raw, member.name)

    return out


_SURICATA_ACTIONS = {
    "alert", "pass", "drop", "reject", "rejectsrc", "rejectdst",
    "rejectboth", "rejectpkt", "log", "activate", "dynamic", "bypass",
}


def parse_suricata_rules(path: str | Path, *, dataset: str = "suricata-rules",
                         source: str = "Suricata rules", version: str = "",
                         source_uri: str = "", license: str = "",
                         validation_status: str = "unverified") -> list[dict[str, Any]]:
    """Classify active and commented-out rules in files/directories/tar archives.

    Ordinary comments are ignored. Compressed archives are read member-by-member
    and are never extracted to the filesystem.
    """
    root = Path(path)
    if not root.exists():
        raise FileNotFoundError(root)

    archive_input = root.is_file() and (
        root.name.lower().endswith(".tar.gz") or root.suffix.lower() in {".tar", ".tgz"}
    )
    if root.is_dir():
        files = sorted(p for p in root.rglob("*.rules") if p.is_file())
    elif root.is_file() and not archive_input and root.suffix.lower() == ".rules":
        files = [root]
    else:
        files = []

    action_text = "|".join(sorted(_SURICATA_ACTIONS, key=len, reverse=True))
    active_re = re.compile(r"^\s*(" + action_text + r")\s+\S+\s+(?=.*\()")
    disabled_re = re.compile(r"^\s*#\s*(" + action_text + r")\s+\S+\s+(?=.*\()")
    out: list[dict[str, Any]] = []

    def consume_lines(lines: Iterable[str], file_label: str) -> None:
        for line_number, line in enumerate(lines, 1):
            original = line.rstrip("\r\n")
            if not original.strip():
                continue
            disabled_match = disabled_re.match(original)
            active_match = active_re.match(original)
            if disabled_match:
                state, action = "disabled", disabled_match.group(1).lower()
                rule = re.sub(r"^\s*#\s*", "", original, count=1).strip()
            elif active_match:
                state, action, rule = "active", active_match.group(1).lower(), original.strip()
            else:
                continue
            stable_key = f"{state}\0{file_label}\0{line_number}\0{rule}"
            digest = hashlib.sha256(stable_key.encode("utf-8")).hexdigest()
            payload = {
                "id": f"suricata:{state}:{digest}",
                "name": f"{state.title()} Suricata {action} rule",
                "action": action,
                "status": state,
                "rule": rule,
                "file": file_label,
                "line_number": line_number,
                "content": rule,
            }
            out.append(_normalize(payload, dataset=dataset, source=source, version=version,
                                  source_uri=source_uri, license=license,
                                  validation_status=validation_status))

    for file_path in files:
        try:
            file_label = str(file_path.relative_to(root)) if root.is_dir() else file_path.name
        except ValueError:
            file_label = file_path.name
        with file_path.open("r", encoding="utf-8", errors="replace") as handle:
            consume_lines(handle, file_label)

    if archive_input:
        with tarfile.open(root, "r:*") as archive:
            for member in sorted(archive.getmembers(), key=lambda entry: entry.name):
                if not member.isfile() or Path(member.name).suffix.lower() != ".rules":
                    continue
                handle = archive.extractfile(member)
                if handle is None:
                    continue
                text = handle.read().decode("utf-8", errors="replace")
                consume_lines(io.StringIO(text), member.name)

    return out

PARSERS = {
    "nvd": parse_nvd,
    "cisa-kev": parse_cisa_kev,
    "attack-stix": parse_attack_stix,
    "cwe-xml": parse_cwe_xml,
    "cpe": parse_cpe,
    "d3fend-jsonld": parse_d3fend_jsonld,
    "mbc-stix": parse_mbc_stix,
    "suricata-rules": parse_suricata_rules,
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
        dataset=dataset or {
            "nvd": "cve", "cisa-kev": "cisa-kev", "attack-stix": "mitre-attack",
            "cwe-xml": "cwe", "cpe": "cpe", "d3fend-jsonld": "mitre-d3fend",
            "mbc-stix": "mitre-mbc", "suricata-rules": "suricata-rules",
        }[kind],
        source=source or {
            "nvd": "NVD", "cisa-kev": "CISA KEV", "attack-stix": "MITRE ATT&CK",
            "cwe-xml": "MITRE CWE", "cpe": "NVD CPE Dictionary",
            "d3fend-jsonld": "MITRE D3FEND", "mbc-stix": "MITRE MBC",
            "suricata-rules": "Suricata rules",
        }[kind],
        version=version, source_uri=source_uri, license=license,
        validation_status=validation_status,
    )
    result = ingest_parsed(records, db_path=db_path)
    result.update({"success": True, "source_type": kind, "path": str(path)})
    return result
