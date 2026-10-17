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
import zipfile
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


def _read_nvd_array_header(handle: Any) -> tuple[str, int | None, str]:
    """Read only the JSON header before the top-level NVD vulnerability array."""
    buffer = ""
    array_pattern = re.compile(r'"(vulnerabilities|CVE_Items)"\s*:\s*\[')
    while True:
        match = array_pattern.search(buffer)
        if match:
            header = buffer[:match.start()]
            declared_match = re.search(r'"totalResults"\s*:\s*(\d+)', header)
            declared_total = int(declared_match.group(1)) if declared_match else None
            # Some older exports and fixtures omit totalResults. Validate it
            # strictly whenever supplied; the official bulk-feed runner separately
            # authenticates every artifact against NVD's .meta checksum and size.
            return match.group(1), declared_total, buffer[match.end():]
        chunk = handle.read(64 * 1024)
        if not chunk:
            raise ValueError("NVD JSON does not contain a vulnerabilities or CVE_Items array")
        buffer += chunk
        if len(buffer) > 8 * 1024 * 1024:
            raise ValueError("NVD JSON header exceeds 8 MiB without a top-level CVE array")


def _iter_json_array_items(handle: Any, initial_buffer: str) -> Iterable[Any]:
    """Stream one JSON array item at a time with bounded input buffering."""
    decoder = json.JSONDecoder()
    buffer = initial_buffer
    while True:
        buffer = buffer.lstrip()
        if not buffer:
            chunk = handle.read(64 * 1024)
            if not chunk:
                raise ValueError("unexpected EOF inside NVD vulnerability array")
            buffer = chunk
            continue

        if buffer.startswith(","):
            buffer = buffer[1:]
            continue

        if buffer.startswith("]"):
            tail = buffer[1:] + handle.read()
            # NVD's CVE array is the final top-level value in both known feed
            # formats; only the object closing brace and whitespace may follow.
            if not re.fullmatch(r"\s*}\s*", tail):
                raise ValueError("unexpected trailing bytes after NVD CVE array")
            return

        try:
            item, consumed = decoder.raw_decode(buffer)
        except json.JSONDecodeError as exc:
            chunk = handle.read(64 * 1024)
            if not chunk:
                raise ValueError(f"invalid or truncated JSON item in NVD feed: {exc}") from exc
            buffer += chunk
            continue

        yield item
        buffer = buffer[consumed:]


def _nvd_record(
    item: Any,
    *,
    dataset: str,
    source: str,
    version: str,
    source_uri: str,
    license: str,
    validation_status: str,
) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise ValueError("NVD vulnerability array contains a non-object item")
    cve = item.get("cve", item)
    if not isinstance(cve, dict):
        raise ValueError("NVD vulnerability item does not contain a CVE object")
    cve_id = cve.get("id")
    if not cve_id:
        cve_id = cve.get("CVE_data_meta", {}).get("ID")
    if not cve_id:
        raise ValueError("NVD vulnerability item is missing its CVE identifier")
    descriptions = cve.get("descriptions", [])
    desc = next(
        (x.get("value") for x in descriptions if isinstance(x, dict) and x.get("lang") == "en"),
        None,
    )
    if desc is None:
        desc = next(
            (x.get("value") for x in descriptions if isinstance(x, dict)),
            cve.get("description", {}).get("description_data", [{}])[0].get("value", "")
            if isinstance(cve.get("description"), dict) else "",
        )
    content = {
        "id": cve_id,
        "description": desc or "",
        "source_identifier": cve.get("sourceIdentifier"),
        "published": cve.get("published") or cve.get("publishedDate"),
        "last_modified": cve.get("lastModified") or cve.get("lastModifiedDate"),
        "references": cve.get("references", []),
        "metrics": cve.get("metrics", {}),
        "weaknesses": cve.get("weaknesses", []),
        "configurations": cve.get("configurations", []),
    }
    content["content"] = json.dumps(content, ensure_ascii=False, sort_keys=True, default=str)
    return _normalize(
        content,
        dataset=dataset,
        source=source,
        version=version,
        source_uri=source_uri,
        license=license,
        validation_status=validation_status,
    )


def iter_parse_nvd(
    path: str | Path,
    *,
    dataset: str = "cve",
    source: str = "NVD",
    version: str = "",
    source_uri: str = "",
    license: str = "",
    validation_status: str = "unverified",
) -> Iterable[dict[str, Any]]:
    """Stream NVD 1.x/2.x CVE records; do not materialize an entire feed in RAM."""
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(p)
    with p.open("rb") as prefix_handle:
        prefix = prefix_handle.read(256).lstrip()
    if prefix.startswith(b"version https://git-lfs.github.com/spec/v1"):
        raise ValueError(
            f"Git LFS pointer detected instead of dataset content: {p}. "
            "Restore the LFS object and verify its original SHA-256 and size before parsing."
        )

    opener = gzip.open if p.name.lower().endswith(".gz") else open
    with opener(p, "rt", encoding="utf-8") as handle:
        array_key, declared_total, buffer = _read_nvd_array_header(handle)
        array_count = 0
        record_count = 0
        for item in _iter_json_array_items(handle, buffer):
            array_count += 1
            record = _nvd_record(
                item,
                dataset=dataset,
                source=source,
                version=version,
                source_uri=source_uri,
                license=license,
                validation_status=validation_status,
            )
            record_count += 1
            yield record

        if declared_total is not None and declared_total != array_count:
            raise ValueError(
                f"NVD feed totalResults={declared_total} but contains {array_count} "
                f"items in the {array_key} array"
            )
        if record_count != array_count:
            raise ValueError(
                f"NVD feed parser produced {record_count} records from {array_count} array items"
            )


def parse_nvd(
    path: str | Path,
    *,
    dataset: str = "cve",
    source: str = "NVD",
    version: str = "",
    source_uri: str = "",
    license: str = "",
    validation_status: str = "unverified",
) -> list[dict[str, Any]]:
    """Compatibility wrapper returning a list; batch ingestion should use iter_parse_nvd."""
    return list(iter_parse_nvd(
        path,
        dataset=dataset,
        source=source,
        version=version,
        source_uri=source_uri,
        license=license,
        validation_status=validation_status,
    ))


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



def iter_parse_attack_bundle(
    path: str | Path,
    *,
    dataset: str = "mitre_attack",
    source: str = "MITRE ATT&CK STIX 2.1",
    version: str = "",
    source_uri: str = "",
    license: str = "",
    validation_status: str = "unverified",
) -> Iterable[dict[str, Any]]:
    """Normalize every STIX bundle object and index its external ATT&CK IDs.

    Full source attributes remain in metadata_json. Searchable content also
    contains a compact list of external IDs, names, aliases and relationship
    endpoints so techniques such as T1059.001 are retrievable by canonical ID.
    """
    raw = _read_json(path)
    objects = raw.get("objects", []) if isinstance(raw, dict) else raw
    if not isinstance(objects, list):
        raise ValueError("ATT&CK STIX file does not contain an objects list")
    for index, obj in enumerate(objects):
        if not isinstance(obj, dict):
            raise ValueError(f"ATT&CK STIX object at index {index} is not a JSON object")
        stix_id = str(obj.get("id") or "").strip()
        if not stix_id:
            raise ValueError(f"ATT&CK STIX object at index {index} is missing its id")

        external_ids: list[str] = []
        references = obj.get("external_references", [])
        if references is not None and not isinstance(references, list):
            raise ValueError(f"ATT&CK external_references is not a list for {stix_id}")
        for reference in references or []:
            if not isinstance(reference, dict):
                continue
            external_id = reference.get("external_id")
            if isinstance(external_id, str) and external_id.strip():
                external_ids.append(external_id.strip())
        external_ids = sorted(set(external_ids))
        name = str(obj.get("name") or "").strip()
        description = str(obj.get("description") or "").strip()
        aliases = obj.get("aliases", [])
        if not isinstance(aliases, list):
            aliases = []
        relationship_parts = []
        if obj.get("relationship_type"):
            relationship_parts.append(f"Relationship type: {obj['relationship_type']}")
        if obj.get("source_ref"):
            relationship_parts.append(f"Source object: {obj['source_ref']}")
        if obj.get("target_ref"):
            relationship_parts.append(f"Target object: {obj['target_ref']}")

        searchable = [
            f"STIX ID: {stix_id}",
            f"Object type: {obj.get('type', '')}",
            f"Name: {name}" if name else "",
            f"Description: {description}" if description else "",
            f"External IDs: {' '.join(external_ids)}" if external_ids else "",
            f"Aliases: {' '.join(str(alias) for alias in aliases)}" if aliases else "",
            *relationship_parts,
        ]
        raw_record = dict(obj)
        raw_record["title"] = name or (external_ids[0] if external_ids else stix_id)
        raw_record["content"] = "\n".join(part for part in searchable if part)
        raw_record["external_ids"] = external_ids
        yield _normalize(
            raw_record,
            dataset=dataset,
            source=source,
            version=version,
            source_uri=source_uri,
            license=license,
            validation_status=validation_status,
        )


def parse_attack_stix_bundle(
    path: str | Path,
    *,
    dataset: str = "mitre_attack",
    source: str = "MITRE ATT&CK STIX 2.1",
    version: str = "",
    source_uri: str = "",
    license: str = "",
    validation_status: str = "unverified",
) -> list[dict[str, Any]]:
    """Compatibility wrapper for callers requiring a list of all STIX objects."""
    return list(iter_parse_attack_bundle(
        path, dataset=dataset, source=source, version=version,
        source_uri=source_uri, license=license,
        validation_status=validation_status,
    ))

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


def _iter_cwe_xml_stream(
    handle: Any,
    *,
    dataset: str,
    source: str,
    version: str,
    source_uri: str,
    license: str,
    validation_status: str,
) -> Iterable[dict[str, Any]]:
    """Stream logical CWE catalog entries while preserving each complete entry."""
    selected = {"Weakness", "Category", "View"}
    stack: list[Any] = []
    record_depth: int | None = None
    for event, elem in ET.iterparse(handle, events=("start", "end")):
        tag = elem.tag.rsplit("}", 1)[-1]
        if event == "start":
            stack.append(elem)
            if len(stack) == 3 and tag in selected:
                record_depth = len(stack)
            continue

        depth = len(stack)
        if record_depth is not None and depth == record_depth:
            element_type = tag
            catalog_id = str(elem.attrib.get("ID") or elem.attrib.get("Id") or "").strip()
            if not catalog_id:
                raise ValueError(f"CWE {element_type} catalog entry is missing ID")

            if element_type == "Weakness":
                record_id = f"CWE-{catalog_id}"
            else:
                record_id = f"cwe-{element_type.casefold()}-{catalog_id}"

            name = " ".join(str(elem.attrib.get("Name") or "").split())
            descriptions: list[str] = []
            for child in list(elem):
                child_name = child.tag.rsplit("}", 1)[-1]
                if child_name == "Name" and not name:
                    name = " ".join("".join(child.itertext()).split())
                elif child_name in {
                    "Description", "Summary", "Extended_Description", "ExtendedDescription",
                }:
                    value = " ".join("".join(child.itertext()).split())
                    if value:
                        descriptions.append(value)

            xml_text = ET.tostring(elem, encoding="unicode")
            evidence = {
                "id": record_id,
                "catalog_id": catalog_id,
                "catalog_element": element_type,
                "name": name,
                "descriptions": descriptions,
                "xml": xml_text,
            }
            raw = {
                "id": record_id,
                "title": f"{record_id}: {name}".strip().rstrip(":"),
                "content": json.dumps(evidence, ensure_ascii=False, sort_keys=True),
                "catalog_id": catalog_id,
                "catalog_element": element_type,
                "name": name,
                "descriptions": descriptions,
            }
            yield _normalize(
                raw,
                dataset=dataset,
                source=source,
                version=version,
                source_uri=source_uri,
                license=license,
                validation_status=validation_status,
            )
            elem.clear()
            record_depth = None
        elif record_depth is None:
            # Keep descendants intact inside an active catalog record; clearing
            # them early would erase Name/Description before the parent is read.
            elem.clear()
        stack.pop()


def iter_parse_cwe_xml(
    path: str | Path,
    *,
    dataset: str = "cwe",
    source: str = "MITRE CWE",
    version: str = "",
    source_uri: str = "",
    license: str = "",
    validation_status: str = "unverified",
) -> Iterable[dict[str, Any]]:
    """Stream Weakness, Category and View records from CWE XML or a ZIP catalog."""
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(p)
    with p.open("rb") as handle:
        prefix = handle.read(256).lstrip()
    if prefix.startswith(b"version https://git-lfs.github.com/spec/v1"):
        raise ValueError(
            f"Git LFS pointer detected instead of dataset content: {p}. "
            "Restore the LFS object and verify its original SHA-256 and size before parsing."
        )

    common = {
        "dataset": dataset,
        "source": source,
        "version": version,
        "source_uri": source_uri,
        "license": license,
        "validation_status": validation_status,
    }
    if p.suffix.casefold() == ".zip":
        with zipfile.ZipFile(p) as archive:
            members = sorted(
                name for name in archive.namelist()
                if not name.endswith("/") and name.casefold().endswith(".xml")
            )
            preferred = [name for name in members if "cwec_" in Path(name).name.casefold()]
            if preferred:
                members = preferred
            if len(members) != 1:
                raise ValueError(
                    f"CWE ZIP must resolve to exactly one XML catalog; found {len(members)}"
                )
            with archive.open(members[0], "r") as handle:
                yield from _iter_cwe_xml_stream(handle, **common)
        return

    if p.suffix.casefold() != ".xml":
        raise ValueError(f"unsupported CWE catalog format: {p.suffix}")
    with p.open("rb") as handle:
        yield from _iter_cwe_xml_stream(handle, **common)


def parse_cwe_xml(
    path: str | Path,
    *,
    dataset: str = "cwe",
    source: str = "MITRE CWE",
    version: str = "",
    source_uri: str = "",
    license: str = "",
    validation_status: str = "unverified",
) -> list[dict[str, Any]]:
    """Compatibility wrapper returning the streaming parser's records as a list."""
    return list(iter_parse_cwe_xml(
        path,
        dataset=dataset,
        source=source,
        version=version,
        source_uri=source_uri,
        license=license,
        validation_status=validation_status,
    ))


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



def iter_parse_sigma_rules(
    path: str | Path,
    *,
    dataset: str = "sigma",
    source: str = "SigmaHQ Sigma rules",
    version: str = "",
    source_uri: str = "",
    license: str = "",
    validation_status: str = "unverified",
) -> Iterable[dict[str, Any]]:
    """Parse Sigma YAML rules from a ZIP archive into searchable structured records."""
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(p)
    if p.suffix.casefold() != ".zip":
        raise ValueError(f"Sigma rule archive must be ZIP: {p}")
    with zipfile.ZipFile(p) as archive:
        names = sorted(
            name for name in archive.namelist()
            if not name.endswith("/")
            and Path(name).suffix.casefold() in {".yml", ".yaml"}
        )
        if not names:
            raise ValueError(f"Sigma ZIP contains no YAML rules: {p}")
        try:
            import yaml
        except ImportError as exc:
            raise RuntimeError(
                "Sigma YAML ingestion requires PyYAML; install the project dependencies first"
            ) from exc

        for name in names:
            raw_bytes = archive.read(name)
            try:
                rule = yaml.safe_load(raw_bytes.decode("utf-8-sig"))
            except Exception as exc:
                raise ValueError(f"invalid Sigma YAML rule {name}: {exc}") from exc
            if not isinstance(rule, dict):
                raise ValueError(f"Sigma YAML rule must be a mapping: {name}")
            rule_id = str(rule.get("id") or "").strip()
            title = str(rule.get("title") or "").strip()
            if not rule_id or not title:
                raise ValueError(f"Sigma rule must declare both id and title: {name}")
            content = json.dumps(rule, ensure_ascii=False, sort_keys=True, default=str)
            normalized = {
                "id": rule_id,
                "title": title,
                "content": content,
                "description": rule.get("description", ""),
                "status": rule.get("status", ""),
                "author": rule.get("author", ""),
                "date": rule.get("date", ""),
                "modified": rule.get("modified", ""),
                "tags": rule.get("tags", []),
                "references": rule.get("references", []),
                "logsource": rule.get("logsource", {}),
                "detection": rule.get("detection", {}),
                "sigma_file": name,
            }
            yield _normalize(
                normalized,
                dataset=dataset,
                source=f"{source}!{name}",
                version=version,
                source_uri=source_uri,
                license=license,
                validation_status=validation_status,
            )


def parse_sigma_rules(
    path: str | Path,
    *,
    dataset: str = "sigma",
    source: str = "SigmaHQ Sigma rules",
    version: str = "",
    source_uri: str = "",
    license: str = "",
    validation_status: str = "unverified",
) -> list[dict[str, Any]]:
    """Compatibility wrapper returning Sigma rule records as a list."""
    return list(iter_parse_sigma_rules(
        path, dataset=dataset, source=source, version=version,
        source_uri=source_uri, license=license,
        validation_status=validation_status,
    ))

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
    "attack-stix-bundle": parse_attack_stix_bundle,
    "cwe-xml": parse_cwe_xml,
    "cpe": parse_cpe,
    "d3fend-jsonld": parse_d3fend_jsonld,
    "mbc-stix": parse_mbc_stix,
    "suricata-rules": parse_suricata_rules,
}

def ingest_parsed(records: Iterable[dict[str, Any]], *, db_path: str | Path) -> dict[str, int]:
    """Persist parser output using the same evidence contract as normal ingestion."""
    from .knowledge import _extract_relations, open_store
    # open_store creates the parent directory, schema, FTS indexes and metadata.
    db = open_store(db_path)
    inserted = updated = duplicates = processed_records = 0
    try:
        for record in records:
            processed_records += 1
            old = db.execute(
                "SELECT record_id, dataset, content_sha256 FROM knowledge_records WHERE record_id=?",
                (record["record_id"],),
            ).fetchone()
            if old and old["content_sha256"] == record["content_sha256"] and old["dataset"] == record["dataset"]:
                duplicates += 1
                if processed_records % 1000 == 0:
                    db.commit()
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
                    if processed_records % 1000 == 0:
                        db.commit()
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
            # This parser path can revisit the same CVE across yearly, recent and
            # modified NVD feeds. When an existing record changes, reindex its
            # chunks atomically with the latest content rather than leaving stale
            # chunks from the previous description in the FTS index.
            _index_chunks(db, record, replace_existing=bool(old))
            if processed_records % 1000 == 0:
                db.commit()
        db.commit()
    finally:
        db.close()
    return {"records": inserted + updated + duplicates, "processed_records": processed_records,
            "inserted": inserted, "updated": updated, "duplicates": duplicates}


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
