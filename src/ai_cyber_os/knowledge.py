"""Evidence-first local knowledge/RAG pipeline for AI-CYBER.

The first implementation deliberately uses SQLite FTS5 from the Python standard
library. It requires no paid API, model, vector service, or network access.
Datasets are ingested as normalized evidence records with provenance and
content hashes. Retrieval is lexical and deterministic; semantic embeddings can
be added later without changing the record contract.
"""
from __future__ import annotations

import csv
import gzip
import hashlib
import io
import json
import re
import sqlite3
import tarfile
import zipfile
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

SCHEMA_VERSION = 4
DEFAULT_DB = Path.home() / ".ai-cyber" / "knowledge.db"
SUPPORTED_SUFFIXES = {".jsonl", ".ndjson", ".json", ".csv", ".txt", ".md", ".xml", ".yaml", ".yml", ".gz", ".zip", ".tgz", ".tar", ".rules", ".zeek"}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS knowledge_records (
    record_id TEXT PRIMARY KEY,
    dataset TEXT NOT NULL,
    source TEXT NOT NULL,
    source_uri TEXT,
    license TEXT,
    validation_status TEXT NOT NULL DEFAULT 'unverified',
    version TEXT,
    title TEXT,
    content TEXT NOT NULL,
    content_sha256 TEXT NOT NULL,
    metadata_json TEXT NOT NULL,
    schema_version INTEGER NOT NULL,
    ingested_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_knowledge_dataset ON knowledge_records(dataset);
CREATE INDEX IF NOT EXISTS idx_knowledge_hash ON knowledge_records(content_sha256);
CREATE TABLE IF NOT EXISTS knowledge_relations (
    record_id TEXT NOT NULL,
    relation_type TEXT NOT NULL,
    target_id TEXT NOT NULL,
    PRIMARY KEY (record_id, relation_type, target_id),
    FOREIGN KEY (record_id) REFERENCES knowledge_records(record_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_knowledge_relations_target
    ON knowledge_relations(relation_type, target_id);
CREATE VIRTUAL TABLE IF NOT EXISTS knowledge_fts USING fts5(
    record_id UNINDEXED,
    dataset UNINDEXED,
    title,
    content,
    tokenize='unicode61'
);
CREATE TABLE IF NOT EXISTS knowledge_chunks (
    chunk_id TEXT PRIMARY KEY,
    record_id TEXT NOT NULL,
    chunk_index INTEGER NOT NULL,
    content TEXT NOT NULL,
    content_sha256 TEXT NOT NULL,
    FOREIGN KEY (record_id) REFERENCES knowledge_records(record_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_knowledge_chunks_record ON knowledge_chunks(record_id, chunk_index);
CREATE VIRTUAL TABLE IF NOT EXISTS knowledge_chunks_fts USING fts5(
    chunk_id UNINDEXED,
    record_id UNINDEXED,
    dataset UNINDEXED,
    title UNINDEXED,
    content,
    tokenize='unicode61'
);
"""


def _extract_relations(text: str) -> list[tuple[str, str]]:
    """Compatibility wrapper around the cross-dataset relationship extractor."""
    from .security_relationships import extract_security_relations

    return extract_security_relations(text)

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()

def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value)

def _hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

CHUNK_SIZE = 4000
CHUNK_OVERLAP = 400

def _chunk_text(text: str, *, size: int = CHUNK_SIZE, overlap: int = CHUNK_OVERLAP) -> list[str]:
    if size <= 0 or overlap < 0 or overlap >= size:
        raise ValueError('invalid chunk parameters')
    if len(text) <= size:
        return [text]
    chunks: list[str] = []
    start = 0
    while start < len(text):
        end = min(len(text), start + size)
        if end < len(text):
            boundary = max(text.rfind('\n', start, end), text.rfind(' ', start, end))
            if boundary > start + size // 2:
                end = boundary
        chunk = text[start:end].strip()
        if chunk:
            chunks.append(chunk)
        if end >= len(text):
            break
        start = max(start + 1, end - overlap)
    return chunks

def _index_chunks(db: sqlite3.Connection, record: dict[str, Any]) -> None:
    db.execute('DELETE FROM knowledge_chunks_fts WHERE record_id=?', (record['record_id'],))
    db.execute('DELETE FROM knowledge_chunks WHERE record_id=?', (record['record_id'],))
    for index, chunk in enumerate(_chunk_text(record['content'])):
        chunk_id = f"{record['record_id']}#chunk-{index}"
        db.execute(
            'INSERT INTO knowledge_chunks(chunk_id,record_id,chunk_index,content,content_sha256) VALUES (?,?,?,?,?)',
            (chunk_id, record['record_id'], index, chunk, _hash(chunk)),
        )
        db.execute(
            'INSERT INTO knowledge_chunks_fts(chunk_id,record_id,dataset,title,content) VALUES (?,?,?,?,?)',
            (chunk_id, record['record_id'], record['dataset'], record['title'], chunk),
        )

def _safe_id(dataset: str, source: str, content: str) -> str:
    return hashlib.sha256(
        (dataset + "\0" + source + "\0" + content).encode("utf-8")
    ).hexdigest()

def open_store(path: str | Path = DEFAULT_DB) -> sqlite3.Connection:
    # A fresh install may not have the hidden application-data directory yet.
    # Create it before SQLite opens the file, otherwise live status/search routes
    # can terminate the HTTP connection with "unable to open database file".
    db_path = Path(path).expanduser()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(str(db_path))
    db.row_factory = sqlite3.Row
    db.executescript(_SCHEMA)
    columns = {row["name"] for row in db.execute("PRAGMA table_info(knowledge_records)")}
    if "source_uri" not in columns:
        db.execute("ALTER TABLE knowledge_records ADD COLUMN source_uri TEXT")
    if "validation_status" not in columns:
        db.execute(
            "ALTER TABLE knowledge_records ADD COLUMN validation_status TEXT NOT NULL DEFAULT 'unverified'"
        )
    missing_chunks = db.execute(
        """SELECT k.record_id, k.dataset, k.title, k.content
           FROM knowledge_records k
           LEFT JOIN knowledge_chunks c ON c.record_id=k.record_id
           WHERE c.record_id IS NULL
           LIMIT 1000"""
    ).fetchall()
    for row in missing_chunks:
        _index_chunks(
            db,
            {
                "record_id": row["record_id"],
                "dataset": row["dataset"],
                "title": row["title"],
                "content": row["content"],
            },
        )
    db.commit()
    return db

def _normalize(raw: Any, *, dataset: str, source: str, license: str = "",
               version: str = "", source_uri: str = "",
               validation_status: str = "unverified") -> dict[str, Any]:
    if isinstance(raw, dict):
        title = _text(raw.get("title") or raw.get("name") or raw.get("msg") or raw.get("id") or raw.get("@id"))
        explicit_content = raw.get("content") or raw.get("text") or raw.get("description")
        content = _text(explicit_content) if explicit_content is not None else _text(raw)
        record_source = _text(raw.get("source") or source)
        record_license = _text(raw.get("license") or license)
        record_version = _text(raw.get("version") or version)
        record_uri = _text(raw.get("source_uri") or source_uri)
        record_validation = _text(raw.get("validation_status") or validation_status)
        metadata = {str(k): v for k, v in raw.items()
                    if k not in {"content", "text", "description", "title", "name"}}
    else:
        title = Path(source).name
        content = _text(raw)
        record_source = source
        record_license = license
        record_version = version
        metadata = {}
        record_uri = source_uri
        record_validation = validation_status
    content = content.strip()
    if not content:
        raise ValueError("record content is empty")
    rid_value = (raw.get("id") or raw.get("@id")) if isinstance(raw, dict) else None
    rid = _text(rid_value) if rid_value else ""
    record_id = rid or _safe_id(dataset, record_source, content)
    return {
        "record_id": record_id,
        "dataset": dataset,
        "source": record_source,
        "source_uri": record_uri,
        "license": record_license,
        "validation_status": record_validation,
        "version": record_version,
        "title": title[:500],
        "content": content,
        "content_sha256": _hash(content),
        "metadata_json": json.dumps(metadata, ensure_ascii=False, sort_keys=True, default=str),
        "schema_version": SCHEMA_VERSION,
        "ingested_at": _now(),
    }

def _iter_json_value(raw: Any) -> Iterable[Any]:
    """Yield logical records from common catalog, STIX, and JSON-LD envelopes."""
    if isinstance(raw, dict):
        for key in ("vulnerabilities", "products", "objects", "rules", "data", "items", "@graph"):
            value = raw.get(key)
            if isinstance(value, list):
                yield from value
                return
    if isinstance(raw, list):
        yield from raw
    else:
        yield raw


def _iter_text_stream(handle: Iterable[str], *, dataset: str, source: str,
                      license: str, version: str, source_uri: str,
                      validation_status: str) -> Iterable[dict[str, Any]]:
    for line in handle:
        if not line.strip():
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError:
            raw = line.rstrip("\n")
        yield _normalize(raw, dataset=dataset, source=source, license=license,
                         version=version, source_uri=source_uri,
                         validation_status=validation_status)


_SURICATA_RULE_ACTION = r"(?:alert|pass|drop|reject|rejectsrc|rejectdst|rejectboth|sdrop|log)"


def _iter_suricata_rule_values(text: str) -> Iterable[dict[str, Any]]:
    """Yield active and explicitly disabled Suricata rule lines, not file text."""
    active_re = re.compile(rf"^\s*(?P<action>{_SURICATA_RULE_ACTION})\s+", re.IGNORECASE)
    disabled_re = re.compile(rf"^\s*#\s*(?P<action>{_SURICATA_RULE_ACTION})\s+", re.IGNORECASE)
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        disabled_match = disabled_re.match(line)
        active_match = active_re.match(line)
        if disabled_match:
            enabled = False
            action = disabled_match.group("action").lower()
        elif active_match:
            enabled = True
            action = active_match.group("action").lower()
        else:
            continue

        sid_match = re.search(r"\bsid\s*:\s*(\d+)\s*;", line, re.IGNORECASE)
        rev_match = re.search(r"\brev\s*:\s*(\d+)\s*;", line, re.IGNORECASE)
        msg_match = re.search(r'\bmsg\s*:\s*"((?:\\.|[^"])*)"', line, re.IGNORECASE)
        yield {
            "content": line,
            "enabled": enabled,
            "action": action,
            "sid": sid_match.group(1) if sid_match else None,
            "rev": rev_match.group(1) if rev_match else None,
            "msg": msg_match.group(1) if msg_match else "",
            "line_number": line_number,
        }


def _local_xml_name(tag: str) -> str:
    return tag.split("}")[-1].split(":")[-1]


def _iter_xml_values(stream: Any, record_elements: set[str] | None = None):
    """Yield XML values, optionally limiting output to logical catalog records.

    With an explicit record element list, only matching entities directly under
    the catalog's plural container (depth 3: root/container/entity) are emitted.
    Nested descriptive/reference elements are retained inside the entity payload
    and are never counted as independent records.
    """
    selected = {_local_xml_name(x) for x in (record_elements or set())}
    if not selected:
        for _, elem in ET.iterparse(stream, events=("end",)):
            if (elem.text and elem.text.strip()) or elem.attrib:
                yield {
                    "tag": elem.tag,
                    "attributes": dict(elem.attrib),
                    "text": (elem.text or "").strip(),
                }
            elem.clear()
        return

    stack = []
    record_depth = None
    for event, elem in ET.iterparse(stream, events=("start", "end")):
        if event == "start":
            stack.append(elem)
            if len(stack) == 3 and _local_xml_name(elem.tag) in selected:
                record_depth = len(stack)
            continue

        depth = len(stack)
        if record_depth is not None:
            if depth == record_depth:
                yield {
                    "tag": _local_xml_name(elem.tag),
                    "attributes": dict(elem.attrib),
                    "xml": ET.tostring(elem, encoding="unicode"),
                }
                elem.clear()
                record_depth = None
        else:
            elem.clear()
        stack.pop()


def iter_records(path: str | Path, *, dataset: str | None = None,
                 source: str | None = None, license: str = "",
                 version: str = "", source_uri: str = "",
                 validation_status: str = "unverified",
                 record_elements: Iterable[str] | None = None,
                 record_extensions: Iterable[str] | None = None,
                 record_format: str | None = None) -> Iterable[dict[str, Any]]:
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(p)
    ds = dataset or p.stem
    src = source or str(p)
    selected_elements = {_local_xml_name(x) for x in (record_elements or ())}
    selected_extensions = {
        str(x).lower() if str(x).startswith(".") else "." + str(x).lower()
        for x in (record_extensions or ())
    }
    format_key = str(record_format or "").strip().lower()
    default_archive_extensions = {
        ".json", ".jsonl", ".ndjson", ".csv", ".txt", ".md",
        ".xml", ".yaml", ".yml", ".rules", ".zeek",
    }

    def normalized(value: Any, item_source: str):
        return _normalize(value, dataset=ds, source=item_source, license=license,
                          version=version, source_uri=source_uri,
                          validation_status=validation_status)

    if p.name.endswith(".tar.gz") or p.suffix.lower() in {".tgz", ".tar"}:
        with tarfile.open(p, "r:*") as archive:
            for member in archive:
                if not member.isfile():
                    continue
                name = Path(member.name)
                suffix = name.suffix.lower()
                allowed = selected_extensions or default_archive_extensions
                if suffix not in allowed:
                    continue
                if "mbc" in format_key and name.name.lower() == "manifest.json":
                    # The repository's acquisition manifest describes the repo; it
                    # is not one of the STIX evidence objects in the data count.
                    continue
                handle = archive.extractfile(member)
                if handle is None:
                    continue
                item_source = f"{src}!{member.name}"
                if suffix == ".json":
                    raw = json.loads(handle.read().decode("utf-8", errors="replace"))
                    for item in _iter_json_value(raw):
                        yield normalized(item, item_source)
                elif suffix in {".jsonl", ".ndjson"}:
                    text = handle.read().decode("utf-8", errors="replace")
                    yield from (
                        normalized_record for normalized_record in
                        _iter_text_stream(io.StringIO(text), dataset=ds, source=item_source,
                                          license=license, version=version,
                                          source_uri=source_uri,
                                          validation_status=validation_status)
                    )
                elif suffix == ".csv":
                    text = handle.read().decode("utf-8-sig", errors="replace")
                    for row in csv.DictReader(io.StringIO(text, newline="")):
                        yield normalized(row, item_source)
                elif suffix == ".xml":
                    for value in _iter_xml_values(io.BytesIO(handle.read()), selected_elements):
                        yield normalized(value, item_source)
                elif suffix in {".yaml", ".yml"} and "sigma" in format_key:
                    text = handle.read().decode("utf-8", errors="replace")
                    import yaml

                    raw = yaml.safe_load(text)
                    if not isinstance(raw, dict):
                        raise ValueError(f"Sigma rule must be a YAML mapping: {member.name}")
                    if not isinstance(raw.get("title"), str) or not raw["title"].strip():
                        raise ValueError(f"Sigma rule has no non-empty title: {member.name}")
                    if not isinstance(raw.get("logsource"), dict):
                        raise ValueError(f"Sigma rule has no logsource mapping: {member.name}")
                    if not isinstance(raw.get("detection"), dict):
                        raise ValueError(f"Sigma rule has no detection mapping: {member.name}")
                    raw = dict(raw)
                    raw["content"] = yaml.safe_dump(raw, sort_keys=True, allow_unicode=True)
                    yield normalized(raw, item_source)
                elif suffix == ".rules" or "suricata" in format_key:
                    text = handle.read().decode("utf-8", errors="replace")
                    for value in _iter_suricata_rule_values(text):
                        yield normalized(value, item_source)
                else:
                    text = handle.read().decode("utf-8", errors="replace")
                    yield normalized(text, item_source)
        return

    if p.suffix.lower() == ".zip":
        with zipfile.ZipFile(p) as archive:
            names = [name for name in archive.namelist() if not name.endswith("/")]
            # If a manifest describes a rule archive, it can select YAML files
            # explicitly so README/version metadata is not counted as a rule.
            for name in names:
                suffix = Path(name).suffix.lower()
                allowed = selected_extensions or default_archive_extensions
                if suffix not in allowed:
                    continue
                raw_bytes = archive.read(name)
                text = raw_bytes.decode("utf-8", errors="replace")
                item_source = f"{src}!{name}"
                if suffix == ".json":
                    raw = json.loads(text)
                    for item in _iter_json_value(raw):
                        yield normalized(item, item_source)
                elif suffix in {".jsonl", ".ndjson"}:
                    yield from _iter_text_stream(io.StringIO(text), dataset=ds,
                                                 source=item_source, license=license,
                                                 version=version, source_uri=source_uri,
                                                 validation_status=validation_status)
                elif suffix == ".csv":
                    for row in csv.DictReader(io.StringIO(text, newline="")):
                        yield normalized(row, item_source)
                elif suffix == ".xml":
                    for value in _iter_xml_values(io.BytesIO(raw_bytes), selected_elements):
                        yield normalized(value, item_source)
                else:
                    yield normalized(text, item_source)
        return

    if p.suffix.lower() == ".gz":
        inner_suffix = Path(p.name[:-3]).suffix.lower()
        if inner_suffix in {".jsonl", ".ndjson"}:
            # Stream large compressed line-oriented feeds (notably CPE shards)
            # instead of decompressing the complete dataset into RAM.
            with gzip.open(p, "rt", encoding="utf-8", errors="replace", newline="") as handle:
                yield from _iter_text_stream(handle, dataset=ds, source=src,
                                             license=license, version=version,
                                             source_uri=source_uri,
                                             validation_status=validation_status)
        elif inner_suffix == ".csv":
            with gzip.open(p, "rt", encoding="utf-8-sig", errors="replace", newline="") as handle:
                for row in csv.DictReader(
                    line for line in handle if not line.lstrip().startswith("#")
                ):
                    yield normalized(row, src)
        else:
            with gzip.open(p, "rb") as fh:
                raw_bytes = fh.read()
            text = raw_bytes.decode("utf-8", errors="replace")
            if inner_suffix == ".json":
                raw = json.loads(text)
                for item in _iter_json_value(raw):
                    yield normalized(item, src)
            elif inner_suffix == ".xml":
                for value in _iter_xml_values(io.BytesIO(raw_bytes), selected_elements):
                    yield normalized(value, src)
            else:
                yield normalized(text, src)
        return

    suffix = p.suffix.lower()
    if suffix not in SUPPORTED_SUFFIXES:
        raise ValueError(f"unsupported dataset format: {suffix}")

    if suffix in {".jsonl", ".ndjson"}:
        with p.open(encoding="utf-8") as handle:
            yield from _iter_text_stream(handle, dataset=ds, source=src, license=license,
                                         version=version, source_uri=source_uri,
                                         validation_status=validation_status)
    elif suffix == ".json":
        raw = json.loads(p.read_text(encoding="utf-8"))
        for item in _iter_json_value(raw):
            yield normalized(item, src)
    elif suffix == ".csv":
        with p.open(newline="", encoding="utf-8-sig") as handle:
            for row in csv.DictReader(handle):
                yield normalized(row, src)
    elif suffix == ".xml":
        for value in _iter_xml_values(p, selected_elements):
            yield normalized(value, src)
    elif suffix == ".rules" or "suricata" in format_key:
        for value in _iter_suricata_rule_values(
            p.read_text(encoding="utf-8", errors="replace")
        ):
            yield normalized(value, src)
    else:
        yield normalized(p.read_text(encoding="utf-8", errors="replace"), src)


def ingest_file(path: str | Path, *, db_path: str | Path = DEFAULT_DB,
                dataset: str | None = None, source: str | None = None,
                license: str = "", version: str = "", source_uri: str = "",
                validation_status: str = "unverified",
                record_elements: Iterable[str] | None = None,
                record_extensions: Iterable[str] | None = None,
                record_format: str | None = None) -> dict[str, Any]:
    records_seen = 0
    inserted = 0
    updated = 0
    duplicates = 0
    db = open_store(db_path)
    try:
        for record in iter_records(
            path,
            dataset=dataset,
            source=source,
            license=license,
            version=version,
            source_uri=source_uri,
            validation_status=validation_status,
            record_elements=record_elements,
            record_extensions=record_extensions,
            record_format=record_format,
        ):
            records_seen += 1
            old = db.execute(
                "SELECT record_id, dataset, content_sha256 FROM knowledge_records WHERE record_id=?",
                (record["record_id"],),
            ).fetchone()
            if old and old["content_sha256"] == record["content_sha256"] and old["dataset"] == record["dataset"]:
                duplicates += 1
                continue
            # A shared identifier such as CVE-... legitimately appears in multiple
            # datasets. Never let one source overwrite another source's evidence.
            if old and old["dataset"] != record["dataset"]:
                base_id = record["record_id"]
                record["metadata_json"] = json.dumps(
                    {
                        **json.loads(record["metadata_json"]),
                        "external_id": base_id,
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                    default=str,
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
                (record_id,dataset,source,source_uri,license,version,validation_status,title,content,content_sha256,
                 metadata_json,schema_version,ingested_at)
                VALUES (:record_id,:dataset,:source,:source_uri,:license,:version,:validation_status,:title,:content,
                        :content_sha256,:metadata_json,:schema_version,:ingested_at)""",
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
            _index_chunks(db, record)
            if records_seen % 1000 == 0:
                db.commit()
        db.commit()
    finally:
        db.close()
    return {
        "success": True,
        "records_seen": records_seen,
        "inserted": inserted,
        "updated": updated,
        "duplicates": duplicates,
        "dataset": dataset or Path(path).stem,
        "validation_status": validation_status or "unverified",
    }

def search(query: str, *, db_path: str | Path = DEFAULT_DB,
           limit: int = 10, dataset: str | None = None) -> list[dict[str, Any]]:
    query = re.sub(r"[^\w\-.: ]+", " ", query, flags=re.UNICODE).strip()
    if not query:
        return []
    # Quote each token so CVE/ATT&CK identifiers remain literal FTS terms.
    fts_query = " AND ".join(
        chr(34) + token.replace(chr(34), " ") + chr(34)
        for token in query.split()
    )
    limit = max(1, min(int(limit), 50))
    db = open_store(db_path)
    try:
        # SQLite FTS5 auxiliary functions such as bm25() must be evaluated
        # directly in the FTS query context. They cannot reliably be wrapped
        # in a GROUP BY/aggregate subquery on all supported SQLite builds.
        # Evaluate one row at a time here, then aggregate chunk scores in Python.
        match_sql = """
            SELECT record_id, bm25(knowledge_chunks_fts) AS score
            FROM knowledge_chunks_fts
            WHERE knowledge_chunks_fts MATCH ?
        """
        matches = db.execute(match_sql, (fts_query,)).fetchall()

        best_scores: dict[str, float] = {}
        for row in matches:
            record_id = row["record_id"]
            score = float(row["score"])
            previous = best_scores.get(record_id)
            if previous is None or score < previous:
                best_scores[record_id] = score

        # FTS5's unicode61 tokenizer splits hyphenated identifiers such as
        # CVE-2026-9999 into multiple tokens. For security identifiers, also
        # perform an exact canonical-ID lookup so namespaced copies from other
        # datasets remain retrievable without weakening normal lexical search.
        exact_ids: list[str] = []
        if re.fullmatch(r"(?i)(?:CVE-\d{4}-[A-Z0-9][A-Z0-9._-]*|CWE-\d+|T\d{4}(?:\.\d{3})?)", query):
            exact_rows = db.execute(
                """SELECT record_id FROM knowledge_records
                   WHERE record_id=? OR record_id LIKE ?
                   ORDER BY record_id""",
                (query.upper(), "%:" + query.upper()),
            ).fetchall()
            exact_ids = [row["record_id"] for row in exact_rows]

        ranked_ids = sorted(
            best_scores,
            key=lambda record_id: (best_scores[record_id], record_id),
        )
        # Exact identifier matches are authoritative and must rank before
        # ordinary FTS matches. They may have no FTS hit because of tokenization.
        ranked_ids = exact_ids + [record_id for record_id in ranked_ids if record_id not in exact_ids]

        if not best_scores and not exact_ids:
            return []
        if dataset is not None:
            allowed = {
                row["record_id"]
                for row in db.execute(
                    "SELECT record_id FROM knowledge_records WHERE dataset=?",
                    (dataset,),
                ).fetchall()
            }
            ranked_ids = [record_id for record_id in ranked_ids if record_id in allowed]

        ranked_ids = ranked_ids[:limit]
        if not ranked_ids:
            return []

        placeholders = ",".join("?" for _ in ranked_ids)
        rows = db.execute(
            f"SELECT * FROM knowledge_records WHERE record_id IN ({placeholders})",
            ranked_ids,
        ).fetchall()
        records = {row["record_id"]: dict(row) for row in rows}
        return [records[record_id] for record_id in ranked_ids if record_id in records]
    finally:
        db.close()
def status(*, db_path: str | Path = DEFAULT_DB) -> dict[str, Any]:
    db = open_store(db_path)
    try:
        total = db.execute("SELECT COUNT(*) FROM knowledge_records").fetchone()[0]
        datasets = db.execute(
            "SELECT dataset, COUNT(*) AS records FROM knowledge_records GROUP BY dataset ORDER BY dataset"
        ).fetchall()
        relations = db.execute("SELECT COUNT(*) FROM knowledge_relations").fetchone()[0]
        return {"ready": True, "records": total, "relations": relations,
                "datasets": [{"dataset": r["dataset"], "records": r["records"]} for r in datasets],
                "schema_version": SCHEMA_VERSION, "db": str(db_path)}
    finally:
        db.close()
