"""Evidence-first local knowledge/RAG pipeline for AI-CYBER.

The first implementation deliberately uses SQLite FTS5 from the Python standard
library. It requires no paid API, model, vector service, or network access.
Datasets are ingested as normalized evidence records with provenance and
content hashes. Retrieval is lexical and deterministic; semantic embeddings can
be added later without changing the record contract.
"""
from __future__ import annotations

import csv
import hashlib
import json
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

SCHEMA_VERSION = 2
DEFAULT_DB = Path.home() / ".ai-cyber" / "knowledge.db"
SUPPORTED_SUFFIXES = {".jsonl", ".ndjson", ".json", ".csv", ".txt", ".md"}

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
CREATE VIRTUAL TABLE IF NOT EXISTS knowledge_fts USING fts5(
    record_id UNINDEXED,
    dataset UNINDEXED,
    title,
    content,
    tokenize='unicode61'
);
"""

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

def _safe_id(dataset: str, source: str, content: str) -> str:
    return hashlib.sha256(
        (dataset + "\0" + source + "\0" + content).encode("utf-8")
    ).hexdigest()

def open_store(path: str | Path = DEFAULT_DB) -> sqlite3.Connection:
    db = sqlite3.connect(str(path))
    db.row_factory = sqlite3.Row
    db.executescript(_SCHEMA)
    columns = {row["name"] for row in db.execute("PRAGMA table_info(knowledge_records)")}
    if "source_uri" not in columns:
        db.execute("ALTER TABLE knowledge_records ADD COLUMN source_uri TEXT")
    if "validation_status" not in columns:
        db.execute(
            "ALTER TABLE knowledge_records ADD COLUMN validation_status TEXT NOT NULL DEFAULT 'unverified'"
        )
    db.commit()
    return db

def _normalize(raw: Any, *, dataset: str, source: str, license: str = "",
               version: str = "", source_uri: str = "",
               validation_status: str = "unverified") -> dict[str, Any]:
    if isinstance(raw, dict):
        title = _text(raw.get("title") or raw.get("name") or raw.get("id"))
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
    rid = _text(raw.get("id")) if isinstance(raw, dict) and raw.get("id") else ""
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

def iter_records(path: str | Path, *, dataset: str | None = None,
                 source: str | None = None, license: str = "",
                 version: str = "", source_uri: str = "",
                 validation_status: str = "unverified") -> Iterable[dict[str, Any]]:
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(p)
    if p.suffix.lower() not in SUPPORTED_SUFFIXES:
        raise ValueError(f"unsupported dataset format: {p.suffix}")
    ds = dataset or p.stem
    src = source or str(p)
    suffix = p.suffix.lower()
    if suffix in {".jsonl", ".ndjson"}:
        with p.open(encoding="utf-8") as handle:
            for line_no, line in enumerate(handle, 1):
                if not line.strip():
                    continue
                try:
                    raw = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"invalid JSON on line {line_no}: {exc}") from exc
                yield _normalize(raw, dataset=ds, source=src, license=license, version=version, source_uri=source_uri, validation_status=validation_status)
    elif suffix == ".json":
        raw = json.loads(p.read_text(encoding="utf-8"))
        items = raw if isinstance(raw, list) else [raw]
        for item in items:
            yield _normalize(item, dataset=ds, source=src, license=license, version=version, source_uri=source_uri, validation_status=validation_status)
    elif suffix == ".csv":
        with p.open(encoding="utf-8", newline="") as handle:
            for row in csv.DictReader(handle):
                yield _normalize(row, dataset=ds, source=src, license=license, version=version, source_uri=source_uri, validation_status=validation_status)
    else:
        yield _normalize(p.read_text(encoding="utf-8"), dataset=ds, source=src, license=license, version=version, source_uri=source_uri, validation_status=validation_status)

def ingest_file(path: str | Path, *, db_path: str | Path = DEFAULT_DB,
                dataset: str | None = None, source: str | None = None,
                license: str = "", version: str = "", source_uri: str = "",
                validation_status: str = "") -> dict[str, Any]:
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
        ):
            records_seen += 1
            old = db.execute(
                "SELECT record_id, content_sha256 FROM knowledge_records WHERE record_id=?",
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
            db.execute(
                "INSERT INTO knowledge_fts(record_id,dataset,title,content) VALUES (?,?,?,?)",
                (record["record_id"], record["dataset"], record["title"], record["content"]),
            )
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
    fts_query = " AND ".join(chr(34) + token.replace(chr(34), " ") + chr(34)
                             for token in query.split())
    limit = max(1, min(int(limit), 50))
    db = open_store(db_path)
    try:
        if dataset:
            rows = db.execute(
                """SELECT k.*, bm25(knowledge_fts) AS score
                   FROM knowledge_fts f JOIN knowledge_records k ON k.record_id=f.record_id
                   WHERE knowledge_fts MATCH ? AND k.dataset=?
                   ORDER BY score LIMIT ?""",
                (fts_query, dataset, limit),
            ).fetchall()
        else:
            rows = db.execute(
                """SELECT k.*, bm25(knowledge_fts) AS score
                   FROM knowledge_fts f JOIN knowledge_records k ON k.record_id=f.record_id
                   WHERE knowledge_fts MATCH ?
                   ORDER BY score LIMIT ?""",
                (fts_query, limit),
            ).fetchall()
        return [dict(row) for row in rows]
    finally:
        db.close()

def status(*, db_path: str | Path = DEFAULT_DB) -> dict[str, Any]:
    db = open_store(db_path)
    try:
        total = db.execute("SELECT COUNT(*) FROM knowledge_records").fetchone()[0]
        datasets = db.execute(
            "SELECT dataset, COUNT(*) AS records FROM knowledge_records GROUP BY dataset ORDER BY dataset"
        ).fetchall()
        return {"ready": True, "records": total,
                "datasets": [{"dataset": r["dataset"], "records": r["records"]} for r in datasets],
                "schema_version": SCHEMA_VERSION, "db": str(db_path)}
    finally:
        db.close()
