"""Local-first cyber knowledge ingestion and RAG-ready lexical retrieval.

This module intentionally stays provider-free: SQLite FTS5 is the deterministic
retrieval primitive, while returned evidence packets are suitable for a later
generation layer. No method claims that retrieved text is true merely because
it was indexed.
"""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

_TOKEN_RE = re.compile(r"[\w]+", re.UNICODE)
_DEFAULT_MAX_CONTEXT_CHARS = 12_000
_MAX_QUERY_TOKENS = 32
_MAX_TOKEN_LENGTH = 128


class KnowledgeStore:
    """Persistent knowledge index backed by SQLite + FTS5."""

    SCHEMA_VERSION = "knowledge.v2"

    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init()

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.db_path, timeout=10)
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA busy_timeout=5000")
        return db

    @staticmethod
    def _table_columns(db: sqlite3.Connection, table: str) -> set[str]:
        return {row[1] for row in db.execute(f"PRAGMA table_info({table})")}

    def _init(self) -> None:
        with self._connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS knowledge_documents(
                    doc_id TEXT PRIMARY KEY,
                    dataset_id TEXT NOT NULL,
                    artifact_path TEXT NOT NULL,
                    record_id TEXT NOT NULL,
                    source TEXT,
                    version TEXT,
                    payload_json TEXT NOT NULL,
                    content_hash TEXT,
                    ingested_at TEXT NOT NULL DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS knowledge_meta(
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                """
            )

            columns = self._table_columns(db, "knowledge_documents")
            if "content_hash" not in columns:
                db.execute("ALTER TABLE knowledge_documents ADD COLUMN content_hash TEXT")
            if "ingested_at" not in columns:
                db.execute(
                    "ALTER TABLE knowledge_documents ADD COLUMN ingested_at TEXT NOT NULL DEFAULT ''"
                )

            fts_exists = bool(
                db.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='knowledge_fts'"
                ).fetchone()
            )
            if fts_exists:
                fts_columns = self._table_columns(db, "knowledge_fts")
                if not {"doc_id", "content", "source"}.issubset(fts_columns):
                    db.execute("DROP TABLE knowledge_fts")
                    fts_exists = False

            if not fts_exists:
                try:
                    db.execute(
                        """
                        CREATE VIRTUAL TABLE knowledge_fts USING fts5(
                            doc_id UNINDEXED,
                            content,
                            source,
                            tokenize='unicode61'
                        )
                        """
                    )
                except sqlite3.OperationalError as exc:
                    raise RuntimeError(
                        "SQLite FTS5 is required for the AI-CYBER knowledge layer"
                    ) from exc

            db.execute(
                "INSERT OR REPLACE INTO knowledge_meta(key,value) VALUES (?,?)",
                ("schema_version", self.SCHEMA_VERSION),
            )
            db.commit()

            doc_count = db.execute(
                "SELECT COUNT(*) FROM knowledge_documents"
            ).fetchone()[0]
            fts_count = db.execute("SELECT COUNT(*) FROM knowledge_fts").fetchone()[0]
            if doc_count != fts_count:
                self._rebuild_fts_in_connection(db)

    @staticmethod
    def _validate_identity(
        dataset_id: str, artifact_path: str, record_id: str
    ) -> None:
        if not all(
            isinstance(value, str) and value.strip()
            for value in (dataset_id, artifact_path, record_id)
        ):
            raise ValueError("dataset_id, artifact_path and record_id are required")

    @staticmethod
    def _serialize_payload(payload: Mapping[str, Any]) -> tuple[str, str]:
        if not isinstance(payload, Mapping):
            raise TypeError("payload must be a mapping")
        normalized = dict(payload)
        content = json.dumps(
            normalized,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        return content, hashlib.sha256(content.encode("utf-8")).hexdigest()

    @staticmethod
    def _doc_id(dataset_id: str, artifact_path: str, record_id: str) -> str:
        return f"{dataset_id}:{artifact_path}:{record_id}"

    def _upsert_in_connection(
        self,
        db: sqlite3.Connection,
        *,
        dataset_id: str,
        artifact_path: str,
        record_id: str,
        payload: Mapping[str, Any],
        source: str | None,
        version: str | None,
    ) -> None:
        self._validate_identity(dataset_id, artifact_path, record_id)
        content, content_hash = self._serialize_payload(payload)
        doc_id = self._doc_id(dataset_id, artifact_path, record_id)
        now = datetime.now(timezone.utc).isoformat()

        db.execute("DELETE FROM knowledge_fts WHERE doc_id=?", (doc_id,))
        db.execute("DELETE FROM knowledge_documents WHERE doc_id=?", (doc_id,))
        db.execute(
            """
            INSERT INTO knowledge_documents(
                doc_id,dataset_id,artifact_path,record_id,source,version,
                payload_json,content_hash,ingested_at
            ) VALUES (?,?,?,?,?,?,?,?,?)
            """,
            (
                doc_id,
                dataset_id,
                artifact_path,
                record_id,
                source,
                version,
                content,
                content_hash,
                now,
            ),
        )
        db.execute(
            "INSERT INTO knowledge_fts(doc_id,content,source) VALUES (?,?,?)",
            (doc_id, content, source or ""),
        )

    def upsert_record(
        self,
        *,
        dataset_id: str,
        artifact_path: str,
        record_id: str,
        payload: Mapping[str, Any],
        source: str | None = None,
        version: str | None = None,
    ) -> None:
        """Atomically insert or replace one knowledge document."""
        with self._connect() as db:
            self._upsert_in_connection(
                db,
                dataset_id=dataset_id,
                artifact_path=artifact_path,
                record_id=record_id,
                payload=payload,
                source=source,
                version=version,
            )

    def ingest_dataset_store(self, dataset_db: str | Path) -> int:
        """Atomically replace all knowledge documents represented by a dataset DB."""
        dataset_db = Path(dataset_db)
        if not dataset_db.is_file():
            raise FileNotFoundError(dataset_db)

        with sqlite3.connect(dataset_db) as src:
            src.execute("PRAGMA foreign_keys=ON")
            tables = {
                row[0]
                for row in src.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            if "records" not in tables:
                raise ValueError("dataset store is missing required table: records")
            if "provenance" not in tables:
                raise ValueError("dataset store is missing required table: provenance")

            rows = src.execute(
                """
                SELECT dataset_id,artifact_path,record_id,payload_json
                FROM records
                ORDER BY dataset_id,artifact_path,record_id
                """
            ).fetchall()
            provenance = {}
            for row in src.execute(
                """
                SELECT dataset_id,artifact_path,source,version
                FROM provenance
                ORDER BY rowid
                """
            ):
                provenance[(row[0], row[1])] = (row[2], row[3])

        catalog_ids = set()
        if "dataset_catalog" in tables:
            catalog_ids = {
                row[0]
                for row in src.execute("SELECT dataset_id FROM dataset_catalog")
            }
        dataset_ids = sorted(catalog_ids | {row[0] for row in rows})
        with self._connect() as db:
            try:
                for dataset_id in dataset_ids:
                    db.execute(
                        "DELETE FROM knowledge_fts WHERE doc_id LIKE ?",
                        (f"{dataset_id}:%",),
                    )
                    db.execute(
                        "DELETE FROM knowledge_documents WHERE dataset_id=?",
                        (dataset_id,),
                    )

                for dataset_id, artifact_path, record_id, payload_json in rows:
                    try:
                        payload = json.loads(payload_json)
                    except json.JSONDecodeError as exc:
                        raise ValueError(
                            f"invalid payload JSON for {dataset_id}/{artifact_path}/{record_id}"
                        ) from exc
                    if not isinstance(payload, dict):
                        raise ValueError(
                            f"payload must be a JSON object for "
                            f"{dataset_id}/{artifact_path}/{record_id}"
                        )
                    source, version = provenance.get((dataset_id, artifact_path), (None, None))
                    source = source or payload.get("source")
                    version = version or payload.get("version")
                    self._upsert_in_connection(
                        db,
                        dataset_id=dataset_id,
                        artifact_path=artifact_path,
                        record_id=record_id,
                        payload=payload,
                        source=source,
                        version=version,
                    )

                db.execute(
                    "INSERT OR REPLACE INTO knowledge_meta(key,value) VALUES (?,?)",
                    ("last_ingested_records", str(len(rows))),
                )
                db.execute(
                    "INSERT OR REPLACE INTO knowledge_meta(key,value) VALUES (?,?)",
                    ("last_ingested_datasets", str(len(dataset_ids))),
                )
            except Exception:
                db.rollback()
                raise

        return len(rows)

    @staticmethod
    def _build_match_query(query: str, *, operator: str) -> str:
        tokens = _TOKEN_RE.findall(query.casefold())
        tokens = [token[:_MAX_TOKEN_LENGTH] for token in tokens if token.strip()]
        if not tokens:
            return ""
        tokens = list(dict.fromkeys(tokens[:_MAX_QUERY_TOKENS]))
        quoted = ['"' + token.replace('"', '""') + '"' for token in tokens]
        return f" {operator} ".join(quoted)

    @staticmethod
    def _validate_limit(limit: int) -> int:
        if isinstance(limit, bool):
            raise TypeError("limit must be an integer")
        try:
            value = int(limit)
        except (TypeError, ValueError) as exc:
            raise ValueError("limit must be an integer") from exc
        if value < 1:
            raise ValueError("limit must be >= 1")
        return min(value, 100)

    def search(
        self,
        query: str,
        limit: int = 5,
        *,
        dataset_id: str | None = None,
        source: str | None = None,
        version: str | None = None,
    ) -> list[dict[str, Any]]:
        """Retrieve traceable evidence using deterministic lexical search.

        FTS operators supplied by callers are treated as plain text, not query
        syntax. Search first requires all extracted terms, then falls back to OR
        semantics when the strict query has no matches.
        """
        if not isinstance(query, str):
            raise TypeError("query must be a string")
        if not query.strip():
            return []

        limit = self._validate_limit(limit)
        and_query = self._build_match_query(query, operator="AND")
        if not and_query:
            return []

        def run(match_query: str) -> list[tuple[Any, ...]]:
            with self._connect() as db:
                return db.execute(
                    """
                    SELECT
                        d.doc_id,d.dataset_id,d.artifact_path,d.record_id,
                        d.source,d.version,d.payload_json,
                        bm25(knowledge_fts) AS score,
                        snippet(knowledge_fts, 1, '[', ']', '…', 24) AS snippet
                    FROM knowledge_fts
                    JOIN knowledge_documents d ON d.doc_id=knowledge_fts.doc_id
                    WHERE knowledge_fts MATCH ?
                      AND (? IS NULL OR d.dataset_id=?)
                      AND (? IS NULL OR d.source=?)
                      AND (? IS NULL OR d.version=?)
                    ORDER BY score ASC, d.doc_id ASC
                    LIMIT ?
                    """,
                    (
                        match_query,
                        dataset_id,
                        dataset_id,
                        source,
                        source,
                        version,
                        version,
                        limit,
                    ),
                ).fetchall()

        rows = run(and_query)
        if not rows and len(_TOKEN_RE.findall(query)) > 1:
            rows = run(self._build_match_query(query, operator="OR"))

        hits: list[dict[str, Any]] = []
        for rank, row in enumerate(rows, 1):
            payload = json.loads(row[6])
            raw_score = float(row[7])
            hits.append(
                {
                    "rank": rank,
                    "doc_id": row[0],
                    "dataset_id": row[1],
                    "artifact_path": row[2],
                    "record_id": row[3],
                    "source": row[4],
                    "version": row[5],
                    "payload": payload,
                    "score": raw_score,
                    "relevance": -raw_score,
                    "snippet": row[8],
                }
            )
        return hits

    def retrieve(self, query: str, top_k: int = 5, **filters: str | None) -> list[dict[str, Any]]:
        """RAG-facing alias for search."""
        return self.search(query, limit=top_k, **filters)

    @staticmethod
    def prepare_context(
        hits: list[Mapping[str, Any]],
        max_chars: int = _DEFAULT_MAX_CONTEXT_CHARS,
    ) -> dict[str, Any]:
        """Build a bounded, traceable evidence packet for a later generator."""
        if isinstance(max_chars, bool) or not isinstance(max_chars, int) or max_chars < 256:
            raise ValueError("max_chars must be an integer >= 256")

        blocks: list[str] = []
        citations: list[dict[str, Any]] = []
        used = 0

        for hit in hits:
            payload = hit.get("payload")
            if not isinstance(payload, Mapping):
                continue
            rank = hit.get("rank", len(citations) + 1)
            citation_id = f"[{rank}]"
            body = json.dumps(dict(payload), ensure_ascii=False, sort_keys=True, indent=2)
            header = (
                f"{citation_id} dataset={hit.get('dataset_id', '')} "
                f"artifact={hit.get('artifact_path', '')} "
                f"record={hit.get('record_id', '')} "
                f"source={hit.get('source') or 'unspecified'} "
                f"version={hit.get('version') or 'unspecified'}"
            )
            block = header + "\n" + body
            separator = "\n\n" if blocks else ""
            if used + len(separator) + len(block) > max_chars:
                break
            blocks.append(block)
            used += len(separator) + len(block)
            citations.append(
                {
                    "citation": citation_id,
                    "doc_id": hit.get("doc_id"),
                    "dataset_id": hit.get("dataset_id"),
                    "artifact_path": hit.get("artifact_path"),
                    "record_id": hit.get("record_id"),
                    "source": hit.get("source"),
                    "version": hit.get("version"),
                    "rank": hit.get("rank"),
                    "score": hit.get("score"),
                }
            )

        return {
            "context": "\n\n".join(blocks),
            "citations": citations,
            "included": len(blocks),
            "truncated": len(blocks) < len(hits),
            "max_chars": max_chars,
        }

    def retrieve_context(
        self,
        query: str,
        top_k: int = 5,
        *,
        max_chars: int = _DEFAULT_MAX_CONTEXT_CHARS,
        dataset_id: str | None = None,
        source: str | None = None,
        version: str | None = None,
    ) -> dict[str, Any]:
        """Return query, evidence hits, bounded context, and citations."""
        hits = self.search(
            query,
            limit=top_k,
            dataset_id=dataset_id,
            source=source,
            version=version,
        )
        packet = self.prepare_context(hits, max_chars=max_chars)
        packet["query"] = query
        packet["hits"] = hits
        return packet

    def _rebuild_fts_in_connection(self, db: sqlite3.Connection) -> int:
        db.execute("DELETE FROM knowledge_fts")
        rows = db.execute(
            "SELECT doc_id,payload_json,source FROM knowledge_documents ORDER BY doc_id"
        ).fetchall()
        for doc_id, content, source in rows:
            db.execute(
                "INSERT INTO knowledge_fts(doc_id,content,source) VALUES (?,?,?)",
                (doc_id, content, source or ""),
            )
        return len(rows)

    def rebuild_index(self) -> int:
        """Rebuild the FTS index from canonical knowledge_documents."""
        with self._connect() as db:
            count = self._rebuild_fts_in_connection(db)
            db.execute(
                "INSERT OR REPLACE INTO knowledge_meta(key,value) VALUES (?,?)",
                ("last_rebuilt_records", str(count)),
            )
        return count

    def verify_integrity(self) -> dict[str, Any]:
        """Verify document/index counts and orphan coverage."""
        with self._connect() as db:
            document_count = db.execute(
                "SELECT COUNT(*) FROM knowledge_documents"
            ).fetchone()[0]
            fts_count = db.execute("SELECT COUNT(*) FROM knowledge_fts").fetchone()[0]
            orphan_fts = db.execute(
                """
                SELECT COUNT(*)
                FROM knowledge_fts f
                LEFT JOIN knowledge_documents d ON d.doc_id=f.doc_id
                WHERE d.doc_id IS NULL
                """
            ).fetchone()[0]
            orphan_documents = db.execute(
                """
                SELECT COUNT(*)
                FROM knowledge_documents d
                LEFT JOIN knowledge_fts f ON f.doc_id=d.doc_id
                WHERE f.doc_id IS NULL
                """
            ).fetchone()[0]
            bad_hashes = 0
            for content, stored_hash in db.execute(
                "SELECT payload_json,content_hash FROM knowledge_documents"
            ):
                if stored_hash and hashlib.sha256(content.encode("utf-8")).hexdigest() != stored_hash:
                    bad_hashes += 1

            content_mismatches = db.execute(
                """
                SELECT COUNT(*)
                FROM knowledge_documents d
                JOIN knowledge_fts f ON f.doc_id=d.doc_id
                WHERE f.content != d.payload_json
                """
            ).fetchone()[0]

        ok = (
            document_count == fts_count
            and orphan_fts == 0
            and orphan_documents == 0
            and bad_hashes == 0
            and content_mismatches == 0
        )
        return {
            "ok": ok,
            "documents": document_count,
            "fts_rows": fts_count,
            "orphan_fts": orphan_fts,
            "orphan_documents": orphan_documents,
            "bad_hashes": bad_hashes,
            "content_mismatches": content_mismatches,
        }

    def health(self) -> dict[str, Any]:
        """Return a compact operational health snapshot."""
        with self._connect() as db:
            fts5 = bool(
                db.execute(
                    "SELECT 1 FROM sqlite_master "
                    "WHERE type='table' AND name='knowledge_fts'"
                ).fetchone()
            )
            documents = db.execute(
                "SELECT COUNT(*) FROM knowledge_documents"
            ).fetchone()[0]
            datasets = db.execute(
                "SELECT COUNT(DISTINCT dataset_id) FROM knowledge_documents"
            ).fetchone()[0]
            meta = dict(db.execute("SELECT key,value FROM knowledge_meta").fetchall())

        integrity = self.verify_integrity()
        return {
            "ok": fts5 and integrity["ok"],
            "fts5": fts5,
            "documents": documents,
            "datasets": datasets,
            "schema_version": self.SCHEMA_VERSION,
            "meta": meta,
            "integrity": integrity,
        }

    def count(self) -> int:
        with self._connect() as db:
            return db.execute("SELECT COUNT(*) FROM knowledge_documents").fetchone()[0]

def test_get_record_fetches_by_canonical_identity(tmp_path):
    store = KnowledgeStore(tmp_path / "knowledge.sqlite")
    store.upsert_record(dataset_id="d1", artifact_path="a.jsonl", record_id="r1", payload={"title":"canonical"}, source="d1", version="1")
    hit = store.get_record("d1","a.jsonl","r1")
    assert hit is not None and hit["doc_id"] == "d1:a.jsonl:r1"
    assert hit["payload"]["title"] == "canonical"
    assert store.get_record("d1","a.jsonl","missing") is None
