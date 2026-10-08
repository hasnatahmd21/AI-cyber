"""Local-first cyber knowledge ingestion and lexical retrieval using SQLite FTS5."""
from __future__ import annotations
import json, sqlite3
from pathlib import Path
from typing import Any

class KnowledgeStore:
    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init()

    def _connect(self):
        return sqlite3.connect(self.db_path)

    def _init(self):
        with self._connect() as db:
            db.executescript("""
            CREATE TABLE IF NOT EXISTS knowledge_documents(
                doc_id TEXT PRIMARY KEY, dataset_id TEXT NOT NULL,
                artifact_path TEXT NOT NULL, record_id TEXT NOT NULL,
                source TEXT, version TEXT, payload_json TEXT NOT NULL
            );
            CREATE VIRTUAL TABLE IF NOT EXISTS knowledge_fts USING fts5(
                doc_id UNINDEXED, content, source, tokenize='unicode61'
            );
            CREATE TABLE IF NOT EXISTS knowledge_meta(
                key TEXT PRIMARY KEY, value TEXT NOT NULL
            );
            """)

    def upsert_record(self, *, dataset_id: str, artifact_path: str,
                      record_id: str, payload: dict[str, Any],
                      source: str | None = None, version: str | None = None) -> None:
        doc_id = f"{dataset_id}:{artifact_path}:{record_id}"
        content = json.dumps(payload, ensure_ascii=False, sort_keys=True)
        with self._connect() as db:
            db.execute("DELETE FROM knowledge_fts WHERE doc_id=?", (doc_id,))
            db.execute("DELETE FROM knowledge_documents WHERE doc_id=?", (doc_id,))
            db.execute("INSERT INTO knowledge_documents VALUES (?,?,?,?,?,?,?)",
                       (doc_id, dataset_id, artifact_path, record_id, source, version, content))
            db.execute("INSERT INTO knowledge_fts(doc_id,content,source) VALUES (?,?,?)",
                       (doc_id, content, source or ""))

    def ingest_dataset_store(self, dataset_db: str | Path) -> int:
        count = 0
        with sqlite3.connect(dataset_db) as src:
            rows = src.execute(
                "SELECT dataset_id,artifact_path,record_id,payload_json FROM records"
            ).fetchall()
            prov = {(r[0], r[1]): (r[2], r[3]) for r in src.execute(
                "SELECT dataset_id,artifact_path,source,version FROM provenance"
            )}
        for dataset_id, artifact_path, record_id, payload_json in rows:
            source, version = prov.get((dataset_id, artifact_path), (None, None))
            self.upsert_record(dataset_id=dataset_id, artifact_path=artifact_path,
                               record_id=record_id, payload=json.loads(payload_json),
                               source=source, version=version)
            count += 1
        with self._connect() as db:
            db.execute("INSERT OR REPLACE INTO knowledge_meta VALUES (?,?)",
                       ("last_ingested_records", str(count)))
        return count

    def search(self, query: str, limit: int = 5) -> list[dict[str, Any]]:
        if not query.strip():
            return []
        limit = max(1, min(int(limit), 100))
        with self._connect() as db:
            rows = db.execute(
                """SELECT d.doc_id,d.dataset_id,d.artifact_path,d.record_id,
                          d.source,d.version,d.payload_json,bm25(knowledge_fts) AS score
                   FROM knowledge_fts f JOIN knowledge_documents d ON d.doc_id=f.doc_id
                   WHERE knowledge_fts MATCH ? ORDER BY score LIMIT ?""",
                (query, limit),
            ).fetchall()
        return [{"doc_id": r[0], "dataset_id": r[1], "artifact_path": r[2],
                 "record_id": r[3], "source": r[4], "version": r[5],
                 "payload": json.loads(r[6]), "score": r[7]} for r in rows]

    def count(self) -> int:
        with self._connect() as db:
            return db.execute("SELECT count(*) FROM knowledge_documents").fetchone()[0]
