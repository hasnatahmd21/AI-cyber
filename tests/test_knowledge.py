import json
from pathlib import Path

from ai_cyber_os.knowledge import ingest_file, search, status


def test_ingest_jsonl_is_provenance_aware(tmp_path: Path):
    data = tmp_path / "cves.jsonl"
    data.write_text(
        '{"id":"CVE-TEST-1","title":"Test CVE","description":"remote code execution vulnerability","license":"CC0"}\n'
        '{"id":"CVE-TEST-2","description":"denial of service vulnerability"}\n',
        encoding="utf-8",
    )
    db = tmp_path / "knowledge.db"
    result = ingest_file(data, db_path=db, dataset="cve-test", source="test-fixture")
    assert result["success"] is True
    assert result["inserted"] == 2
    assert status(db_path=db)["records"] == 2
    hits = search("remote code execution", db_path=db)
    assert hits and hits[0]["record_id"] == "CVE-TEST-1"
    assert hits[0]["source"] == "test-fixture"
    assert hits[0]["content_sha256"]


def test_duplicate_ingest_is_idempotent(tmp_path: Path):
    data = tmp_path / "data.jsonl"
    data.write_text('{"id":"X","content":"same evidence"}\n', encoding="utf-8")
    db = tmp_path / "knowledge.db"
    first = ingest_file(data, db_path=db, dataset="demo")
    second = ingest_file(data, db_path=db, dataset="demo")
    assert first["inserted"] == 1
    assert second["duplicates"] == 1
    assert status(db_path=db)["records"] == 1


def test_empty_query_is_safe(tmp_path: Path):
    assert search("", db_path=tmp_path / "knowledge.db") == []


def test_identifier_search_handles_hyphens(tmp_path: Path):
    data = tmp_path / "ids.jsonl"
    data.write_text('{"id":"CVE-2026-1234","content":"CVE-2026-1234 remote code execution"}\n', encoding="utf-8")
    db = tmp_path / "knowledge.db"
    ingest_file(data, db_path=db, dataset="cve")
    hits = search("CVE-2026-1234", db_path=db)
    assert hits and hits[0]["record_id"] == "CVE-2026-1234"


def test_provenance_status_is_persisted(tmp_path: Path):
    data = tmp_path / "intel.jsonl"
    data.write_text(
        '{"id":"I-1","content":"verified threat evidence"}\n',
        encoding="utf-8",
    )
    db = tmp_path / "knowledge.db"
    ingest_file(
        data,
        db_path=db,
        dataset="intel",
        source="fixture",
        source_uri="https://example.invalid/source",
        license="CC0",
        version="2026-10",
        validation_status="validated",
    )
    hit = search("verified threat evidence", db_path=db)[0]
    assert hit["source"] == "fixture"
    assert hit["source_uri"] == "https://example.invalid/source"
    assert hit["license"] == "CC0"
    assert hit["version"] == "2026-10"
    assert hit["validation_status"] == "validated"
    assert status(db_path=db)["schema_version"] == 5


def test_rag_context_is_evidence_only(tmp_path: Path):
    from ai_cyber_os.rag import build_context

    data = tmp_path / "rag.jsonl"
    data.write_text(
        '{"id":"R-1","content":"known exploitation evidence","source":"fixture"}\n',
        encoding="utf-8",
    )
    db = tmp_path / "knowledge.db"
    ingest_file(data, db_path=db, dataset="threats")
    context = build_context("known exploitation", db_path=db)
    assert context["evidence_only"] is True
    assert context["count"] == 1
    assert context["evidence"][0]["record_id"] == "R-1"
    assert context["evidence"][0]["source"] == "fixture"
    assert "content_sha256" in context["evidence"][0]
    assert "identifiers" in context
    assert "related" in context


def test_gzip_jsonl_ingestion(tmp_path: Path):
    import gzip
    data = tmp_path / "feed.jsonl.gz"
    with gzip.open(data, "wt", encoding="utf-8") as handle:
        handle.write('{"id":"GZ-1","content":"compressed CVE evidence"}\n')
    db = tmp_path / "knowledge.db"
    result = ingest_file(data, db_path=db, dataset="compressed")
    assert result["success"] is True
    assert result["inserted"] == 1
    assert search("compressed CVE evidence", db_path=db)[0]["record_id"] == "GZ-1"


def test_zip_json_ingestion(tmp_path: Path):
    import zipfile
    data = tmp_path / "feed.zip"
    with zipfile.ZipFile(data, "w") as archive:
        archive.writestr("feed.json", '[{"id":"ZIP-1","content":"archived evidence"}]')
    db = tmp_path / "knowledge.db"
    result = ingest_file(data, db_path=db, dataset="archive")
    assert result["success"] is True
    assert result["inserted"] == 1
    assert search("archived evidence", db_path=db)[0]["record_id"] == "ZIP-1"


def test_same_identifier_from_different_datasets_is_not_overwritten(tmp_path: Path):
    first = tmp_path / "nvd.jsonl"
    second = tmp_path / "kev.jsonl"
    first.write_text(
        '{"id":"CVE-2026-9999","content":"NVD description","source":"NVD"}\n',
        encoding="utf-8",
    )
    second.write_text(
        '{"id":"CVE-2026-9999","content":"KEV description","source":"CISA KEV"}\n',
        encoding="utf-8",
    )
    db = tmp_path / "knowledge.db"
    ingest_file(first, db_path=db, dataset="nvd", source="NVD")
    ingest_file(second, db_path=db, dataset="cisa-kev", source="CISA KEV")
    hits = search("CVE-2026-9999", db_path=db, limit=10)
    assert len(hits) == 2
    assert {item["dataset"] for item in hits} == {"nvd", "cisa-kev"}
    assert {item["record_id"] for item in hits} == {
        "CVE-2026-9999", "cisa-kev:CVE-2026-9999"
    }


def test_long_evidence_is_chunked_and_retrieved(tmp_path: Path):
    data = tmp_path / "long.jsonl"
    content = ("context " * 700) + " unique-critical-marker"
    data.write_text(
        '{"id":"LONG-1","content":' + json.dumps(content) + '}\n',
        encoding="utf-8",
    )
    db = tmp_path / "knowledge.db"
    ingest_file(data, db_path=db, dataset="long", source="fixture", validation_status="fixture-validated")
    hits = search("unique-critical-marker", db_path=db)
    assert hits and hits[0]["record_id"] == "LONG-1"

    import sqlite3
    conn = sqlite3.connect(db)
    try:
        count = conn.execute(
            "SELECT COUNT(*) FROM knowledge_chunks WHERE record_id=?",
            ("LONG-1",),
        ).fetchone()[0]
    finally:
        conn.close()
    assert count > 1


def test_epss_csv_gzip_preserves_cve_as_searchable_record_id(tmp_path: Path):
    import gzip

    data = tmp_path / "epss.csv.gz"
    with gzip.open(data, "wt", encoding="utf-8", newline="") as handle:
        handle.write("cve,epss,percentile\n")
        handle.write("CVE-2026-1234,0.8123,0.998\n")
        handle.write("CVE-2026-5678,0.0042,0.31\n")

    db = tmp_path / "knowledge.db"
    result = ingest_file(
        data,
        db_path=db,
        dataset="epss",
        source="EPSS fixture",
        source_uri="https://example.invalid/epss",
        version="fixture-v1",
        validation_status="fixture-validated",
    )

    assert result["success"] is True
    assert result["inserted"] == 2
    hits = search("CVE-2026-1234", db_path=db, dataset="epss")
    assert len(hits) == 1
    assert hits[0]["record_id"] == "CVE-2026-1234"
    assert hits[0]["title"] == "CVE-2026-1234"
    assert hits[0]["source_uri"] == "https://example.invalid/epss"
    assert hits[0]["validation_status"] == "fixture-validated"


def test_cpe_jsonl_gzip_preserves_canonical_cpe_name_as_record_id(tmp_path: Path):
    import gzip

    data = tmp_path / "cpe-products.jsonl.gz"
    row = {
        "cpeName": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:java:*:*",
        "cpeNameId": "11111111-2222-4333-8444-555555555555",
        "titles": [{"title": "Apache Log4j 2.14.1", "lang": "en"}],
    }
    with gzip.open(data, "wt", encoding="utf-8") as handle:
        handle.write(json.dumps(row) + "\n")

    db = tmp_path / "knowledge.db"
    result = ingest_file(
        data,
        db_path=db,
        dataset="cpe",
        source="NVD CPE fixture",
        source_uri="https://example.invalid/cpe",
        version="fixture-v1",
        validation_status="fixture-validated",
    )
    hits = search("cpe:2.3:a:apache:log4j:2.14.1", db_path=db, dataset="cpe")

    assert result["inserted"] == 1
    assert hits and hits[0]["record_id"] == row["cpeName"]
    assert hits[0]["title"] == row["cpeName"]
    assert hits[0]["source_uri"] == "https://example.invalid/cpe"


def test_open_store_repairs_legacy_chunks_and_persists_completion_marker(tmp_path: Path):
    import sqlite3
    from ai_cyber_os.knowledge import open_store

    data = tmp_path / "legacy.jsonl"
    data.write_text(
        '{"id":"LEGACY-CHUNK-1","content":"legacy evidence requiring a chunk"}\n',
        encoding="utf-8",
    )
    db_path = tmp_path / "knowledge.db"
    result = ingest_file(data, db_path=db_path, dataset="legacy")
    assert result["success"] is True

    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            "DELETE FROM knowledge_chunks_fts WHERE record_id=?",
            ("LEGACY-CHUNK-1",),
        )
        conn.execute(
            "DELETE FROM knowledge_chunks WHERE record_id=?",
            ("LEGACY-CHUNK-1",),
        )
        # Simulate a DB created before the one-time migration marker existed.
        conn.execute(
            "DELETE FROM knowledge_meta WHERE key='chunk_backfill_v1_complete'"
        )
        conn.commit()
    finally:
        conn.close()

    conn = open_store(db_path)
    try:
        chunk_count = conn.execute(
            "SELECT COUNT(*) FROM knowledge_chunks WHERE record_id=?",
            ("LEGACY-CHUNK-1",),
        ).fetchone()[0]
        fts_count = conn.execute(
            "SELECT COUNT(*) FROM knowledge_chunks_fts WHERE record_id=?",
            ("LEGACY-CHUNK-1",),
        ).fetchone()[0]
        marker = conn.execute(
            "SELECT value FROM knowledge_meta WHERE key='chunk_backfill_v1_complete'"
        ).fetchone()
    finally:
        conn.close()

    assert chunk_count == 1
    assert fts_count == 1
    assert marker is not None and marker[0] == "true"



def test_chunk_index_skips_full_fts_delete_for_new_record(tmp_path: Path):
    from ai_cyber_os import knowledge

    db = tmp_path / "chunk-index.db"
    conn = knowledge.open_store(db)
    statements = []
    conn.set_trace_callback(statements.append)
    record = {
        "record_id": "NEW-CHUNK-1",
        "dataset": "fixture",
        "title": "New chunk",
        "content": "first version of evidence " * 300,
    }
    try:
        knowledge._index_chunks(conn, record)
        conn.commit()
        assert not any(
            statement.lstrip().upper().startswith("DELETE FROM KNOWLEDGE_CHUNKS_FTS")
            for statement in statements
        )
        assert conn.execute(
            "SELECT COUNT(*) FROM knowledge_chunks WHERE record_id=?",
            (record["record_id"],),
        ).fetchone()[0] > 1
        assert conn.execute(
            "SELECT COUNT(*) FROM knowledge_chunks_fts WHERE record_id=?",
            (record["record_id"],),
        ).fetchone()[0] > 1

        statements.clear()
        record["content"] = "replacement evidence " * 300
        knowledge._index_chunks(conn, record, replace_existing=True)
        conn.commit()
        assert any(
            statement.lstrip().upper().startswith("DELETE FROM KNOWLEDGE_CHUNKS_FTS")
            for statement in statements
        )
        assert conn.execute(
            "SELECT COUNT(*) FROM knowledge_chunks_fts WHERE record_id=?",
            (record["record_id"],),
        ).fetchone()[0] == conn.execute(
            "SELECT COUNT(*) FROM knowledge_chunks WHERE record_id=?",
            (record["record_id"],),
        ).fetchone()[0]
    finally:
        conn.close()


def test_dataset_filtered_search_avoids_dataset_wide_id_scan(tmp_path: Path, monkeypatch):
    from ai_cyber_os import knowledge

    wanted = tmp_path / "wanted.jsonl"
    other = tmp_path / "other.jsonl"
    wanted.write_text(
        '{"id":"FILTER-1","content":"shared searchable candidate evidence"}\n',
        encoding="utf-8",
    )
    other.write_text(
        '{"id":"OTHER-1","content":"shared searchable candidate evidence"}\n',
        encoding="utf-8",
    )
    db = tmp_path / "knowledge.db"
    ingest_file(wanted, db_path=db, dataset="wanted")
    ingest_file(other, db_path=db, dataset="other")

    statements = []
    original_open_store = knowledge.open_store

    def traced_open_store(path=knowledge.DEFAULT_DB):
        connection = original_open_store(path)
        connection.set_trace_callback(statements.append)
        return connection

    monkeypatch.setattr(knowledge, "open_store", traced_open_store)
    hits = knowledge.search(
        "shared searchable candidate evidence",
        db_path=db,
        dataset="wanted",
        limit=5,
    )

    assert [row["record_id"] for row in hits] == ["FILTER-1"]
    normalized = [" ".join(statement.upper().split()) for statement in statements]
    assert any(
        "SELECT RECORD_ID FROM KNOWLEDGE_RECORDS WHERE DATASET='WANTED'"
        in statement
        and "RECORD_ID IN (" in statement
        for statement in normalized
    )
    assert not any(
        statement.startswith(
            "SELECT RECORD_ID FROM KNOWLEDGE_RECORDS WHERE DATASET='WANTED'"
        )
        and "RECORD_ID IN (" not in statement
        for statement in normalized
    )


def test_chunk_index_recovers_orphaned_chunk_primary_key_collision(tmp_path: Path):
    from ai_cyber_os import knowledge

    db = tmp_path / "orphaned-chunk.db"
    conn = knowledge.open_store(db)
    record = {
        "record_id": "NVD-CVE-EXAMPLE",
        "dataset": "nvd_cve",
        "title": "NVD CVE example",
        "content": "verified vulnerability evidence",
    }
    try:
        # Simulate an interrupted/legacy build that left a chunk without its
        # corresponding record row or FTS row.
        chunk_id = f"{record['record_id']}#chunk-0"
        conn.execute(
            "INSERT INTO knowledge_chunks(chunk_id,record_id,chunk_index,content,content_sha256) "
            "VALUES (?,?,?,?,?)",
            (chunk_id, record["record_id"], 0, "stale", "0" * 64),
        )
        conn.commit()

        knowledge._index_chunks(conn, record)
        conn.commit()

        chunk = conn.execute(
            "SELECT content, content_sha256 FROM knowledge_chunks WHERE chunk_id=?",
            (chunk_id,),
        ).fetchone()
        fts = conn.execute(
            "SELECT COUNT(*) FROM knowledge_chunks_fts WHERE chunk_id=?",
            (chunk_id,),
        ).fetchone()[0]
        assert chunk is not None and chunk["content"] == record["content"]
        assert chunk["content_sha256"] == knowledge._hash(record["content"])
        assert fts == 1
    finally:
        conn.close()


def test_parsed_ingestion_replaces_old_chunks_when_record_content_changes(tmp_path: Path):
    from ai_cyber_os import knowledge
    from ai_cyber_os.threat_intel import ingest_parsed

    db = tmp_path / "parsed-record-update.db"
    record_id = "CVE-2026-987654"
    old_record = knowledge._normalize(
        {
            "id": record_id,
            "title": "Fixture vulnerability",
            "content": "obsoleteevidenceonly " * 900,
        },
        dataset="nvd_cve",
        source="NVD fixture",
        validation_status="fixture-validated",
    )
    first = ingest_parsed([old_record], db_path=db)
    assert first["processed_records"] == 1
    assert search("obsoleteevidenceonly", db_path=db, dataset="nvd_cve")
    assert status(db_path=db)["records"] == 1

    new_record = knowledge._normalize(
        {
            "id": record_id,
            "title": "Fixture vulnerability",
            "content": "replacementmarkerxyz latest evidence",
        },
        dataset="nvd_cve",
        source="NVD fixture",
        validation_status="fixture-validated",
    )
    second = ingest_parsed([new_record], db_path=db)
    assert second["processed_records"] == 1
    assert status(db_path=db)["records"] == 1
    assert search("obsoleteevidenceonly", db_path=db, dataset="nvd_cve") == []
    hits = search("replacementmarkerxyz", db_path=db, dataset="nvd_cve")
    assert hits and hits[0]["record_id"] == record_id

    conn = knowledge.open_store(db)
    try:
        chunks = conn.execute(
            "SELECT content FROM knowledge_chunks WHERE record_id=? ORDER BY chunk_index",
            (record_id,),
        ).fetchall()
        chunk_fts = conn.execute(
            "SELECT content FROM knowledge_chunks_fts WHERE record_id=?",
            (record_id,),
        ).fetchall()
    finally:
        conn.close()
    assert len(chunks) == len(knowledge._chunk_text(new_record["content"])) == 1
    assert len(chunk_fts) == 1
    assert chunks[0]["content"] == new_record["content"]
    assert chunk_fts[0]["content"] == new_record["content"]
