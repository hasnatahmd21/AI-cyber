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
    assert status(db_path=db)["schema_version"] == 2



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
