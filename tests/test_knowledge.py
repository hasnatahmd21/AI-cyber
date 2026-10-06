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
