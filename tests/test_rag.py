from ai_cyber_os.rag import build_context
from ai_cyber_os.knowledge import ingest_file


def test_rag_context_is_evidence_only_and_preserves_provenance(tmp_path):
    data = tmp_path / "x.jsonl"
    data.write_text('{"id":"CVE-2026-9000","description":"CWE-79 issue"}\n', encoding="utf-8")
    db = tmp_path / "k.db"
    ingest_file(
        data,
        db_path=db,
        dataset="test",
        source="fixture",
        source_uri="https://example.test/security-record/CVE-2026-9000",
        license="test-fixture",
        version="fixture-v1",
        validation_status="fixture-validated",
    )
    context = build_context("CVE-2026-9000", db_path=db)
    assert context["evidence_only"] is True
    assert context["count"] == 1
    evidence = context["evidence"][0]
    assert evidence["record_id"] == "CVE-2026-9000"
    assert evidence["dataset"] == "test"
    assert evidence["source_uri"] == "https://example.test/security-record/CVE-2026-9000"
    assert evidence["license"] == "test-fixture"
    assert evidence["version"] == "fixture-v1"
    assert evidence["validation_status"] == "fixture-validated"
    assert len(evidence["content_sha256"]) == 64
    assert context["identifiers"]["cve"] == ["CVE-2026-9000"]
    assert "CVE-2026-9000" in context["related"]
