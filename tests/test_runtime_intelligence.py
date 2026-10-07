from ai_cyber_os.runtime_intelligence import analyze
from ai_cyber_os.knowledge import ingest_file


def test_runtime_intelligence_contract(tmp_path):
    data = tmp_path / "evidence.jsonl"
    data.write_text('{"id":"CVE-2026-7777","description":"CWE-22 example"}\n', encoding="utf-8")
    db = tmp_path / "knowledge.db"
    ingest_file(data, db_path=db, dataset="fixture", source="fixture", validation_status="fixture-validated")
    result = analyze("CVE-2026-7777", db_path=db)
    assert result["success"] is True
    assert result["answer"] is None
    assert result["answer_status"] == "not_generated"
    assert result["evidence_only"] is True
    assert result["evidence"][0]["validation_status"] == "fixture-validated"
