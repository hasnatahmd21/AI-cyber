import hashlib, json
from ai_cyber_os.continuous_update import update_from_manifests

def test_continuous_update_is_idempotent(tmp_path):
    project = tmp_path / "project"; project.mkdir()
    data = project / "fixture.jsonl"
    data.write_text(json.dumps({"id":"CVE-2099-5000","description":"fixture"})+"\n", encoding="utf-8")
    sha = hashlib.sha256(data.read_bytes()).hexdigest()
    manifest = project / "fixture.manifest.json"
    manifest.write_text(json.dumps({"dataset":"fixture","version":"1","source":"fixture","source_uri":"local://fixture","license":"test","local_path":"fixture.jsonl","sha256":sha,"record_count":1,"schema":{"type":"object"},"ingestion_status":"ready","validation_status":"fixture-validated"}), encoding="utf-8")
    db = project / "knowledge.db"; state = project / "state.json"
    first = update_from_manifests([manifest], db_path=db, state_path=state)
    second = update_from_manifests([manifest], db_path=db, state_path=state)
    assert first["ingested"] == 1
    assert second["unchanged"] == 1
