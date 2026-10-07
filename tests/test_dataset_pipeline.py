from pathlib import Path
import sqlite3
from ai_cyber_os.dataset_pipeline import validate_manifest, ingest_and_verify

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "docs/datasets/manifest.json"
DB = ROOT / ".test_dataset_pipeline.sqlite"

def test_manifest_integrity_and_counts():
    import json
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    result = validate_manifest(manifest, ROOT)
    assert result["artifact_count"] == 2
    assert result["record_count"] == 2
    assert all(len(x["sha256"]) == 64 for x in result["artifacts"])

def test_multi_artifact_ingestion_and_provenance():
    if DB.exists(): DB.unlink()
    result = ingest_and_verify(MANIFEST, ROOT, DB)
    assert result["artifact_count"] == 2
    assert result["record_count"] == 2
    with sqlite3.connect(DB) as conn:
        assert conn.execute("select count(*) from dataset_catalog").fetchone()[0] == 1
        assert conn.execute("select count(*) from artifacts").fetchone()[0] == 2
        assert conn.execute("select count(*) from records").fetchone()[0] == 2
        assert conn.execute("select count(*) from provenance").fetchone()[0] == 2
    DB.unlink()
