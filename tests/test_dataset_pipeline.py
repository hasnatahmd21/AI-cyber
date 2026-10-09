import hashlib
import json
from pathlib import Path

import pytest

from ai_cyber_os.dataset_pipeline import ingest_manifest, inspect_dataset
from ai_cyber_os.intelligence import correlate, extract_identifiers


def _manifest(root: Path, payload: str, *, sha256: str | None = None, count: int = 2) -> Path:
    data = root / "datasets" / "fixtures.jsonl"
    data.parent.mkdir(parents=True)
    data.write_text(payload, encoding="utf-8")
    digest = sha256 or hashlib.sha256(payload.encode("utf-8")).hexdigest()
    manifest_dir = root / "datasets" / "manifests"
    manifest_dir.mkdir(parents=True)
    manifest = manifest_dir / "fixture.json"
    manifest.write_text(json.dumps({
        "dataset": "fixture-threat-intel",
        "version": "test-1",
        "source": "local-test",
        "source_uri": "https://example.invalid/test",
        "license": "CC0",
        "local_path": "datasets/fixtures.jsonl",
        "sha256": digest,
        "record_count": count,
        "schema": {"type": "jsonl"},
        "ingestion_status": "ready",
        "validation_status": "fixture-validated",
    }), encoding="utf-8")
    return manifest


def test_manifest_pipeline_verifies_integrity(tmp_path: Path):
    payload = (
        '{"id":"CVE-2026-1000","title":"Example","description":"CVE-2026-1000 '
        'maps to CWE-79 and ATT&CK T1059.001"}\n'
        '{"id":"CVE-2026-1001","description":"second evidence"}\n'
    )
    manifest = _manifest(tmp_path, payload)
    inspected = inspect_dataset(manifest)
    assert inspected["ready"] is True
    result = ingest_manifest(manifest, db_path=tmp_path / "knowledge.db")
    assert result["ready"] is True
    assert result["inserted"] == 2


def test_manifest_pipeline_rejects_bad_checksum(tmp_path: Path):
    payload = '{"id":"X","content":"evidence"}\n'
    manifest = _manifest(tmp_path, payload, sha256="0" * 64, count=1)
    assert inspect_dataset(manifest)["sha256_matches"] is False
    with pytest.raises(ValueError, match="SHA-256"):
        ingest_manifest(manifest, db_path=tmp_path / "knowledge.db")


def test_identifier_extraction_and_relation_correlation(tmp_path: Path):
    payload = '{"id":"CVE-2026-2000","content":"CVE-2026-2000 CWE-89 ATT&CK T1059.001"}\n'
    manifest = _manifest(tmp_path, payload, count=1)
    db = tmp_path / "knowledge.db"
    ingest_manifest(manifest, db_path=db)
    ids = extract_identifiers(payload)
    assert ids["cve"] == ["CVE-2026-2000"]
    result = correlate("CVE-2026-2000", db_path=str(db))
    assert result["evidence_only"] is True
    assert result["related"]["CVE-2026-2000"][0]["record_id"] == "CVE-2026-2000"



def test_manifest_rejects_boolean_and_string_record_counts(tmp_path: Path):
    payload = '{"id":"fixture","content":"evidence"}\\n'
    manifest = _manifest(tmp_path, payload, count=1)
    data = json.loads(manifest.read_text(encoding="utf-8"))
    data["record_count"] = True
    manifest.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match="record_count must be an integer"):
        inspect_dataset(manifest)


def test_manifest_rejects_symlink_escape(tmp_path: Path):
    payload = '{"id":"fixture","content":"evidence"}\\n'
    manifest = _manifest(tmp_path, payload, count=1)
    outside = tmp_path.parent / f"{tmp_path.name}-outside.jsonl"
    outside.write_text(payload, encoding="utf-8")
    link = tmp_path / "datasets" / "escape.jsonl"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is unavailable on this platform")
    data = json.loads(manifest.read_text(encoding="utf-8"))
    data["local_path"] = "datasets/escape.jsonl"
    manifest.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match="remain inside the project"):
        inspect_dataset(manifest)


def test_checksum_can_be_explicitly_skipped_but_count_cannot(tmp_path: Path):
    payload = '{"id":"fixture-checksum-optout","content":"evidence"}\\n'
    manifest = _manifest(tmp_path, payload, sha256="0" * 64, count=1)
    result = ingest_manifest(
        manifest, db_path=tmp_path / "knowledge.db", require_checksum=False
    )
    assert result["ready"] is True
    assert result["inspection"]["sha256_matches"] is False

    data = json.loads(manifest.read_text(encoding="utf-8"))
    data["record_count"] = 99
    manifest.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match="record count"):
        ingest_manifest(
            manifest, db_path=tmp_path / "knowledge-count.db",
            require_checksum=False
        )


def test_multi_artifact_manifest_rejects_non_integer_record_count(tmp_path: Path):
    data_dir = tmp_path / "datasets"
    data_dir.mkdir()
    payload = '{"id":"fixture","content":"evidence"}\\n'
    artifact = data_dir / "one.jsonl"
    artifact.write_text(payload, encoding="utf-8")
    manifest_dir = data_dir / "manifests"
    manifest_dir.mkdir()
    manifest = manifest_dir / "multi.json"
    manifest.write_text(json.dumps({
        "dataset": "multi-fixture",
        "version": "1",
        "artifacts": [{
            "path": "datasets/one.jsonl",
            "sha256": hashlib.sha256(payload.encode("utf-8")).hexdigest(),
            "record_count": 1.5,
        }],
    }), encoding="utf-8")
    with pytest.raises(ValueError, match="record_count must be an integer"):
        inspect_dataset(manifest)
