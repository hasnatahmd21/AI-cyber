from __future__ import annotations

import hashlib
import json
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from ai_cyber_os.dataset_pipeline import (
    LEGACY_SCHEMA,
    SCHEMA,
    DatasetIntegrityError,
    ManifestValidationError,
    count_records,
    ingest_and_verify,
    ingest_manifest,
    iter_records,
    validate_manifest,
    verify_store,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_MANIFEST = ROOT / "docs/datasets/manifest.json"
FIXTURE_DB = ROOT / ".test_dataset_pipeline.sqlite"


def _write_jsonl(path: Path, rows: list[dict], trailing_newline: bool = True) -> str:
    payload = "\n".join(
        json.dumps(row, sort_keys=True, separators=(",", ":")) for row in rows
    )
    if trailing_newline:
        payload += "\n"
    path.write_text(payload, encoding="utf-8")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _manifest(
    root: Path,
    *,
    dataset_id: str = "test-dataset",
    version: str = "1.0.0",
    artifacts: list[dict] | None = None,
    schema: str = SCHEMA,
) -> tuple[Path, dict]:
    manifest_path = root / "manifest.json"
    manifest = {
        "schema": schema,
        "dataset_id": dataset_id,
        "version": version,
        "created_by": "tests",
        "provenance": {
            "source": "pytest-fixture",
            "origin": "test",
            "license": "internal",
            "acquired_at": "test-run",
        },
        "artifacts": artifacts or [],
    }
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return manifest_path, manifest


def _artifact(root: Path, filename: str, rows: list[dict], **provenance) -> dict:
    path = root / filename
    digest = _write_jsonl(path, rows)
    return {
        "path": filename,
        "format": "jsonl",
        "records": len(rows),
        "sha256": digest,
        "provenance": provenance or {
            "source": "artifact-fixture",
            "version": "1.0",
        },
    }


def test_repository_fixture_is_integrity_valid():
    manifest = json.loads(FIXTURE_MANIFEST.read_text(encoding="utf-8"))
    result = validate_manifest(manifest, ROOT)
    assert result["dataset_id"] == "ai-cyber-core-smoke"
    assert result["artifact_count"] == 2
    assert result["record_count"] == 2
    assert all(len(item["sha256"]) == 64 for item in result["artifacts"])


def test_legacy_manifest_schema_remains_readable():
    manifest = json.loads(FIXTURE_MANIFEST.read_text(encoding="utf-8"))
    manifest["schema"] = LEGACY_SCHEMA
    result = validate_manifest(manifest, ROOT)
    assert result["schema"] == LEGACY_SCHEMA
    assert result["record_count"] == 2


def test_multi_artifact_ingestion_provenance_and_integrity(tmp_path: Path):
    a = _artifact(tmp_path, "a.jsonl", [{"record_id": "a-1", "value": "alpha"}])
    b = _artifact(
        tmp_path,
        "b.jsonl",
        [{"record_id": "b-1", "value": "beta"}],
        source="trusted-source",
        version="2.0",
        license="Apache-2.0",
    )
    manifest_path, manifest = _manifest(tmp_path, artifacts=[a, b])
    db = tmp_path / "datasets.sqlite"

    result = ingest_and_verify(manifest_path, tmp_path, db)
    assert result["artifact_count"] == 2
    assert result["record_count"] == 2
    assert result["verified"] is True

    with sqlite3.connect(db) as conn:
        assert conn.execute("select count(*) from dataset_catalog").fetchone()[0] == 1
        assert conn.execute("select count(*) from artifacts").fetchone()[0] == 2
        assert conn.execute("select count(*) from records").fetchone()[0] == 2
        provenance = conn.execute(
            "select source,version,origin,license from provenance where artifact_path=?",
            ("b.jsonl",),
        ).fetchone()
        assert provenance == ("trusted-source", "2.0", "test", "Apache-2.0")

    check = verify_store(db, tmp_path, dataset_id=manifest["dataset_id"])
    assert check["ok"] is True
    assert check["artifact_count"] == 2
    assert check["record_count"] == 2


def test_reingestion_is_idempotent(tmp_path: Path):
    a = _artifact(tmp_path, "a.jsonl", [{"record_id": "same", "value": "stable"}])
    manifest_path, _ = _manifest(tmp_path, artifacts=[a])
    db = tmp_path / "datasets.sqlite"

    first = ingest_manifest(manifest_path, tmp_path, db)
    second = ingest_manifest(manifest_path, tmp_path, db)

    assert first["artifact_count"] == second["artifact_count"] == 1
    assert first["record_count"] == second["record_count"] == 1
    with sqlite3.connect(db) as conn:
        assert conn.execute("select count(*) from records").fetchone()[0] == 1


def test_removed_artifact_is_reconciled_without_touching_other_dataset(tmp_path: Path):
    a = _artifact(tmp_path, "a.jsonl", [{"record_id": "a-1"}])
    b = _artifact(tmp_path, "b.jsonl", [{"record_id": "b-1"}])
    manifest_path, manifest = _manifest(
        tmp_path,
        dataset_id="reconcile",
        artifacts=[a, b],
    )
    db = tmp_path / "datasets.sqlite"
    ingest_manifest(manifest_path, tmp_path, db)

    c = _artifact(tmp_path, "c.jsonl", [{"record_id": "c-1"}])
    manifest["artifacts"] = [a, c]
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    # SHA-256 is part of the artifact contract and must be recomputed after edits.
    ingest_manifest(manifest_path, tmp_path, db)

    with sqlite3.connect(db) as conn:
        paths = [
            row[0]
            for row in conn.execute(
                "select artifact_path from artifacts where dataset_id=? order by artifact_path",
                ("reconcile",),
            )
        ]
        assert paths == ["a.jsonl", "c.jsonl"]
        assert conn.execute(
            "select count(*) from records where dataset_id=?",
            ("reconcile",),
        ).fetchone()[0] == 2


def test_sha256_tamper_is_rejected(tmp_path: Path):
    artifact = _artifact(tmp_path, "a.jsonl", [{"record_id": "a-1", "value": "original"}])
    manifest_path, _ = _manifest(tmp_path, artifacts=[artifact])
    artifact_path = tmp_path / "a.jsonl"
    artifact_path.write_text(
        artifact_path.read_text(encoding="utf-8").replace("original", "tampered"),
        encoding="utf-8",
    )

    with pytest.raises(ManifestValidationError, match="SHA256 mismatch"):
        ingest_manifest(manifest_path, tmp_path, tmp_path / "datasets.sqlite")


def test_record_count_tamper_is_rejected(tmp_path: Path):
    artifact = _artifact(tmp_path, "a.jsonl", [{"record_id": "a-1"}])
    artifact["records"] = 2
    manifest_path, _ = _manifest(tmp_path, artifacts=[artifact])

    with pytest.raises(ManifestValidationError, match="record count mismatch"):
        ingest_manifest(manifest_path, tmp_path, tmp_path / "datasets.sqlite")


@pytest.mark.parametrize(
    "bad_path",
    ["../escape.jsonl", "/tmp/escape.jsonl", "docs/../escape.jsonl", "./a.jsonl"],
)
def test_artifact_path_escape_and_noncanonical_paths_are_rejected(
    tmp_path: Path,
    bad_path: str,
):
    outside = tmp_path.parent / "escape.jsonl"
    outside.write_text('{"record_id":"outside"}\n', encoding="utf-8")
    manifest_path, _ = _manifest(
        tmp_path,
        artifacts=[
            {
                "path": bad_path,
                "format": "jsonl",
                "records": 1,
                "sha256": hashlib.sha256(outside.read_bytes()).hexdigest(),
            }
        ],
    )
    with pytest.raises((ManifestValidationError, FileNotFoundError)):
        validate_manifest(
            json.loads(manifest_path.read_text(encoding="utf-8")),
            tmp_path,
        )


def test_symlink_artifact_is_rejected(tmp_path: Path):
    source = tmp_path / "outside.jsonl"
    source.write_text('{"record_id":"outside"}\n', encoding="utf-8")
    link = tmp_path / "link.jsonl"
    try:
        link.symlink_to(source)
    except OSError:
        pytest.skip("symlinks are unavailable in this environment")
    artifact = {
        "path": "link.jsonl",
        "format": "jsonl",
        "records": 1,
        "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
    }
    manifest_path, _ = _manifest(tmp_path, artifacts=[artifact])
    with pytest.raises(ManifestValidationError, match="symlink"):
        validate_manifest(
            json.loads(manifest_path.read_text(encoding="utf-8")),
            tmp_path,
        )


@pytest.mark.parametrize(
    "mutator",
    [
        lambda a: a.update({"sha256": "A" * 64}),
        lambda a: a.update({"sha256": "g" * 64}),
        lambda a: a.update({"format": "csv"}),
        lambda a: a.update({"format": "json"}),
        lambda a: a.update({"records": True}),
        lambda a: a.update({"path": 123}),
    ],
)
def test_invalid_artifact_contracts_are_rejected(tmp_path: Path, mutator):
    artifact = _artifact(tmp_path, "a.jsonl", [{"record_id": "a-1"}])
    mutator(artifact)
    manifest_path, _ = _manifest(tmp_path, artifacts=[artifact])
    with pytest.raises(ManifestValidationError):
        validate_manifest(
            json.loads(manifest_path.read_text(encoding="utf-8")),
            tmp_path,
        )


def test_duplicate_record_ids_are_rejected(tmp_path: Path):
    artifact = _artifact(
        tmp_path,
        "a.jsonl",
        [{"record_id": "dup"}, {"record_id": "dup"}],
    )
    manifest_path, _ = _manifest(tmp_path, artifacts=[artifact])
    with pytest.raises(ManifestValidationError, match="duplicate record_id"):
        validate_manifest(
            json.loads(manifest_path.read_text(encoding="utf-8")),
            tmp_path,
        )


def test_invalid_explicit_record_identifier_is_rejected(tmp_path: Path):
    artifact = _artifact(
        tmp_path,
        "a.jsonl",
        [{"record_id": "../bad"}],
    )
    manifest_path, _ = _manifest(tmp_path, artifacts=[artifact])
    with pytest.raises(ManifestValidationError, match="record_id"):
        validate_manifest(
            json.loads(manifest_path.read_text(encoding="utf-8")),
            tmp_path,
        )


@pytest.mark.parametrize(
    "text",
    [
        '{"record_id":"a","value":1,"value":2}\n',
        '{"record_id":"a","value":NaN}\n',
        '{"record_id":"a","value":Infinity}\n',
        "not-json\n",
    ],
)
def test_non_strict_or_malformed_json_is_rejected(tmp_path: Path, text: str):
    path = tmp_path / "a.jsonl"
    path.write_text(text, encoding="utf-8")
    artifact = {
        "path": "a.jsonl",
        "format": "jsonl",
        "records": 1,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }
    manifest_path, _ = _manifest(tmp_path, artifacts=[artifact])
    with pytest.raises(ManifestValidationError):
        validate_manifest(
            json.loads(manifest_path.read_text(encoding="utf-8")),
            tmp_path,
        )


def test_json_collection_and_iter_records_are_supported(tmp_path: Path):
    path = tmp_path / "records.json"
    path.write_text(
        json.dumps({"records": [{"record_id": "one"}, {"record_id": "two"}]}),
        encoding="utf-8",
    )
    assert count_records(path) == 2
    assert [row["record_id"] for row in iter_records(path)] == ["one", "two"]
    artifact = {
        "path": "records.json",
        "format": "json",
        "records": 2,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }
    manifest_path, _ = _manifest(tmp_path, artifacts=[artifact])
    assert validate_manifest(
        json.loads(manifest_path.read_text(encoding="utf-8")),
        tmp_path,
    )["record_count"] == 2


def test_multiple_json_collection_keys_are_rejected(tmp_path: Path):
    path = tmp_path / "records.json"
    path.write_text(
        json.dumps({"records": [{"record_id": "one"}], "items": [{"record_id": "two"}]}),
        encoding="utf-8",
    )
    artifact = {
        "path": "records.json",
        "format": "json",
        "records": 2,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }
    manifest_path, _ = _manifest(tmp_path, artifacts=[artifact])
    with pytest.raises(ManifestValidationError, match="multiple record collections"):
        validate_manifest(
            json.loads(manifest_path.read_text(encoding="utf-8")),
            tmp_path,
        )


def test_limits_prevent_unbounded_input(tmp_path: Path):
    artifact = _artifact(tmp_path, "a.jsonl", [{"record_id": "one"}, {"record_id": "two"}])
    manifest_path, manifest = _manifest(tmp_path, artifacts=[artifact])
    with pytest.raises(ManifestValidationError, match="record limit"):
        validate_manifest(manifest, tmp_path, max_records=1)

    with pytest.raises(ManifestValidationError, match="artifact size"):
        validate_manifest(manifest, tmp_path, max_artifact_bytes=1)


def test_database_tampering_is_detected(tmp_path: Path):
    artifact = _artifact(tmp_path, "a.jsonl", [{"record_id": "a-1", "value": "clean"}])
    manifest_path, manifest = _manifest(tmp_path, artifacts=[artifact])
    db = tmp_path / "datasets.sqlite"
    ingest_and_verify(manifest_path, tmp_path, db)

    with sqlite3.connect(db) as conn:
        conn.execute(
            """
            update records
            set payload_json='{"record_id":"a-1","value":"tampered"}'
            where dataset_id=? and artifact_path=? and record_id=?
            """,
            (manifest["dataset_id"], "a.jsonl", "a-1"),
        )

    result = verify_store(db, tmp_path, dataset_id=manifest["dataset_id"])
    assert result["ok"] is False
    assert any("stored payload mismatch" in error for error in result["errors"])


def test_source_tampering_after_ingestion_is_detected(tmp_path: Path):
    artifact = _artifact(tmp_path, "a.jsonl", [{"record_id": "a-1", "value": "clean"}])
    manifest_path, manifest = _manifest(tmp_path, artifacts=[artifact])
    db = tmp_path / "datasets.sqlite"
    ingest_and_verify(manifest_path, tmp_path, db)

    path = tmp_path / "a.jsonl"
    path.write_text(
        path.read_text(encoding="utf-8").replace("clean", "tampered"),
        encoding="utf-8",
    )
    result = verify_store(db, tmp_path, dataset_id=manifest["dataset_id"])
    assert result["ok"] is False
    assert any("manifest verification failed" in error for error in result["errors"])


def test_failed_ingestion_does_not_partially_replace_existing_dataset(tmp_path: Path):
    good = _artifact(tmp_path, "a.jsonl", [{"record_id": "keep", "value": "good"}])
    manifest_path, manifest = _manifest(
        tmp_path,
        dataset_id="transactional",
        artifacts=[good],
    )
    db = tmp_path / "datasets.sqlite"
    ingest_manifest(manifest_path, tmp_path, db)

    bad = _artifact(tmp_path, "b.jsonl", [{"record_id": "new"}])
    bad["sha256"] = "0" * 64
    manifest["artifacts"] = [good, bad]
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ManifestValidationError):
        ingest_manifest(manifest_path, tmp_path, db)

    with sqlite3.connect(db) as conn:
        rows = conn.execute(
            "select artifact_path,record_id,payload_json from records where dataset_id=?",
            ("transactional",),
        ).fetchall()
        assert rows == [("a.jsonl", "keep", '{"record_id":"keep","value":"good"}')]


def test_manifest_mutation_during_transaction_rolls_back(tmp_path: Path, monkeypatch):
    import ai_cyber_os.dataset_pipeline as pipeline

    artifact = _artifact(tmp_path, "a.jsonl", [{"record_id": "a-1", "value": "stable"}])
    manifest_path, manifest = _manifest(
        tmp_path,
        dataset_id="manifest-race",
        artifacts=[artifact],
    )
    db = tmp_path / "datasets.sqlite"

    original_scan = pipeline._scan_artifact
    calls = {"count": 0}

    def wrapped_scan(*args, **kwargs):
        result = original_scan(*args, **kwargs)
        calls["count"] += 1
        if calls["count"] == 2:
            manifest["version"] = "9.9.9"
            manifest_path.write_text(
                json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        return result

    monkeypatch.setattr(pipeline, "_scan_artifact", wrapped_scan)
    with pytest.raises(DatasetIntegrityError, match="manifest changed"):
        ingest_manifest(manifest_path, tmp_path, db)

    with sqlite3.connect(db) as conn:
        assert conn.execute("select count(*) from dataset_catalog").fetchone()[0] == 0
        assert conn.execute("select count(*) from records").fetchone()[0] == 0


def test_cli_returns_nonzero_on_integrity_failure(tmp_path: Path):
    artifact = _artifact(tmp_path, "a.jsonl", [{"record_id": "a-1"}])
    manifest_path, _ = _manifest(tmp_path, artifacts=[artifact])
    (tmp_path / "a.jsonl").write_text('{"record_id":"changed"}\n', encoding="utf-8")
    db = tmp_path / "cli.sqlite"

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "ai_cyber_os.dataset_pipeline",
            "--manifest",
            str(manifest_path),
            "--root",
            str(tmp_path),
            "--db",
            str(db),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode != 0
    assert "SHA256 mismatch" in proc.stderr


def test_fixture_db_is_cleaned_up():
    if FIXTURE_DB.exists():
        FIXTURE_DB.unlink()
    assert not FIXTURE_DB.exists()
