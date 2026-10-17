"""Tests for the read-only runtime gate used by the persistent RAG/API."""
from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

import pytest

from ai_cyber_os.knowledge import ingest_file
from ai_cyber_os.knowledge_runtime import (
    APPROVED_DATASETS,
    KnowledgeRuntimeBlocked,
    configured_database_path,
    require_runtime_database,
    verify_database,
)


def _make_populated_db(tmp_path: Path, *, extra_dataset: str | None = None) -> Path:
    db_path = tmp_path / "knowledge-v1.sqlite3"
    datasets = list(APPROVED_DATASETS)
    if extra_dataset:
        datasets.append(extra_dataset)

    for index, dataset in enumerate(datasets):
        source_path = tmp_path / f"{dataset}.jsonl"
        source_path.write_text(
            json.dumps({
                "id": f"fixture-{dataset}-{index}",
                "title": f"{dataset} runtime verification fixture",
                "description": f"Unique evidence about {dataset} runtime-verification fixture {index}.",
            }) + "\n",
            encoding="utf-8",
        )
        result = ingest_file(
            source_path,
            db_path=db_path,
            dataset=dataset,
            source="unit-test-fixture",
            source_uri=f"https://fixtures.invalid/knowledge/{dataset}/{index}",
            license="unit-test-only",
            version="fixture-v1",
            validation_status="fixture-verified",
        )
        assert result["success"] is True

    ledger = {
        dataset: hashlib.sha256((dataset + "-manifest").encode("utf-8")).hexdigest()
        for dataset in APPROVED_DATASETS
    }
    connection = sqlite3.connect(db_path)
    try:
        connection.execute(
            "INSERT INTO knowledge_meta(key,value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            ("source_manifest_digests", json.dumps(ledger, sort_keys=True, separators=(",", ":"))),
        )
        connection.commit()
    finally:
        connection.close()
    return db_path


def test_missing_database_is_not_created(tmp_path: Path):
    missing = tmp_path / "not-built-yet.sqlite3"
    result = verify_database(missing, deep=True)
    assert result["success"] is False
    assert result["overall"] == "BLOCKED"
    assert "does not exist" in result["errors"][0]
    assert not missing.exists()


def test_strict_runtime_fails_closed_without_creating_missing_db(tmp_path: Path, monkeypatch):
    missing = tmp_path / "published-db-not-mounted.sqlite3"
    monkeypatch.setenv("AI_CYBER_KNOWLEDGE_DB", str(missing))
    monkeypatch.setenv("AI_CYBER_REQUIRE_VERIFIED_DB", "1")
    assert configured_database_path() == missing
    with pytest.raises(KnowledgeRuntimeBlocked, match="not runtime-ready"):
        require_runtime_database()
    assert not missing.exists()


def test_populated_exact_11_dataset_db_passes_deep_read_only_gate(tmp_path: Path):
    db_path = _make_populated_db(tmp_path)
    before = hashlib.sha256(db_path.read_bytes()).hexdigest()
    result = verify_database(db_path, deep=True)
    after = hashlib.sha256(db_path.read_bytes()).hexdigest()

    assert result["success"] is True
    assert result["overall"] == "PASS"
    assert result["sqlite_integrity_check"] == "ok"
    assert result["records"] == len(APPROVED_DATASETS)
    assert set(result["datasets"]) == set(APPROVED_DATASETS)
    assert result["knowledge_fts_rows"] == result["records"]
    assert result["chunk_fts_rows"] == result["chunks"]
    assert result["source_manifest_ledger_verified"] is True
    assert before == after, "read-only verification must not modify the database"


def test_out_of_scope_nvd_dataset_is_rejected(tmp_path: Path):
    db_path = _make_populated_db(tmp_path, extra_dataset="nvd_cve")
    result = verify_database(db_path, deep=False)
    assert result["success"] is False
    assert "nvd_cve" in result["unexpected_datasets"]
    assert any("outside the approved scope" in error for error in result["errors"])


def test_changed_or_incomplete_manifest_ledger_is_rejected(tmp_path: Path):
    db_path = _make_populated_db(tmp_path)
    connection = sqlite3.connect(db_path)
    try:
        connection.execute(
            "UPDATE knowledge_meta SET value=? WHERE key='source_manifest_digests'",
            (json.dumps({"capec": "not-a-sha256"}),),
        )
        connection.commit()
    finally:
        connection.close()

    result = verify_database(db_path, deep=False)
    assert result["success"] is False
    assert result["source_manifest_ledger_verified"] is False
    assert any("exactly cover" in error for error in result["errors"])
    assert any("SHA-256" in error for error in result["errors"])
