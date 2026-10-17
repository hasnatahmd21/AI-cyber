"""End-to-end sampled evidence/answer-grounding evaluation tests."""
from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

from ai_cyber_os.knowledge import ingest_file
from ai_cyber_os.knowledge_runtime import APPROVED_DATASETS
from ai_cyber_os.security_evaluation_runtime import evaluate_permanent_database


def _make_11_source_db(tmp_path: Path) -> Path:
    db_path = tmp_path / "knowledge-v1.sqlite3"
    for index, dataset in enumerate(APPROVED_DATASETS):
        source_path = tmp_path / f"{dataset}.jsonl"
        body = (
            f"The real dataset fixture describes {dataset.replace('_', ' ')} security evidence. "
            f"Distinctive sample token {dataset.replace('_', '')} verifies exact retrieval."
        )
        source_path.write_text(
            json.dumps({
                "id": f"FIXTURE-{dataset.upper()}-{index}",
                "title": f"{dataset} evidence fixture",
                "description": body,
            }) + "\n",
            encoding="utf-8",
        )
        result = ingest_file(
            source_path,
            db_path=db_path,
            dataset=dataset,
            source="offline-evaluation-fixture",
            source_uri=f"https://fixtures.invalid/{dataset}/{index}",
            license="fixture-only",
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


def test_live_evaluator_checks_ten_real_rows_across_eleven_scope(tmp_path: Path):
    db_path = _make_11_source_db(tmp_path)
    result = evaluate_permanent_database(db_path, deep_verify=True)

    assert result["success"] is True
    assert result["overall"] == "PASS"
    assert result["sample_size_requested"] == 10
    assert result["sample_count"] == result["passed"] == 10
    assert result["failed"] == 0
    assert len(result["source_families_sampled"]) == 10
    assert len(result["source_families_not_sampled"]) == 1
    assert all(row["pass"] for row in result["samples"])
    for row in result["samples"]:
        assert row["checks"]["exact_record_retrieved"] is True
        assert row["checks"]["provenance_matches_selected_db_row"] is True
        assert row["checks"]["evidence_hash_and_validation_pass"] is True
        assert row["checks"]["extractive_output_is_grounded"] is True
        assert row["checks"]["unsupported_identifier_negative_control_rejected"] is True


def test_live_evaluator_fails_closed_for_wrong_sample_size(tmp_path: Path):
    db_path = _make_11_source_db(tmp_path)
    result = evaluate_permanent_database(db_path, sample_size=9, deep_verify=False)
    assert result["success"] is False
    assert result["overall"] == "BLOCKED"
    assert "exactly 10" in result["errors"][0]
