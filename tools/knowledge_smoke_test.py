#!/usr/bin/env python3
"""Self-contained smoke test for the AI-CYBER knowledge pipeline."""
from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path

from ai_cyber_os.dataset_pipeline import ingest_manifest, inspect_dataset
from ai_cyber_os.intelligence import correlate


def main() -> int:
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        dataset = root / "datasets" / "smoke.jsonl"
        manifests = root / "datasets" / "manifests"
        manifests.mkdir(parents=True)
        payload = (
            '{"id":"CVE-2099-0001","title":"Smoke CVE","description":'
            '"remote code execution; CWE-78; ATT&CK T1059.001"}\n'
        )
        dataset.write_text(payload, encoding="utf-8")
        manifest = manifests / "smoke.json"
        manifest.write_text(json.dumps({
            "dataset": "smoke-threat-intel",
            "version": "1",
            "source": "local-smoke-fixture",
            "source_uri": "https://example.invalid/smoke",
            "license": "CC0",
            "local_path": "datasets/smoke.jsonl",
            "sha256": hashlib.sha256(payload.encode()).hexdigest(),
            "record_count": 1,
            "schema": {"type": "jsonl"},
            "ingestion_status": "ready",
            "validation_status": "fixture-validated",
        }), encoding="utf-8")
        db = root / "knowledge.db"
        inspected = inspect_dataset(manifest)
        assert inspected["ready"] is True, inspected
        ingested = ingest_manifest(manifest, db_path=db)
        assert ingested["inserted"] == 1, ingested
        result = correlate("CVE-2099-0001", db_path=str(db))
        assert result["related"]["CVE-2099-0001"], result
        print(json.dumps({
            "success": True,
            "records": ingested["records_seen"],
            "relations": sum(len(v) for v in result["related"].values()),
        }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
