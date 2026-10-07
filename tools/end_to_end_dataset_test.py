#!/usr/bin/env python3
"""Complete offline dataset -> manifest -> integrity -> ingest -> RAG test."""
from __future__ import annotations
import argparse, hashlib, json, tempfile
from pathlib import Path
from ai_cyber_os.continuous_update import update_from_manifests
from ai_cyber_os.dataset_pipeline import ingest_manifest, sha256_file
from ai_cyber_os.rag import build_context

def main() -> int:
    p = argparse.ArgumentParser(); p.add_argument("--keep", action="store_true"); args = p.parse_args()
    ctx = tempfile.TemporaryDirectory(prefix="ai-cyber-e2e-"); root = Path(ctx.name); data_dir = root / "datasets"; data_dir.mkdir()
    data = data_dir / "fixture.jsonl"
    data.write_text(json.dumps({"id":"CVE-2099-7000","description":"CWE-79 network fixture"})+"\n"+json.dumps({"id":"T1059","description":"command fixture"})+"\n", encoding="utf-8")
    manifest = data_dir / "fixture.manifest.json"
    manifest.write_text(json.dumps({"dataset":"e2e-fixture","version":"1","source":"offline-fixture","source_uri":"local://e2e","license":"test","local_path":"datasets/fixture.jsonl","sha256":sha256_file(data),"record_count":2,"schema":{"type":"object"},"ingestion_status":"ready","validation_status":"fixture-validated"}, indent=2), encoding="utf-8")
    db = root / "knowledge.db"
    result = ingest_manifest(manifest, db_path=db)
    assert result["ready"] and result["inspection"]["sha256_matches"]
    context = build_context("CVE-2099-7000", db_path=db)
    assert context["evidence_only"] and context["evidence"][0]["record_id"] == "CVE-2099-7000"
    state = root / "update-state.json"
    update = update_from_manifests([manifest], db_path=db, state_path=state)
    assert update["success"]
    repeat = update_from_manifests([manifest], db_path=db, state_path=state)
    assert repeat["unchanged"] == 1
    print(json.dumps({"success":True,"records":2,"sha256":result["inspection"]["sha256"],"rag_evidence_only":True,"first_update_ingested":update["ingested"],"repeat_unchanged":repeat["unchanged"]}, indent=2))
    if args.keep: print("artifacts="+str(root)); ctx = None
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
