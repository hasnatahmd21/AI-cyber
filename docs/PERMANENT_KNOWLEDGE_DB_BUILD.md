# Permanent Knowledge DB build runner

This branch adds a guarded, single-command orchestration layer for the existing
AI-CYBER dataset-manifest, ingestion, and evidence-only RAG code.

## What the runner does

- Downloads NVD 2.0 yearly + recent + modified feeds and writes the NVD manifest.
- Uses resumable HTTP transfers and validates HTTP Range behavior.
- Runs the combined source-specific parser/readiness gate.
- Calls ingest_manifest_directory with the locked 12 raw sources. That function
  preflights the complete manifest set before opening the target DB.
- Keeps source attribution, hashes, validation status, chunk/FTS indexes,
  relationship extraction, and ingestion checkpoints through the existing code.
- Derives CVSS records from stored NVD evidence and verifies the derived records.
- Runs SQLite integrity/FTS checks and real-record RAG retrieval probes with
  source/provenance fields.
- Writes a JSON build report containing the result, record counts, DB hash, and
  per-dataset evidence.

It does not upload raw feeds or push commits. It never deletes or silently
replaces an existing DB. It only resumes an existing build if its source-manifest
digest ledger matches the exact current manifest snapshot.

## Run on the intended Kaggle working branch

Use Python 3.11+ and ensure the working tree is the
fix/dataset-parser-readiness branch containing the 12-source manifests, raw
artifacts, NVD scripts, Knowledge DB, and RAG code. The runner must not be placed
in main or run against an unrelated checkout.

Install the project dependencies, then execute:

    python -m pip install -e .
    python scripts/build_permanent_knowledge_db.py

Default target:

    /kaggle/working/AI-CYBER-Knowledge-DB/ai_cyber_knowledge.sqlite3

Default JSON report:

    build-output/knowledge-db-build-report.json

A run that reports BLOCKED/FAIL has not passed. In particular, no ingestion
should begin until NVD manifest creation and the combined 12-source gate pass.
The database and report should be saved/exported from Kaggle if they must survive
a future session reset; /kaggle/working is a session workspace, not by itself a
cross-session persistence guarantee.

## Test coverage added

tests/test_resumable_download.py checks that a truncated HTTP transfer resumes
from the retained partial and that a server ignoring Range requests triggers a
safe restart rather than appending a duplicate body.

    python -m pytest -q tests/test_resumable_download.py
