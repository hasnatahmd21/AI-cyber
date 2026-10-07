# AI-CYBER datasets

Datasets are external evidence sources for the local knowledge/RAG pipeline.

## Rules

1. Do not commit large raw datasets blindly. Prefer a source URL, license, version, checksum and an ingestion manifest.
2. Small redistributable fixtures may live under this directory for tests.
3. Every dataset must record provenance and license information.
4. Ingestion normalizes JSONL/NDJSON, JSON, CSV, TXT and Markdown into SQLite FTS5.
5. Duplicate content is detected by SHA-256 and repeated ingestion is idempotent.
6. The knowledge layer is retrieval-only: it does not invent records or claim that a dataset was validated unless ingestion succeeded.

## Suggested layout

```
datasets/
  manifests/
  threat_intel/
  vulnerabilities/
  network/
  malware/
  llm_training/
  evaluation/
```

## CLI

After `pip install -e .`:

```
ai-cyber-knowledge status
ai-cyber-knowledge ingest datasets/vulnerabilities/example.jsonl --dataset cve
ai-cyber-knowledge search "remote code execution"
ai-cyber-knowledge context "remote code execution"
```

The default SQLite store is local to the machine at `~/.ai-cyber/knowledge.db`.
Set `AI_CYBER_REPORT_DIR` only for reports; the knowledge DB is intentionally
kept separate so raw data and operational reports are not mixed.

The `context` command returns evidence-only RAG context with record IDs, provenance, validation status and content hashes; it does not generate security conclusions.
