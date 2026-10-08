# AI-CYBER Intelligence Integration Evaluation

The integration layer is evidence-first and offline by default.

## Registered evaluation surfaces

- Phase 5 — Network/Threat Intelligence Integration: NVD/CVE + CVSS metadata, CISA KEV, MITRE ATT&CK STIX, CWE, CPE, Suricata EVE, Zeek JSON, parser -> canonical evidence -> SQLite/FTS5 -> RAG/runtime.
- Phase 6 — Malware Intelligence Evaluation: structured hash/feature metadata, identity requirements, canonical evidence, ingestion/RAG/runtime.

These are integration-evaluation labels and do not replace the existing canonical HYDRA Phase 6 governance/security implementation.

## Continuous update

Operators provide downloaded dataset manifests. The updater loads the manifest, verifies path confinement, SHA-256 and record count, ingests verified data, records a fingerprint, and skips unchanged datasets on later runs.

No live feed, credentials, external execution, or fabricated freshness claim is introduced.

## End-to-end verification

tools/end_to_end_dataset_test.py exercises dataset -> manifest -> SHA-256 -> record count -> ingestion -> relations/FTS5 -> RAG -> continuous-update idempotency.


## Phase 13 — Security Evaluation Pipeline

The canonical Phase 13 evaluator is `ai_cyber_os.security_evaluation`. It is
deterministic and model-agnostic: it does not use an LLM to declare evidence
correct.

The evaluation gate covers three layers:

1. Retrieval quality — Precision@k, Recall@k, MRR, and nDCG against a gold
   evidence set.
2. Evidence integrity — required record identity/content/source, trusted
   validation state, SHA-256 recomputation, and optional provenance completeness
   (URI, license, version).
3. Security output validation — structured claims and reasoning steps must cite
   retrieved evidence; security identifiers (CVE/CWE/ATT&CK/CPE) must be
   grounded in those citations; unknown evidence IDs and unsupported identifiers
   fail closed.

The full gate is exposed as:

```bash
ai-cyber-evaluate evaluation/security_cases.json \
  --outputs evaluation/security_outputs.json \
  --db /path/to/knowledge.db
```

The output is a machine-readable JSON report. Non-zero exit status means at
least one configured evaluation gate failed.

The included `evaluation/security_cases.json` and
`evaluation/security_outputs.json` are explicit offline evaluator fixtures.
They are test material only and are not presented as real security
intelligence.

The standalone CI/Kaggle check is:

```bash
python tools/phase13_security_evaluation_test.py
```

It creates its own temporary offline evidence store, verifies a complete
retrieval -> evidence-integrity -> grounded-output run, and then intentionally
tamper-tests a retrieved record to prove the evaluator fails closed.
