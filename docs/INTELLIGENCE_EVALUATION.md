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
