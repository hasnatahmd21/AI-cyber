# Knowledge / RAG pipeline

AI-CYBER now has a local-first evidence pipeline:

dataset
  -> manifest
  -> SHA-256 + record-count gate
  -> JSONL/NDJSON/JSON/CSV/TXT/MD normalization
  -> provenance + content hash
  -> SQLite knowledge store
  -> FTS5 retrieval
  -> CVE/CWE/ATT&CK/CPE identifier relations
  -> evidence correlation

## Dataset workflow

1. Put a small test fixture under the appropriate datasets directory, or keep
   the real dataset outside GitHub.
2. Create a manifest under datasets/manifests/.
3. Set the source, license, version, checksum and expected record count.
4. Inspect before indexing.
5. Ingest only after the manifest gates pass.
6. Query evidence with the knowledge CLI.

Example commands:

    python tools/ingest_dataset.py datasets/manifests/example.json --db ~/.ai-cyber/knowledge.db --inspect
    python tools/ingest_dataset.py datasets/manifests/example.json --db ~/.ai-cyber/knowledge.db
    ai-cyber-knowledge search "remote code execution"
    ai-cyber-knowledge correlate "CVE-2026-1234"
    ai-cyber-knowledge status

correlate returns source, version, validation status and content hashes for
related evidence. It does not invent a relationship when the identifier is
not present in indexed records.

## Integrity boundary

validation_status is provenance metadata. A local ingestion pass does not mean
the upstream dataset is independently verified. Failed checksum or record
count gates stop indexing by default.

Large raw datasets, malware binaries, and other non-redistributable material
must remain outside the Git repository and be represented by manifests.

## Supported threat-intelligence adapters

The offline source adapters accept operator-downloaded files and preserve the
manifest's provenance instead of silently fetching or trusting remote content:

- `nvd` — NVD CVE JSON 2.x, including NVD metrics/CVSS fields.
- `cisa-kev` — CISA Known Exploited Vulnerabilities JSON.
- `attack-stix` — MITRE ATT&CK STIX 2.0/2.1 JSON.
- `cwe-xml` — MITRE CWE XML exports.
- `cpe` — common NVD CPE JSON/XML exports.

Example:

    ai-cyber-knowledge ingest-source nvd /path/to/nvdcve.json --version 2.0 --validation-status source-checked

The official NVD feed documentation describes the 2.0 JSON vulnerability and CPE
feeds and the use of modified feeds for synchronization. citeturn0search1turn0search2
MITRE documents ATT&CK STIX as the machine-readable source for automated
ingestion, and CWE publishes XML downloads for current releases. citeturn0search6turn0search0
The official CPE dictionary is maintained under NIST/NVD responsibility. citeturn0search3

These references describe upstream formats; they do not make a local dataset
validated. The manifest validation_status remains the authoritative local
provenance label.
