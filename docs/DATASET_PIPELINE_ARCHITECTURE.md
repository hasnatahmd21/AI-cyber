# AI-CYBER Dataset Pipeline

## Purpose

The dataset pipeline is the canonical ingestion boundary between repository dataset artifacts and local SQLite knowledge data. It must reject unverifiable or unsafe inputs rather than silently normalizing them.

## Contract

A manifest declares a schema version, stable dataset identifier and version, repository-relative artifact paths, explicit artifact format, expected record count, exact SHA-256 digest, and provenance metadata.

Supported artifact formats are json, jsonl, and ndjson. JSON records must be objects. JSONL/NDJSON ignores blank lines but validates every non-empty line as one JSON object.

## Integrity model

Validation is deterministic and strict:

1. Manifest and artifact paths must remain inside the dataset root.
2. Absolute paths, traversal components, non-canonical paths, and symlinks are rejected.
3. Artifact format must match the filename extension.
4. SHA-256 values must be lowercase 64-character hexadecimal strings.
5. Record counts are checked against the parsed records.
6. Duplicate JSON keys and non-standard JSON constants are rejected.
7. Explicit record identifiers must be safe, non-empty identifiers and must be unique inside each artifact.
8. Configurable artifact-size and record-count limits prevent unbounded ingestion.

## Transactional ingestion

The target SQLite store is updated inside one transaction. Existing records for a dataset artifact are replaced atomically, while artifacts removed from the current manifest are reconciled out of the store. A source mutation detected during the second pass causes rollback rather than partial replacement.

The store records dataset catalog metadata and manifest SHA-256, artifact metadata and provenance, canonicalized record payloads, and per-record payload SHA-256 hashes.

## Post-ingest verification

The verify_store function checks the stored catalog, manifest, artifact set, source artifact hashes and counts, database counts, record identities, and canonical payload hashes. The ingest_and_verify function uses that check as a release gate.

The resulting chain is:

manifest -> source artifact -> validated records -> SQLite -> integrity verification

No generative model, remote API, or fabricated evidence is involved in this layer.

## Compatibility

Manifest schema v1 remains readable for migration compatibility, while repository canonical fixtures use schema v2. The SQLite layer also performs additive migration of fields introduced by the hardened implementation.

## CI gate

The dataset-pipeline-hardening workflow runs Python compilation, the full adversarial dataset-pipeline regression suite, and an explicit canonical manifest -> SQLite -> verification smoke gate.

The dataset pipeline gate is intentionally scoped to this component so unrelated legacy runtime tests cannot mask or falsely fail the dataset contract.
