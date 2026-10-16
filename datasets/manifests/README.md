# Dataset manifests

One JSON manifest belongs to each externally sourced dataset.

Required fields:

- dataset, version
- source, source_uri
- license
- local_path
- sha256
- record_count
- schema
- ingestion_status
- validation_status

Large raw datasets may be persisted through Git LFS or another controlled
artifact store. `local_path` is relative to the repository root when a local
copy is available. For multi-artifact datasets, each artifact records its own
path, SHA-256, compressed byte size, logical record count, role, and optional
format-specific `count_kind` used by the readiness parser.

`inspect_dataset(...)` returning `ready=true` means only that the referenced
local artifacts exist and their declared SHA-256, byte-size, and format-specific
record-count checks match. It does **not** mean database ingestion, RAG wiring,
runtime persistence, or retrieval evaluation has passed. Those are later gates.

Keep `ingestion_status` as `not-started` or `pending` until the dedicated
Knowledge DB ingestion stage actually runs. Source acquisition, source readiness,
database ingestion, and RAG/runtime readiness must remain separate states.
The placeholder `example.json` is never a real dataset and must not be counted
or ingested.


## Public-release licence and attribution gate

Public Knowledge DB releases require each source manifest to set `license_verified: true` and record an HTTPS official terms URL. This means the source-level terms were checked for this pinned snapshot; it does **not** grant rights to redistribute unrelated third-party text, references, or rule content embedded in a source. The release builder generates a third-party notices ledger, hashes declared local upstream licence files, and bundles them with the manifest snapshot. Dataset-specific author/copyright notices must be preserved when displaying or exporting retrieved evidence. Suricata rules are treated as a mixed, SID-scoped licence: the public release is rejected if a parsed rule falls in the upstream ETPRO-only SID range.
