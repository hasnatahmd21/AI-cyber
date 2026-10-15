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
