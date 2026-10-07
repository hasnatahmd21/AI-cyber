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

Large raw datasets stay outside GitHub. local_path is relative to the
repository root when a local copy is available. The pipeline verifies the
checksum and record count before indexing.

ready=true means the local integrity and ingestion gates passed. It does not
mean the upstream source was independently validated.
