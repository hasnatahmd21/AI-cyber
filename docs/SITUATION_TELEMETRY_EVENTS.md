# Situation / Telemetry / Events Layer

#6 adds a local-first SQLite store for observed telemetry and security events.

It provides deterministic event identity, UTC normalization, typed event/severity/subject fields, bounded JSON payloads, evidence references, related canonical record IDs, idempotent ingestion, atomic batches, bounded filtering, time-window correlation, situation snapshots, and SHA-256 integrity verification.

Correlation and situation snapshots are evidence grouping only. They do not infer compromise, attribution, attack classification, or remediation.

No network access, LLM inference, command execution, or autonomous action is performed by this layer.
