# AI-CYBER Knowledge Layer

The knowledge layer is local-first and requires no paid API or embedding service.

Flow:
1. Dataset manifest is validated with SHA256 and record counts.
2. Dataset artifacts are ingested into the canonical SQLite dataset store.
3. KnowledgeStore.ingest_dataset_store() copies records plus provenance into a separate knowledge database.
4. SQLite FTS5 provides deterministic lexical retrieval.
5. Results retain dataset, artifact, record ID, source, version, payload and score for traceability.

This is the deterministic retrieval foundation for the next RAG stage. External/vector embeddings can be added later without replacing the canonical dataset/provenance layer.
