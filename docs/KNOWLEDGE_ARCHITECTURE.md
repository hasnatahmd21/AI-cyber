# AI-CYBER Knowledge / RAG Foundation

The AI-CYBER knowledge layer is a local-first, provider-free retrieval foundation.
It uses SQLite + FTS5 as the deterministic lexical index and never treats
retrieval itself as proof that a claim is true.

## Canonical flow

1. The dataset pipeline validates artifact hashes and record counts.
2. Validated records are stored in the canonical SQLite dataset store.
3. KnowledgeStore.ingest_dataset_store() atomically replaces the represented
   dataset slice in the knowledge store and carries artifact provenance forward.
4. FTS5 indexes the canonical payload for deterministic lexical retrieval.
5. search() returns ranked, traceable evidence with dataset/artifact/record IDs,
   provenance, a snippet, and both raw BM25 score and a higher-is-better
   relevance value.
6. retrieve_context() creates a bounded evidence packet plus citations for a
   later generation layer.

## Retrieval safety

Caller-supplied FTS operators are not executed as FTS syntax. Queries are
tokenized and converted into quoted terms. Retrieval uses strict AND matching
first and falls back to OR matching only when strict matching returns no rows.

Optional exact filters are available for dataset_id, source, and version.
Result ordering is deterministic by BM25 score and document ID.

## Integrity

Every knowledge document stores a SHA-256 hash of its canonical JSON payload.
verify_integrity() checks document/index counts, orphaned rows, and hashes.
rebuild_index() reconstructs FTS5 exclusively from the canonical document table.

## RAG boundary

The package prepares evidence; it does not generate an LLM answer, claim
that retrieval proves a fact, or fabricate operational/security execution.
That generation/evaluation layer is intentionally separate and can consume the
traceable context packet later.

## Existing-runtime boundary

This foundation is additive. It does not import or replace the canonical
27-phase HYDRA runtime and does not depend on the legacy monolithic source
files retained for forensic purposes.
