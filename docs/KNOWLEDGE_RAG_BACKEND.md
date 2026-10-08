# Knowledge/RAG Backend Integration

## Scope
KnowledgeRAGBackend is the #5 integration facade between the #1 SQLite/FTS5 KnowledgeStore, the #3 canonical SecurityKnowledgeRecord contract, and the #4 connected relationship graph.

The backend stays local-first and provider-free. It only retrieves, connects, and packages evidence. It does not call an LLM, execute commands, or turn retrieved data into claims of truth.

## Ingestion
Canonical records are fully pre-validated. The same records are synchronized into the lexical store and relationship graph. Declared relationships and typed relationships are then resolved, followed by an integrated integrity gate.

Family-store import requires the #3 source database to pass its integrity check and revalidates every stored content hash before import.

source_dataset and source_artifact are mandatory for backend identity because both the RAG document ID and graph record-node identity depend on them.

## Retrieval
query() first performs deterministic lexical retrieval. Every lexical hit is mapped to its graph node using the exact dataset/artifact/record identity. A bounded breadth-first traversal then expands connected record nodes.

Connected records are rehydrated from the RAG store by exact identity, so graph expansion cannot silently invent text or use a fuzzy match.

The final packet is produced by KnowledgeStore.prepare_context, preserving bounded context and dataset, artifact, record, source, version, and citation metadata. Each hit also records whether it came from lexical retrieval or graph expansion and the graph depth used.

## Boundaries
FTS query sanitization remains the responsibility of #1. Relationship ambiguity/orphans remain the responsibility of #4. This layer consumes those explicit states and never guesses through them.

No autonomous actions, command execution, external API calls, or LLM generation are part of #5.
