"""Integrated local-first backend for lexical RAG plus connected security knowledge."""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .knowledge import KnowledgeStore
from .relationships import CrossDatasetRelationshipStore, node_id_for_record
from .security_families import SecurityFamilyError, SecurityFamilyStore, SecurityKnowledgeRecord, normalize_record

SCHEMA_VERSION = "knowledge_rag_backend.v1"

class BackendIntegrationError(RuntimeError):
    """Raised when the integrated backend contract cannot be maintained."""

@dataclass(frozen=True)
class BackendLimits:
    max_graph_depth: int = 3
    max_graph_nodes_per_hit: int = 100
    max_combined_hits: int = 100
    max_context_chars: int = 12_000

    def __post_init__(self) -> None:
        if isinstance(self.max_graph_depth, bool) or not 0 <= self.max_graph_depth <= 8:
            raise BackendIntegrationError("max_graph_depth must be between 0 and 8")
        if isinstance(self.max_graph_nodes_per_hit, bool) or not 1 <= self.max_graph_nodes_per_hit <= 5000:
            raise BackendIntegrationError("max_graph_nodes_per_hit must be between 1 and 5000")
        if isinstance(self.max_combined_hits, bool) or not 1 <= self.max_combined_hits <= 5000:
            raise BackendIntegrationError("max_combined_hits must be between 1 and 5000")
        if isinstance(self.max_context_chars, bool) or not 256 <= self.max_context_chars <= 1_000_000:
            raise BackendIntegrationError("max_context_chars must be between 256 and 1000000")

class KnowledgeRAGBackend:
    """Facade joining the #1 lexical index with the #4 connected graph.

    Retrieval only: no LLM calls, command execution, or autonomous actions.
    """

    SCHEMA_VERSION = SCHEMA_VERSION

    def __init__(self, knowledge_db: str | Path, relationship_db: str | Path, *, limits: BackendLimits | None = None):
        self.knowledge = KnowledgeStore(knowledge_db)
        self.relationships = CrossDatasetRelationshipStore(relationship_db)
        self.limits = limits or BackendLimits()

    @staticmethod
    def _validate_records(records: Iterable[SecurityKnowledgeRecord]) -> list[SecurityKnowledgeRecord]:
        normalized = list(records)
        for record in normalized:
            if not isinstance(record, SecurityKnowledgeRecord):
                raise BackendIntegrationError("records must be SecurityKnowledgeRecord instances")
            if not record.source_dataset or not record.source_artifact:
                raise BackendIntegrationError(f"{record.record_id}: source_dataset and source_artifact are required")
        return normalized

    def ingest_records(self, records: Iterable[SecurityKnowledgeRecord], *, resolve_relationships: bool = True) -> dict[str, Any]:
        """Synchronize canonical records into both stores after full pre-validation."""
        normalized = self._validate_records(records)
        graph_result = self.relationships.ingest_records(normalized)
        for record in normalized:
            self.knowledge.upsert_record(
                dataset_id=record.source_dataset, artifact_path=record.source_artifact,
                record_id=record.record_id, payload=record.canonical_payload,
                source=record.source_dataset, version=record.source_version,
            )
        declarations = self.relationships.resolve_declared_links() if resolve_relationships else {"resolved": 0, "orphan": 0, "ambiguous": 0, "pending": 0}
        typed = self.relationships.resolve_typed_relationships() if resolve_relationships else {"created": 0, "skipped_ambiguous": 0}
        integrity = self.verify_integrity()
        if not integrity["ok"]:
            raise BackendIntegrationError("backend integrity gate failed: " + "; ".join(integrity["errors"]))
        return {"records": len(normalized), "knowledge_records": self.knowledge.count(), "graph": graph_result, "declarations": declarations, "typed_relationships": typed, "integrity": integrity}

    def ingest_family_store(self, family_store_db: str | Path) -> dict[str, Any]:
        """Import only from an integrity-verified #3 security-family SQLite store."""
        family_store_db = Path(family_store_db)
        source = SecurityFamilyStore(family_store_db)
        source_integrity = source.verify_integrity()
        if not source_integrity["ok"]:
            raise BackendIntegrationError("security-family source integrity failed: " + "; ".join(source_integrity["errors"]))
        records: list[SecurityKnowledgeRecord] = []
        with sqlite3.connect(family_store_db) as db:
            rows = db.execute("SELECT record_id,payload_json,content_hash FROM security_records ORDER BY record_id").fetchall()
        for record_id, payload_json, stored_hash in rows:
            try:
                record = normalize_record(json.loads(payload_json))
            except (json.JSONDecodeError, SecurityFamilyError) as exc:
                raise BackendIntegrationError(f"invalid family record {record_id}: {exc}") from exc
            if record.content_hash != stored_hash:
                raise BackendIntegrationError(f"family record hash mismatch: {record_id}")
            records.append(record)
        result = self.ingest_records(records)
        result["source_family_store"] = str(family_store_db)
        result["source_integrity"] = source_integrity
        return result

    def query(self, query: str, *, top_k: int = 5, graph_depth: int | None = None, graph_limit: int | None = None, max_context_chars: int | None = None, dataset_id: str | None = None, source: str | None = None, version: str | None = None) -> dict[str, Any]:
        """Run lexical retrieval followed by bounded graph expansion."""
        depth = self.limits.max_graph_depth if graph_depth is None else graph_depth
        limit = self.limits.max_graph_nodes_per_hit if graph_limit is None else graph_limit
        context_limit = self.limits.max_context_chars if max_context_chars is None else max_context_chars
        if isinstance(depth, bool) or not isinstance(depth, int) or not 0 <= depth <= 8:
            raise BackendIntegrationError("graph_depth must be an integer between 0 and 8")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 5000:
            raise BackendIntegrationError("graph_limit must be an integer between 1 and 5000")
        if isinstance(context_limit, bool) or not isinstance(context_limit, int) or not 256 <= context_limit <= 1_000_000:
            raise BackendIntegrationError("max_context_chars must be an integer between 256 and 1000000")
        lexical_hits = self.knowledge.search(query, limit=top_k, dataset_id=dataset_id, source=source, version=version)
        combined: list[dict[str, Any]] = []
        seen: set[str] = set()
        paths: list[dict[str, Any]] = []
        for hit in lexical_hits:
            if hit["doc_id"] not in seen:
                combined.append({**hit, "retrieval_source": "lexical", "graph_depth": 0})
                seen.add(hit["doc_id"])
            start = node_id_for_record(hit["dataset_id"], hit["artifact_path"], hit["record_id"])
            traversal = self.relationships.traverse(start, max_depth=depth, direction="both", limit=limit)
            for item in traversal[1:]:
                node = self.relationships.get_node(item["node_id"])
                if node is None or node.node_type != "record":
                    continue
                related = self.knowledge.get_record(node.dataset_id, node.artifact_path, node.record_id)
                if related is None:
                    continue
                paths.append({
                    "from_record_id": hit["record_id"], "from_dataset": hit["dataset_id"],
                    "record_id": node.record_id, "dataset_id": node.dataset_id,
                    "artifact_path": node.artifact_path, "depth": item["depth"],
                    "via_relation": item["via_relation"], "edge_direction": item["edge_direction"],
                })
                if related["doc_id"] in seen:
                    continue
                combined.append({**related, "retrieval_source": "graph", "graph_depth": item["depth"], "rank": len(combined) + 1})
                seen.add(related["doc_id"])
                if len(combined) >= self.limits.max_combined_hits:
                    break
            if len(combined) >= self.limits.max_combined_hits:
                break
        for rank, hit in enumerate(combined, 1):
            hit["rank"] = rank
        packet = self.knowledge.prepare_context(combined, max_chars=context_limit)
        packet.update({
            "schema_version": SCHEMA_VERSION, "query": query, "hits": combined,
            "lexical_hits": lexical_hits, "graph_relationships": paths,
            "graph_expanded_hits": sum(h["retrieval_source"] == "graph" for h in combined),
            "bounded": True,
        })
        return packet

    def verify_integrity(self) -> dict[str, Any]:
        """Require both component stores to be healthy and record counts to align."""
        knowledge = self.knowledge.verify_integrity()
        graph = self.relationships.verify_integrity()
        knowledge_records = self.knowledge.count()
        graph_records = self.relationships.count(node_type="record")
        errors: list[str] = []
        if not knowledge["ok"]: errors.append("knowledge store integrity failure")
        if not graph["ok"]: errors.append("relationship store integrity failure")
        if knowledge_records != graph_records:
            errors.append(f"record count mismatch: knowledge={knowledge_records}, graph={graph_records}")
        return {"ok": not errors, "schema_version": SCHEMA_VERSION, "knowledge": knowledge, "relationships": graph, "knowledge_records": knowledge_records, "graph_records": graph_records, "record_count_aligned": knowledge_records == graph_records, "errors": errors}

    def health(self) -> dict[str, Any]:
        integrity = self.verify_integrity()
        return {"ok": integrity["ok"], "schema_version": SCHEMA_VERSION, "knowledge": self.knowledge.health(), "relationships": self.relationships.health(), "record_count_aligned": integrity["record_count_aligned"], "errors": integrity["errors"]}

__all__ = ["BackendIntegrationError", "BackendLimits", "KnowledgeRAGBackend", "SCHEMA_VERSION"]
