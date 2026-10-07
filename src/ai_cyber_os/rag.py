"""Evidence-backed retrieval context for AI-CYBER.

This layer deliberately does not generate conclusions. It retrieves records from
the local knowledge store and formats only source-backed evidence for a caller
(HYDRA, an evaluator, or a future local model).
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from .knowledge import DEFAULT_DB, search


def retrieve(
    query: str,
    *,
    db_path: str | Path = DEFAULT_DB,
    limit: int = 8,
    dataset: str | None = None,
) -> list[dict[str, Any]]:
    return search(query, db_path=db_path, limit=limit, dataset=dataset)


def build_context(
    query: str,
    *,
    db_path: str | Path = DEFAULT_DB,
    limit: int = 8,
    dataset: str | None = None,
) -> dict[str, Any]:
    records = retrieve(query, db_path=db_path, limit=limit, dataset=dataset)
    evidence = []
    for record in records:
        evidence.append(
            {
                "record_id": record["record_id"],
                "dataset": record["dataset"],
                "title": record.get("title", ""),
                "content": record["content"],
                "source": record["source"],
                "source_uri": record.get("source_uri") or "",
                "license": record.get("license") or "",
                "version": record.get("version") or "",
                "validation_status": record.get("validation_status") or "unverified",
                "content_sha256": record["content_sha256"],
                "score": record.get("score"),
            }
        )
    return {
        "query": query,
        "evidence": evidence,
        "count": len(evidence),
        "evidence_only": True,
    }
