"""Canonical intelligence facade used by HYDRA-facing callers.

Keeps retrieval separate from the historical HYDRA implementation while
providing one stable contract for runtime/UI/evaluation integrations.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from .rag import build_context
from .knowledge import DEFAULT_DB


def analyze(query: str, *, db_path: str | Path = DEFAULT_DB,
            limit: int = 8, dataset: str | None = None) -> dict[str, Any]:
    """Return only locally indexed, provenance-preserving evidence."""
    if not isinstance(query, str) or not query.strip():
        raise ValueError("query must be non-empty")
    context = build_context(query.strip(), db_path=db_path, limit=limit, dataset=dataset)
    return {
        "success": True,
        "query": context["query"],
        "evidence_only": True,
        "evidence": context["evidence"],
        "identifiers": context["identifiers"],
        "related": context["related"],
        "answer": None,
        "answer_status": "not_generated",
    }
