"""Evidence correlation helpers for AI-CYBER threat intelligence."""
from __future__ import annotations

import re
from typing import Any

from .knowledge import open_store, search

PATTERNS = {
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I),
    "cwe": re.compile(r"\bCWE-\d+\b", re.I),
    "attack": re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.I),
    "cpe": re.compile(r"\bcpe:2\.3:[^\s\"']+", re.I),
}


def extract_identifiers(text: str) -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}
    for kind, pattern in PATTERNS.items():
        values = sorted({m.upper() for m in pattern.findall(text)})
        if values:
            found[kind] = values
    return found


def correlate(
    query: str,
    *,
    db_path: str,
    limit: int = 10,
    dataset: str | None = None,
) -> dict[str, Any]:
    hits = search(query, db_path=db_path, limit=limit, dataset=dataset)
    identifiers = extract_identifiers(query)
    for hit in hits:
        hit["identifiers"] = extract_identifiers(
            f'{hit.get("title", "")} {hit.get("content", "")}'
        )
    related: dict[str, list[dict[str, Any]]] = {}
    db = open_store(db_path)
    try:
        for kind, values in identifiers.items():
            for identifier in values:
                rows = db.execute(
                    """SELECT r.record_id, r.dataset, r.source, r.version,
                              r.validation_status, r.title, r.content_sha256
                       FROM knowledge_relations rel
                       JOIN knowledge_records r ON r.record_id=rel.record_id
                       WHERE rel.relation_type=? AND rel.target_id=?
                       ORDER BY r.dataset, r.record_id LIMIT ?""",
                    (kind, identifier, limit),
                ).fetchall()
                related[identifier] = [dict(row) for row in rows]
    finally:
        db.close()
    return {
        "success": True,
        "query": query,
        "identifiers": identifiers,
        "results": hits,
        "related": related,
        "evidence_only": True,
    }
