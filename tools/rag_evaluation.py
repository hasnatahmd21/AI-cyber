#!/usr/bin/env python3
"""Deterministic evidence-retrieval evaluation runner.

Evaluation cases specify a query and expected record IDs. No LLM judgement is
used, so regressions are reproducible and auditable.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from ai_cyber_os.rag import build_context


def evaluate(cases: list[dict], db: str) -> dict:
    results = []
    for case in cases:
        context = build_context(case["query"], db_path=db, limit=int(case.get("limit", 8)))
        actual = [e["record_id"] for e in context["evidence"]]
        expected = list(case.get("expected_record_ids", []))
        missing = [x for x in expected if x not in actual]
        results.append({
            "id": case.get("id", case["query"]),
            "query": case["query"],
            "expected_record_ids": expected,
            "actual_record_ids": actual,
            "missing": missing,
            "pass": not missing,
        })
    return {"success": all(x["pass"] for x in results), "cases": results,
            "passed": sum(x["pass"] for x in results), "failed": sum(not x["pass"] for x in results)}


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("cases", type=Path)
    p.add_argument("--db", required=True)
    args = p.parse_args()
    cases = json.loads(args.cases.read_text(encoding="utf-8"))
    result = evaluate(cases, args.db)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
