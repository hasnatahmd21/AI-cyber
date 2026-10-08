#!/usr/bin/env python3
"""Backward-compatible deterministic RAG retrieval evaluation runner."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ai_cyber_os.security_evaluation import (
    EvaluationThresholds,
    evaluate_retrieval_cases,
    load_cases,
)


def evaluate(cases: list[dict], db: str) -> dict:
    """Preserve the historical API while using the hardened evaluator."""
    return evaluate_retrieval_cases(cases, db)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate AI-CYBER RAG retrieval against a gold evidence set."
    )
    parser.add_argument("cases", type=Path)
    parser.add_argument("--db", required=True)
    parser.add_argument("--min-recall", type=float, default=1.0)
    parser.add_argument("--min-precision", type=float, default=0.5)
    parser.add_argument("--min-mrr", type=float, default=1.0)
    parser.add_argument("--min-ndcg", type=float, default=0.9)
    args = parser.parse_args()

    thresholds = EvaluationThresholds(
        min_recall_at_k=args.min_recall,
        min_precision_at_k=args.min_precision,
        min_mrr=args.min_mrr,
        min_ndcg_at_k=args.min_ndcg,
    )
    result = evaluate_retrieval_cases(
        load_cases(args.cases),
        args.db,
        thresholds=thresholds,
    )
    print(json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
