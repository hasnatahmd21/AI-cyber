#!/usr/bin/env python3
"""Run the deterministic AI-CYBER security evaluation pipeline."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ai_cyber_os.security_evaluation import (
    EvaluationThresholds,
    evaluate_end_to_end,
    load_cases,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Evaluate AI-CYBER retrieval quality, evidence integrity, "
            "and evidence-grounded security outputs."
        )
    )
    parser.add_argument("cases", type=Path)
    parser.add_argument("--db", required=True, help="SQLite knowledge database path")
    parser.add_argument("--report", type=Path, help="Optional JSON report output path")
    parser.add_argument("--min-recall", type=float, default=1.0)
    parser.add_argument("--min-precision", type=float, default=0.5)
    parser.add_argument("--min-mrr", type=float, default=1.0)
    parser.add_argument("--min-ndcg", type=float, default=0.9)
    parser.add_argument("--min-evidence-quality", type=float, default=0.9)
    parser.add_argument("--min-output-grounding", type=float, default=1.0)
    args = parser.parse_args()

    thresholds = EvaluationThresholds(
        min_recall_at_k=args.min_recall,
        min_precision_at_k=args.min_precision,
        min_mrr=args.min_mrr,
        min_ndcg_at_k=args.min_ndcg,
        min_evidence_quality=args.min_evidence_quality,
        min_output_grounding=args.min_output_grounding,
    )
    cases = load_cases(args.cases)
    result = evaluate_end_to_end(cases, args.db, thresholds=thresholds)

    payload = json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True)
    print(payload)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(payload + "\n", encoding="utf-8")
    return 0 if result["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
