#!/usr/bin/env python3
"""Standalone Phase 13 security-evaluation verification.

Creates only explicit offline fixtures, runs the complete evaluation gate, then
proves that evidence tampering is detected. No network or live cyber execution
is used.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from ai_cyber_os.knowledge import ingest_file
from ai_cyber_os.rag import build_context
from ai_cyber_os.security_evaluation import (
    EvaluationThresholds,
    evaluate_evidence_quality,
    evaluate_end_to_end,
)


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="ai-cyber-phase13-") as td:
        root = Path(td)
        data = root / "fixture.jsonl"
        data.write_text(
            json.dumps(
                {
                    "id": "CVE-2099-1001",
                    "title": "Offline fixture vulnerability",
                    "description": (
                        "CVE-2099-1001 is an offline fixture vulnerability "
                        "associated with CWE-79."
                    ),
                }
            )
            + "\n"
            + json.dumps(
                {
                    "id": "CWE-79",
                    "title": "Offline fixture weakness",
                    "description": "CWE-79 is an offline fixture weakness record.",
                }
            )
            + "\n",
            encoding="utf-8",
        )
        db = root / "knowledge.db"
        ingest_file(
            data,
            db_path=db,
            dataset="phase13-fixture",
            source="offline-phase13-fixture",
            source_uri="https://example.invalid/ai-cyber/phase13-fixture",
            license="CC0",
            version="fixture-1",
            validation_status="fixture-validated",
        )

        cases = [
            {
                "id": "cve",
                "query": "CVE-2099-1001",
                "limit": 1,
                "k": 1,
                "expected_record_ids": ["CVE-2099-1001"],
                "relevance": {"CVE-2099-1001": 3},
            },
            {
                "id": "cwe",
                "query": "CWE-79",
                "limit": 1,
                "k": 1,
                "expected_record_ids": ["CWE-79"],
                "relevance": {"CWE-79": 3},
            },
        ]
        outputs = {
            "cve": {
                "answer": "CVE-2099-1001 is associated with CWE-79.",
                "claims": [
                    {
                        "claim_id": "c1",
                        "text": "CVE-2099-1001 is associated with CWE-79.",
                        "evidence_ids": ["CVE-2099-1001"],
                    }
                ],
            },
            "cwe": {
                "answer": "CWE-79 is described by the cited fixture record.",
                "claims": [
                    {
                        "claim_id": "c1",
                        "text": "CWE-79 is described by the cited fixture record.",
                        "evidence_ids": ["CWE-79"],
                    }
                ],
            },
        }

        result = evaluate_end_to_end(
            cases,
            db,
            outputs=outputs,
            thresholds=EvaluationThresholds(),
        )
        if not result["success"]:
            print(json.dumps({"success": False, "evaluation": result}, indent=2))
            return 1

        context = build_context("CVE-2099-1001", db_path=db, limit=1)
        tampered = dict(context["evidence"][0])
        tampered["content"] = "tampered evidence"
        tamper_result = evaluate_evidence_quality([tampered])
        if tamper_result["pass"]:
            print(
                json.dumps(
                    {"success": False, "error": "tampered evidence was accepted"},
                    indent=2,
                )
            )
            return 1

        print(
            json.dumps(
                {
                    "success": True,
                    "phase": 13,
                    "checks": {
                        "end_to_end_evaluation": True,
                        "tamper_detection": True,
                    },
                    "aggregate": result["aggregate"],
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
