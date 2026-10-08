import json
from pathlib import Path

from ai_cyber_os.knowledge import ingest_file
from ai_cyber_os.security_evaluation import (
    EvaluationThresholds,
    evaluate_evidence_quality,
    evaluate_end_to_end,
    evaluate_retrieval_case,
    evaluate_retrieval_cases,
    validate_security_output,
)


def _fixture_db(tmp_path: Path) -> Path:
    data = tmp_path / "evidence.jsonl"
    data.write_text(
        "\n".join(
            [
                json.dumps({
                    "id": "CVE-2099-1001",
                    "title": "Fixture vulnerability",
                    "description": "CVE-2099-1001 is a fixture vulnerability associated with CWE-79.",
                }),
                json.dumps({
                    "id": "CWE-79",
                    "title": "Fixture CWE",
                    "description": "CWE-79 is a fixture weakness description.",
                }),
            ]
        ) + "\n",
        encoding="utf-8",
    )
    db = tmp_path / "knowledge.db"
    ingest_file(
        data,
        db_path=db,
        dataset="fixture",
        source="offline-fixture",
        source_uri="https://example.invalid/security-evaluation-fixture",
        license="CC0",
        version="fixture-1",
        validation_status="fixture-validated",
    )
    return db


def _context(db: Path, query: str):
    from ai_cyber_os.rag import build_context
    return build_context(query, db_path=db, limit=3)


def test_retrieval_metrics_and_gold_gate(tmp_path: Path):
    db = _fixture_db(tmp_path)
    context = _context(db, "CVE-2099-1001")
    result = evaluate_retrieval_case(
        {
            "id": "case",
            "query": "CVE-2099-1001",
            "expected_record_ids": ["CVE-2099-1001"],
            "k": 1,
        },
        context,
    )
    assert result["metrics"]["precision_at_k"] == 1.0
    assert result["metrics"]["recall_at_k"] == 1.0
    assert result["metrics"]["mrr"] == 1.0
    assert result["metrics"]["ndcg_at_k"] == 1.0
    assert result["missing_record_ids"] == []


def test_evidence_quality_detects_hash_tampering(tmp_path: Path):
    db = _fixture_db(tmp_path)
    context = _context(db, "CVE-2099-1001")
    tampered = dict(context["evidence"][0])
    tampered["content"] = "tampered evidence"
    result = evaluate_evidence_quality([tampered])
    assert result["pass"] is False
    assert result["records"][0]["checks"]["content_hash_valid"] is False


def test_grounded_security_output_passes(tmp_path: Path):
    db = _fixture_db(tmp_path)
    context = _context(db, "CVE-2099-1001")
    output = {
        "answer": "CVE-2099-1001 is associated with CWE-79.",
        "claims": [
            {
                "claim_id": "c1",
                "text": "CVE-2099-1001 is associated with CWE-79.",
                "evidence_ids": ["CVE-2099-1001"],
            }
        ],
    }
    result = validate_security_output(output, context)
    assert result["pass"] is True
    assert result["score"] == 1.0


def test_unsupported_security_identifier_fails(tmp_path: Path):
    db = _fixture_db(tmp_path)
    context = _context(db, "CVE-2099-1001")
    output = {
        "answer": "CVE-2099-1001 is associated with CVE-2099-9999.",
        "claims": [
            {
                "claim_id": "c1",
                "text": "CVE-2099-1001 is associated with CVE-2099-9999.",
                "evidence_ids": ["CVE-2099-1001"],
            }
        ],
    }
    result = validate_security_output(output, context)
    assert result["pass"] is False
    assert "CVE-2099-9999" in result["unsupported_answer_identifiers"]


def test_end_to_end_requires_output_grounding(tmp_path: Path):
    db = _fixture_db(tmp_path)
    cases = [{
        "id": "fixture-cve-cwe",
        "query": "CVE-2099-1001",
        "limit": 1,
        "k": 1,
        "expected_record_ids": ["CVE-2099-1001"],
        "relevance": {"CVE-2099-1001": 3},
        "expected_output": {
            "answer": "CVE-2099-1001 is associated with CWE-79.",
            "claims": [{
                "claim_id": "c1",
                "text": "CVE-2099-1001 is associated with CWE-79.",
                "evidence_ids": ["CVE-2099-1001"],
            }],
        },
    }]
    result = evaluate_end_to_end(cases, db)
    assert result["success"] is True


def test_retrieval_batch_passes_with_real_store(tmp_path: Path):
    db = _fixture_db(tmp_path)
    cases = [
        {
            "id": "cve",
            "query": "CVE-2099-1001",
            "limit": 1,
            "k": 1,
            "expected_record_ids": ["CVE-2099-1001"],
        },
        {
            "id": "cwe",
            "query": "CWE-79",
            "limit": 1,
            "k": 1,
            "expected_record_ids": ["CWE-79"],
        },
    ]
    result = evaluate_retrieval_cases(
        cases,
        db,
        thresholds=EvaluationThresholds(),
    )
    assert result["success"] is True
    assert result["passed"] == 2
