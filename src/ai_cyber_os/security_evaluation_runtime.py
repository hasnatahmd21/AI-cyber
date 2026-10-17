"""End-to-end evidence-backed evaluation against a populated Knowledge DB.

The current production RAG contract is extractive/evidence-only. This evaluator
checks retrieval and provenance, constructs a strictly cited extractive answer,
and validates grounding plus negative controls. It does not claim to evaluate
LLM semantic accuracy because no answer-generating model is invoked.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
import sqlite3
from pathlib import Path
from typing import Any

from .knowledge_runtime import APPROVED_DATASETS, verify_database
from .rag import build_context
from .security_evaluation import (
    EvaluationThresholds,
    evaluate_end_to_end,
    evaluate_evidence_quality,
    evaluate_retrieval_case,
    validate_security_output,
)

_SAMPLE_SIZE = 10
_STOP = {
    "about", "false", "true", "null", "https", "http", "description",
    "references", "created", "modified", "updated", "source", "payload",
    "record", "object", "value", "name",
}


def _sample_one_per_dataset(db_path: Path) -> list[dict[str, Any]]:
    """Select one uniformly random source-backed row from each approved family."""
    connection = sqlite3.connect(db_path.resolve().as_uri() + "?mode=ro", uri=True, timeout=60)
    connection.row_factory = sqlite3.Row
    rows: list[dict[str, Any]] = []
    try:
        for dataset in APPROVED_DATASETS:
            row = connection.execute(
                """
                SELECT record_id, dataset, title, content, source, source_uri,
                       license, version, validation_status, content_sha256
                  FROM knowledge_records
                 WHERE dataset = ?
                   AND length(trim(COALESCE(content, ''))) > 0
                   AND length(trim(COALESCE(source_uri, ''))) > 0
                   AND length(COALESCE(content_sha256, '')) = 64
                 ORDER BY RANDOM()
                 LIMIT 1
                """,
                (dataset,),
            ).fetchone()
            if row is None:
                raise RuntimeError(
                    f"dataset {dataset!r} has no real non-empty record with source URI/hash"
                )
            rows.append(dict(row))
    finally:
        connection.close()
    return rows


def _make_query(record: dict[str, Any]) -> str:
    """Construct a reproducible text query from the selected record itself."""
    content = str(record.get("content") or "")[:3000]
    terms: list[str] = []
    seen: set[str] = set()
    for token in re.findall(r"[A-Za-z0-9_]{4,}", content):
        folded = token.casefold()
        if folded in _STOP or folded in seen:
            continue
        terms.append(token)
        seen.add(folded)
        if len(terms) == 6:
            break
    if len(terms) < 3:
        for token in re.findall(r"[A-Za-z0-9_]{3,}", str(record.get("title") or "")):
            folded = token.casefold()
            if folded in _STOP or folded in seen:
                continue
            terms.append(token)
            seen.add(folded)
            if len(terms) == 6:
                break
    query = " ".join(terms)
    if not query:
        raise RuntimeError(
            f"record {record.get('record_id')!r} cannot yield a grounded retrieval query"
        )
    return query


def _extractive_output(record: dict[str, Any]) -> dict[str, Any]:
    """Return only a verbatim source extract, with a claim citing its record."""
    content = str(record["content"]).strip()
    # Return only text that is also inside the cited content. Title metadata may
    # contain an identifier absent from the content body and must not be silently
    # upgraded into a content-grounded security claim.
    answer = content
    return {
        "answer": answer,
        "claims": [{
            "claim_id": "source-extract-1",
            "text": content,
            "evidence_ids": [str(record["record_id"])],
        }],
    }


def _negative_identifier_control(output: dict[str, Any], evidence: dict[str, Any]) -> dict[str, Any]:
    """Ensure the output gate rejects an identifier not supported by the cited row."""
    cited = str(evidence.get("content") or "").upper()
    candidate = "CVE-9999-99999999"
    while candidate in cited:
        number = int(candidate.rsplit("-", 1)[1]) + 1
        candidate = f"CVE-9999-{number}"
    mutated = {
        "answer": str(output["answer"]) + f" Unsupported test identifier: {candidate}.",
        "claims": [{
            "claim_id": "negative-control-1",
            "text": str(output["claims"][0]["text"]) + f" {candidate}",
            "evidence_ids": list(output["claims"][0]["evidence_ids"]),
        }],
    }
    return {"output": mutated, "unsupported_identifier": candidate}


def evaluate_permanent_database(
    db_path: str | Path,
    *,
    sample_size: int = _SAMPLE_SIZE,
    deep_verify: bool = True,
    rng: random.Random | None = None,
) -> dict[str, Any]:
    """Evaluate exactly ten real records drawn from ten of the approved 11 datasets.

    The selected set covers ten distinct source families, each with a random
    real row; the remaining family is randomly omitted. All tests execute
    retrieval against the supplied DB and validate citation/provenance directly.
    """
    path = Path(db_path).expanduser().resolve()
    report: dict[str, Any] = {
        "evaluator": "ai_cyber_os.security_evaluation_runtime",
        "evaluator_version": "1.0.0",
        "database_file": path.name,
        "sample_size_requested": sample_size,
        "approved_dataset_count": len(APPROVED_DATASETS),
        "success": False,
        "overall": "BLOCKED",
        "evaluation_contract": (
            "Retrieval fidelity, evidence content hash/provenance, extractive answer grounding, "
            "and unsupported-identifier rejection. This is not an LLM semantic-answer test."
        ),
        "samples": [],
        "errors": [],
    }
    if sample_size != _SAMPLE_SIZE:
        report["errors"].append("the production gate is fixed to exactly 10 records")
        return report

    db_check = verify_database(path, deep=deep_verify)
    report["database_verification"] = {
        key: value for key, value in db_check.items()
        if key not in {"database_file"}
    }
    if db_check.get("success") is not True:
        report["errors"].append(
            "configured permanent Knowledge DB did not pass the read-only gate: "
            + "; ".join(str(value) for value in db_check.get("errors", []))
        )
        return report

    try:
        candidates = _sample_one_per_dataset(path)
        sampler = rng or random.SystemRandom()
        selected = sampler.sample(candidates, sample_size)
        for sample_index, record in enumerate(selected, start=1):
            dataset = str(record["dataset"])
            record_id = str(record["record_id"])
            query = _make_query(record)
            item: dict[str, Any] = {
                "dataset": dataset,
                "sample_record_id_sha256": hashlib.sha256(record_id.encode("utf-8")).hexdigest(),
                "query_sha256": hashlib.sha256(query.encode("utf-8")).hexdigest(),
                "query_term_count": len(query.split()),
                "pass": False,
                "checks": {},
                "errors": [],
            }
            try:
                context = build_context(query, db_path=path, limit=50, dataset=dataset)
                matches = [
                    evidence for evidence in context.get("evidence", [])
                    if evidence.get("record_id") == record_id
                ]
                if not matches:
                    raise RuntimeError("the selected real record was not returned by RAG retrieval")
                evidence = matches[0]
                exact_source = all((
                    evidence.get("dataset") == dataset,
                    evidence.get("title", "") == (record.get("title") or ""),
                    evidence.get("source") == record.get("source"),
                    evidence.get("source_uri") == record.get("source_uri"),
                    evidence.get("license") == record.get("license"),
                    evidence.get("version") == record.get("version"),
                    evidence.get("validation_status") == record.get("validation_status"),
                    evidence.get("content_sha256") == record.get("content_sha256"),
                ))
                evidence_result = evaluate_evidence_quality(
                    [evidence],
                    min_quality=0.9,
                )
                extractive = _extractive_output(evidence)
                output_result = validate_security_output(extractive, {"evidence": [evidence]})
                case_id = f"stage4-sample-{sample_index}"
                end_to_end = evaluate_end_to_end(
                    [{
                        "id": case_id,
                        "query": query,
                        "limit": 1,
                        "k": 1,
                        "expected_record_ids": [record_id],
                        "relevance": {record_id: 3.0},
                    }],
                    path,
                    outputs={case_id: extractive},
                    thresholds=EvaluationThresholds(),
                )
                end_to_end_pass = (
                    end_to_end.get("success") is True
                    and end_to_end.get("cases_total") == 1
                    and end_to_end.get("passed") == 1
                )
                negative = _negative_identifier_control(extractive, evidence)
                negative_result = validate_security_output(
                    negative["output"], {"evidence": [evidence]}
                )
                retrieval_result = evaluate_retrieval_case(
                    {
                        "id": f"stage4-{dataset}",
                        "query": query,
                        "expected_record_ids": [record_id],
                        "relevance": {record_id: 3.0},
                        "k": max(1, len(context.get("evidence", []))),
                    },
                    context,
                )
                checks = {
                    "exact_record_retrieved": True,
                    "provenance_matches_selected_db_row": exact_source,
                    "evidence_hash_and_validation_pass": evidence_result.get("pass") is True,
                    "extractive_output_is_grounded": output_result.get("pass") is True,
                    "one_result_end_to_end_gate_passed": end_to_end_pass,
                    "unsupported_identifier_negative_control_rejected": (
                        negative_result.get("pass") is False
                        and negative["unsupported_identifier"]
                        in negative_result.get("unsupported_answer_identifiers", [])
                    ),
                    "retrieval_recall": retrieval_result["metrics"]["recall_at_k"],
                    "retrieval_mrr": retrieval_result["metrics"]["mrr"],
                    "retrieval_ndcg_at_k": retrieval_result["metrics"]["ndcg_at_k"],
                }
                item["checks"] = checks
                item["evidence_quality"] = {
                    "mean_quality_score": evidence_result.get("mean_quality_score"),
                    "records_with_core_integrity": evidence_result.get("records_with_core_integrity"),
                }
                item["output_grounding"] = {
                    "pass": output_result.get("pass"),
                    "score": output_result.get("score"),
                    "errors": output_result.get("errors", []),
                }
                item["end_to_end_gate"] = {
                    "success": end_to_end.get("success") is True,
                    "cases_total": end_to_end.get("cases_total"),
                    "passed": end_to_end.get("passed"),
                    "failed": end_to_end.get("failed"),
                    "aggregate": end_to_end.get("aggregate", {}),
                    "case_pass": end_to_end_pass,
                }
                item["negative_control"] = {
                    "unsupported_identifier": negative["unsupported_identifier"],
                    "rejected": checks["unsupported_identifier_negative_control_rejected"],
                    "errors": negative_result.get("errors", []),
                }
                required_checks = (
                    "exact_record_retrieved",
                    "provenance_matches_selected_db_row",
                    "evidence_hash_and_validation_pass",
                    "extractive_output_is_grounded",
                    "one_result_end_to_end_gate_passed",
                    "unsupported_identifier_negative_control_rejected",
                )
                item["pass"] = all(checks[name] is True for name in required_checks)
                if not item["pass"]:
                    item["errors"].append("one or more end-to-end evidence/answer grounding gates failed")
            except Exception as exc:
                item["errors"].append(f"{type(exc).__name__}: {exc}")
            report["samples"].append(item)

    except Exception as exc:
        report["errors"].append(f"{type(exc).__name__}: {exc}")

    passed = sum(item.get("pass") is True for item in report["samples"])
    report.update({
        "sample_count": len(report["samples"]),
        "passed": passed,
        "failed": len(report["samples"]) - passed,
        "source_families_sampled": sorted({str(x.get("dataset")) for x in report["samples"]}),
        "source_families_not_sampled": sorted(
            set(APPROVED_DATASETS) - {str(x.get("dataset")) for x in report["samples"]}
        ),
        "success": passed == _SAMPLE_SIZE and not report["errors"],
        "overall": "PASS" if passed == _SAMPLE_SIZE and not report["errors"] else "FAIL",
    })
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, default=None)
    parser.add_argument("--report", type=Path, default=None)
    parser.add_argument("--quick", action="store_true", help="Use a quick metadata/scope gate after the builder's full integrity check")
    args = parser.parse_args(argv)
    from .knowledge_runtime import configured_database_path
    path = args.db or configured_database_path()
    result = evaluate_permanent_database(path, deep_verify=not args.quick)
    payload = json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True, default=str)
    print(payload)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(payload + "\n", encoding="utf-8")
    return 0 if result.get("success") is True else 2


if __name__ == "__main__":
    raise SystemExit(main())
