"""Deterministic security evaluation for AI-CYBER knowledge and RAG outputs.

The evaluator is deliberately evidence-first and model-agnostic. It measures
retrieval quality, validates provenance/hash integrity, and checks structured
security outputs for citation/identifier grounding. It never invents a
security conclusion and never treats an unverified source as verified.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .rag import build_context


EVALUATOR_VERSION = "1.0.0"
_IDENTIFIER_PATTERNS = {
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I),
    "cwe": re.compile(r"\bCWE-\d+\b", re.I),
    "attack": re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.I),
    "cpe": re.compile(r"\bcpe:2\.3:\S+", re.I),
}
_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{1,}")
_STOPWORDS = {
    "a", "an", "and", "are", "as", "at", "be", "by", "for", "from",
    "has", "have", "in", "is", "it", "of", "on", "or", "that", "the",
    "to", "was", "were", "with", "this", "these", "those",
}


@dataclass(frozen=True)
class EvaluationThresholds:
    """Quality gates for a security/RAG evaluation run."""

    min_recall_at_k: float = 1.0
    min_precision_at_k: float = 0.5
    min_mrr: float = 1.0
    min_ndcg_at_k: float = 0.9
    min_evidence_quality: float = 0.9
    min_output_grounding: float = 1.0

    def __post_init__(self) -> None:
        for name in (
            "min_recall_at_k",
            "min_precision_at_k",
            "min_mrr",
            "min_ndcg_at_k",
            "min_evidence_quality",
            "min_output_grounding",
        ):
            value = float(getattr(self, name))
            if not 0.0 <= value <= 1.0:
                raise ValueError(f"{name} must be between 0 and 1")


def _unique(values: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(str(value) for value in values))


def _string_list(value: Any, field_name: str) -> tuple[list[str], list[str]]:
    """Return a strict list of strings plus schema errors."""
    if not isinstance(value, (list, tuple)):
        return [], [f"{field_name} must be a list"]
    values = [str(item).strip() for item in value]
    if any(not item for item in values):
        return [], [f"{field_name} cannot contain empty values"]
    return _unique(values), []


def _normalize_identifier(value: str) -> str:
    return value.strip().upper()


def extract_security_identifiers(text: str) -> dict[str, list[str]]:
    """Extract canonical security identifiers from arbitrary text."""
    found: dict[str, list[str]] = {}
    for kind, pattern in _IDENTIFIER_PATTERNS.items():
        values = _unique(
            _normalize_identifier(match)
            for match in pattern.findall(text or "")
        )
        if values:
            found[kind] = values
    return found


def _flatten_identifiers(mapping: Mapping[str, Sequence[str]]) -> set[str]:
    return {
        _normalize_identifier(value)
        for values in mapping.values()
        for value in values
    }


def _tokenize(text: str) -> set[str]:
    return {
        token.lower()
        for token in _TOKEN_RE.findall(text or "")
        if token.lower() not in _STOPWORDS and len(token) > 2
    }


def _lexical_overlap(claim: str, evidence: str) -> float:
    claim_tokens = _tokenize(claim)
    evidence_tokens = _tokenize(evidence)
    if not claim_tokens:
        return 1.0
    return len(claim_tokens & evidence_tokens) / len(claim_tokens)


def _mean(values: Sequence[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def precision_at_k(actual: Sequence[str], relevant: Sequence[str], k: int) -> float:
    """Binary precision@k with duplicate retrievals de-duplicated for safety."""
    k = max(0, int(k))
    if k == 0:
        return 0.0
    relevant_set = set(relevant)
    ranked = _unique(actual)[:k]
    return len(set(ranked) & relevant_set) / k


def recall_at_k(actual: Sequence[str], relevant: Sequence[str], k: int) -> float:
    """Binary recall@k over the complete gold evidence set."""
    relevant_set = set(relevant)
    if not relevant_set:
        return 1.0
    ranked = set(_unique(actual)[: max(0, int(k))])
    return len(ranked & relevant_set) / len(relevant_set)


def reciprocal_rank(actual: Sequence[str], relevant: Sequence[str]) -> float:
    """Reciprocal rank of the first relevant result."""
    relevant_set = set(relevant)
    for rank, record_id in enumerate(_unique(actual), start=1):
        if record_id in relevant_set:
            return 1.0 / rank
    return 0.0


def ndcg_at_k(
    actual: Sequence[str],
    relevance: Mapping[str, float],
    k: int,
) -> float:
    """Normalized discounted cumulative gain for a ranked retrieval result."""
    ranked = _unique(actual)[: max(0, int(k))]

    def dcg(items: Sequence[tuple[int, float]]) -> float:
        return sum(
            gain / math.log2(rank + 1)
            for rank, (_, gain) in items
            if gain > 0
        )

    observed = dcg(
        [(rank, float(relevance.get(record_id, 0.0)))
         for rank, record_id in enumerate(ranked, start=1)]
    )
    ideal_gains = sorted(
        (max(0.0, float(gain)) for gain in relevance.values()),
        reverse=True,
    )[: max(0, int(k))]
    ideal = dcg(list(enumerate(ideal_gains, start=1)))
    return 1.0 if ideal == 0.0 else observed / ideal


def evaluate_retrieval_case(
    case: Mapping[str, Any],
    context: Mapping[str, Any],
) -> dict[str, Any]:
    """Evaluate one query against a gold evidence set."""
    expected = _unique(case.get("expected_record_ids", []))
    actual = _unique(
        str(item.get("record_id"))
        for item in context.get("evidence", [])
        if item.get("record_id")
    )
    if not expected:
        raise ValueError("evaluation case requires expected_record_ids")

    k = int(case.get("k", case.get("limit", len(actual) or 1)))
    k = max(1, min(k, 50))
    relevance = {
        str(record_id): float(score)
        for record_id, score in dict(case.get("relevance", {})).items()
    }
    for record_id in expected:
        relevance.setdefault(record_id, 1.0)

    metrics = {
        "precision_at_k": precision_at_k(actual, expected, k),
        "recall_at_k": recall_at_k(actual, expected, k),
        "mrr": reciprocal_rank(actual, expected),
        "ndcg_at_k": ndcg_at_k(actual, relevance, k),
    }
    missing = [record_id for record_id in expected if record_id not in actual[:k]]
    unexpected = [record_id for record_id in actual[:k] if record_id not in set(expected)]

    return {
        "case_id": str(case.get("id", case.get("query", "case"))),
        "query": str(case.get("query", "")),
        "k": k,
        "expected_record_ids": expected,
        "actual_record_ids": actual[:k],
        "missing_record_ids": missing,
        "unexpected_record_ids": unexpected,
        "metrics": metrics,
        "passed_recall": metrics["recall_at_k"] >= float(case.get("min_recall", 1.0)),
        "passed_ranking": metrics["mrr"] >= float(case.get("min_mrr", 1.0))
        and metrics["ndcg_at_k"] >= float(case.get("min_ndcg", 0.9)),
    }


def evaluate_retrieval_cases(
    cases: Sequence[Mapping[str, Any]],
    db_path: str | Path,
    *,
    thresholds: EvaluationThresholds | None = None,
) -> dict[str, Any]:
    """Run retrieval evaluation using the real local knowledge store."""
    thresholds = thresholds or EvaluationThresholds()
    results: list[dict[str, Any]] = []

    for case in cases:
        query = str(case.get("query", "")).strip()
        if not query:
            results.append({
                "case_id": str(case.get("id", "case")),
                "pass": False,
                "error": "query must be non-empty",
            })
            continue

        limit = max(1, min(int(case.get("limit", 8)), 50))
        context = build_context(
            query,
            db_path=db_path,
            limit=limit,
            dataset=case.get("dataset"),
        )
        result = evaluate_retrieval_case(case, context)
        metrics = result["metrics"]
        result["pass"] = (
            metrics["recall_at_k"] >= thresholds.min_recall_at_k
            and metrics["precision_at_k"] >= thresholds.min_precision_at_k
            and metrics["mrr"] >= thresholds.min_mrr
            and metrics["ndcg_at_k"] >= thresholds.min_ndcg_at_k
            and not result["missing_record_ids"]
        )
        results.append(result)

    passed = sum(bool(item.get("pass")) for item in results)
    return {
        "evaluator_version": EVALUATOR_VERSION,
        "success": bool(results) and passed == len(results),
        "cases_total": len(results),
        "passed": passed,
        "failed": len(results) - passed,
        "aggregate": {
            "recall_at_k": _mean([item["metrics"]["recall_at_k"] for item in results if "metrics" in item]),
            "precision_at_k": _mean([item["metrics"]["precision_at_k"] for item in results if "metrics" in item]),
            "mrr": _mean([item["metrics"]["mrr"] for item in results if "metrics" in item]),
            "ndcg_at_k": _mean([item["metrics"]["ndcg_at_k"] for item in results if "metrics" in item]),
        },
        "cases": results,
    }


def _validate_evidence_record(record: Mapping[str, Any]) -> dict[str, Any]:
    """Validate provenance and cryptographic integrity for one retrieved record."""
    content = str(record.get("content", ""))
    stored_hash = str(record.get("content_sha256", ""))
    computed_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
    checks = {
        "record_id_present": bool(str(record.get("record_id", "")).strip()),
        "content_present": bool(content.strip()),
        "source_present": bool(str(record.get("source", "")).strip()),
        "source_uri_present": bool(str(record.get("source_uri", "")).strip()),
        "license_present": bool(str(record.get("license", "")).strip()),
        "version_present": bool(str(record.get("version", "")).strip()),
        "validation_status_trusted": str(record.get("validation_status", "")).strip().lower()
        not in {"", "unverified", "unknown"},
        "content_hash_valid": bool(re.fullmatch(r"[0-9a-f]{64}", stored_hash, re.I))
        and stored_hash.lower() == computed_hash,
    }
    # Core evidence integrity is hard-gated; optional provenance fields contribute
    # to the quality score but are not assumed to exist for local datasets.
    core = (
        checks["record_id_present"]
        and checks["content_present"]
        and checks["source_present"]
        and checks["content_hash_valid"]
        and checks["validation_status_trusted"]
    )
    optional_quality = sum(
        bool(checks[name])
        for name in (
            "source_uri_present",
            "license_present",
            "version_present",
            "validation_status_trusted",
        )
    ) / 4.0
    quality = 0.8 if core else 0.0
    quality += 0.2 * optional_quality
    return {
        "record_id": str(record.get("record_id", "")),
        "quality_score": round(quality, 6),
        "core_integrity": core,
        "checks": checks,
        "computed_content_sha256": computed_hash,
        "stored_content_sha256": stored_hash,
    }


def evaluate_evidence_quality(
    evidence: Sequence[Mapping[str, Any]],
    *,
    min_quality: float = 0.9,
) -> dict[str, Any]:
    """Score provenance, validation state and content-hash integrity."""
    records = [_validate_evidence_record(record) for record in evidence]
    score = _mean([float(item["quality_score"]) for item in records])
    core_integrity = all(bool(item["core_integrity"]) for item in records)
    return {
        "records_total": len(records),
        "records_with_core_integrity": sum(bool(item["core_integrity"]) for item in records),
        "mean_quality_score": round(score, 6),
        "pass": bool(records)
        and core_integrity
        and score >= float(min_quality),
        "records": records,
    }


def _evidence_map(context: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    return {
        str(item["record_id"]): item
        for item in context.get("evidence", [])
        if item.get("record_id")
    }


def _assertion_identifiers_are_grounded(
    claim_text: str,
    evidence_records: Sequence[Mapping[str, Any]],
) -> tuple[bool, list[str]]:
    identifiers = _flatten_identifiers(extract_security_identifiers(claim_text))
    if not identifiers:
        return True, []
    evidence_text = " ".join(
        f'{record.get("title", "")} {record.get("content", "")}'
        for record in evidence_records
    ).upper()
    missing = sorted(identifier for identifier in identifiers if identifier not in evidence_text)
    return not missing, missing


def validate_security_output(
    output: Mapping[str, Any] | str,
    context: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate structured security reasoning/output against retrieved evidence.

    Contract:
      answer: string
      claims: [{claim_id, text, evidence_ids}]
      reasoning_steps: optional [{step_id, text, evidence_ids}]
    """
    if isinstance(output, str):
        try:
            parsed = json.loads(output)
        except json.JSONDecodeError as exc:
            return {
                "pass": False,
                "score": 0.0,
                "errors": [f"invalid JSON output: {exc}"],
            }
    else:
        parsed = dict(output)

    if not isinstance(parsed, dict):
        return {"pass": False, "score": 0.0, "errors": ["output must be an object"]}

    errors: list[str] = []
    evidence_by_id = _evidence_map(context)
    allowed_ids = set(evidence_by_id)

    answer = parsed.get("answer")
    claims = parsed.get("claims")
    reasoning_steps = parsed.get("reasoning_steps", [])

    if not isinstance(answer, str) or not answer.strip():
        errors.append("answer must be a non-empty string")
    if not isinstance(claims, list) or not claims:
        errors.append("claims must be a non-empty list")
        claims = []
    if reasoning_steps is None:
        reasoning_steps = []
    if not isinstance(reasoning_steps, list):
        errors.append("reasoning_steps must be a list")
        reasoning_steps = []

    claim_results: list[dict[str, Any]] = []
    grounded_claims = 0
    cited_ids: set[str] = set()
    seen_claim_ids: set[str] = set()

    for index, claim in enumerate(claims):
        if not isinstance(claim, dict):
            errors.append(f"claim[{index}] must be an object")
            continue
        claim_id = str(claim.get("claim_id", f"claim-{index + 1}")).strip()
        text = str(claim.get("text", "")).strip()
        evidence_ids, schema_errors = _string_list(
            claim.get("evidence_ids", []), f"claim[{index}].evidence_ids"
        )
        cited_ids.update(evidence_ids)
        claim_errors: list[str] = list(schema_errors)

        if not claim_id:
            claim_errors.append("claim_id is empty")
        elif claim_id in seen_claim_ids:
            claim_errors.append("duplicate claim_id")
        else:
            seen_claim_ids.add(claim_id)
        if not text:
            claim_errors.append("text is empty")
        if not evidence_ids:
            claim_errors.append("must cite at least one evidence_id")

        unknown = [value for value in evidence_ids if value not in allowed_ids]
        if unknown:
            claim_errors.append(f"unknown evidence_ids: {unknown}")

        cited_records = [evidence_by_id[value] for value in evidence_ids if value in evidence_by_id]
        identifiers_grounded, missing_identifiers = _assertion_identifiers_are_grounded(
            text,
            cited_records,
        )
        if not identifiers_grounded:
            claim_errors.append(
                f"security identifiers not grounded by cited evidence: {missing_identifiers}"
            )

        lexical = max(
            (_lexical_overlap(text, str(record.get("content", ""))) for record in cited_records),
            default=0.0,
        )
        has_identifiers = bool(extract_security_identifiers(text))
        grounded = not claim_errors and (
            identifiers_grounded
            if has_identifiers
            else lexical >= 0.20
        )
        if not grounded and not claim_errors:
            claim_errors.append(
                f"insufficient lexical grounding ({lexical:.3f} < 0.200)"
            )
        if grounded:
            grounded_claims += 1

        claim_results.append({
            "claim_id": claim_id,
            "pass": grounded,
            "grounding_score": round(1.0 if grounded else 0.0, 6),
            "lexical_overlap": round(lexical, 6),
            "missing_identifiers": missing_identifiers,
            "errors": claim_errors,
        })

    step_results: list[dict[str, Any]] = []
    grounded_steps = 0
    seen_step_ids: set[str] = set()
    for index, step in enumerate(reasoning_steps):
        if not isinstance(step, dict):
            errors.append(f"reasoning_steps[{index}] must be an object")
            continue
        step_id = str(step.get("step_id", f"step-{index + 1}")).strip()
        text = str(step.get("text", "")).strip()
        evidence_ids, schema_errors = _string_list(
            step.get("evidence_ids", []), f"reasoning_steps[{index}].evidence_ids"
        )
        cited_ids.update(evidence_ids)
        step_errors: list[str] = list(schema_errors)
        if not step_id:
            step_errors.append("step_id is empty")
        elif step_id in seen_step_ids:
            step_errors.append("duplicate step_id")
        else:
            seen_step_ids.add(step_id)
        if not text:
            step_errors.append("text is empty")
        if not evidence_ids:
            step_errors.append("must cite at least one evidence_id")
        if any(value not in allowed_ids for value in evidence_ids):
            step_errors.append("contains unknown evidence_id")
        if step_errors:
            grounded = False
        else:
            cited_records = [evidence_by_id[value] for value in evidence_ids]
            identifiers_grounded, missing_identifiers = _assertion_identifiers_are_grounded(
                text, cited_records
            )
            lexical = max(
                (_lexical_overlap(text, str(record.get("content", ""))) for record in cited_records),
                default=0.0,
            )
            grounded = identifiers_grounded or lexical >= 0.20
            if not grounded:
                step_errors.append("insufficient evidence grounding")
        if grounded:
            grounded_steps += 1
        step_results.append({
            "step_id": step_id,
            "pass": grounded,
            "errors": step_errors,
        })

    # Validate any security identifier appearing in the answer itself. Every such
    # identifier must be supported by at least one cited evidence record.
    answer_identifiers = _flatten_identifiers(extract_security_identifiers(answer or ""))
    cited_text = " ".join(
        str(evidence_by_id[value].get("content", ""))
        for value in cited_ids
        if value in evidence_by_id
    ).upper()
    unsupported_answer_identifiers = sorted(
        identifier for identifier in answer_identifiers if identifier not in cited_text
    )
    if unsupported_answer_identifiers:
        errors.append(
            "answer contains unsupported security identifiers: "
            + ", ".join(unsupported_answer_identifiers)
        )

    all_claims_grounded = grounded_claims == len(claims) and bool(claims)
    all_steps_grounded = grounded_steps == len(reasoning_steps)
    score_parts = [grounded_claims / len(claims)] if claims else [0.0]
    if reasoning_steps:
        score_parts.append(grounded_steps / len(reasoning_steps))
    score = _mean(score_parts)

    return {
        "pass": not errors
        and all_claims_grounded
        and all_steps_grounded
        and not unsupported_answer_identifiers,
        "score": round(score, 6),
        "grounded_claims": grounded_claims,
        "claims_total": len(claims),
        "grounded_reasoning_steps": grounded_steps,
        "reasoning_steps_total": len(reasoning_steps),
        "unsupported_answer_identifiers": unsupported_answer_identifiers,
        "claims": claim_results,
        "reasoning_steps": step_results,
        "errors": errors,
    }


def evaluate_end_to_end(
    cases: Sequence[Mapping[str, Any]],
    db_path: str | Path,
    *,
    outputs: Mapping[str, Mapping[str, Any] | str] | None = None,
    thresholds: EvaluationThresholds | None = None,
) -> dict[str, Any]:
    """Evaluate retrieval, evidence integrity and optional generated outputs."""
    thresholds = thresholds or EvaluationThresholds()
    outputs = outputs or {}
    case_results: list[dict[str, Any]] = []

    for case in cases:
        case_id = str(case.get("id", case.get("query", "case")))
        query = str(case.get("query", "")).strip()
        if not query:
            case_results.append({"case_id": case_id, "pass": False, "error": "query must be non-empty"})
            continue

        limit = max(1, min(int(case.get("limit", 8)), 50))
        context = build_context(
            query,
            db_path=db_path,
            limit=limit,
            dataset=case.get("dataset"),
        )
        retrieval = evaluate_retrieval_case(case, context)
        metrics = retrieval["metrics"]
        evidence = evaluate_evidence_quality(
            context.get("evidence", []),
            min_quality=thresholds.min_evidence_quality,
        )

        output = outputs.get(case_id, case.get("expected_output"))
        output_result: dict[str, Any]
        if output is None:
            output_result = {
                "status": "not_provided",
                "pass": False,
                "score": 0.0,
                "errors": ["no generated security output supplied for evaluation"],
            }
        else:
            output_result = {
                "status": "evaluated",
                **validate_security_output(output, context),
            }

        output_gate = (
            output_result["pass"]
            and float(output_result.get("score", 0.0)) >= thresholds.min_output_grounding
        )

        case_pass = (
            metrics["recall_at_k"] >= thresholds.min_recall_at_k
            and metrics["precision_at_k"] >= thresholds.min_precision_at_k
            and metrics["mrr"] >= thresholds.min_mrr
            and metrics["ndcg_at_k"] >= thresholds.min_ndcg_at_k
            and evidence["pass"]
            and output_gate
            and not retrieval["missing_record_ids"]
        )
        case_results.append({
            "case_id": case_id,
            "query": query,
            "pass": case_pass,
            "retrieval": retrieval,
            "evidence_quality": evidence,
            "output_validation": output_result,
        })

    passed = sum(bool(item.get("pass")) for item in case_results)
    retrieval_cases = [item["retrieval"]["metrics"] for item in case_results if "retrieval" in item]
    evidence_scores = [
        float(item["evidence_quality"]["mean_quality_score"])
        for item in case_results
        if "evidence_quality" in item
    ]
    output_scores = [
        float(item["output_validation"].get("score", 0.0))
        for item in case_results
        if item.get("output_validation", {}).get("status") == "evaluated"
    ]
    aggregate = {
        "precision_at_k": round(_mean([m["precision_at_k"] for m in retrieval_cases]), 6),
        "recall_at_k": round(_mean([m["recall_at_k"] for m in retrieval_cases]), 6),
        "mrr": round(_mean([m["mrr"] for m in retrieval_cases]), 6),
        "ndcg_at_k": round(_mean([m["ndcg_at_k"] for m in retrieval_cases]), 6),
        "evidence_quality": round(_mean(evidence_scores), 6),
        "output_grounding": round(_mean(output_scores), 6),
    }
    return {
        "evaluator_version": EVALUATOR_VERSION,
        "success": bool(case_results) and passed == len(case_results),
        "cases_total": len(case_results),
        "passed": passed,
        "failed": len(case_results) - passed,
        "aggregate": aggregate,
        "gates": {
            "min_recall_at_k": thresholds.min_recall_at_k,
            "min_precision_at_k": thresholds.min_precision_at_k,
            "min_mrr": thresholds.min_mrr,
            "min_ndcg_at_k": thresholds.min_ndcg_at_k,
            "min_evidence_quality": thresholds.min_evidence_quality,
            "min_output_grounding": thresholds.min_output_grounding,
        },
        "cases": case_results,
    }


def load_cases(path: str | Path) -> list[dict[str, Any]]:
    """Load evaluation cases from a JSON array or {"cases": [...]} document."""
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    cases = payload.get("cases") if isinstance(payload, dict) else payload
    if not isinstance(cases, list):
        raise ValueError("evaluation case file must contain a JSON array or a 'cases' array")
    return [dict(case) for case in cases]


def main() -> int:
    """CLI entry point for the full security evaluation gate."""
    import argparse

    parser = argparse.ArgumentParser(
        description=(
            "Evaluate AI-CYBER retrieval quality, evidence integrity, "
            "and evidence-grounded security outputs."
        )
    )
    parser.add_argument("cases", type=Path)
    parser.add_argument("--db", required=True, help="SQLite knowledge database path")
    parser.add_argument(
        "--outputs",
        type=Path,
        required=True,
        help="JSON object mapping case IDs to generated security outputs",
    )
    parser.add_argument("--report", type=Path, help="Optional JSON report path")
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
    outputs = load_outputs(args.outputs)

    result = evaluate_end_to_end(
        cases,
        args.db,
        outputs=outputs,
        thresholds=thresholds,
    )
    payload = json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True)
    print(payload)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(payload + "\n", encoding="utf-8")
    return 0 if result["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
