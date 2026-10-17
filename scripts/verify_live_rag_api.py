#!/usr/bin/env python3
"""Verify all 11 approved datasets through the real localhost evidence-only RAG API."""
from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import sys
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from typing import Any

REQUIRED_DATASETS = (
    "capec", "cisa_kev", "cpe", "cwe", "epss", "mitre_attack",
    "mitre_d3fend", "mitre_mbc", "sigma", "suricata", "zeek_intel",
)
FIXED_PROBES = (
    ("cisa_kev", "CVE-2021-44228"),
    ("cwe", "CWE-79"),
    ("mitre_attack", "T1059.001"),
)
STOP_TERMS = {
    "false", "true", "null", "https", "http", "description", "references",
    "created", "modified", "updated", "source", "payload", "record",
}


def post_json(url: str, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    request = Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=60) as response:
            status = response.status
            body = json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        status = exc.code
        body = json.loads(exc.read().decode("utf-8"))
    if not isinstance(body, dict):
        raise ValueError("API returned a non-object JSON body")
    return status, body


def _sample_record(db_path: Path, dataset: str) -> dict[str, Any]:
    connection = sqlite3.connect(
        f"file:{db_path.resolve().as_posix()}?mode=ro", uri=True, timeout=60
    )
    connection.row_factory = sqlite3.Row
    try:
        row = connection.execute(
            """
            SELECT record_id, dataset, title, content, source_uri,
                   content_sha256, validation_status
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
    finally:
        connection.close()
    if row is None:
        raise RuntimeError(f"dataset {dataset!r} has no source-backed record for live API sampling")
    return dict(row)


def _query_from_content(row: dict[str, Any]) -> str:
    # The query terms come from the expected record's content, so a returned
    # match can be checked by record ID and exact provenance rather than merely
    # counting any result from the same dataset.
    content = str(row.get("content") or "")[:3500]
    tokens = re.findall(r"[A-Za-z0-9_]{5,}", content)
    terms: list[str] = []
    seen: set[str] = set()
    for token in tokens:
        folded = token.casefold()
        if folded in STOP_TERMS or folded in seen:
            continue
        terms.append(token)
        seen.add(folded)
        if len(terms) == 6:
            break
    if len(terms) < 3:
        title = str(row.get("title") or "")
        for token in re.findall(r"[A-Za-z0-9_]{3,}", title):
            folded = token.casefold()
            if folded not in STOP_TERMS and folded not in seen:
                terms.append(token)
                seen.add(folded)
            if len(terms) == 6:
                break
    query = " ".join(terms)
    if not query:
        raise RuntimeError(
            f"could not construct a grounded sample query for record {row.get('record_id')!r}"
        )
    return query


def _provenance_ok(evidence: dict[str, Any]) -> bool:
    digest = str(evidence.get("content_sha256") or "")
    return bool(
        evidence.get("record_id")
        and evidence.get("dataset")
        and evidence.get("source_uri")
        and len(digest) == 64
        and all(ch in "0123456789abcdef" for ch in digest.lower())
        and evidence.get("validation_status")
    )


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db-path", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args(argv)
    db_path = args.db_path.expanduser().resolve()
    report_path = args.report.expanduser().resolve()
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report: dict[str, Any] = {
        "db_path": str(db_path),
        "api_network_scope": "127.0.0.1 only",
        "approved_dataset_count": len(REQUIRED_DATASETS),
        "sampled_dataset_count": 0,
        "tests": [],
        "success": False,
        "evaluation_contract": (
            "Evidence-only retrieval and source/provenance fidelity. This API does not generate "
            "natural-language answers; no generative-answer correctness is claimed."
        ),
    }

    server = None
    thread = None
    try:
        if not db_path.is_file() or db_path.stat().st_size <= 0:
            raise FileNotFoundError(f"populated DB file missing or empty: {db_path}")

        # Sample one actual persisted row from every approved dataset.
        sampled = [_sample_record(db_path, dataset) for dataset in REQUIRED_DATASETS]
        env = os.environ.copy()
        env["AI_CYBER_KNOWLEDGE_DB"] = str(db_path)
        src = str(Path(__file__).resolve().parents[1] / "src")
        env["PYTHONPATH"] = src + os.pathsep + env.get("PYTHONPATH", "")
        env["AI_CYBER_REQUIRE_VERIFIED_DB"] = "1"
        os.environ.update({
            "AI_CYBER_KNOWLEDGE_DB": str(db_path),
            "AI_CYBER_REQUIRE_VERIFIED_DB": "1",
            "PYTHONPATH": env["PYTHONPATH"],
        })
        if src not in sys.path:
            sys.path.insert(0, src)
        from ai_cyber_os.knowledge_runtime import configured_database_path, verify_database

        db_gate = verify_database(db_path, deep=True)
        report["pre_api_database_verification"] = db_gate
        if db_gate.get("success") is not True:
            raise RuntimeError(
                "configured Knowledge DB failed the read-only integrity/scope gate: "
                + json.dumps(db_gate.get("errors", []), ensure_ascii=False)
            )

        from ai_cyber_os import ui
        from ai_cyber_os.knowledge import status

        configured_db = configured_database_path().expanduser().resolve()
        if configured_db != db_path:
            raise RuntimeError(f"RAG/API DB mismatch: UI uses {configured_db}, build uses {db_path}")
        store_status = status(db_path=db_path)
        if int(store_status.get("records", 0)) <= 0:
            raise RuntimeError("Knowledge DB contains zero records")

        server = ThreadingHTTPServer(("127.0.0.1", 0), ui.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base_url = f"http://127.0.0.1:{server.server_port}"

        for row in sampled:
            dataset = str(row["dataset"])
            query = _query_from_content(row)
            http_status, body = post_json(
                f"{base_url}/api/knowledge",
                {"action": "context", "query": query, "dataset": dataset, "limit": 50},
            )
            evidence = body.get("evidence", [])
            selected = next(
                (item for item in evidence if item.get("record_id") == row["record_id"]),
                None,
            ) if isinstance(evidence, list) else None
            provenance_matches = bool(
                selected
                and selected.get("dataset") == dataset
                and selected.get("title", "") == (row.get("title") or "")
                and selected.get("source_uri") == row.get("source_uri")
                and selected.get("content_sha256") == row.get("content_sha256")
                and selected.get("validation_status") == row.get("validation_status")
            )
            passed = bool(
                http_status == 200
                and body.get("success") is True
                and body.get("evidence_only") is True
                and int(body.get("count", 0)) > 0
                and selected
                and _provenance_ok(selected)
                and provenance_matches
            )
            report["tests"].append({
                "kind": "random-real-record",
                "dataset": dataset,
                "query": query,
                "expected_record_id": row["record_id"],
                "expected_title": row.get("title"),
                "expected_content_sha256": row.get("content_sha256"),
                "http_status": http_status,
                "success": body.get("success"),
                "evidence_only": body.get("evidence_only"),
                "evidence_count": body.get("count", 0),
                "expected_record_retrieved": bool(selected),
                "provenance_verified": provenance_matches,
                "pass": passed,
            })
            if not passed:
                raise RuntimeError(
                    f"live API did not return the selected {dataset} record with exact provenance: "
                    + json.dumps(report["tests"][-1], sort_keys=True, default=str)
                )

        for dataset, query in FIXED_PROBES:
            http_status, body = post_json(
                f"{base_url}/api/knowledge",
                {"action": "context", "query": query, "dataset": dataset, "limit": 10},
            )
            evidence = body.get("evidence", [])
            first = evidence[0] if isinstance(evidence, list) and evidence else {}
            passed = bool(
                http_status == 200
                and body.get("success") is True
                and body.get("evidence_only") is True
                and int(body.get("count", 0)) > 0
                and first.get("dataset") == dataset
                and _provenance_ok(first)
            )
            report["tests"].append({
                "kind": "fixed-security-identifier",
                "dataset": dataset,
                "query": query,
                "http_status": http_status,
                "success": body.get("success"),
                "evidence_only": body.get("evidence_only"),
                "evidence_count": body.get("count", 0),
                "sample_record_id": first.get("record_id"),
                "provenance_verified": _provenance_ok(first),
                "pass": passed,
            })
            if not passed:
                raise RuntimeError(
                    f"live API identifier probe failed for {dataset}/{query}: "
                    + json.dumps(report["tests"][-1], sort_keys=True, default=str)
                )

        report.update({
            "success": True,
            "overall": "PASS",
            "sampled_dataset_count": len(sampled),
            "database_status": store_status,
            "ui_default_db": str(configured_db),
            "passed_tests": sum(row["pass"] is True for row in report["tests"]),
            "failed_tests": sum(row["pass"] is not True for row in report["tests"]),
            "evidence": (
                "The real localhost /api/knowledge route retrieved one sampled persisted record "
                "from each of the 11 approved datasets and passed three fixed security-identifier "
                "probes with exact source/hash/validation provenance."
            ),
        })
    except Exception as exc:
        report.update({
            "success": False,
            "overall": "FAIL",
            "error": f"{type(exc).__name__}: {exc}",
            "passed_tests": sum(row.get("pass") is True for row in report["tests"]),
            "failed_tests": sum(row.get("pass") is not True for row in report["tests"]),
        })
    finally:
        if server is not None:
            server.shutdown()
            server.server_close()
        if thread is not None:
            thread.join(timeout=5)

    report_path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False, default=str) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(report, indent=2, ensure_ascii=False, default=str))
    print(f"LIVE_RAG_API_REPORT={report_path}")
    return 0 if report["success"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
