#!/usr/bin/env python3
"""Exercise the populated Knowledge DB through the real localhost RAG API only."""
from __future__ import annotations

import argparse
import json
import os
import sys
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen


def post_json(url: str, payload: dict) -> tuple[int, dict]:
    request = Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=30) as response:
            status = response.status
            body = json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        status = exc.code
        body = json.loads(exc.read().decode("utf-8"))
    if not isinstance(body, dict):
        raise ValueError("API returned a non-object JSON body")
    return status, body


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db-path", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args(argv)
    db_path = args.db_path.expanduser().resolve()
    report_path = args.report.expanduser().resolve()
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report = {
        "db_path": str(db_path),
        "api_network_scope": "127.0.0.1 only",
        "tests": [],
        "success": False,
    }
    try:
        if not db_path.is_file() or db_path.stat().st_size == 0:
            raise FileNotFoundError(f"populated DB file missing or empty: {db_path}")
        os.environ["AI_CYBER_KNOWLEDGE_DB"] = str(db_path)
        src = str(Path(__file__).resolve().parents[1] / "src")
        if src not in sys.path:
            sys.path.insert(0, src)
        from ai_cyber_os import ui
        from ai_cyber_os.knowledge import status

        configured_db = Path(ui.DEFAULT_DB).expanduser().resolve()
        if configured_db != db_path:
            raise RuntimeError(
                f"RAG/API DB mismatch: UI uses {configured_db}, build uses {db_path}"
            )
        store_status = status(db_path=db_path)
        if int(store_status.get("records", 0)) <= 0:
            raise RuntimeError("Knowledge DB contains zero records")

        server = ThreadingHTTPServer(("127.0.0.1", 0), ui.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base_url = f"http://127.0.0.1:{server.server_port}"
        probes = (
            ("nvd_cve", "CVE-2021-44228"),
            ("cwe", "CWE-79"),
            ("mitre_attack", "T1059"),
            ("cvss", "CVSS"),
        )
        try:
            for dataset, query in probes:
                http_status, body = post_json(
                    f"{base_url}/api/knowledge",
                    {"action": "context", "query": query, "dataset": dataset, "limit": 5},
                )
                evidence = body.get("evidence", [])
                first = evidence[0] if isinstance(evidence, list) and evidence else {}
                digest = str(first.get("content_sha256") or "")
                source_ok = bool(
                    first.get("record_id")
                    and first.get("dataset") == dataset
                    and first.get("source")
                    and len(digest) == 64
                    and all(ch in "0123456789abcdef" for ch in digest.lower())
                )
                passed = (
                    http_status == 200
                    and body.get("success") is True
                    and body.get("evidence_only") is True
                    and int(body.get("count", 0)) > 0
                    and source_ok
                )
                row = {
                    "dataset": dataset,
                    "query": query,
                    "http_status": http_status,
                    "success": body.get("success"),
                    "evidence_only": body.get("evidence_only"),
                    "evidence_count": body.get("count", 0),
                    "provenance_verified": source_ok,
                    "sample_record_id": first.get("record_id"),
                    "pass": passed,
                }
                report["tests"].append(row)
                if not passed:
                    raise RuntimeError(
                        f"live RAG API probe failed for {dataset}/{query}: "
                        + json.dumps(row, sort_keys=True)
                    )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

        report.update({
            "success": True,
            "overall": "PASS",
            "database_status": store_status,
            "ui_default_db": str(configured_db),
            "evidence": "The real localhost /api/knowledge context route retrieved persisted records with evidence-only mode and source/hash provenance from the requested database.",
        })
    except Exception as exc:
        report.update({
            "success": False,
            "overall": "FAIL",
            "error": f"{type(exc).__name__}: {exc}",
        })
    report_path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )
    print(json.dumps(report, indent=2, ensure_ascii=False, default=str))
    print(f"LIVE_RAG_API_REPORT={report_path}")
    return 0 if report["success"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
