#!/usr/bin/env python3
"""Build and verify the AI-CYBER Knowledge DB using the repo's manifest pipeline.

No Git push is performed. NVD feed acquisition is resumable. All required source
manifests/artifacts must pass readiness before ingestion starts. Builds resume only
when the DB's exact source-manifest digest ledger matches the present snapshot.
"""
from __future__ import annotations

import argparse
import datetime as dt
import faulthandler
import hashlib
import importlib.util
import json
import os
import re
import sqlite3
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

CHUNK = 1024 * 1024


def resumable_download_to(url: str, target: Path, *, retries: int = 5, timeout: int = 180) -> None:
    """Resume a broken HTTP transfer through validated Range requests."""
    target.parent.mkdir(parents=True, exist_ok=True)
    part = target.with_name(target.name + ".part")
    last_error = None
    for attempt in range(1, retries + 1):
        offset = part.stat().st_size if part.is_file() else 0
        headers = {"User-Agent": "AI-CYBER-Knowledge-DB-builder/1.0", "Accept-Encoding": "identity"}
        if offset:
            headers["Range"] = f"bytes={offset}-"
        request = urllib.request.Request(url, headers=headers)
        try:
            try:
                response = urllib.request.urlopen(request, timeout=timeout)
            except urllib.error.HTTPError as exc:
                match = re.fullmatch(r"bytes\s+\*/(\d+)", str(exc.headers.get("Content-Range", "")).strip(), re.I)
                if exc.code == 416 and offset and match and int(match.group(1)) == offset:
                    part.replace(target)
                    return
                raise
            with response:
                status = int(getattr(response, "status", response.getcode()))
                raw_length = response.headers.get("Content-Length", "")
                content_length = int(raw_length) if raw_length.isdigit() else None
                expected_segment, expected_total = content_length, None
                if status == 206:
                    match = re.fullmatch(r"bytes\s+(\d+)-(\d+)/(\d+|\*)",
                                          str(response.headers.get("Content-Range", "")).strip(), re.I)
                    if not match:
                        raise ValueError("invalid Content-Range on resumed transfer")
                    start, end = int(match.group(1)), int(match.group(2))
                    if start != offset or end < start:
                        raise ValueError(f"unexpected Content-Range for offset {offset}")
                    expected_segment = end - start + 1
                    if content_length is not None and content_length != expected_segment:
                        raise ValueError("Content-Length disagrees with Content-Range")
                    expected_total = int(match.group(3)) if match.group(3) != "*" else None
                    mode = "ab" if offset else "wb"
                elif status == 200:
                    # A server that ignores Range must replace the partial, not append.
                    mode, offset, expected_total = "wb", 0, content_length
                else:
                    raise ValueError(f"unexpected HTTP status {status}")
                received = 0
                with part.open(mode) as output:
                    while True:
                        block = response.read1(CHUNK) if hasattr(response, "read1") else response.read(CHUNK)
                        if not block:
                            break
                        output.write(block)
                        received += len(block)
                    output.flush()
                    os.fsync(output.fileno())
                if expected_segment is not None and received != expected_segment:
                    raise ConnectionError(f"short segment: expected {expected_segment}, got {received}")
                size = part.stat().st_size
                if expected_total is not None and size > expected_total:
                    part.unlink(missing_ok=True)
                    raise ValueError(f"assembled data exceeds HTTP total {expected_total}")
                if expected_total is not None and size < expected_total:
                    raise ConnectionError(f"partial retained: {size}/{expected_total}")
                if size <= 0:
                    raise ValueError("empty HTTP response")
                part.replace(target)
                return
        except Exception as exc:
            last_error = exc
            print(f"DOWNLOAD RETRY {attempt}/{retries}: {type(exc).__name__}: {exc}; partial={part.stat().st_size if part.exists() else 0}", flush=True)
            if attempt < retries:
                time.sleep(min(2 ** (attempt - 1), 8))
    raise RuntimeError(f"download failed after {retries} attempts: {url}") from last_error


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(CHUNK), b""):
            h.update(block)
    return h.hexdigest()


def read_json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object in {path}")
    return value


def source_snapshot(manifest_dir: Path) -> str:
    digests = {}
    for path in sorted(manifest_dir.rglob("*.json")):
        if path.name.casefold() == "example.json":
            continue
        manifest = read_json(path)
        name = str(manifest.get("dataset") or path.stem)
        if name in digests:
            raise ValueError(f"duplicate manifest for {name}")
        digests[name] = sha256_file(path)
    return json.dumps(digests, sort_keys=True, separators=(",", ":"))


def can_resume(db_path: Path, manifest_dir: Path) -> tuple[bool, str]:
    if not db_path.exists():
        return False, "new database path"
    if db_path.stat().st_size == 0:
        raise RuntimeError(f"refusing to reuse a zero-byte DB: {db_path}")
    conn = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
    try:
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not {"knowledge_meta", "knowledge_records"}.issubset(tables):
            raise RuntimeError("existing file is not an AI-CYBER Knowledge DB; use a new path")
        meta = {str(k): str(v) for k, v in conn.execute("SELECT key,value FROM knowledge_meta")}
    finally:
        conn.close()
    pinned = meta.get("source_manifest_digests")
    if not pinned:
        raise RuntimeError("existing DB lacks source-manifest digest ledger; use a new path")
    if pinned != source_snapshot(manifest_dir):
        raise RuntimeError("source manifest snapshot changed; use a new versioned --db-path, existing DB untouched")
    return True, "source-manifest digest ledger matches"


def _nvd_download_to(url: str, target: Path) -> None:
    """Use short bounded retries for tiny NVD metadata files, resumable transfer for feeds.

    A metadata endpoint stall must not consume up to 15 minutes per yearly feed.
    Feed downloads retain the longer timeout and resume behavior because the
    compressed NVD archives can be large.
    """
    if url.split("?", 1)[0].lower().endswith(".meta"):
        resumable_download_to(url, target, retries=2, timeout=20)
    else:
        resumable_download_to(url, target, retries=5, timeout=180)


def load_nvd_module(root: Path):
    source = root / "scripts" / "kaggle_nvd_feed_readiness.py"
    spec = importlib.util.spec_from_file_location("_ai_cyber_nvd_for_db_build", source)
    if spec is None or spec.loader is None:
        raise FileNotFoundError(f"cannot load {source}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    module.download_to = _nvd_download_to
    return module


def latest_gate_report(root: Path):
    reports = sorted((root / "datasets" / "acquisition_reports").glob("parser-readiness-*.json"),
                     key=lambda p: p.stat().st_mtime)
    return reports[-1] if reports else None


def _stable_table_fingerprints(conn: sqlite3.Connection) -> dict[str, str]:
    """Hash stable knowledge tables, excluding volatile open/access metadata."""
    queries = {
        "record_table_sha256": (
            "SELECT record_id,dataset,source,source_uri,license,validation_status,version,"
            "title,content,content_sha256,metadata_json,schema_version,ingested_at "
            "FROM knowledge_records ORDER BY record_id"
        ),
        "relations_table_sha256": (
            "SELECT record_id,relation_type,target_id FROM knowledge_relations "
            "ORDER BY record_id,relation_type,target_id"
        ),
        "chunks_table_sha256": (
            "SELECT chunk_id,record_id,chunk_index,content,content_sha256 "
            "FROM knowledge_chunks ORDER BY chunk_id"
        ),
    }
    fingerprints: dict[str, str] = {}
    for name, query in queries.items():
        digest = hashlib.sha256()
        cursor = conn.execute(query)
        while True:
            rows = cursor.fetchmany(1000)
            if not rows:
                break
            for row in rows:
                encoded = json.dumps(
                    list(row), ensure_ascii=False, separators=(",", ":"), default=str
                ).encode("utf-8")
                digest.update(encoded)
                digest.update(b"\\n")
        fingerprints[name] = digest.hexdigest()
    return fingerprints


def validate_db_and_rag(db_path: Path, required_datasets: tuple[str, ...]) -> dict:
    from ai_cyber_os.knowledge import SCHEMA_VERSION, DATABASE_VERSION, open_store, status, search
    from ai_cyber_os.rag import build_context
    conn = open_store(db_path)
    try:
        integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
        fk_issues = conn.execute("PRAGMA foreign_key_check").fetchall()
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type IN ('table','view')")}
        expected_tables = {"knowledge_records", "knowledge_relations", "knowledge_fts",
                           "knowledge_chunks", "knowledge_chunks_fts", "knowledge_meta",
                           "knowledge_ingestion_checkpoints"}
        missing_tables = sorted(expected_tables - tables)
        dataset_counts = {str(name): int(n) for name, n in conn.execute(
            "SELECT dataset,COUNT(*) FROM knowledge_records GROUP BY dataset")}
        records = int(conn.execute("SELECT COUNT(*) FROM knowledge_records").fetchone()[0])
        fts_records = int(conn.execute("SELECT COUNT(*) FROM knowledge_fts").fetchone()[0])
        chunks = int(conn.execute("SELECT COUNT(*) FROM knowledge_chunks").fetchone()[0])
        chunk_fts = int(conn.execute("SELECT COUNT(*) FROM knowledge_chunks_fts").fetchone()[0])
        conn.execute("INSERT INTO knowledge_fts(knowledge_fts) VALUES('integrity-check')")
        conn.execute("INSERT INTO knowledge_chunks_fts(knowledge_chunks_fts) VALUES('integrity-check')")
        stable_fingerprints = _stable_table_fingerprints(conn)
        conn.commit()
    finally:
        conn.close()
    missing = [name for name in required_datasets if dataset_counts.get(name, 0) <= 0]
    if dataset_counts.get("cvss", 0) <= 0:
        missing.append("cvss (derived)")
    probes = []
    for dataset, query in (("nvd_cve", "CVE-2021-44228"), ("cwe", "CWE-79"),
                           ("mitre_attack", "T1059"), ("cvss", "CVSS")):
        hits = search(query, db_path=db_path, dataset=dataset, limit=5)
        context = build_context(query, db_path=db_path, dataset=dataset, limit=5)
        first = (context.get("evidence") or [{}])[0]
        passed = bool(hits and context.get("count", 0) and context.get("evidence_only") is True
                      and first.get("record_id") and first.get("source") and first.get("content_sha256"))
        probes.append({"dataset": dataset, "query": query, "hits": len(hits),
                       "context_count": context.get("count", 0), "evidence_only": context.get("evidence_only") is True,
                       "provenance_present": bool(first.get("record_id") and first.get("source") and first.get("content_sha256")),
                       "pass": passed, "sample_ids": [row.get("record_id") for row in context.get("evidence", [])[:3]]})
    persisted = search("CVE-2021-44228", db_path=db_path, dataset="nvd_cve", limit=5)
    report_status = status(db_path=db_path)
    failures = []
    if integrity != "ok": failures.append(f"SQLite integrity check: {integrity}")
    if fk_issues: failures.append(f"foreign-key issues: {len(fk_issues)}")
    if missing_tables: failures.append(f"missing tables: {missing_tables}")
    if missing: failures.append(f"missing dataset records: {missing}")
    if fts_records != records: failures.append(f"FTS records {fts_records} != base records {records}")
    if chunk_fts != chunks: failures.append(f"chunk FTS {chunk_fts} != chunks {chunks}")
    if not persisted: failures.append("NVD retrieval did not survive database reopen")
    if any(not p["pass"] for p in probes): failures.append("one or more RAG probes failed")
    return {"pass": not failures, "failures": failures, "db_path": str(db_path.resolve()),
            "db_bytes": db_path.stat().st_size, "db_sha256": sha256_file(db_path),
            "sqlite_integrity": integrity, "foreign_key_issues": len(fk_issues),
            "missing_tables": missing_tables, "records": records, "fts_records": fts_records,
            "chunks": chunks, "chunk_fts": chunk_fts, "dataset_counts": dataset_counts,
            "missing_datasets": missing, "schema_version": SCHEMA_VERSION,
            "database_version": DATABASE_VERSION, **stable_fingerprints,
            "rag_smoke_probes": probes,
            "nvd_hits_after_reopen": len(persisted), "status_after_reopen": report_status}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--db-path", type=Path, default=None)
    parser.add_argument("--report", type=Path, default=None)
    parser.add_argument("--start-year", type=int, default=2002)
    parser.add_argument("--end-year", type=int, default=None)
    args = parser.parse_args(argv)
    root = args.project_root.expanduser().resolve()
    output = root / "build-output"
    output.mkdir(parents=True, exist_ok=True)
    db_path = (args.db_path.expanduser().resolve() if args.db_path is not None else
               Path("/kaggle/working/AI-CYBER-Knowledge-DB/ai_cyber_knowledge.sqlite3")
               if Path("/kaggle/working").is_dir() else (output / "ai_cyber_knowledge.sqlite3").resolve())
    report_path = (args.report or output / "knowledge-db-build-report.json").expanduser().resolve()
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report = {"started_at": dt.datetime.now(dt.timezone.utc).isoformat(), "project_root": str(root),
              "db_path": str(db_path), "push_performed": False, "database_deleted_or_overwritten": False,
              "ingestion_performed": False, "steps": []}
    try:
        faulthandler.enable()
        faulthandler.dump_traceback_later(600, repeat=True)
        print("Watchdog enabled: traceback every 600 seconds.", flush=True)
        required = [root / ".git", root / "scripts/kaggle_nvd_feed_readiness.py",
                    root / "scripts/kaggle_dataset_parser_readiness_gate.py",
                    root / "src/ai_cyber_os/dataset_pipeline.py", root / "src/ai_cyber_os/knowledge.py",
                    root / "src/ai_cyber_os/rag.py"]
        missing_files = [str(path) for path in required if not path.exists()]
        if missing_files:
            raise FileNotFoundError(f"required project files missing: {missing_files}")
        manifests = root / "datasets" / "manifests"
        resume, reason = can_resume(db_path, manifests)
        os.environ["AI_CYBER_KNOWLEDGE_DB"] = str(db_path)
        if str(root / "src") not in sys.path:
            sys.path.insert(0, str(root / "src"))
        nvd_manifest = manifests / "nvd_cve.json"
        if resume:
            if not nvd_manifest.is_file():
                raise RuntimeError("pinned DB exists but NVD manifest is missing; refusing unsafe resume")
            report["steps"].append({"step": "resume pinned snapshot", "pass": True, "details": reason})
        else:
            print("STAGE 1/4: acquiring and checksum-verifying NVD feeds; the source gate itself does not create a database.", flush=True)
            nvd = load_nvd_module(root)
            nvd_report = output / "nvd-acquisition-report.json"
            end_year = args.end_year or dt.datetime.now(dt.timezone.utc).year
            exit_code = nvd.main(["--project-root", str(root), "--start-year", str(args.start_year),
                                  "--end-year", str(end_year), "--report", str(nvd_report)])
            gate_path = latest_gate_report(root)
            gate = read_json(gate_path) if gate_path else {}
            if not nvd_manifest.is_file() or exit_code != 0 or gate.get("overall") != "PASS":
                report.update({"overall": "BLOCKED", "success": False,
                               "evidence": "Combined source readiness not PASS; database ingestion did not start.",
                               "nvd_exit_code": exit_code, "gate_report_path": str(gate_path) if gate_path else None,
                               "gate_report": gate, "ingestion_performed": False})
                report["finished_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
                report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
                print(json.dumps(report, indent=2, ensure_ascii=False, default=str), flush=True)
                print(f"BUILD_REPORT={report_path}", flush=True)
                return 2
            report["steps"].append({"step": "NVD acquisition + combined readiness", "pass": True,
                                    "gate_report_path": str(gate_path), "gate_overall": gate.get("overall")})
        print("STAGE 2/4: validating artifact hashes and sizes, reusing parser-readiness counts from the just-passed gate, and streaming per-dataset ingestion progress.", flush=True)
        from ai_cyber_os.dataset_pipeline import DEFAULT_REQUIRED_DATASETS, ingest_manifest_directory
        result = ingest_manifest_directory(manifests, db_path=db_path,
                                           required_datasets=DEFAULT_REQUIRED_DATASETS, require_checksum=True,
                                           prevalidated_counts=True)
        report["ingestion_report"] = result
        report["ingestion_performed"] = bool(result.get("ingestion_performed"))
        if result.get("overall") != "PASS" or result.get("success") is not True:
            report.update({"overall": result.get("overall", "FAIL"), "success": False,
                           "evidence": result.get("evidence", "ingestion/readiness did not pass"),
                           "finished_at": dt.datetime.now(dt.timezone.utc).isoformat()})
            report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
            print(json.dumps(report, indent=2, ensure_ascii=False, default=str))
            print(f"BUILD_REPORT={report_path}")
            return 2
        if not db_path.is_file() or db_path.stat().st_size <= 0:
            raise RuntimeError("ingestion reported PASS but the target Knowledge DB file is missing or empty; refusing to run verification")
        print(f"STAGE 3/4: ingestion finished; database_bytes={db_path.stat().st_size}; starting SQLite/FTS and direct RAG verification.", flush=True)
        verification = validate_db_and_rag(db_path, tuple(DEFAULT_REQUIRED_DATASETS))
        if not db_path.is_file() or db_path.stat().st_size <= 0:
            raise RuntimeError("database disappeared or became empty during verification")
        report.update({"database_verification": verification, "success": bool(verification["pass"]),
                       "overall": "PASS" if verification["pass"] else "FAIL",
                       "evidence": ("All raw sources ingested; CVSS derived; SQLite/FTS and live RAG probes passed."
                                    if verification["pass"] else "Database created, but verification/RAG checks failed."),
                       "finished_at": dt.datetime.now(dt.timezone.utc).isoformat()})
        report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
        print(json.dumps(report, indent=2, ensure_ascii=False, default=str))
        print(f"BUILD_REPORT={report_path}", flush=True)
        print(f"DATABASE_PATH={db_path}", flush=True)
        print(f"STAGE 4/4: database_build_overall={report['overall']} database_bytes={db_path.stat().st_size if db_path.is_file() else 0}", flush=True)
        return 0 if verification["pass"] and db_path.is_file() and db_path.stat().st_size > 0 else 2
    except Exception as exc:
        report.update({"overall": "FAIL", "success": False, "error": f"{type(exc).__name__}: {exc}",
                       "finished_at": dt.datetime.now(dt.timezone.utc).isoformat()})
        report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
        print(json.dumps(report, indent=2, ensure_ascii=False, default=str))
        print(f"BUILD_REPORT={report_path}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
