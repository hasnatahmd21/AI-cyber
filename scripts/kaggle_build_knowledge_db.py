#!/usr/bin/env python3
"""Build and verify the versioned AI-CYBER Knowledge DB after readiness PASS.

This command is deliberately fail-closed:
  1. the real-artifact/readiness gate must pass before the target DB is opened;
  2. all required manifests pass checksum, byte-size, and parser-count preflight;
  3. ingestion uses per-artifact checkpoints and can be restarted;
  4. retrieval/citation and a separate-process restart smoke test run afterward;
  5. durable persistence is explicit: a private Kaggle Dataset version or Git LFS; local-only output is never called permanent.

A database in /kaggle/working is not durable by itself. Use --persist-kaggle-dataset-id OWNER/SLUG to publish a private, versioned Kaggle Dataset, or use --persist-lfs.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REQUIRED = (
    "capec", "cisa_kev", "cpe", "cwe", "epss", "mitre_attack",
    "mitre_d3fend", "mitre_mbc", "sigma", "suricata", "zeek_intel",
)
PROBE_CVE = "CVE-2021-44228"
PROBE_CWE = "CWE-79"
PROBE_ATTACK = "T1059.001"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_json(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".part")
    temp.write_text(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True, default=str) + "\n",
                    encoding="utf-8")
    temp.replace(path)


def sqlite_integrity_smoke_test(
    db_path: Path,
    required_datasets: list[str] | tuple[str, ...],
) -> dict[str, Any]:
    """Read-only integrity and source-scope verification of the built Knowledge DB."""
    if not db_path.is_file() or db_path.stat().st_size <= 0:
        raise RuntimeError(f"Knowledge DB is missing or empty: {db_path}")
    connection = sqlite3.connect(f"file:{db_path.resolve().as_posix()}?mode=ro", uri=True, timeout=60)
    try:
        integrity_rows = [str(row[0]) for row in connection.execute("PRAGMA integrity_check")]
        integrity = integrity_rows[0] if len(integrity_rows) == 1 else "; ".join(integrity_rows)
        if integrity_rows != ["ok"]:
            raise RuntimeError(f"SQLite PRAGMA integrity_check failed: {integrity_rows[:10]}")
        metadata = {
            str(row[0]): str(row[1])
            for row in connection.execute("SELECT key,value FROM knowledge_meta")
        }
        counts = {
            str(row[0]): int(row[1])
            for row in connection.execute(
                "SELECT dataset,COUNT(*) FROM knowledge_records GROUP BY dataset ORDER BY dataset"
            )
        }
        record_count = int(connection.execute("SELECT COUNT(*) FROM knowledge_records").fetchone()[0])
        fts_count = int(connection.execute("SELECT COUNT(*) FROM knowledge_fts").fetchone()[0])
        chunk_count = int(connection.execute("SELECT COUNT(*) FROM knowledge_chunks").fetchone()[0])
        chunk_fts_count = int(connection.execute("SELECT COUNT(*) FROM knowledge_chunks_fts").fetchone()[0])
        checkpoint_rows = {
            str(row[0]): int(row[1])
            for row in connection.execute(
                "SELECT status,COUNT(*) FROM knowledge_ingestion_checkpoints GROUP BY status"
            )
        }
    finally:
        connection.close()

    required = set(required_datasets)
    actual = set(counts)
    missing = sorted(required - actual)
    unexpected = sorted(actual - required)
    excluded_rows = sorted(actual & {"nvd_cve", "cvss"})
    if metadata.get("database_version") != "ai-cyber-knowledge-v1":
        raise RuntimeError(f"Unexpected database version: {metadata.get('database_version')!r}")
    if not metadata.get("source_manifest_digests"):
        raise RuntimeError("Knowledge DB has no pinned source-manifest digest ledger")
    if record_count <= 0 or missing:
        raise RuntimeError(f"Knowledge DB has no records for all required datasets; missing={missing}")
    if unexpected or excluded_rows:
        raise RuntimeError(
            f"Knowledge DB dataset scope differs from the approved 11-source set; "
            f"unexpected={unexpected}, excluded={excluded_rows}"
        )
    if fts_count != record_count:
        raise RuntimeError(
            f"Knowledge FTS index count mismatch: records={record_count}, FTS rows={fts_count}"
        )
    if chunk_fts_count != chunk_count:
        raise RuntimeError(
            f"Knowledge chunk FTS index count mismatch: chunks={chunk_count}, chunk FTS rows={chunk_fts_count}"
        )
    unfinished = {key: value for key, value in checkpoint_rows.items() if key != "complete" and value}
    if unfinished:
        raise RuntimeError(f"Knowledge DB contains unfinished/failed ingestion checkpoints: {unfinished}")
    return {
        "status": "PASS",
        "sqlite_integrity_check": integrity,
        "database_version": metadata.get("database_version"),
        "schema_version": metadata.get("schema_version"),
        "record_count": record_count,
        "datasets": counts,
        "fts_rows": fts_count,
        "chunks": chunk_count,
        "chunk_fts_rows": chunk_fts_count,
        "checkpoint_status_counts": checkpoint_rows,
        "source_manifest_ledger_present": True,
        "excluded_dataset_rows": excluded_rows,
    }



def print_build_summary(report: dict[str, Any], report_path: Path) -> None:
    """Print compact stage results; the full auditable evidence stays in the JSON report."""
    batch = report.get("batch_ingestion") or {}
    core = report.get("core_query_smoke_test") or {}
    queries = core.get("queries") or {}
    dataset_results = []
    for row in batch.get("results", []):
        dataset_results.append({
            "dataset": row.get("dataset"),
            "status": "PASS" if row.get("success") is True else "FAIL",
            "records": row.get("records", row.get("processed_records", 0)),
            "inserted": row.get("inserted", 0),
            "updated": row.get("updated", 0),
            "duplicates": row.get("duplicates", 0),
            "skipped_artifacts": row.get("skipped_artifacts", 0),
        })
    rag_queries_ok = bool(queries) and all(
        item.get("success") is True
        and item.get("evidence_only") is True
        and item.get("has_citations") is True
        and item.get("rag", {}).get("success") is True
        and item.get("rag", {}).get("has_citations") is True
        for item in queries.values()
    )
    stages = {
        "source_readiness": report.get("source_readiness", "NOT_RUN"),
        "11_dataset_integrity_preflight": (
            "PASS" if batch.get("overall") == "PASS" and batch.get("ready") is True
            else batch.get("overall", "NOT_RUN")
        ),
        "sqlite_ingestion": (
            "PASS" if batch.get("overall") == "PASS" and report.get("ingestion_performed") is True
            and (report.get("sqlite_integrity_smoke_test") or {}).get("status") == "PASS"
            else "NOT_RUN" if not report.get("ingestion_performed") else batch.get("overall", "FAIL")
        ),
        "runtime_and_direct_rag": "PASS" if rag_queries_ok else "NOT_RUN" if not queries else "FAIL",
        "fresh_process_restart": "PASS" if report.get("restart_smoke_test") else "NOT_RUN",
        "permanent_storage": report.get("permanent_persistence", "NOT_CONFIRMED"),
    }
    db_status = report.get("database_status") or (batch.get("store_status") or {})
    summary = {
        "status": report.get("overall", "UNKNOWN"),
        "stages": stages,
        "required_dataset_count": len(report.get("required_datasets", [])),
        "readiness_inspections_reused": report.get("readiness_inspections_reused", 0),
        "pipeline_preflight_inspections_reused": batch.get("preflight_inspection_reuse_count", 0),
        "datasets": dataset_results,
        "database": {
            "path": report.get("database_path"),
            "records": db_status.get("records"),
            "chunks": db_status.get("chunks"),
            "bytes": report.get("database_byte_size"),
            "sha256": report.get("database_sha256"),
        },
        "rag_queries": {
            key: {
                "runtime_success": item.get("success"),
                "runtime_count": item.get("count"),
                "direct_rag_success": item.get("rag", {}).get("success"),
                "direct_rag_count": item.get("rag", {}).get("count"),
                "citations": item.get("rag", {}).get("has_citations"),
            }
            for key, item in queries.items()
        },
        "error": report.get("evidence") if report.get("overall") not in {
            "PASS", "LOCAL_BUILD_PASS_PERSISTENCE_PENDING"
        } else None,
        "report_file": str(report_path),
    }
    print("[knowledge-db-summary] " + json.dumps(
        summary, ensure_ascii=False, sort_keys=True, default=str
    ), flush=True)


def run_readiness_gate(raw_root: Path, report_path: Path) -> dict[str, Any]:
    gate = REPOSITORY_ROOT / "scripts" / "kaggle_dataset_parser_readiness_gate.py"
    if not gate.is_file():
        raise FileNotFoundError(f"readiness gate script missing: {gate}")
    proc = subprocess.run(
        [sys.executable, str(gate), "--raw-root", str(raw_root), "--report", str(report_path)],
        cwd=REPOSITORY_ROOT, text=True, capture_output=True, check=False,
    )
    if not report_path.is_file():
        raise RuntimeError(
            "readiness gate did not produce a report; "
            f"exit={proc.returncode}, stdout={proc.stdout[-2000:]}, stderr={proc.stderr[-2000:]}"
        )
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["gate_exit_code"] = proc.returncode
    if proc.returncode != 0 and report.get("overall") == "PASS":
        raise RuntimeError("readiness report says PASS but gate exit code is non-zero")
    return report


def restart_smoke_test(db_path: Path, cve_id: str) -> dict[str, Any]:
    """Import default DB path in a new Python process and verify rows survive restart."""
    env = os.environ.copy()
    env["AI_CYBER_KNOWLEDGE_DB"] = str(db_path)
    env["PYTHONPATH"] = str(REPOSITORY_ROOT / "src") + os.pathsep + env.get("PYTHONPATH", "")
    program = (
        "import json\n"
        "from ai_cyber_os.knowledge import DEFAULT_DB, status, search\n"
        "from ai_cyber_os.runtime_intelligence import analyze\n"
        "from ai_cyber_os.rag import build_context\n"
        "s=status()\n"
        "hits=search(" + repr(cve_id) + ", dataset='cisa_kev', limit=10)\n"
        "a=analyze(" + repr(cve_id) + ", dataset='cisa_kev', limit=10)\n"
        "r=build_context(" + repr(cve_id) + ", db_path=DEFAULT_DB, dataset='cisa_kev', limit=10)\n"
        "e=r.get('evidence',[])\n"
        "print(json.dumps({'default_db':str(DEFAULT_DB.resolve()),'status':s,'hits':"
        "[{'record_id':x['record_id'],'dataset':x['dataset']} for x in hits],"
        "'analysis':{'success':a.get('success'),'evidence_only':a.get('evidence_only'),"
        "'count':len(a.get('evidence',[])),'has_citations':bool(a.get('evidence',[])) and all("
        "bool(x.get('source_uri')) and bool(x.get('content_sha256')) and "
        "bool(x.get('validation_status')) for x in a.get('evidence',[]))},"
        "'rag':{'success':bool(e) and r.get('evidence_only') is True,"
        "'evidence_only':r.get('evidence_only'),'count':r.get('count',len(e)),"
        "'has_citations':bool(e) and all(bool(x.get('source_uri')) and "
        "bool(x.get('content_sha256')) and bool(x.get('validation_status')) for x in e),"
        "'evidence':[{'record_id':x.get('record_id'),'dataset':x.get('dataset'),"
        "'source_uri':x.get('source_uri'),'content_sha256':x.get('content_sha256'),"
        "'validation_status':x.get('validation_status')} for x in e]}}))\n"
    )
    proc = subprocess.run(
        [sys.executable, "-c", program],
        cwd=REPOSITORY_ROOT,
        env=env,
        text=True,
        capture_output=True,
        timeout=180,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"restart/retrieval process failed: {proc.stderr[-3000:]}")
    data = json.loads(proc.stdout.strip().splitlines()[-1])
    if Path(data["default_db"]).resolve() != db_path.resolve():
        raise RuntimeError(
            f"runtime default DB path mismatch: expected {db_path}, got {data['default_db']}"
        )
    if data["status"].get("records", 0) <= 0:
        raise RuntimeError("restart test found an empty Knowledge DB")
    if not data["hits"]:
        raise RuntimeError(f"CISA KEV CVE probe returned no records after process restart: {cve_id}")
    if not data["analysis"].get("success") or not data["analysis"].get("evidence_only"):
        raise RuntimeError("runtime intelligence did not return an evidence-only result")
    if not data["analysis"].get("has_citations"):
        raise RuntimeError("runtime-intelligence evidence is missing source URI/hash/validation citation fields")
    if not data.get("rag", {}).get("success") or not data["rag"].get("evidence_only"):
        raise RuntimeError("direct RAG build_context retrieval failed after process restart")
    if not data["rag"].get("has_citations"):
        raise RuntimeError("direct RAG evidence is missing source URI/hash/validation citation fields after restart")
    return data



def core_query_smoke_test(
    db_path: Path,
    cve_id: str = PROBE_CVE,
    cwe_id: str = PROBE_CWE,
    attack_id: str = PROBE_ATTACK,
) -> dict[str, Any]:
    """Check CISA KEV CVE, CWE and ATT&CK retrieval in a fresh Python process."""
    env = os.environ.copy()
    env["AI_CYBER_KNOWLEDGE_DB"] = str(db_path)
    env["PYTHONPATH"] = str(REPOSITORY_ROOT / "src") + os.pathsep + env.get("PYTHONPATH", "")
    probes = {
        "cve": {"query": cve_id, "dataset": "cisa_kev"},
        "cwe": {"query": cwe_id, "dataset": "cwe"},
        "attack": {"query": attack_id, "dataset": "mitre_attack"},
    }
    program = (
        "import json\n"
        "from ai_cyber_os.knowledge import DEFAULT_DB, status\n"
        "from ai_cyber_os.runtime_intelligence import analyze\n"
        "from ai_cyber_os.rag import build_context\n"
        "probes = " + repr(probes) + "\n"
        "out = {}\n"
        "for family, spec in probes.items():\n"
        "    result = analyze(spec['query'], db_path=DEFAULT_DB, dataset=spec['dataset'], limit=10)\n"
        "    evidence = result.get('evidence', [])\n"
        "    rag_result = build_context(spec['query'], db_path=DEFAULT_DB, dataset=spec['dataset'], limit=10)\n"
        "    rag_evidence = rag_result.get('evidence', [])\n"
        "    out[family] = {\n"
        "        'query': spec['query'], 'dataset': spec['dataset'],\n"
        "        'success': result.get('success') is True,\n"
        "        'evidence_only': result.get('evidence_only') is True,\n"
        "        'count': len(evidence),\n"
        "        'has_citations': bool(evidence) and all(\n"
        "            bool(row.get('source_uri')) and bool(row.get('content_sha256'))\n"
        "            and bool(row.get('validation_status')) for row in evidence),\n"
        "        'evidence': [{\n"
        "            'record_id': row.get('record_id'), 'dataset': row.get('dataset'),\n"
        "            'source_uri': row.get('source_uri'), 'version': row.get('version'),\n"
        "            'validation_status': row.get('validation_status'),\n"
        "            'content_sha256': row.get('content_sha256'),\n"
        "        } for row in evidence],\n"
        "        'rag': {\n"
        "            'success': bool(rag_evidence) and rag_result.get('evidence_only') is True,\n"
        "            'evidence_only': rag_result.get('evidence_only') is True,\n"
        "            'count': rag_result.get('count', len(rag_evidence)),\n"
        "            'has_citations': bool(rag_evidence) and all(\n"
        "                bool(row.get('source_uri')) and bool(row.get('content_sha256'))\n"
        "                and bool(row.get('validation_status')) for row in rag_evidence),\n"
        "            'evidence': [{\n"
        "                'record_id': row.get('record_id'), 'dataset': row.get('dataset'),\n"
        "                'source_uri': row.get('source_uri'),\n"
        "                'validation_status': row.get('validation_status'),\n"
        "                'content_sha256': row.get('content_sha256'),\n"
        "            } for row in rag_evidence],\n"
        "        },\n"
        "    }\n"
        "print(json.dumps({'default_db': str(DEFAULT_DB.resolve()), 'status': status(), 'queries': out}))\n"
    )
    proc = subprocess.run(
        [sys.executable, "-c", program],
        cwd=REPOSITORY_ROOT,
        env=env,
        text=True,
        capture_output=True,
        timeout=300,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"core query smoke test process failed: {proc.stderr[-3000:]}")
    data = json.loads(proc.stdout.strip().splitlines()[-1])
    if Path(data["default_db"]).resolve() != db_path.resolve():
        raise RuntimeError(
            f"core query process used the wrong DB path: expected {db_path}, got {data['default_db']}"
        )
    if int(data.get("status", {}).get("records", 0)) <= 0:
        raise RuntimeError("core query process found an empty Knowledge DB")
    for family, query_result in data["queries"].items():
        if not query_result.get("success") or not query_result.get("evidence_only"):
            raise RuntimeError(f"{family.upper()} query did not return an evidence-only runtime result")
        if int(query_result.get("count", 0)) <= 0:
            raise RuntimeError(
                f"{family.upper()} query {query_result.get('query')!r} returned no result "
                f"from dataset {query_result.get('dataset')!r}"
            )
        if not query_result.get("has_citations"):
            raise RuntimeError(
                f"{family.upper()} runtime-intelligence query returned evidence without source URI/hash/validation citation fields"
            )
        rag_result = query_result.get("rag", {})
        if not rag_result.get("success") or not rag_result.get("evidence_only"):
            raise RuntimeError(
                f"{family.upper()} direct rag.build_context query returned no evidence-only context"
            )
        if int(rag_result.get("count", 0)) <= 0 or not rag_result.get("has_citations"):
            raise RuntimeError(
                f"{family.upper()} direct RAG evidence is empty or missing source/hash/validation provenance"
            )
    return data

def persist_via_lfs(db_path: Path, report_path: Path, branch: str) -> dict[str, Any]:
    """Explicit, opt-in durable publishing of the verified SQLite artifact."""
    git_root = REPOSITORY_ROOT
    if not (git_root / ".git").exists():
        raise RuntimeError("--persist-lfs requires running inside the AI-CYBER Git checkout")
    current = subprocess.run(
        ["git", "-C", str(git_root), "branch", "--show-current"],
        text=True, capture_output=True, check=True,
    ).stdout.strip()
    if current != branch:
        raise RuntimeError(f"current Git branch is {current!r}; refusing to publish to {branch!r}")
    try:
        relative_db = db_path.resolve().relative_to(git_root.resolve()).as_posix()
        relative_report = report_path.resolve().relative_to(git_root.resolve()).as_posix()
    except ValueError as exc:
        raise ValueError("database and report must be inside the repository to publish with Git LFS") from exc

    # Keep the real-artifact readiness evidence next to the published DB/report.
    # The report must not point at a file that disappears with the Kaggle session.
    relative_readiness_report = None
    if report_path.is_file():
        try:
            build_report = json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"cannot read build report before LFS publication: {report_path}") from exc
        readiness_value = build_report.get("source_readiness_report")
        if readiness_value:
            readiness_path = Path(str(readiness_value)).expanduser().resolve()
            try:
                relative_readiness_report = readiness_path.relative_to(git_root.resolve()).as_posix()
            except ValueError as exc:
                raise ValueError("source-readiness report must be inside the repository for Git LFS persistence") from exc
            if not readiness_path.is_file():
                raise FileNotFoundError(f"source-readiness report missing before LFS publication: {readiness_path}")

    import shutil
    if not shutil.which("git-lfs"):
        raise RuntimeError("git-lfs is required for --persist-lfs; no database was pushed")
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not token:
        try:
            from kaggle_secrets import UserSecretsClient
            token = UserSecretsClient().get_secret("cyber repo")
        except Exception as exc:
            raise RuntimeError('GitHub token unavailable; configure Kaggle secret "cyber repo"') from exc
    if not token or not token.strip():
        raise RuntimeError('GitHub token is empty; configure Kaggle secret "cyber repo"')

    subprocess.run(["git", "-C", str(git_root), "lfs", "install", "--local"], check=True)
    subprocess.run(["git", "-C", str(git_root), "lfs", "track", relative_db], check=True)
    files_to_stage = [".gitattributes", relative_db, relative_report]
    if relative_readiness_report:
        files_to_stage.append(relative_readiness_report)
    subprocess.run(["git", "-C", str(git_root), "add", "--", *files_to_stage], check=True)
    staged = subprocess.run(["git", "-C", str(git_root), "diff", "--cached", "--quiet"], check=False)
    if staged.returncode == 0:
        return {"status": "already-persisted", "branch": branch, "database_path": relative_db}
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    subprocess.run(
        ["git", "-C", str(git_root), "config", "user.name", "AI-CYBER Knowledge DB Builder"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(git_root), "config", "user.email", "ai-cyber-knowledge-db@users.noreply.github.com"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(git_root), "commit", "-m", f"data: persist verified Knowledge DB {stamp}"],
        check=True,
    )
    ask_fd, ask_name = tempfile.mkstemp(prefix="ai-cyber-db-askpass-")
    os.close(ask_fd)
    askpass = Path(ask_name)
    try:
        askpass.write_text("#!/bin/sh\nprintf '%s\\n' \"$GITHUB_TOKEN\"\n", encoding="utf-8")
        askpass.chmod(0o700)
        env = os.environ.copy()
        env["GITHUB_TOKEN"] = token.strip()
        env["GIT_ASKPASS"] = str(askpass)
        env["GIT_TERMINAL_PROMPT"] = "0"
        subprocess.run(
            ["git", "-C", str(git_root), "remote", "set-url", "origin",
             "https://x-access-token@github.com/hasnatahmd21/AI-cyber.git"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(git_root), "push", "origin", branch],
            check=True, env=env,
        )
        sha = subprocess.run(
            ["git", "-C", str(git_root), "rev-parse", "HEAD"],
            text=True, capture_output=True, check=True,
        ).stdout.strip()
        return {"status": "pushed", "branch": branch, "commit": sha, "database_path": relative_db, "source_readiness_report_path": relative_readiness_report}
    finally:
        askpass.unlink(missing_ok=True)




def persist_lfs_confirmation_report(report_path: Path, branch: str) -> dict[str, Any]:
    """Commit and push the final post-persistence report after the DB push succeeds.

    The first LFS commit necessarily contains a PUBLISH_PENDING report. This
    second, report-only commit records confirmation only after the DB commit was
    accepted by the remote. It never stages the database a second time.
    """
    git_root = REPOSITORY_ROOT
    if not (git_root / ".git").exists():
        raise RuntimeError("--persist-lfs report finalization requires the Git checkout")
    current = subprocess.run(
        ["git", "-C", str(git_root), "branch", "--show-current"],
        text=True, capture_output=True, check=True,
    ).stdout.strip()
    if current != branch:
        raise RuntimeError(
            f"current Git branch is {current!r}; refusing report update on {branch!r}"
        )
    try:
        relative_report = report_path.resolve().relative_to(git_root.resolve()).as_posix()
    except ValueError as exc:
        raise ValueError("final persistence report must be inside the repository") from exc
    if not report_path.is_file():
        raise FileNotFoundError(f"final persistence report missing: {report_path}")

    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not token:
        try:
            from kaggle_secrets import UserSecretsClient
            token = UserSecretsClient().get_secret("cyber repo")
        except Exception as exc:
            raise RuntimeError(
                'GitHub token unavailable to publish the final report; configure Kaggle secret "cyber repo"'
            ) from exc
    if not isinstance(token, str) or not token.strip():
        raise RuntimeError("GitHub token is empty; final persistence report was not pushed")

    subprocess.run(
        ["git", "-C", str(git_root), "add", "--", relative_report],
        check=True,
    )
    staged = subprocess.run(
        ["git", "-C", str(git_root), "diff", "--cached", "--quiet"],
        check=False,
    )
    if staged.returncode == 0:
        sha = subprocess.run(
            ["git", "-C", str(git_root), "rev-parse", "HEAD"],
            text=True, capture_output=True, check=True,
        ).stdout.strip()
        return {"status": "already-committed", "branch": branch, "commit": sha}
    if staged.returncode != 1:
        raise RuntimeError(
            f"unable to inspect staged final report (git diff exit {staged.returncode})"
        )

    subprocess.run(
        ["git", "-C", str(git_root), "config", "user.name", "AI-CYBER Knowledge DB Builder"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(git_root), "config", "user.email",
         "ai-cyber-knowledge-db@users.noreply.github.com"],
        check=True,
    )
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    subprocess.run(
        ["git", "-C", str(git_root), "commit", "-m",
         f"report: confirm Knowledge DB persistence {stamp}"],
        check=True,
    )

    ask_fd, ask_name = tempfile.mkstemp(prefix="ai-cyber-report-askpass-")
    os.close(ask_fd)
    askpass = Path(ask_name)
    try:
        askpass.write_text(
            "#!/bin/sh\nprintf '%s\\n' \"$GITHUB_TOKEN\"\n", encoding="utf-8"
        )
        askpass.chmod(0o700)
        env = os.environ.copy()
        env["GITHUB_TOKEN"] = token.strip()
        env["GIT_ASKPASS"] = str(askpass)
        env["GIT_TERMINAL_PROMPT"] = "0"
        subprocess.run(
            ["git", "-C", str(git_root), "remote", "set-url", "origin",
             "https://x-access-token@github.com/hasnatahmd21/AI-cyber.git"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(git_root), "push", "origin", branch],
            check=True, env=env,
        )
        sha = subprocess.run(
            ["git", "-C", str(git_root), "rev-parse", "HEAD"],
            text=True, capture_output=True, check=True,
        ).stdout.strip()
        return {"status": "pushed", "branch": branch, "commit": sha,
                "report_path": relative_report}
    finally:
        askpass.unlink(missing_ok=True)

def _kaggle_credentials() -> dict[str, str]:
    """Resolve Kaggle API token or legacy credentials without logging secrets."""
    env = os.environ.copy()
    if env.get("KAGGLE_API_TOKEN"):
        return env
    if env.get("KAGGLE_USERNAME") and env.get("KAGGLE_KEY"):
        return env

    # In Kaggle Notebooks, API tokens can be stored as attached Kaggle Secrets.
    try:
        from kaggle_secrets import UserSecretsClient
        client = UserSecretsClient()
        for secret_name in ("KAGGLE_API_TOKEN", "kaggle-api-token", "kaggle api token"):
            try:
                token = client.get_secret(secret_name)
            except Exception:
                continue
            if isinstance(token, str) and token.strip():
                env["KAGGLE_API_TOKEN"] = token.strip()
                return env
    except Exception:
        pass

    config_roots: list[Path] = []
    if env.get("KAGGLE_CONFIG_DIR"):
        config_roots.append(Path(env["KAGGLE_CONFIG_DIR"]).expanduser())
    config_roots.extend([
        Path.home() / ".kaggle",
        Path(os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config"))) / "kaggle",
    ])
    # New token-based CLI auth uses access_token; legacy auth uses kaggle.json.
    for root in config_roots:
        for token_path in (root / "access_token", root / "access_token.txt"):
            try:
                token = token_path.read_text(encoding="utf-8").strip()
            except OSError:
                continue
            if token:
                env["KAGGLE_API_TOKEN"] = token
                return env
        candidate = root / "kaggle.json"
        if not candidate.is_file():
            continue
        try:
            payload = json.loads(candidate.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        username = payload.get("username")
        key = payload.get("key")
        if isinstance(username, str) and username.strip() and isinstance(key, str) and key.strip():
            env["KAGGLE_USERNAME"] = username.strip()
            env["KAGGLE_KEY"] = key.strip()
            env["KAGGLE_CONFIG_DIR"] = str(root)
            return env

    raise RuntimeError(
        'Kaggle Dataset persistence needs a Kaggle API token or legacy credentials. '
        'Attach a Kaggle Secret named "KAGGLE_API_TOKEN", set KAGGLE_API_TOKEN, '
        'or provide ~/.kaggle/access_token or ~/.kaggle/kaggle.json. '
        'The separate GitHub secret "cyber repo" is not a Kaggle API credential.'
    )


def persist_via_kaggle_dataset(
    db_path: Path,
    report_path: Path,
    report_data: dict[str, Any],
    dataset_id: str,
    action: str,
    *,
    cve_id: str = PROBE_CVE,
    cwe_id: str = PROBE_CWE,
    attack_id: str = PROBE_ATTACK,
) -> dict[str, Any]:
    """Publish the verified SQLite DB to a private, versioned Kaggle Dataset.

    Kaggle datasets are private by default. This code never passes the public
    flag and uses the 'other' metadata label because the operational DB contains
    several separately licensed upstream sources.
    """
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,48}/[a-z0-9][a-z0-9-]{2,49}", dataset_id):
        raise ValueError("Kaggle dataset ID must look like owner/slug using lowercase letters, digits and hyphens")
    if action not in {"create", "version"}:
        raise ValueError("Kaggle dataset action must be create or version")
    if not db_path.is_file():
        raise FileNotFoundError(f"Knowledge DB does not exist: {db_path}")

    db = sqlite3.connect(str(db_path))
    try:
        check = db.execute("PRAGMA integrity_check").fetchone()
        if not check or check[0] != "ok":
            raise RuntimeError(f"SQLite integrity_check failed: {check[0] if check else 'no result'}")
        record_count = int(db.execute("SELECT COUNT(*) FROM knowledge_records").fetchone()[0])
        if record_count <= 0:
            raise RuntimeError("refusing to publish an empty Knowledge DB")
        meta = {str(row[0]): str(row[1]) for row in db.execute("SELECT key,value FROM knowledge_meta")}
    finally:
        db.close()

    kaggle_env = _kaggle_credentials()
    kaggle_cli = shutil.which("kaggle")
    if not kaggle_cli:
        install = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--quiet", "--disable-pip-version-check", "kaggle"],
            text=True, capture_output=True, check=False, timeout=600,
        )
        if install.returncode != 0:
            raise RuntimeError(f"Kaggle CLI installation failed: {install.stderr[-2000:]}")
        kaggle_cli = shutil.which("kaggle")
    if not kaggle_cli:
        raise RuntimeError("Kaggle CLI is still unavailable after installation")

    upload_dir = Path(tempfile.mkdtemp(prefix="ai-cyber-kaggle-publish-", dir=str(db_path.parent)))
    db_upload = upload_dir / "knowledge-v1.sqlite3"
    try:
        try:
            os.link(db_path, db_upload)
        except OSError:
            shutil.copy2(db_path, db_upload)

        safe_report = dict(report_data)
        safe_report["permanent_persistence"] = "PUBLISH_REQUESTED"
        safe_report["database_path_in_artifact"] = db_upload.name
        write_json(upload_dir / "knowledge-db-build-report.json", safe_report)

        # Preserve the exact manifests and source-readiness report beside the
        # DB. This keeps the data-source checksum/count evidence portable after
        # the notebook checkout or Kaggle working directory is gone.
        source_manifest_hashes: dict[str, str] = {}
        manifests_root_value = report_data.get("manifests_dir")
        if manifests_root_value:
            manifests_root = Path(str(manifests_root_value)).expanduser().resolve()
            if manifests_root.is_dir():
                # Keep each manifest as a root-level file: Kaggle CLI
                # defaults to --dir-mode skip, so nested directories would be
                # silently omitted from the published artifact.
                source_manifest_files: dict[str, str] = {}
                for manifest_file in sorted(manifests_root.rglob("*.json")):
                    if not manifest_file.is_file() or manifest_file.name.casefold() == "example.json":
                        continue
                    if manifest_file.stem.casefold() in {"nvd_cve", "cvss"}:
                        continue
                    try:
                        manifest_payload = json.loads(manifest_file.read_text(encoding="utf-8"))
                    except (OSError, json.JSONDecodeError):
                        # The readiness gate has already failed closed for malformed
                        # in-scope manifests; do not copy malformed out-of-scope data.
                        raise RuntimeError(f"source manifest became unreadable during publication: {manifest_file}")
                    manifest_identity = str(manifest_payload.get("dataset") or manifest_file.stem) if isinstance(manifest_payload, dict) else manifest_file.stem
                    if manifest_identity.casefold() in {"nvd_cve", "cvss"}:
                        continue
                    relative = manifest_file.relative_to(manifests_root)
                    relative_name = relative.as_posix()
                    prefix = hashlib.sha256(relative_name.encode("utf-8")).hexdigest()[:10]
                    target_name = f"source-manifest-{prefix}-{manifest_file.name}"
                    target = upload_dir / target_name
                    shutil.copy2(manifest_file, target)
                    source_manifest_hashes[relative_name] = sha256_file(target)
                    source_manifest_files[relative_name] = target_name

        readiness_report_copy = None
        readiness_report_sha256 = None
        readiness_report_value = report_data.get("source_readiness_report")
        if readiness_report_value:
            readiness_report_source = Path(str(readiness_report_value)).expanduser().resolve()
            if readiness_report_source.is_file():
                readiness_report_copy = upload_dir / "source-readiness-report.json"
                shutil.copy2(readiness_report_source, readiness_report_copy)
                readiness_report_sha256 = sha256_file(readiness_report_copy)

        write_json(upload_dir / "database-artifact-manifest.json", {
            "artifact_version": "ai-cyber-knowledge-v1",
            "database_file": db_upload.name,
            "sha256": sha256_file(db_upload),
            "byte_size": db_upload.stat().st_size,
            "records": record_count,
            "schema_version": meta.get("schema_version", ""),
            "database_version": meta.get("database_version", ""),
            "source_readiness_report": (
                readiness_report_copy.name if readiness_report_copy else None
            ),
            "source_readiness_report_sha256": readiness_report_sha256,
            "source_manifest_count": len(source_manifest_hashes),
            "source_manifest_sha256": source_manifest_hashes,
            "source_manifest_files": source_manifest_files if manifests_root_value and Path(str(manifests_root_value)).is_dir() else {},
            "license_model": (
                "Mixed-source database. The Kaggle dataset uses the 'other' metadata label; "
                "this does not relicense upstream records. See per-record provenance/license fields."
            ),
        })
        write_json(upload_dir / "dataset-metadata.json", {
            "title": "AI-CYBER Knowledge DB v1",
            "subtitle": "Private versioned evidence-backed cyber knowledge store",
            "id": dataset_id,
            "licenses": [{"name": "other"}],
            "description": (
                "Private AI-CYBER operational Knowledge DB with deterministic record IDs, "
                "SQLite FTS retrieval, provenance, source version, source URI, validation status "
                "and SHA-256 per record. It aggregates independent upstream security datasets "
                "under their own terms. The 'other' label is not a blanket relicense; do not "
                "make this dataset public without a separate source-license review."
            ),
            "userSpecifiedSources": (
                "Per-source information is preserved in database records and the build report. "
                "This artifact is intended to remain private unless redistribution is separately reviewed."
            ),
        })

        if action == "create":
            command = [
                kaggle_cli, "datasets", "create", "-p", str(upload_dir),
                "--dir-mode", "skip", "--keep-tabular", "--quiet",
            ]
        else:
            stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%MZ")
            command = [
                kaggle_cli, "datasets", "version", "-p", str(upload_dir),
                "--message", f"AI-CYBER Knowledge DB v1 verified {stamp}",
                "--dir-mode", "skip", "--keep-tabular", "--quiet",
            ]
        result = subprocess.run(
            command, text=True, capture_output=True, check=False,
            timeout=7200, env=kaggle_env,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"Kaggle Dataset {action} failed (exit {result.returncode}): "
                f"{result.stderr[-3000:] or result.stdout[-3000:]}"
            )

        verification = subprocess.run(
            [kaggle_cli, "datasets", "status", dataset_id],
            text=True, capture_output=True, check=False,
            timeout=600, env=kaggle_env,
        )
        if verification.returncode != 0:
            raise RuntimeError(
                "Kaggle upload command returned success, but dataset status verification failed: "
                f"{verification.stderr[-2000:] or verification.stdout[-2000:]}"
            )

        # Existence alone is not proof that the uploaded bytes are readable.
        # Download the published version in a fresh directory and compare the
        # exact DB digest before marking persistence confirmed.
        restore_dir = Path(tempfile.mkdtemp(prefix="ai-cyber-kaggle-restore-", dir=str(db_path.parent)))
        download = subprocess.run(
            [
                kaggle_cli, "datasets", "download", "-d", dataset_id,
                "-p", str(restore_dir), "--unzip",
            ],
            text=True, capture_output=True, check=False,
            timeout=7200, env=kaggle_env,
        )
        if download.returncode != 0:
            raise RuntimeError(
                "Kaggle Dataset status exists, but restoring the published DB failed: "
                f"{download.stderr[-3000:] or download.stdout[-3000:]}"
            )
        restored_db = restore_dir / db_upload.name
        if not restored_db.is_file():
            candidates = list(restore_dir.rglob(db_upload.name))
            if len(candidates) == 1:
                restored_db = candidates[0]
        if not restored_db.is_file():
            raise RuntimeError(
                "Kaggle Dataset download succeeded but did not contain knowledge-v1.sqlite3"
            )
        restored_sha = sha256_file(restored_db)
        source_sha = sha256_file(db_path)
        if restored_sha != source_sha:
            raise RuntimeError(
                f"restored Knowledge DB SHA-256 differs from the published local DB: "
                f"expected {source_sha}, got {restored_sha}"
            )
        restore_restart = restart_smoke_test(restored_db, PROBE_CVE)
        restore_core_queries = core_query_smoke_test(
            restored_db, cve_id, cwe_id, attack_id
        )
        # The restored DB may be several gigabytes; remove the temporary second
        # copy after exact-hash and fresh-process verification to free workspace.
        shutil.rmtree(restore_dir, ignore_errors=True)

        return {
            "status": "published-restored-hash-and-restart-verified",
            "restore_directory_cleaned": True,
            "provider": "Kaggle Dataset",
            "dataset_id": dataset_id,
            "access": "private; public flag was not used",
            "action": action,
            "database_sha256": source_sha,
            "restored_database_sha256": restored_sha,
            "restored_hash_matches": restored_sha == source_sha,
            "database_byte_size": db_path.stat().st_size,
            "record_count": record_count,
            "restore_restart_test": restore_restart,
            "restore_core_query_test": restore_core_queries,
            "upload_dir": str(upload_dir),
            "cli_output": result.stdout[-2000:],
            "status_output": verification.stdout[-2000:],
            "download_output": download.stdout[-2000:],
        }
    except Exception:
        # Keep the upload package for diagnosis/retry if a publish attempt fails.
        raise

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-root", type=Path, default=REPOSITORY_ROOT / "datasets" / "raw")
    parser.add_argument("--manifests-dir", type=Path, default=REPOSITORY_ROOT / "datasets" / "manifests")
    parser.add_argument("--db-path", type=Path, required=True,
                        help="Explicit versioned SQLite path; default is intentionally not guessed")
    parser.add_argument("--report", type=Path, default=None)
    parser.add_argument("--probe-cve", default=PROBE_CVE)
    parser.add_argument("--probe-cwe", default=PROBE_CWE)
    parser.add_argument("--probe-attack", default=PROBE_ATTACK)
    parser.add_argument("--require", action="append", default=[],
                        help="Optional replacement required-source list; may be repeated")
    parser.add_argument("--persist-lfs", action="store_true",
                        help="Publish the DB to this Git branch via Git LFS (may be unsuitable for large DBs)")
    parser.add_argument("--persist-kaggle-dataset-id", default=None, metavar="OWNER/SLUG",
                        help="Publish the verified DB as a private Kaggle Dataset or new version")
    parser.add_argument("--kaggle-dataset-action", choices=("create", "version"), default="create",
                        help="Create a new private Kaggle Dataset or add a version to an existing one")
    parser.add_argument("--accept-local-only", action="store_true",
                        help="Allow exit 0 for a verified local build when durable persistence is not confirmed")
    parser.add_argument("--branch", default=os.environ.get("AI_CYBER_BRANCH", "fix/dataset-parser-readiness"))
    args = parser.parse_args(argv)
    if args.persist_lfs and args.persist_kaggle_dataset_id:
        parser.error("choose only one durable persistence target: --persist-lfs or --persist-kaggle-dataset-id")

    raw_root = args.raw_root.expanduser().resolve()
    manifests_dir = args.manifests_dir.expanduser().resolve()
    db_path = args.db_path.expanduser().resolve()
    report_path = (args.report or REPOSITORY_ROOT / "datasets" / "acquisition_reports" /
                   f"knowledge-db-build-{dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json").expanduser().resolve()
    report: dict[str, Any] = {
        "report_version": 1,
        "started_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "repository": "hasnatahmd21/AI-cyber",
        "branch": args.branch,
        "database_path": str(db_path),
        "raw_root": str(raw_root),
        "manifests_dir": str(manifests_dir),
        "database_version": "ai-cyber-knowledge-v1",
        "required_datasets": sorted(set(args.require or DEFAULT_REQUIRED)),
        "ingestion_performed": False,
        "permanent_persistence": "NOT_CONFIRMED",
    }

    # Validate durable-persistence preconditions before a potentially long
    # ingestion run. Missing credentials must not waste hours creating a local
    # DB that cannot be published to the requested destination.
    if args.persist_lfs or args.persist_kaggle_dataset_id:
        try:
            if args.persist_lfs:
                db_path.relative_to(REPOSITORY_ROOT.resolve())
                report_path.relative_to(REPOSITORY_ROOT.resolve())
                if not (REPOSITORY_ROOT / ".git").is_dir():
                    raise RuntimeError("--persist-lfs requires the checked-out Git repository")
                current_branch = subprocess.run(
                    ["git", "-C", str(REPOSITORY_ROOT), "branch", "--show-current"],
                    text=True, capture_output=True, check=True,
                ).stdout.strip()
                if current_branch != args.branch:
                    raise RuntimeError(
                        f"current Git branch is {current_branch!r}, expected {args.branch!r}"
                    )
                if not shutil.which("git-lfs"):
                    raise RuntimeError("git-lfs is required for --persist-lfs")
                token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
                if not token:
                    try:
                        from kaggle_secrets import UserSecretsClient
                        token = UserSecretsClient().get_secret("cyber repo")
                    except Exception as exc:
                        raise RuntimeError(
                            'GitHub token unavailable; configure Kaggle secret "cyber repo"'
                        ) from exc
                if not token or not token.strip():
                    raise RuntimeError('GitHub token "cyber repo" is empty')
                os.environ["GITHUB_TOKEN"] = token.strip()

            if args.persist_kaggle_dataset_id:
                if not re.fullmatch(
                    r"[a-z0-9][a-z0-9-]{1,48}/[a-z0-9][a-z0-9-]{2,49}",
                    args.persist_kaggle_dataset_id,
                ):
                    raise ValueError(
                        "Kaggle dataset ID must look like owner/slug using lowercase letters, digits and hyphens"
                    )
                _kaggle_credentials()
        except Exception as exc:
            report.update({
                "overall": "BLOCKED",
                "evidence": f"{type(exc).__name__}: {exc}",
                "ingestion_performed": False,
                "permanent_persistence": "NOT_CONFIRMED",
            })
            write_json(report_path, report)
            print_build_summary(report, report_path)
            print(f"REPORT_FILE={report_path}")
            return 2

    try:
        # Set the shared path before importing the DB/RAG/backend modules.
        os.environ["AI_CYBER_KNOWLEDGE_DB"] = str(db_path)
        os.environ["PYTHONPATH"] = str(REPOSITORY_ROOT / "src") + os.pathsep + os.environ.get("PYTHONPATH", "")
        sys.path.insert(0, str(REPOSITORY_ROOT / "src"))

        readiness_path = report_path.with_name(report_path.stem + "-source-readiness.json")
        print("[knowledge-db-progress] source_readiness_start", flush=True)
        readiness = run_readiness_gate(raw_root, readiness_path)
        manifest_summary = readiness.get("manifest_readiness") or {}
        print(
            "[knowledge-db-progress] source_readiness_complete "
            + json.dumps({
                "overall": readiness.get("overall"),
                "manifest_readiness": {
                    "overall": manifest_summary.get("overall"),
                    "count": manifest_summary.get("count"),
                    "pass": manifest_summary.get("pass"),
                    "blocked": manifest_summary.get("blocked"),
                    "fail": manifest_summary.get("fail"),
                },
                "parser_checks": [
                    {"dataset": row.get("dataset"), "status": row.get("status")}
                    for row in readiness.get("datasets", [])
                ],
            }, ensure_ascii=False, sort_keys=True, default=str),
            flush=True,
        )
        report["source_readiness_report"] = str(readiness_path)
        report["source_readiness"] = readiness.get("overall")
        report["source_readiness_counts"] = readiness.get("manifest_readiness", {})
        if readiness.get("overall") != "PASS":
            report.update({
                "overall": readiness.get("overall", "BLOCKED"),
                "evidence": "Source readiness is not PASS. No database was opened or created and no ingestion was performed.",
                "ingestion_performed": False,
            })
            write_json(report_path, report)
            print_build_summary(report, report_path)
            print(f"REPORT_FILE={report_path}")
            return 2

        # Reuse the exact integrity/count inspection already produced by the
        # readiness gate. ingest_manifest_directory still validates manifest
        # digests and re-hashes artifact bytes immediately before ingestion.
        readiness_inspections: dict[str, dict[str, Any]] = {}
        readiness_names: set[str] = set()
        manifest_readiness = readiness.get("manifest_readiness", {})
        for row in manifest_readiness.get("datasets", []):
            if row.get("status") != "PASS":
                continue
            dataset = str(row.get("dataset") or "")
            manifest_value = row.get("manifest")
            inspection = row.get("inspection")
            if dataset not in set(report["required_datasets"]):
                continue
            if not manifest_value or not isinstance(inspection, dict):
                raise RuntimeError(
                    f"readiness gate omitted reusable inspection evidence for {dataset!r}"
                )
            manifest_path = Path(str(manifest_value)).expanduser().resolve()
            if not manifest_path.is_file():
                raise FileNotFoundError(
                    f"manifest disappeared after readiness gate: {manifest_path}"
                )
            readiness_inspections[str(manifest_path)] = {
                "manifest_sha256": sha256_file(manifest_path),
                "inspection": inspection,
            }
            readiness_names.add(dataset)
        expected_readiness_names = set(report["required_datasets"])
        if readiness_names != expected_readiness_names:
            raise RuntimeError(
                "readiness gate inspections do not exactly cover the selected 11-source set; "
                f"missing={sorted(expected_readiness_names - readiness_names)}, "
                f"unexpected={sorted(readiness_names - expected_readiness_names)}"
            )
        report["readiness_inspections_reused"] = len(readiness_inspections)

        from ai_cyber_os.dataset_pipeline import ingest_manifest_directory
        from ai_cyber_os.knowledge import status as knowledge_status
        from ai_cyber_os.rag import build_context

        def report_ingestion_progress(event: dict[str, Any]) -> None:
            # Emit one compact line per manifest/artifact stage so notebook users
            # can distinguish active ingestion from a stalled cell.
            print(
                "[knowledge-db-progress] "
                + json.dumps(event, ensure_ascii=False, sort_keys=True, default=str),
                flush=True,
            )

        batch_options: dict[str, Any] = {
            "required_datasets": tuple(report["required_datasets"]),
            "progress_callback": report_ingestion_progress,
            "preflight_inspections": readiness_inspections,
        }
        preflight_and_ingestion = ingest_manifest_directory(
            manifests_dir, db_path=db_path, **batch_options
        )
        report["batch_ingestion"] = preflight_and_ingestion
        report["ingestion_performed"] = bool(preflight_and_ingestion.get("ingestion_performed"))
        if preflight_and_ingestion.get("overall") != "PASS":
            report["overall"] = preflight_and_ingestion.get("overall", "FAIL")
            report["evidence"] = "Batch source preflight/ingestion did not PASS."
            write_json(report_path, report)
            print_build_summary(report, report_path)
            print(f"REPORT_FILE={report_path}")
            return 2

        report["database_status"] = knowledge_status(db_path=db_path)
        report["sqlite_integrity_smoke_test"] = sqlite_integrity_smoke_test(
            db_path, report["required_datasets"]
        )
        report["core_query_smoke_test"] = core_query_smoke_test(
            db_path, args.probe_cve, args.probe_cwe, args.probe_attack
        )
        context = build_context(
            args.probe_cve, db_path=db_path, limit=10, dataset="cisa_kev"
        )
        report["cisa_kev_cve_query"] = {
            "query": args.probe_cve,
            "dataset": "cisa_kev",
            "count": context.get("count", 0),
            "evidence_only": context.get("evidence_only", False),
            "evidence": [{
                "record_id": row.get("record_id"),
                "dataset": row.get("dataset"),
                "source_uri": row.get("source_uri"),
                "version": row.get("version"),
                "validation_status": row.get("validation_status"),
                "content_sha256": row.get("content_sha256"),
            } for row in context.get("evidence", [])],
        }
        if not context.get("evidence"):
            raise RuntimeError(
                f"CISA KEV CVE retrieval probe returned no results for {args.probe_cve}"
            )
        if not context.get("evidence_only"):
            raise RuntimeError("RAG result did not preserve evidence-only contract")
        if not all(row.get("source_uri") and row.get("content_sha256") and row.get("validation_status")
                   for row in context["evidence"]):
            raise RuntimeError("one or more RAG results lack source/hash/validation provenance")

        report["restart_smoke_test"] = restart_smoke_test(db_path, args.probe_cve)
        report["database_sha256"] = sha256_file(db_path)
        report["database_byte_size"] = db_path.stat().st_size
        report["build_verification"] = "PASS"
        report["evidence"] = (
            "All eleven required source manifests passed real-artifact readiness and full preflight; "
            "checkpointed ingestion, CISA KEV CVE retrieval, citations, and a fresh-process "
            "persistence test passed."
        )

        if args.persist_lfs:
            report["overall"] = "PASS"
            report["permanent_persistence"] = "PUBLISH_PENDING"
            write_json(report_path, report)
            persistence = persist_via_lfs(db_path, report_path, args.branch)
            report["persistence"] = persistence
            report["permanent_persistence"] = (
                "CONFIRMED_GITHUB_LFS" if persistence.get("status") == "pushed"
                else "ALREADY_PRESENT_IN_GITHUB_LFS"
            )
            report["published_commit"] = persistence.get("commit")
            write_json(report_path, report)
            # Persist the final CONFIRMED report itself. The database was
            # already pushed in persist_via_lfs; this commit stages only report_path.
            report_push = persist_lfs_confirmation_report(report_path, args.branch)
            print_build_summary(report, report_path)
            print(f"REPORT_FILE={report_path}")
            print(f"PERSISTENCE_REPORT_COMMIT={report_push.get('commit')}")
            print(f"PERMANENT_PERSISTENCE={report['permanent_persistence']}")
            return 0

        if args.persist_kaggle_dataset_id:
            report["overall"] = "PASS"
            report["permanent_persistence"] = "PUBLISH_PENDING"
            write_json(report_path, report)
            persistence = persist_via_kaggle_dataset(
                db_path, report_path, report,
                args.persist_kaggle_dataset_id, args.kaggle_dataset_action,
                cve_id=args.probe_cve, cwe_id=args.probe_cwe, attack_id=args.probe_attack,
            )
            report["persistence"] = persistence
            report["permanent_persistence"] = "CONFIRMED_KAGGLE_DATASET_PRIVATE"
            write_json(report_path, report)
            print_build_summary(report, report_path)
            print(f"REPORT_FILE={report_path}")
            print(f"PERMANENT_PERSISTENCE=CONFIRMED_KAGGLE_DATASET_PRIVATE:{args.persist_kaggle_dataset_id}")
            return 0

        report["overall"] = "LOCAL_BUILD_PASS_PERSISTENCE_PENDING"
        report["permanent_persistence"] = "NOT_CONFIRMED"
        report["evidence"] += (
            " The DB is only local; use --persist-kaggle-dataset-id OWNER/SLUG "
            "(private by default) or --persist-lfs, or save this output in an explicitly "
            "durable destination before treating the full task as complete."
        )
        write_json(report_path, report)
        print_build_summary(report, report_path)
        print(f"REPORT_FILE={report_path}")
        print("PERMANENT_PERSISTENCE=NOT_CONFIRMED")
        return 0 if args.accept_local_only else 2
    except Exception as exc:
        report.update({
            "overall": "FAIL",
            "evidence": f"{type(exc).__name__}: {exc}",
            "error_type": type(exc).__name__,
            "ingestion_performed": bool(report.get("ingestion_performed")),
        })
        write_json(report_path, report)
        print_build_summary(report, report_path)
        print(f"REPORT_FILE={report_path}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
