#!/usr/bin/env python3
"""Build and verify the versioned AI-CYBER Knowledge DB after readiness PASS.

This command is deliberately fail-closed:
  1. the real-artifact/readiness gate must pass before the target DB is opened;
  2. all required manifests pass checksum, byte-size, and parser-count preflight;
  3. ingestion uses per-artifact checkpoints and can be restarted;
  4. retrieval/citation and a separate-process restart smoke test run afterward;
  5. permanent GitHub persistence is attempted only when --persist-lfs is explicit.

A database in /kaggle/working is not durable by itself. Use --persist-lfs to
publish the verified DB via Git LFS, or explicitly save the Kaggle run output.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REQUIRED = (
    "capec", "cisa_kev", "cpe", "cwe", "epss", "mitre_attack",
    "mitre_d3fend", "mitre_mbc", "sigma", "suricata", "zeek_intel", "nvd_cve",
)
PROBE_CVE = "CVE-2021-44228"


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
    program = Stringless = (
        "import json\n"
        "from ai_cyber_os.knowledge import DEFAULT_DB, status, search\n"
        "from ai_cyber_os.runtime_intelligence import analyze\n"
        "s=status()\n"
        "hits=search(" + repr(cve_id) + ", limit=10)\n"
        "a=analyze(" + repr(cve_id) + ", limit=10)\n"
        "print(json.dumps({'default_db':str(DEFAULT_DB.resolve()),'status':s,'hits':"
        "[{'record_id':x['record_id'],'dataset':x['dataset']} for x in hits],"
        "'analysis':{'success':a.get('success'),'evidence_only':a.get('evidence_only'),"
        "'count':len(a.get('evidence',[])),'has_citations':all("
        "bool(x.get('source_uri')) and bool(x.get('content_sha256')) and "
        "bool(x.get('validation_status')) for x in a.get('evidence',[]))}}))\n"
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
        raise RuntimeError(f"real CVE probe returned no records after process restart: {cve_id}")
    if not data["analysis"].get("success") or not data["analysis"].get("evidence_only"):
        raise RuntimeError("runtime intelligence did not return an evidence-only result")
    if not data["analysis"].get("has_citations"):
        raise RuntimeError("RAG evidence is missing source URI/hash/validation citation fields")
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
    subprocess.run(["git", "-C", str(git_root), "add", "--", ".gitattributes", relative_db, relative_report], check=True)
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
        return {"status": "pushed", "branch": branch, "commit": sha, "database_path": relative_db}
    finally:
        askpass.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-root", type=Path, default=REPOSITORY_ROOT / "datasets" / "raw")
    parser.add_argument("--manifests-dir", type=Path, default=REPOSITORY_ROOT / "datasets" / "manifests")
    parser.add_argument("--db-path", type=Path, required=True,
                        help="Explicit versioned SQLite path; default is intentionally not guessed")
    parser.add_argument("--report", type=Path, default=None)
    parser.add_argument("--probe-cve", default=PROBE_CVE)
    parser.add_argument("--require", action="append", default=[],
                        help="Optional replacement required-source list; may be repeated")
    parser.add_argument("--persist-lfs", action="store_true",
                        help="After all tests PASS, publish DB/report on this branch via Git LFS")
    parser.add_argument("--branch", default=os.environ.get("AI_CYBER_BRANCH", "fix/dataset-parser-readiness"))
    args = parser.parse_args(argv)

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
        "database_version": "ai-cyber-knowledge-v1",
        "required_datasets": sorted(set(args.require or DEFAULT_REQUIRED)),
        "ingestion_performed": False,
        "permanent_persistence": "NOT_CONFIRMED",
    }

    try:
        # Set the shared path before importing the DB/RAG/backend modules.
        os.environ["AI_CYBER_KNOWLEDGE_DB"] = str(db_path)
        os.environ["PYTHONPATH"] = str(REPOSITORY_ROOT / "src") + os.pathsep + os.environ.get("PYTHONPATH", "")
        sys.path.insert(0, str(REPOSITORY_ROOT / "src"))

        readiness_path = report_path.with_name(report_path.stem + "-source-readiness.json")
        readiness = run_readiness_gate(raw_root, readiness_path)
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
            print(json.dumps(report, indent=2, ensure_ascii=False, default=str))
            print(f"REPORT_FILE={report_path}")
            return 2

        from ai_cyber_os.dataset_pipeline import ingest_manifest_directory
        from ai_cyber_os.knowledge import status as knowledge_status
        from ai_cyber_os.rag import build_context

        batch_options: dict[str, Any] = {"required_datasets": tuple(report["required_datasets"])}
        preflight_and_ingestion = ingest_manifest_directory(
            manifests_dir, db_path=db_path, **batch_options
        )
        report["batch_ingestion"] = preflight_and_ingestion
        report["ingestion_performed"] = bool(preflight_and_ingestion.get("ingestion_performed"))
        if preflight_and_ingestion.get("overall") != "PASS":
            report["overall"] = preflight_and_ingestion.get("overall", "FAIL")
            report["evidence"] = "Batch source preflight/ingestion did not PASS."
            write_json(report_path, report)
            print(json.dumps(report, indent=2, ensure_ascii=False, default=str))
            print(f"REPORT_FILE={report_path}")
            return 2

        report["database_status"] = knowledge_status(db_path=db_path)
        context = build_context(args.probe_cve, db_path=db_path, limit=10)
        report["real_cve_query"] = {
            "query": args.probe_cve,
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
            raise RuntimeError(f"real CVE retrieval probe returned no results for {args.probe_cve}")
        if not context.get("evidence_only"):
            raise RuntimeError("RAG result did not preserve evidence-only contract")
        if not all(row.get("source_uri") and row.get("content_sha256") and row.get("validation_status")
                   for row in context["evidence"]):
            raise RuntimeError("one or more RAG results lack source/hash/validation provenance")

        report["restart_smoke_test"] = restart_smoke_test(db_path, args.probe_cve)
        report["database_sha256"] = sha256_file(db_path)
        report["database_byte_size"] = db_path.stat().st_size
        report["overall"] = "PASS"
        report["evidence"] = (
            "All required source manifests passed real-artifact readiness and full preflight; "
            "checkpointed ingestion, real CVE retrieval, citation fields, and a fresh-process "
            "persistence test passed."
        )
        report["permanent_persistence"] = "PENDING_EXTERNAL_SAVE"
        write_json(report_path, report)

        if args.persist_lfs:
            persistence = persist_via_lfs(db_path, report_path, args.branch)
            report["persistence"] = persistence
            report["permanent_persistence"] = (
                "CONFIRMED_GITHUB_LFS" if persistence.get("status") == "pushed"
                else "ALREADY_PRESENT_IN_GITHUB_LFS"
            )
            report["published_commit"] = persistence.get("commit")
            write_json(report_path, report)

        print(json.dumps(report, indent=2, ensure_ascii=False, default=str))
        print(f"REPORT_FILE={report_path}")
        return 0
    except Exception as exc:
        report.update({
            "overall": "FAIL",
            "evidence": f"{type(exc).__name__}: {exc}",
            "error_type": type(exc).__name__,
            "ingestion_performed": bool(report.get("ingestion_performed")),
        })
        write_json(report_path, report)
        print(json.dumps(report, indent=2, ensure_ascii=False, default=str))
        print(f"REPORT_FILE={report_path}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
