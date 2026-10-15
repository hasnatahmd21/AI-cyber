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
    program = (
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
                copied_manifests = upload_dir / "source-manifests"
                for manifest_file in sorted(manifests_root.rglob("*.json")):
                    if not manifest_file.is_file() or manifest_file.name.casefold() == "example.json":
                        continue
                    relative = manifest_file.relative_to(manifests_root)
                    target = copied_manifests / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(manifest_file, target)
                    source_manifest_hashes[relative.as_posix()] = sha256_file(target)

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
            print(json.dumps(report, indent=2, ensure_ascii=False, default=str))
            print(f"REPORT_FILE={report_path}")
            return 2

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
        from ai_cyber_os.knowledge import status as knowledge_status, search as knowledge_search
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

        derived_rows = preflight_and_ingestion.get("derived_datasets", [])
        cvss_report = next(
            (row for row in derived_rows if row.get("dataset") == "cvss"),
            None,
        )
        if cvss_report is None or cvss_report.get("status") != "PASS":
            raise RuntimeError("batch ingestion did not produce a passing derived CVSS report")
        cvss_derived = cvss_report["derivation"]
        report["cvss_derivation"] = cvss_derived
        cvss_hits = knowledge_search(args.probe_cve, db_path=db_path, dataset="cvss", limit=10)
        report["cvss_query"] = {
            "query": args.probe_cve,
            "count": len(cvss_hits),
            "evidence": [{
                "record_id": row.get("record_id"),
                "source_uri": row.get("source_uri"),
                "version": row.get("version"),
                "validation_status": row.get("validation_status"),
                "content_sha256": row.get("content_sha256"),
            } for row in cvss_hits],
        }
        if int(cvss_derived.get("derived_records_in_database", 0)) <= 0:
            raise RuntimeError("CVSS derivation produced no indexed metric records from NVD data")
        if not cvss_hits:
            raise RuntimeError(f"derived CVSS query returned no evidence for {args.probe_cve}")

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
        report["build_verification"] = "PASS"
        report["evidence"] = (
            "All required source manifests passed real-artifact readiness and full preflight; "
            "checkpointed ingestion, derived CVSS retrieval, citations, and a fresh-process "
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
            print(json.dumps(report, indent=2, ensure_ascii=False, default=str))
            print(f"REPORT_FILE={report_path}")
            print("PERMANENT_PERSISTENCE=CONFIRMED_GITHUB_LFS")
            return 0

        if args.persist_kaggle_dataset_id:
            report["overall"] = "PASS"
            report["permanent_persistence"] = "PUBLISH_PENDING"
            write_json(report_path, report)
            persistence = persist_via_kaggle_dataset(
                db_path, report_path, report,
                args.persist_kaggle_dataset_id, args.kaggle_dataset_action,
            )
            report["persistence"] = persistence
            report["permanent_persistence"] = "CONFIRMED_KAGGLE_DATASET_PRIVATE"
            write_json(report_path, report)
            print(json.dumps(report, indent=2, ensure_ascii=False, default=str))
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
        print(json.dumps(report, indent=2, ensure_ascii=False, default=str))
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
        print(json.dumps(report, indent=2, ensure_ascii=False, default=str))
        print(f"REPORT_FILE={report_path}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
