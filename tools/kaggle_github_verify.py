#!/usr/bin/env python3
"""Portable, fail-closed AI-CYBER verification pipeline.

Designed for both:
  * a fresh Kaggle clone, and
  * GitHub Actions after checkout.

The verifier never treats a partial pass as success. Every check is recorded in
a JSON report; any failed check makes the process exit non-zero.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit


SCHEMA_VERSION = "ai_cyber.verification_pipeline.v1"
DEFAULT_TIMEOUT = 1800
MAX_CAPTURE_CHARS = 20000


@dataclass
class Check:
    name: str
    status: str
    duration_seconds: float
    detail: str = ""
    returncode: int | None = None
    stdout: str = ""
    stderr: str = ""


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def run_command(
    name: str,
    argv: list[str],
    *,
    cwd: Path,
    timeout: int = DEFAULT_TIMEOUT,
) -> Check:
    started = datetime.now(timezone.utc)
    try:
        proc = subprocess.run(
            argv,
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
            shell=False,
        )
        status = "PASS" if proc.returncode == 0 else "FAIL"
        detail = "command completed" if status == "PASS" else "command returned non-zero"
        return Check(
            name=name,
            status=status,
            duration_seconds=(datetime.now(timezone.utc) - started).total_seconds(),
            detail=detail,
            returncode=proc.returncode,
            stdout=proc.stdout[-MAX_CAPTURE_CHARS:],
            stderr=proc.stderr[-MAX_CAPTURE_CHARS:],
        )
    except subprocess.TimeoutExpired as exc:
        return Check(
            name=name,
            status="FAIL",
            duration_seconds=(datetime.now(timezone.utc) - started).total_seconds(),
            detail=f"timeout after {timeout}s",
            returncode=None,
            stdout=str(exc.stdout or "")[-MAX_CAPTURE_CHARS:],
            stderr=str(exc.stderr or "")[-MAX_CAPTURE_CHARS:],
        )
    except OSError as exc:
        return Check(
            name=name,
            status="FAIL",
            duration_seconds=(datetime.now(timezone.utc) - started).total_seconds(),
            detail=f"execution error: {exc}",
            returncode=None,
        )


def git_value(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", *args],
        cwd=repo,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        check=False,
        shell=False,
    )
    if proc.returncode != 0:
        return ""
    return proc.stdout.strip()


def safe_remote(value: str) -> str:
    if not value:
        return ""
    try:
        parsed = urlsplit(value)
        if parsed.scheme and parsed.netloc:
            host = parsed.hostname or ""
            port = f":{parsed.port}" if parsed.port else ""
            return urlunsplit((parsed.scheme, host + port, parsed.path, parsed.query, ""))
    except ValueError:
        pass
    return re.sub(r"//[^/@]+@", "//", value)


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def verify(repo: Path, *, report_path: Path, expected_sha: str | None, expected_ref: str | None) -> int:
    repo = repo.resolve()
    checks: list[Check] = []

    if not (repo / ".git").exists():
        checks.append(Check("git repository", "FAIL", 0.0, "missing .git directory"))
        write_json(report_path, build_report(repo, checks, expected_sha, expected_ref))
        return 1

    head = git_value(repo, "rev-parse", "HEAD")
    ref = git_value(repo, "branch", "--show-current")
    remote = safe_remote(git_value(repo, "remote", "get-url", "origin"))

    if expected_sha:
        status = "PASS" if head == expected_sha else "FAIL"
        checks.append(Check("expected commit", status, 0.0, f"HEAD={head}"))
    if expected_ref:
        remote_ref = git_value(repo, "rev-parse", "--verify", f"refs/remotes/origin/{expected_ref}")
        status = "PASS" if ref == expected_ref or remote_ref == head else "FAIL"
        checks.append(Check("expected ref", status, 0.0, f"branch={ref or 'detached'}"))

    status_clean = subprocess.run(
        ["git", "diff", "--quiet"],
        cwd=repo,
        stdin=subprocess.DEVNULL,
        timeout=30,
        check=False,
        shell=False,
    ).returncode == 0
    checks.append(Check(
        "source checkout clean",
        "PASS" if status_clean else "FAIL",
        0.0,
        "no tracked working-tree modifications" if status_clean else "tracked working-tree modifications detected",
    ))

    canonical_files = [
        repo / "src/ai_cyber_os/hydra.py",
        repo / "src/ai_cyber_os/api.py",
        repo / "src/ai_cyber_os/backend.py",
        repo / "src/ai_cyber_os/knowledge.py",
        repo / "src/ai_cyber_os/relationships.py",
        repo / "src/ai_cyber_os/security_families.py",
        repo / "src/ai_cyber_os/situation.py",
        repo / "src/ai_cyber_os/commands.py",
        repo / "src/ai_cyber_os/ui.py",
    ]
    missing = [str(p.relative_to(repo)) for p in canonical_files if not p.is_file()]
    checks.append(Check(
        "canonical surface present",
        "PASS" if not missing else "FAIL",
        0.0,
        "all expected canonical modules present" if not missing else "missing: " + ", ".join(missing),
    ))

    compile_check = run_command(
        "compile canonical source/tests/tools",
        [sys.executable, "-m", "compileall", "-q", "src", "tests", "tools"],
        cwd=repo,
    )
    checks.append(compile_check)

    install_check = run_command(
        "install editable package",
        [sys.executable, "-m", "pip", "install", "--disable-pip-version-check", "-e", "."],
        cwd=repo,
        timeout=600,
    )
    checks.append(install_check)
    if install_check.status == "FAIL":
        report = build_report(repo, checks, expected_sha, expected_ref)
        write_json(report_path, report)
        return 1

    import_check = run_command(
        "import canonical package",
        [sys.executable, "-c", "import ai_cyber_os; print(ai_cyber_os.__name__)"],
        cwd=repo,
        timeout=120,
    )
    checks.append(import_check)

    dependency_check = run_command(
        "pip dependency consistency",
        [sys.executable, "-m", "pip", "check"],
        cwd=repo,
        timeout=120,
    )
    checks.append(dependency_check)

    with tempfile.TemporaryDirectory(prefix="ai-cyber-verification-") as td:
        report_dir = Path(td)
        inventory_path = report_dir / "forensic_inventory.json"
        inventory = run_command(
            "forensic inventory",
            [sys.executable, "tools/forensic_inventory.py", "--output", str(inventory_path)],
            cwd=repo,
            timeout=300,
        )
        if inventory.status == "PASS" and inventory_path.is_file():
            try:
                data = json.loads(inventory_path.read_text(encoding="utf-8"))
                syntax_errors = data.get("syntax_error_files", [])
                inventory.detail = (
                    f"python_files={data.get('python_file_count', 0)}, "
                    f"syntax_error_files={len(syntax_errors)}, "
                    f"duplicate_definition_files={len(data.get('files_with_duplicate_top_level_definitions', []))}"
                )
                if syntax_errors:
                    inventory.status = "FAIL"
                    inventory.stderr = "syntax errors: " + ", ".join(syntax_errors)
            except (OSError, json.JSONDecodeError) as exc:
                inventory.status = "FAIL"
                inventory.detail = f"invalid inventory report: {exc}"
        checks.append(inventory)

        baseline_files = [
            repo / "docs/FORENSIC_BASELINE.md",
            repo / "docs/FORENSIC_BASELINE.json",
        ]
        missing_baseline = [str(p.relative_to(repo)) for p in baseline_files if not p.is_file() or p.stat().st_size == 0]
        checks.append(Check(
            "forensic baseline artifacts",
            "PASS" if not missing_baseline else "FAIL",
            0.0,
            "baseline artifacts present" if not missing_baseline else "missing/empty: " + ", ".join(missing_baseline),
        ))

    tests = run_command(
        "full pytest regression",
        [sys.executable, "-m", "pytest", "-q"],
        cwd=repo,
        timeout=DEFAULT_TIMEOUT,
    )
    checks.append(tests)

    focused = run_command(
        "hardening adversarial regression",
        [sys.executable, "-m", "pytest", "-q", "tests/test_hardening_regression.py", "tests/test_security_surface.py"],
        cwd=repo,
        timeout=DEFAULT_TIMEOUT,
    )
    checks.append(focused)

    runtime = run_command(
        "canonical 27-phase runtime",
        [
            sys.executable,
            "-c",
            (
                "from ai_cyber_os.hydra import run_hydra_phase; "
                "r=run_hydra_phase('all'); "
                "assert r['summary']['phases']==27 and r['summary']['success'] is True, r; "
                "print('CANONICAL_27_PHASE_RUNTIME=GREEN')"
            ),
        ],
        cwd=repo,
        timeout=DEFAULT_TIMEOUT,
    )
    checks.append(runtime)

    final = run_command(
        "final hardening verification",
        [
            sys.executable,
            "-c",
            (
                "from ai_cyber_os.hydra import run_final_hardening_verification; "
                "r=run_final_hardening_verification(); "
                "assert r['verified'] is True and r['failed']==0, r; "
                "print('FINAL_HARDENING=GREEN')"
            ),
        ],
        cwd=repo,
        timeout=DEFAULT_TIMEOUT,
    )
    checks.append(final)

    return write_and_exit(repo, report_path, checks, expected_sha, expected_ref)


def build_report(repo: Path, checks: list[Check], expected_sha: str | None, expected_ref: str | None) -> dict:
    failures = [c.name for c in checks if c.status != "PASS"]
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": now_utc(),
        "result": "GREEN" if not failures else "FAIL",
        "failure_count": len(failures),
        "failures": failures,
        "repository": {
            "path": str(repo),
            "head_sha": git_value(repo, "rev-parse", "HEAD"),
            "branch": git_value(repo, "branch", "--show-current"),
            "origin": safe_remote(git_value(repo, "remote", "get-url", "origin")),
            "expected_sha": expected_sha,
            "expected_ref": expected_ref,
        },
        "environment": {
            "python": sys.version,
            "platform": platform.platform(),
            "machine": platform.machine(),
            "cwd": os.getcwd(),
        },
        "checks": [asdict(c) for c in checks],
    }


def write_and_exit(
    repo: Path,
    report_path: Path,
    checks: list[Check],
    expected_sha: str | None,
    expected_ref: str | None,
) -> int:
    report = build_report(repo, checks, expected_sha, expected_ref)
    write_json(report_path, report)
    print(json.dumps({
        "result": report["result"],
        "failure_count": report["failure_count"],
        "head_sha": report["repository"]["head_sha"],
        "report": str(report_path),
    }, sort_keys=True))
    return 0 if report["result"] == "GREEN" else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--report", type=Path, default=Path("verification_report.json"))
    parser.add_argument("--expected-sha")
    parser.add_argument("--expected-ref")
    args = parser.parse_args()
    return verify(
        args.repo_root,
        report_path=args.report,
        expected_sha=args.expected_sha,
        expected_ref=args.expected_ref,
    )


if __name__ == "__main__":
    raise SystemExit(main())
