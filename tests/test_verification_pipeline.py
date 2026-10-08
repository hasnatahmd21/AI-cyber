from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VERIFIER = ROOT / "tools" / "kaggle_github_verify.py"


def run_verifier(repo: Path, report: Path, *extra: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(VERIFIER), "--repo-root", str(repo), "--report", str(report), *extra],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
        shell=False,
    )


def test_verifier_requires_git_repository(tmp_path: Path):
    report = tmp_path / "report.json"
    result = run_verifier(tmp_path, report)
    assert result.returncode != 0
    payload = json.loads(report.read_text(encoding="utf-8"))
    assert payload["result"] == "FAIL"
    assert "git repository" in payload["failures"]


def test_verifier_contains_fail_closed_contract():
    source = VERIFIER.read_text(encoding="utf-8")
    assert "shell=False" in source
    assert "result\": \"GREEN\"" in source
    assert "failure_count" in source
    assert "full pytest regression" in source
    assert "canonical 27-phase runtime" in source
    assert "final hardening verification" in source
    assert "forensic inventory" in source


def test_report_writer_is_json_and_redacts_remote_userinfo(tmp_path: Path):
    source = VERIFIER.read_text(encoding="utf-8")
    assert "safe_remote" in source
    assert "urlsplit" in source
