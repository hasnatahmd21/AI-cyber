from __future__ import annotations

import hashlib
import json
from pathlib import Path

from tools.forensic_deep_audit import build_report
from tools.verify_forensic_evidence import verify_report


def _fixture(root: Path) -> dict:
    (root / "src" / "sample").mkdir(parents=True)
    (root / "src" / "sample" / "__init__.py").write_text("", encoding="utf-8")
    (root / "src" / "sample" / "core.py").write_text(
        "def answer():\n    return 42\n", encoding="utf-8"
    )
    (root / "README.md").write_text("evidence fixture\n", encoding="utf-8")
    (root / "same-copy.txt").write_text("evidence fixture\n", encoding="utf-8")
    report = build_report(root)
    report["commit_sha"] = "fixture-commit"
    return report


def test_verifier_accepts_unchanged_report_and_source_manifest(tmp_path: Path):
    report = _fixture(tmp_path)
    assert verify_report(report, tmp_path, expected_commit="fixture-commit") == []


def test_verifier_detects_changed_source_after_report_generation(tmp_path: Path):
    report = _fixture(tmp_path)
    source = tmp_path / "src" / "sample" / "core.py"
    source.write_text("def answer():\n    return 43\n", encoding="utf-8")

    failures = verify_report(report, tmp_path, expected_commit="fixture-commit")
    assert any("SHA-256 mismatch" in failure for failure in failures)
    assert any("manifest mismatch" in failure for failure in failures)


def test_verifier_detects_tampered_ast_hash_and_commit_identity(tmp_path: Path):
    report = _fixture(tmp_path)
    report["files"][0]["sha256"] = "0" * 64

    failures = verify_report(report, tmp_path, expected_commit="different-commit")
    assert any("commit identity mismatch" in failure for failure in failures)
    assert any("AST/inventory SHA-256 mismatch" in failure for failure in failures)


def test_verifier_does_not_follow_symlinked_files(tmp_path: Path):
    outside = tmp_path.parent / f"{tmp_path.name}-outside.py"
    outside.write_text("OUTSIDE_SECRET = 'not copied into the report'\n", encoding="utf-8")
    link = tmp_path / "outside.py"
    link.symlink_to(outside)
    report = _fixture(tmp_path)

    assert verify_report(report, tmp_path, expected_commit="fixture-commit") == []
    assert "OUTSIDE_SECRET" not in json.dumps(report)
    assert hashlib.sha256(outside.read_bytes()).hexdigest() not in {
        item.get("sha256") for item in report["repository_inventory"]["files"]
    }

def test_verifier_reports_malformed_artifact_structure_without_crashing(tmp_path: Path):
    report = _fixture(tmp_path)
    report["summary"] = []
    report["repository_inventory"]["duplicate_content_groups"] = [
        {"sha256": "bad", "paths": None}
    ]

    failures = verify_report(report, tmp_path, expected_commit="fixture-commit")
    assert any("summary is missing or not an object" in failure for failure in failures)
    assert any("duplicate-content groups" in failure for failure in failures)

