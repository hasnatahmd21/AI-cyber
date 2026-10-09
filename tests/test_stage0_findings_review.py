from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from tools.stage0_findings_review import (
    ARCH_MAP,
    CORE,
    LEGACY_FILES,
    ReviewError,
    build_review,
    render_markdown,
)


def _write(root: Path, rel: str, content: str) -> bytes:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = content.encode("utf-8")
    path.write_bytes(raw)
    return raw


def _record(path: str, classification: str, raw: bytes, syntax_ok: bool = True) -> dict:
    return {
        "path": path, "classification": classification, "bytes": len(raw),
        "lines": raw.count(b"\n") + (1 if raw else 0),
        "sha256": hashlib.sha256(raw).hexdigest(), "syntax_ok": syntax_ok,
        "syntax_error": None if syntax_ok else {"line": 3, "column": 9, "message": "invalid syntax"},
        "symbols": [{"name": "example", "line": 1}] if syntax_ok else [],
        "calls": [], "imports": [], "main_guards": [], "duplicate_scoped_symbols": [],
        "side_effect_signals": [], "unused_import_candidates": [], "stub_candidates": [],
        "unreachable_statement_candidates": [], "todo_markers": [], "import_resolution_findings": [],
    }


def _fixture(root: Path, *, legacy_syntax_error: bool = False) -> tuple[dict, str]:
    commit = "a" * 40
    inventory_files, python_records = [], []
    for rel in LEGACY_FILES:
        raw = _write(root, rel, "# preserved historical source\n")
        inventory_files.append({"path": rel, "category": "python_source", "bytes": len(raw),
                                "sha256": hashlib.sha256(raw).hexdigest()})
        python_records.append(_record(rel, "legacy_forensic_candidate", raw,
                                      syntax_ok=not (legacy_syntax_error and rel == LEGACY_FILES[0])))
    core_raw = _write(root, CORE, "def run():\n    return True\n")
    inventory_files.append({"path": CORE, "category": "python_source", "bytes": len(core_raw),
                            "sha256": hashlib.sha256(core_raw).hexdigest()})
    python_records.append(_record(CORE, "package_source", core_raw))
    arch_raw = _write(root, ARCH_MAP, f"# Stage 1 map\n**Snapshot commit:** {commit}\n")
    inventory_files.append({"path": ARCH_MAP, "category": "documentation", "bytes": len(arch_raw),
                            "sha256": hashlib.sha256(arch_raw).hexdigest()})
    report = {
        "schema": "ai-cyber.deep-forensic-audit.v1", "commit_sha": commit,
        "summary": {
            "python_file_count": len(python_records), "legacy_forensic_files_present": list(LEGACY_FILES),
            "cross_file_duplicate_symbol_keys": 1, "files_with_duplicate_scoped_symbols": 0,
            "side_effect_signal_count": 0, "broad_exception_count": 0, "stub_candidate_count": 0,
            "unreachable_statement_candidate_count": 0, "unused_import_candidate_count": 0,
            "import_resolution_finding_count": 0, "todo_marker_count": 0,
            "static_runtime_reachable_files": 4, "entrypoint_file_count": 2,
        },
        "repository_inventory": {"files": inventory_files}, "files": python_records,
        "entrypoints": {"ai_cyber_os.__main__": ["python -m ai_cyber_os"]},
        "entrypoint_files": {"src/ai_cyber_os/__main__.py": {"path": "src/ai_cyber_os/__main__.py", "reasons": ["CLI"]}},
        "cross_file_duplicate_symbols": {"function:example": ["a.py", "b.py"]},
        "security_review": {"rule_counts": {}},
    }
    return report, commit


def test_build_review_reconciles_legacy_and_canonical_evidence(tmp_path: Path):
    report, commit = _fixture(tmp_path)
    review = build_review(report, tmp_path, commit)
    assert review["schema"] == "ai-cyber.stage0-findings-review.v1"
    assert review["status"] == "REVIEW_REQUIRED"
    assert review["automated_green_claim"] is False
    assert review["summary"]["legacy_evidence_count"] == 6
    assert review["canonical_reconciliation"]["core_present"] is True
    assert review["canonical_reconciliation"]["core_syntax_ok"] is True
    assert review["summary"]["inventory_integrity_mismatch_count"] == 0
    assert any(item["id"] == "ST0-P3-CANDIDATES" for item in review["findings"])


def test_rendered_review_is_deterministic(tmp_path: Path):
    report, commit = _fixture(tmp_path)
    one = render_markdown(build_review(report, tmp_path, commit))
    two = render_markdown(build_review(report, tmp_path, commit))
    assert one == two
    assert "Automated green claim:** No" in one
    assert "Preserved legacy source ledger" in one


def test_report_commit_mismatch_is_rejected(tmp_path: Path):
    report, _ = _fixture(tmp_path)
    with pytest.raises(ReviewError, match="Audit commit mismatch"):
        build_review(report, tmp_path, "b" * 40)


def test_checkout_change_blocks_review(tmp_path: Path):
    report, commit = _fixture(tmp_path)
    (tmp_path / LEGACY_FILES[1]).write_text("# changed after audit\n", encoding="utf-8")
    review = build_review(report, tmp_path, commit)
    assert review["status"] == "BLOCKED"
    assert review["summary"]["inventory_integrity_mismatch_count"] == 1
    assert any(item["id"] == "ST0-P3-001" for item in review["findings"])


def test_preserved_legacy_syntax_error_is_explicit(tmp_path: Path):
    report, commit = _fixture(tmp_path, legacy_syntax_error=True)
    review = build_review(report, tmp_path, commit)
    legacy = next(item for item in review["legacy_sources"] if item["path"] == LEGACY_FILES[0])
    assert legacy["state"] == "PRESERVED_SYNTAX_ERROR"
    assert review["summary"]["blocking_nonlegacy_syntax_error_count"] == 0
    assert any(item["status"] == "REVIEW_REQUIRED" and "legacy source" in item["title"].lower()
               for item in review["findings"])


def test_canonical_syntax_error_blocks_review(tmp_path: Path):
    report, commit = _fixture(tmp_path)
    core = next(item for item in report["files"] if item["path"] == CORE)
    core["syntax_ok"] = False
    core["syntax_error"] = {"line": 1, "column": 1, "message": "invalid syntax"}
    review = build_review(report, tmp_path, commit)
    assert review["status"] == "BLOCKED"
    assert review["summary"]["blocking_nonlegacy_syntax_error_count"] == 1


def test_parent_traversal_path_is_rejected(tmp_path: Path):
    report, commit = _fixture(tmp_path)
    report["repository_inventory"]["files"][0]["path"] = "../outside.py"
    with pytest.raises(ReviewError, match="Unsafe repository-relative path"):
        build_review(report, tmp_path, commit)


def test_stale_architecture_snapshot_is_an_explicit_review_item(tmp_path: Path):
    report, commit = _fixture(tmp_path)
    stale = "c" * 40
    raw = _write(tmp_path, ARCH_MAP, f"# Stage 1 map\n**Snapshot commit:** {stale}\n")
    row = next(x for x in report["repository_inventory"]["files"] if x["path"] == ARCH_MAP)
    row.update(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
    review = build_review(report, tmp_path, commit)
    assert review["summary"]["architecture_map_status"] == "STALE_SNAPSHOT"
    assert review["status"] == "REVIEW_REQUIRED"
