from __future__ import annotations

import json
from pathlib import Path

from tools.forensic_deep_audit import build_report, render_markdown


def _report(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text(
        '[project.scripts]\ndemo-cli = "demo.entry:main"\n',
        encoding="utf-8",
    )
    package = tmp_path / "src" / "demo"
    package.mkdir(parents=True, exist_ok=True)
    (package / "__init__.py").write_text("from .entry import main\n", encoding="utf-8")
    (package / "entry.py").write_text(
        '"""Demo runtime entry."""\n'
        "from . import helper\n"
        "import subprocess\n"
        "\n"
        "def main():\n"
        "    # TODO: test this path\n"
        "    return helper.work()\n"
        "\n"
        "def launch():\n"
        "    return subprocess.run(['echo', 'ok'], shell=True)\n"
        "\n"
        "def launch():\n"
        "    try:\n"
        "        return main()\n"
        "    except Exception:\n"
        "        pass\n",
        encoding="utf-8",
    )
    (package / "helper.py").write_text("def work():\n    return 7\n", encoding="utf-8")
    tests = tmp_path / "tests"
    tests.mkdir(exist_ok=True)
    (tests / "broken.py").write_text("def broken(:\n    pass\n", encoding="utf-8")
    (tests / "test_entry.py").write_text("from demo.entry import main\n", encoding="utf-8")
    (package / "note.txt").write_text("same artifact\n", encoding="utf-8")
    (tmp_path / "copy-note.txt").write_text("same artifact\n", encoding="utf-8")
    (tmp_path / ".github" / "workflows").mkdir(parents=True, exist_ok=True)
    (tmp_path / ".github" / "workflows" / "checks.yml").write_text("name: checks\non:\n  push:\njobs:\n  test:\n    steps:\n      - uses: actions/checkout@v4\n      - run: pytest -q\n", encoding="utf-8")
    (tmp_path / "datasets" / "manifests").mkdir(parents=True, exist_ok=True)
    (tmp_path / "datasets" / "manifests" / "fixture.json").write_text(json.dumps({"dataset":"fixture","version":"1","sha256":"a"*64,"record_count":1}), encoding="utf-8")
    return build_report(tmp_path)


def test_deep_audit_indexes_symbols_calls_and_ranges(tmp_path: Path):
    report = _report(tmp_path)
    entry = next(x for x in report["files"] if x["path"] == "src/demo/entry.py")
    assert report["schema"] == "ai-cyber.deep-forensic-audit.v1"
    assert any(s["qualified_name"] == "main" and s["line_start"] == 5 for s in entry["symbols"])
    assert any(c["callee"] == "helper.work" for c in entry["calls"])
    assert any(edge["callee"] == "main" for edge in entry["static_call_edges"])
    assert "<module>:function:launch" in entry["duplicate_scoped_symbols"]
    assert entry["lines"] >= 15


def test_deep_audit_detects_side_effects_comments_and_broad_handlers(tmp_path: Path):
    report = _report(tmp_path)
    entry = next(x for x in report["files"] if x["path"] == "src/demo/entry.py")
    categories = {x["category"] for x in entry["side_effect_signals"]}
    assert "process_or_shell_execution" in categories
    assert "shell_true" in categories
    assert entry["todo_markers"][0]["marker"] == "TODO"
    assert entry["broad_exceptions"][0]["exception"] == "Exception"
    assert entry["broad_exceptions"][0]["suppresses_error"] is True


def test_deep_audit_resolves_static_runtime_reachability_and_syntax_errors(tmp_path: Path):
    report = _report(tmp_path)
    paths = {x["path"]: x for x in report["files"]}
    assert paths["src/demo/entry.py"]["entrypoint_reasons"]
    assert paths["src/demo/helper.py"]["static_runtime_reachable"] is True
    assert paths["tests/broken.py"]["syntax_ok"] is False
    assert report["summary"]["syntax_error_file_count"] == 1
    assert report["summary"]["file_content_manifest_sha256"]
    assert "Runtime map" not in render_markdown(report)
    assert "File-by-file inventory" in render_markdown(report)


def test_audit_output_serializes_deterministically(tmp_path: Path):
    first = _report(tmp_path)
    second = _report(tmp_path)
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


def test_repository_inventory_covers_configs_manifests_and_all_files(tmp_path: Path):
    report = _report(tmp_path)
    inv = report["repository_inventory"]
    assert inv["summary"]["repository_file_count"] >= report["summary"]["python_file_count"]
    assert inv["package_contract"]["scripts"]["demo-cli"] == "demo.entry:main"
    assert any(x["path"] == "pyproject.toml" and x["category"] == "package_configuration" for x in inv["files"])
    assert any(x["path"] == "src/demo/entry.py" for x in inv["files"])
    assert "src/demo" in inv["directories"]
    assert inv["summary"]["configuration_and_manifest_file_count"] >= 1


def test_repository_inventory_reports_duplicate_content_by_hash(tmp_path: Path):
    _report(tmp_path)
    (tmp_path / "copy-one.txt").write_text("same artifact\n", encoding="utf-8")
    (tmp_path / "copy-two.txt").write_text("same artifact\n", encoding="utf-8")
    report = build_report(tmp_path)
    groups = report["repository_inventory"]["duplicate_content_groups"]
    assert any(set(g["paths"]) >= {"copy-one.txt", "copy-two.txt"} for g in groups)


def test_audit_prunes_git_and_virtual_environment_directories(tmp_path: Path):
    _report(tmp_path)
    git_dir = tmp_path / ".git"
    venv_dir = tmp_path / ".venv" / "lib"
    git_dir.mkdir()
    venv_dir.mkdir(parents=True)
    (git_dir / "internal.py").write_text("def should_not_be_scanned(): pass\n", encoding="utf-8")
    (venv_dir / "installed.py").write_text("def should_not_be_scanned(): pass\n", encoding="utf-8")
    report = build_report(tmp_path)
    all_paths = [x["path"] for x in report["repository_inventory"]["files"]]
    python_paths = [x["path"] for x in report["files"]]
    assert not any(path.startswith((".git/", ".venv/")) for path in all_paths + python_paths)


def test_audit_maps_test_files_to_directly_imported_modules(tmp_path: Path):
    report = _report(tmp_path)
    entry = next(x for x in report["files"] if x["path"] == "src/demo/entry.py")
    assert "tests/test_entry.py" in entry["tested_by_test_files"]


def test_audit_flags_unused_imports_stubs_and_unreachable_statements(tmp_path: Path):
    report = _report(tmp_path)
    entry = next(x for x in report["files"] if x["path"] == "src/demo/entry.py")
    assert any(x["bound_name"] == "os" for x in entry["unused_import_candidates"])
    assert any(x["reason"] == "pass_only_body" for x in entry["stub_candidates"])
    assert any(x["source"].startswith("print(") for x in entry["unreachable_statement_candidates"])


def test_audit_marks_unresolved_external_dependency_without_failing_inventory(tmp_path: Path):
    report = _report(tmp_path)
    entry = next(x for x in report["files"] if x["path"] == "src/demo/entry.py")
    assert any(
        x["kind"] == "undeclared_external_dependency_candidate"
        and x["module"] == "unknown_dependency"
        for x in entry["import_resolution_findings"]
    )
