from __future__ import annotations
import hashlib, json
from pathlib import Path
from tools.stage0_audit import build_report, render_markdown, scan_file


def test_hash_inventory_and_syntax_error_are_recorded(tmp_path: Path):
    (tmp_path / "good.py").write_text("class Sample:\n    pass\n", encoding="utf-8")
    bad = tmp_path / "broken.py"
    bad.write_text("def bad(:\n    pass\n", encoding="utf-8")
    report = build_report(tmp_path, commit="fixture-commit")
    good = next(x for x in report["files"] if x["path"] == "good.py")
    broken = next(x for x in report["files"] if x["path"] == "broken.py")
    assert good["sha256"] == hashlib.sha256((tmp_path / "good.py").read_bytes()).hexdigest()
    assert report["audited_commit"] == "fixture-commit"
    assert broken["syntax_error"]["message"]
    assert report["summary"]["syntax_error_file_count"] == 1


def test_duplicate_definitions_and_cross_file_symbols(tmp_path: Path):
    (tmp_path / "a.py").write_text("class Shared:\n    pass\n\ndef work():\n    return 1\n\ndef work():\n    return 2\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("class Shared:\n    pass\n", encoding="utf-8")
    report = build_report(tmp_path)
    a = next(x for x in report["files"] if x["path"] == "a.py")
    assert a["duplicate_top_level_definitions"]["work"] == [4, 7]
    assert "Shared" in report["cross_file_duplicate_definitions"]


def test_import_resolution_marks_stdlib_local_and_external(tmp_path: Path):
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg/__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "pkg/core.py").write_text("VALUE = 1\n", encoding="utf-8")
    (tmp_path / "use.py").write_text("import os\nimport pkg.core\nimport fake_dep_xyz\n", encoding="utf-8")
    row = next(x for x in build_report(tmp_path)["files"] if x["path"] == "use.py")
    labels = {x["module"]: x["classification"] for x in row["imports"]}
    assert labels["os"] == "stdlib" and labels["pkg.core"] == "local"
    assert labels["fake_dep_xyz"] == "external_or_unresolved"


def test_security_indicators_do_not_expose_secret_values(tmp_path: Path):
    path = tmp_path / "suspect.py"
    path.write_text('password = "not-a-real-secret-value"\nsubprocess.run(command, shell=True)\neval(payload)\nrequests.get(url, verify=False)\n', encoding="utf-8")
    row, findings = scan_file(path, tmp_path, [tmp_path], set())
    ids = {x["rule_id"] for x in findings}
    assert {"possible_hardcoded_secret", "shell_command_execution_indicator", "dynamic_code_execution_indicator", "tls_verification_disabled_indicator"} <= ids
    assert "not-a-real-secret-value" not in json.dumps(findings)
    assert row["sha256"]


def test_markdown_records_static_limitations(tmp_path: Path):
    (tmp_path / "test_sample.py").write_text("def test_something():\n    assert 1 == 1\n", encoding="utf-8")
    report = build_report(tmp_path)
    assert "read-only" in render_markdown(report)
    assert "Coverage percentage is intentionally not reported" in render_markdown(report)
    assert report["summary"]["test_function_count"] == 1
