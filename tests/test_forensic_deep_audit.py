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
    package.mkdir(parents=True)
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
    tests.mkdir()
    (tests / "broken.py").write_text("def broken(:\n    pass\n", encoding="utf-8")
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
