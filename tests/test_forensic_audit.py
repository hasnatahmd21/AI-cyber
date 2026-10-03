from pathlib import Path

from tools.forensic_audit import build_report, duplicate_names


def test_duplicate_names_only_returns_repeats():
    assert duplicate_names(["A", "B", "A", "C", "B"]) == {"A": 2, "B": 2}


def test_audit_reports_syntax_and_symbols(tmp_path: Path):
    (tmp_path / "a.py").write_text(
        "class A:\n    def run(self, x):\n        return x\n",
        encoding="utf-8",
    )
    (tmp_path / "broken.py").write_text("def broken(:\n    pass\n", encoding="utf-8")
    report = build_report(tmp_path)
    assert report["python_file_count"] == 2
    good = next(item for item in report["files"] if item["path"].endswith("a.py"))
    broken = next(item for item in report["files"] if item["path"].endswith("broken.py"))
    assert good["syntax_error"] is None
    assert "A" in good["classes"]
    assert "run" in good["functions"]
    assert broken["syntax_error"] is not None


def test_audit_indexes_cross_file_duplicates(tmp_path: Path):
    (tmp_path / "a.py").write_text("class Shared:\n    pass\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("class Shared:\n    pass\n", encoding="utf-8")
    report = build_report(tmp_path)
    assert report["cross_file_duplicate_symbols"]["class:Shared"] == [
        str(tmp_path / "a.py"),
        str(tmp_path / "b.py"),
    ]
