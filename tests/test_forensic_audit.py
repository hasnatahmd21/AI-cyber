from pathlib import Path
from tools.forensic_audit import build_report, duplicate_names

def test_duplicate_names_only_returns_repeats():
    assert duplicate_names(["A","B","A","C","B"]) == {"A":2,"B":2}

def test_audit_finds_python_files(tmp_path: Path):
    (tmp_path/"a.py").write_text("class A:\n    pass\n", encoding="utf-8")
    report = build_report(tmp_path)
    assert report["python_file_count"] == 1
    assert report["files"][0]["classes"] == ["A"]
    assert report["files"][0]["syntax_error"] is None
