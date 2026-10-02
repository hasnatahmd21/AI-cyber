from pathlib import Path

from tools.forensic_audit import build_report, duplicate_names


def test_duplicate_names_only_returns_repeats():
    assert duplicate_names(["A", "B", "A", "C", "B"]) == {"A": 2, "B": 2}


def test_audit_records_definition_location_and_fingerprint(tmp_path: Path):
    (tmp_path / "a.py").write_text(
        "class A:\n    def run(self, x):\n        return x\n",
        encoding="utf-8",
    )
    report = build_report(tmp_path)
    item = report["files"][0]
    assert item["syntax_error"] is None
    assert any(
        d["kind"] == "class" and d["name"] == "A" and d["line"] == 1
        for d in item["definitions"]
    )
    assert any(
        d["kind"] == "function" and d["name"] == "run" and d["line"] == 2
        and d["fingerprint"]
        for d in item["definitions"]
    )


def test_exact_duplicate_bodies_are_separately_indexed(tmp_path: Path):
    source = "class A:\n    pass\n\nclass B:\n    pass\n"
    (tmp_path / "a.py").write_text(source, encoding="utf-8")
    report = build_report(tmp_path)
    assert len(report["exact_duplicate_definition_bodies"]) >= 1
