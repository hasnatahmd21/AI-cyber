from __future__ import annotations

from pathlib import Path

import pytest

import ai_cyber_os.secured as secured


@pytest.mark.parametrize(
    "existing",
    ["none", "hydra-only", "it-tech-only"],
)
def test_first_run_never_automatically_trusts_source_tree(tmp_path, monkeypatch, existing):
    state = tmp_path / ".ai_cyber"
    state.mkdir()
    hydra_baseline = state / "hydra_baseline.json"
    it_tech_baseline = state / "it_tech_baseline.json"

    if existing == "hydra-only":
        hydra_baseline.write_text('{"baseline": {}, "signature": "old"}', encoding="utf-8")
    elif existing == "it-tech-only":
        it_tech_baseline.write_text('{"document": {}, "signature": "old"}', encoding="utf-8")

    monkeypatch.setattr(secured, "_git_clean", lambda _root: True)

    def unexpected_write(*_args, **_kwargs):
        raise AssertionError("missing baseline must not be auto-created")

    monkeypatch.setattr(secured, "write_baseline", unexpected_write)
    monkeypatch.setattr(secured, "write_file_baseline", unexpected_write)

    output = []
    result = secured.main(["--phase", "all", "--json"], root=str(tmp_path), out=output.append)

    assert result == 4
    assert any("automatic first-run trust is disabled" in line for line in output)
    assert hydra_baseline.exists() is (existing == "hydra-only")
    assert it_tech_baseline.exists() is (existing == "it-tech-only")


def test_installed_runtime_prefers_project_checkout_over_site_packages(tmp_path, monkeypatch):
    (tmp_path / "pyproject.toml").write_text("[project]\nname='test-project'\n", encoding="utf-8")
    package = tmp_path / "src" / "ai_cyber_os"
    package.mkdir(parents=True)
    (tmp_path / "IT_tech__MERGED_ALL_FIXES_APPLIED.py").write_text(
        "# trusted project asset\n", encoding="utf-8"
    )
    monkeypatch.chdir(tmp_path)

    assert secured._root() == str(tmp_path)
