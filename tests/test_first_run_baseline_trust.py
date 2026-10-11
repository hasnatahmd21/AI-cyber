from __future__ import annotations

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


def test_explicit_rebaseline_refuses_dirty_source_tree(tmp_path, monkeypatch):
    monkeypatch.setattr(secured, "_git_clean", lambda _root: False)

    def unexpected_write(*_args, **_kwargs):
        raise AssertionError("dirty source must never be signed")

    monkeypatch.setattr(secured, "write_baseline", unexpected_write)
    monkeypatch.setattr(secured, "write_file_baseline", unexpected_write)
    output = []

    result = secured.main(
        ["--defence-rebaseline", "--phase", "phase1", "--json"],
        root=str(tmp_path),
        out=output.append,
    )

    assert result == 4
    assert any("rebaseline refused" in line for line in output)
    assert not (tmp_path / ".ai_cyber" / "hydra_baseline.json").exists()
    assert not (tmp_path / ".ai_cyber" / "it_tech_baseline.json").exists()



@pytest.mark.parametrize(
    "args",
    [
        ["--phase", "all", "--json"],
        ["--defence-rebaseline", "--phase", "all", "--json"],
    ],
)
def test_cli_refuses_execution_and_rebaseline_while_incident_latch_exists(
    tmp_path, monkeypatch, args
):
    import json

    state = tmp_path / ".ai_cyber"
    state.mkdir()
    # Even a malformed latch is a fail-closed incident state; it is never
    # silently ignored or replaced by a fresh clean trust context.
    (state / "defence_latch.json").write_text(
        json.dumps({"unexpected": "schema"}), encoding="utf-8"
    )
    monkeypatch.setattr(secured, "build_system", lambda **_kwargs: pytest.fail(
        "HYDRA runtime must not be built while incident latch is present"
    ))
    monkeypatch.setattr(
        secured, "write_baseline", lambda *_args, **_kwargs: pytest.fail(
            "source must not be rebaselined while incident latch is present"
        )
    )
    monkeypatch.setattr(
        secured, "write_file_baseline", lambda *_args, **_kwargs: pytest.fail(
            "IT-Tech must not be rebaselined while incident latch is present"
        )
    )
    output = []

    result = secured.main(args, root=str(tmp_path), out=output.append)

    assert result == 4
    assert any("latch" in line.lower() and "refused" in line.lower() for line in output)
