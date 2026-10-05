from __future__ import annotations


EXPECTED_PHASES = {f"phase{i}" for i in range(1, 28)}


def _assert_phase_result_healthy(value, path="result"):
    """Fail on hidden failure markers anywhere in a phase result tree."""
    if value is None:
        raise AssertionError(f"{path}: returned None")

    if isinstance(value, bool):
        assert value, f"{path}: returned False"
        return

    if isinstance(value, str):
        normalized = value.strip().upper()
        assert normalized not in {"FAIL", "FAILED", "EXCEPTION", "NO_RESULT", "ERROR"}, (
            f"{path}: {value!r}"
        )
        assert not normalized.startswith(("FAIL:", "FAILED:", "EXCEPTION:", "ERROR:")), (
            f"{path}: {value!r}"
        )
        return

    if isinstance(value, dict):
        assert value.get("success") is not False, f"{path}: success=False"
        assert value.get("verified") is not False, f"{path}: verified=False"
        assert value.get("status") not in {"FAIL", "FAILED", "EXCEPTION", "NO_RESULT", "ERROR"}, (
            f"{path}: status={value.get('status')!r}"
        )
        assert value.get("failed", 0) in (0, False), f"{path}: failed={value.get('failed')!r}"
        assert value.get("tests_failed", 0) in (0, False), (
            f"{path}: tests_failed={value.get('tests_failed')!r}"
        )
        assert not value.get("failures"), f"{path}: failures={value.get('failures')!r}"
        for key, child in value.items():
            _assert_phase_result_healthy(child, f"{path}.{key}")
        return

    if isinstance(value, (list, tuple, set)):
        for index, child in enumerate(value):
            _assert_phase_result_healthy(child, f"{path}[{index}]")


def test_canonical_runtime_imports():
    import ai_cyber_os.hydra as hydra
    assert hydra.__name__ == "ai_cyber_os.hydra"
    assert callable(hydra.run_hydra_phase)
    assert callable(hydra.run_final_hardening_verification)


def test_27_phase_runtime_verification():
    from ai_cyber_os.hydra import run_hydra_phase

    result = run_hydra_phase("all")

    assert EXPECTED_PHASES.issubset(result)
    assert "phase8_agents" in result  # auxiliary verification inside Phase 8
    assert len(EXPECTED_PHASES.intersection(result)) == 27
    assert result["summary"]["phases"] == 27
    assert result["summary"]["auxiliary_checks"] == 1
    assert result["summary"]["success"] is True, result

    for phase in sorted(EXPECTED_PHASES):
        _assert_phase_result_healthy(result[phase], phase)

    _assert_phase_result_healthy(result["phase8_agents"], "phase8_agents")


def test_each_public_phase_dispatches_to_a_real_result():
    from ai_cyber_os.hydra import run_hydra_phase

    for phase_number in range(1, 28):
        result = run_hydra_phase(f"phase{phase_number}")
        _assert_phase_result_healthy(result, f"phase{phase_number}")


def test_final_hardening_verification():
    from ai_cyber_os.hydra import run_final_hardening_verification
    result = run_final_hardening_verification()
    assert result["verified"] is True, result
    assert result["failed"] == 0, result
