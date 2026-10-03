from __future__ import annotations

def test_canonical_runtime_imports():
    import ai_cyber_os.hydra as hydra
    assert hydra.__name__ == "ai_cyber_os.hydra"
    assert callable(hydra.run_hydra_phase)
    assert callable(hydra.run_final_hardening_verification)


def test_27_phase_runtime_verification():
    from ai_cyber_os.hydra import run_hydra_phase
    result = run_hydra_phase("all")
    logical_phases = {f"phase{i}" for i in range(1, 28)}
    assert logical_phases.issubset(result)
    assert "phase8_agents" in result  # auxiliary verification inside Phase 8
    assert len(logical_phases.intersection(result)) == 27
    assert result["summary"]["phases"] == 27
    assert result["summary"]["auxiliary_checks"] == 1
    assert result["summary"]["success"] is True, result


def test_final_hardening_verification():
    from ai_cyber_os.hydra import run_final_hardening_verification
    result = run_final_hardening_verification()
    assert result["verified"] is True, result
    assert result["failed"] == 0, result
