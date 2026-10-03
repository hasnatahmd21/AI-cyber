from __future__ import annotations

def test_canonical_runtime_imports():
    import ai_cyber_os.hydra as hydra
    assert hydra.__name__ == "ai_cyber_os.hydra"
    assert callable(hydra.run_hydra_phase)
    assert callable(hydra.run_final_hardening_verification)


def test_27_phase_runtime_verification():
    from ai_cyber_os.hydra import run_hydra_phase
    result = run_hydra_phase("all")
    assert result["summary"]["phases"] == 27
    assert result["summary"]["success"] is True, result


def test_final_hardening_verification():
    from ai_cyber_os.hydra import run_final_hardening_verification
    result = run_final_hardening_verification()
    assert result["verified"] is True, result
    assert result["failed"] == 0, result
