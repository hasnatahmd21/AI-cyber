import json

from ai_cyber_os.intelligence_hydra import run_hydra_phase

def test_extended_phase5_registration():
    result = run_hydra_phase("phase5-intelligence")
    assert result["success"] is True, json.dumps(result, indent=2, ensure_ascii=False)
    assert result["summary"]["name"].startswith("Phase 5"), json.dumps(result, indent=2, ensure_ascii=False)

def test_extended_phase6_malware_registration():
    result = run_hydra_phase("phase6-malware")
    assert result["success"] is True, json.dumps(result, indent=2, ensure_ascii=False)
    assert result["summary"]["name"].startswith("Phase 6"), json.dumps(result, indent=2, ensure_ascii=False)
