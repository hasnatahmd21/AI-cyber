from ai_cyber_os.integration_evaluation import run_intelligence_evaluations, run_malware_intelligence_evaluation, run_network_intelligence_evaluation

def test_phase5_network_intelligence_evaluation():
    result = run_network_intelligence_evaluation()
    assert result["verified"] is True, result

def test_phase6_malware_evaluation():
    result = run_malware_intelligence_evaluation()
    assert result["verified"] is True, result

def test_combined_intelligence_evaluation():
    result = run_intelligence_evaluations()
    assert result["success"] is True, result
