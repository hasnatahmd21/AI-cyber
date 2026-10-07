"""Extended HYDRA registration for the AI-CYBER intelligence integration layer.

The historical monolith remains canonical. This adapter adds deterministic
integration phases without modifying the legacy Phase 6 governance semantics.
"""
from __future__ import annotations
from typing import Any
from .hydra import run_hydra_phase as run_core_hydra_phase
from .integration_evaluation import run_malware_intelligence_evaluation, run_network_intelligence_evaluation

def run_hydra_phase(name: str) -> dict[str, Any]:
    key = str(name).strip().lower()
    if key in {"phase5-intelligence", "phase5_network", "phase5-network-intelligence"}:
        return {"phase": "5-intelligence", "success": True, "summary": run_network_intelligence_evaluation()}
    if key in {"phase6-malware", "phase6_malware", "phase6-malware-evaluation"}:
        return {"phase": "6-malware", "success": True, "summary": run_malware_intelligence_evaluation()}
    if key in {"intelligence", "all-intelligence"}:
        network = run_network_intelligence_evaluation()
        malware = run_malware_intelligence_evaluation()
        return {"phase": "intelligence", "success": network["verified"] and malware["verified"],
                "summary": {"phase5": network, "phase6_malware": malware}}
    return run_core_hydra_phase(name)

def run_all_extended() -> dict[str, Any]:
    core = run_core_hydra_phase("all")
    network = run_network_intelligence_evaluation()
    malware = run_malware_intelligence_evaluation()
    success = bool(core.get("summary", {}).get("success", False)) and network["verified"] and malware["verified"]
    return {"core": core, "phase5_intelligence": network, "phase6_malware_evaluation": malware,
            "summary": {"success": success, "core_success": core.get("summary", {}).get("success", False),
                        "phase5_intelligence_verified": network["verified"],
                        "phase6_malware_verified": malware["verified"]}}
