#!/usr/bin/env python3
"""Run deterministic AI-CYBER intelligence integration evaluations."""
from __future__ import annotations
import json, sys
from ai_cyber_os.integration_evaluation import run_intelligence_evaluations, run_malware_intelligence_evaluation, run_network_intelligence_evaluation

def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else "all"
    if mode == "network": result = run_network_intelligence_evaluation()
    elif mode == "malware": result = run_malware_intelligence_evaluation()
    elif mode == "all": result = run_intelligence_evaluations()
    else: raise SystemExit("usage: intelligence_evaluation.py [network|malware|all]")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("success", result.get("verified", False)) else 1

if __name__ == "__main__":
    raise SystemExit(main())
