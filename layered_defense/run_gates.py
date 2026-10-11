"""Run stage gates in order; stop at the first failure (spec: next stage only after current passes).
Writes docs/GATE_REPORT.md with evidence.   Usage: python run_gates.py"""
import datetime, subprocess, sys, os, re
ROOT = os.path.dirname(os.path.abspath(__file__))
GATES = [
    ("Gate 0 - contracts + legacy inventory", ["tests.test_contracts"]),
    ("Gate 1 - barrier", ["tests.test_barrier"]),
    ("Gate 2 - layer 1", ["tests.test_layer1"]),
    ("Gate 3 - layer 2", ["tests.test_layer2"]),
    ("Gate 4 - layer 3", ["tests.test_layer3"]),
    ("Gate 5 - cryptography + trust", ["tests.test_crypto_integrity", "tests.test_trust_authority"]),
    ("Gate 6 - isolation + deception", ["tests.test_isolation", "tests.test_deception"]),
    ("Gate 7 - regeneration", ["tests.test_regeneration"]),
    ("Gate 8 - orchestration + audit", ["tests.test_audit_telemetry", "tests.test_orchestrator"]),
    ("Gate 9 - HYDRA integration (42-phase regression)", ["tests.test_hydra_integration"]),
    ("Gate 10 - full system end-to-end", ["tests.test_end_to_end"]),
]
lines = ["# Gate report", f"Generated {datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')}", "",
         "| Gate | Result | Tests | Time |", "|---|---|---|---|"]
ok_all = True
for name, mods in GATES:
    t = datetime.datetime.now()
    cp = subprocess.run([sys.executable, "-m", "unittest", *mods], cwd=ROOT, capture_output=True, text=True)
    n = re.search(r"Ran (\d+) tests?", cp.stderr); n = n.group(1) if n else "?"
    ok = cp.returncode == 0
    lines.append(f"| {name} | {'PASS' if ok else 'FAIL'} | {n} | {(datetime.datetime.now()-t).total_seconds():.1f}s |")
    print(f"{'PASS' if ok else 'FAIL'}  {name}  ({n} tests)")
    if not ok:
        print(cp.stderr[-2000:]); ok_all = False; break
lines += ["", "A gate passing means only that its defined tests passed; it is not proof of the security of the whole system."]
open(os.path.join(ROOT, "docs", "GATE_REPORT.md"), "w").write("\n".join(lines) + "\n")
sys.exit(0 if ok_all else 1)
