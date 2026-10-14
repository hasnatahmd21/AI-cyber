"""Run stage gates in order and stop at the first failure.

By default, the generated report is written outside the repository to avoid
dirtying a checkout during verification. Set AI_CYBER_GATE_REPORT_PATH or pass
--report-path to choose another destination.
Usage: python run_gates.py [--report-path PATH]
"""
import argparse
import datetime
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
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
    ("Gate 9B - HYDRA Brain new-tech integration", ["tests.test_newtech_integration"]),
    ("Gate 10 - full system end-to-end", ["tests.test_end_to_end"]),
    ("Gate 11 - adapters (datasets + audit persistence)", ["tests.test_adapters"]),
    ("Gate 12 - launcher (defence in front of HYDRA)", ["tests.test_launcher"]),
    ("Gate 13 - integrity + regeneration before HYDRA starts", ["tests.test_integrity_gate"]),
    ("Gate 14 - project entry: auto key + defence and HYDRA together", ["tests.test_secured"]),
]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    default_report = os.environ.get(
        "AI_CYBER_GATE_REPORT_PATH",
        str(Path(os.environ.get("TMPDIR", "/tmp")) / "ai-cyber-GATE_REPORT.md"),
    )
    parser.add_argument(
        "--report-path",
        default=default_report,
        help="Where to write the gate report (default: outside the repository)",
    )
    args = parser.parse_args()
    report_path = Path(args.report_path).expanduser().resolve()
    report_path.parent.mkdir(parents=True, exist_ok=True)

    lines = [
        "# Gate report",
        f"Generated {datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')}",
        "",
        "Report path: " + str(report_path),
        "",
        "| Gate | Result | Tests | Time |",
        "|---|---|---|---|",
    ]
    ok_all = True
    for name, modules in GATES:
        started = datetime.datetime.now()
        cp = subprocess.run(
            [sys.executable, "-m", "unittest", *modules],
            cwd=str(ROOT), capture_output=True, text=True,
        )
        match = re.search(r"Ran (\d+) tests?", cp.stderr)
        count = match.group(1) if match else "?"
        ok = cp.returncode == 0
        elapsed = (datetime.datetime.now() - started).total_seconds()
        lines.append(
            f"| {name} | {'PASS' if ok else 'FAIL'} | {count} | {elapsed:.1f}s |"
        )
        print(f"{'PASS' if ok else 'FAIL'}  {name}  ({count} tests)")
        if not ok:
            print(cp.stdout[-2000:])
            print(cp.stderr[-2000:])
            ok_all = False
            break

    lines += [
        "",
        "A gate passing means only that its defined tests passed; "
        "it is not proof of the security of the whole system.",
    ]
    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Gate report written to: {report_path}")
    return 0 if ok_all else 1


if __name__ == "__main__":
    raise SystemExit(main())
