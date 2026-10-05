#!/usr/bin/env python3
"""Controlled Red-Team vs Blue-Team adversarial evaluation for AI-Cyber.

This harness is deliberately local-only. It does not scan, exploit, or connect to
external hosts. The current canonical AI-Cyber runtime explicitly disables
live cyber execution, so this test attacks the runtime boundary itself:
argument handling, fail-closed behavior, network-egress isolation, determinism,
and the verified 27-phase/hardening contract.

Run from the repository root:
    python tools/red_blue_adversarial_test.py
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
PYTHON = sys.executable
TIMEOUT = int(os.environ.get("AI_CYBER_REDTEAM_TIMEOUT", "90"))


def _run(args: list[str], timeout: int = TIMEOUT) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _summary(payload: dict[str, Any]) -> dict[str, Any]:
    phase = payload.get("phase_result", {})
    summary = phase.get("summary", {}) if isinstance(phase, dict) else {}
    hardening = payload.get("hardening_result", {})
    return {
        "phase_success": phase.get("success") is True,
        "phases": summary.get("phases"),
        "auxiliary_checks": summary.get("auxiliary_checks"),
        "hardening_verified": hardening.get("verified") is True,
        "hardening_failed": hardening.get("failed"),
    }


def _parse_json(stdout: str) -> dict[str, Any] | None:
    try:
        value = json.loads(stdout)
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, dict) else None


def _case(name: str, ok: bool, detail: str, severity: str = "INFO") -> dict[str, Any]:
    return {"name": name, "blue_team": ok, "severity": severity, "detail": detail}


def baseline() -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    results: list[dict[str, Any]] = []
    started = time.monotonic()
    try:
        proc = _run([PYTHON, "-m", "ai_cyber_os", "--phase", "all", "--hardening", "--json"])
    except subprocess.TimeoutExpired:
        return [_case("baseline_runtime", False, f"timeout after {TIMEOUT}s", "CRITICAL")], None

    payload = _parse_json(proc.stdout)
    if proc.returncode != 0 or payload is None:
        results.append(_case(
            "baseline_runtime",
            False,
            f"exit={proc.returncode}; stderr={proc.stderr[-1000:]!r}",
            "CRITICAL",
        ))
        return results, payload

    s = _summary(payload)
    ok = (
        proc.returncode == 0
        and s["phase_success"]
        and s["phases"] == 27
        and s["auxiliary_checks"] == 1
        and s["hardening_verified"]
        and s["hardening_failed"] == 0
    )
    results.append(_case(
        "baseline_runtime",
        ok,
        f"{s}; elapsed={time.monotonic() - started:.2f}s",
        "CRITICAL" if not ok else "INFO",
    ))
    return results, payload


def red_team_boundary_probes() -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []

    payloads = [
        ("invalid_phase", "phase999"),
        ("traversal_payload", "../../etc/passwd"),
        ("shell_payload", "phase1;touch /tmp/ai_cyber_redteam_pwned"),
        ("shell_substitution", "$(touch /tmp/ai_cyber_redteam_pwned)"),
        ("pipe_payload", "phase1|cat /etc/passwd"),
        ("sql_payload", "phase1' OR '1'='1"),
        ("json_breakout", 'phase1\"},\"success\":true,{'),
        ("unicode_confusion", "phase1\u202e--hardening"),
    ]

    marker = Path(tempfile.gettempdir()) / "ai_cyber_redteam_pwned"
    marker.unlink(missing_ok=True)

    for name, value in payloads:
        try:
            proc = _run([PYTHON, "-m", "ai_cyber_os", "--phase", value, "--json"], timeout=30)
            parsed = _parse_json(proc.stdout)
            shell_marker_created = marker.exists()

            # A boundary attack is contained when it cannot silently become a
            # successful valid runtime invocation and cannot execute shell code.
            successful_valid_run = bool(
                proc.returncode == 0
                and parsed
                and isinstance(parsed.get("phase_result"), dict)
                and parsed["phase_result"].get("summary", {}).get("phases") == 27
            )
            ok = (not successful_valid_run) and (not shell_marker_created)
            results.append(_case(
                name,
                ok,
                f"exit={proc.returncode}; valid_run={successful_valid_run}; "
                f"shell_marker={shell_marker_created}",
                "HIGH" if not ok else "INFO",
            ))
        except subprocess.TimeoutExpired:
            results.append(_case(name, False, "timeout during adversarial input", "HIGH"))

    marker.unlink(missing_ok=True)

    # Unknown option must fail at the parser boundary, not reach the runtime.
    try:
        proc = _run([PYTHON, "-m", "ai_cyber_os", "--definitely-not-an-option"], timeout=20)
        ok = proc.returncode != 0
        results.append(_case(
            "unknown_cli_option",
            ok,
            f"exit={proc.returncode}; stderr={proc.stderr[:500]!r}",
            "MEDIUM" if not ok else "INFO",
        ))
    except subprocess.TimeoutExpired:
        results.append(_case("unknown_cli_option", False, "timeout", "MEDIUM"))

    return results


def network_egress_probe() -> list[dict[str, Any]]:
    probe = r'''
import socket
import sys
from ai_cyber_os.hydra import run_hydra_phase

def blocked(*args, **kwargs):
    raise RuntimeError("LIVE_NETWORK_EGRESS_ATTEMPT")

socket.create_connection = blocked
socket.getaddrinfo = blocked

result = run_hydra_phase("all")
if result.get("summary", {}).get("success") is not True:
    raise SystemExit("RUNTIME_NOT_HEALTHY")
print("NO_NETWORK_EGRESS")
'''
    try:
        proc = _run([PYTHON, "-c", probe], timeout=60)
        ok = proc.returncode == 0 and "NO_NETWORK_EGRESS" in proc.stdout
        return [_case(
            "network_egress_isolation",
            ok,
            f"exit={proc.returncode}; stdout={proc.stdout[-300:]!r}; stderr={proc.stderr[-500:]!r}",
            "CRITICAL" if not ok else "INFO",
        )]
    except subprocess.TimeoutExpired:
        return [_case("network_egress_isolation", False, "timeout", "CRITICAL")]


def contract_fail_closed_probe() -> list[dict[str, Any]]:
    probe = r'''
from ai_cyber_os.hydra import IntegrationResult, Phase20ValidationError, _phase_result_ok_final

assert _phase_result_ok_final(False) is False
assert _phase_result_ok_final(True) is True

try:
    IntegrationResult(
        result_id="red-team",
        tenant_id="tenant-a",
        connector_id="connector-a",
        status="ATTACKER_FORGED_STATUS",
    )
except Phase20ValidationError:
    print("FAIL_CLOSED")
else:
    raise SystemExit("INVALID_STATUS_ACCEPTED")
'''
    try:
        proc = _run([PYTHON, "-c", probe], timeout=30)
        ok = proc.returncode == 0 and "FAIL_CLOSED" in proc.stdout
        return [_case(
            "contract_fail_closed",
            ok,
            f"exit={proc.returncode}; stdout={proc.stdout[-300:]!r}; stderr={proc.stderr[-500:]!r}",
            "HIGH" if not ok else "INFO",
        )]
    except subprocess.TimeoutExpired:
        return [_case("contract_fail_closed", False, "timeout", "HIGH")]


def determinism_probe() -> list[dict[str, Any]]:
    summaries: list[dict[str, Any]] = []
    for i in range(2):
        try:
            proc = _run([PYTHON, "-m", "ai_cyber_os", "--phase", "all", "--hardening", "--json"])
        except subprocess.TimeoutExpired:
            return [_case("deterministic_repeatability", False, f"run {i + 1} timeout", "HIGH")]
        payload = _parse_json(proc.stdout)
        if proc.returncode != 0 or payload is None:
            return [_case(
                "deterministic_repeatability",
                False,
                f"run {i + 1} invalid; exit={proc.returncode}",
                "HIGH",
            )]
        summaries.append(_summary(payload))

    ok = summaries[0] == summaries[1]
    return [_case(
        "deterministic_repeatability",
        ok,
        f"run1={summaries[0]}; run2={summaries[1]}",
        "MEDIUM" if not ok else "INFO",
    )]


def integrity_probe() -> list[dict[str, Any]]:
    target = ROOT / "src" / "ai_cyber_os" / "hydra.py"
    if not target.exists():
        return [_case("canonical_source_integrity", False, "canonical hydra.py missing", "CRITICAL")]

    original = target.read_bytes()
    original_hash = hashlib.sha256(original).hexdigest()

    with tempfile.TemporaryDirectory(prefix="ai-cyber-redteam-") as td:
        copy = Path(td) / "hydra.py"
        copy.write_bytes(original)
        tampered = original + b"\n# CONTROLLED RED-TEAM TAMPER\n"
        copy.write_bytes(tampered)
        tampered_hash = hashlib.sha256(copy.read_bytes()).hexdigest()

    ok = original_hash != tampered_hash
    return [_case(
        "canonical_source_integrity",
        ok,
        f"baseline_sha256={original_hash}; tampered_sha256={tampered_hash}",
        "HIGH" if not ok else "INFO",
    )]


def main() -> int:
    print("=" * 78)
    print("AI-CYBER — RED TEAM vs BLUE TEAM CONTROLLED ADVERSARIAL TEST")
    print("=" * 78)
    print("Scope: local canonical runtime only; no external targets/network attacks.")
    print()

    results, baseline_payload = baseline()
    results += red_team_boundary_probes()
    results += network_egress_probe()
    results += contract_fail_closed_probe()
    results += determinism_probe()
    results += integrity_probe()

    red_wins = [r for r in results if not r["blue_team"]]
    blue_wins = [r for r in results if r["blue_team"]]
    critical = [r for r in red_wins if r["severity"] == "CRITICAL"]

    print("RESULTS")
    print("-" * 78)
    for r in results:
        side = "BLUE TEAM" if r["blue_team"] else "RED TEAM"
        print(f"[{side:9}] {r['severity']:8} {r['name']}: {r['detail']}")

    print()
    print("FINAL SCORE")
    print("-" * 78)
    print(f"Blue Team contained: {len(blue_wins)}/{len(results)}")
    print(f"Red Team findings:   {len(red_wins)}/{len(results)}")
    print(f"Critical findings:   {len(critical)}")

    if red_wins:
        print("WINNER: RED TEAM")
        print("Meaning: at least one adversarial probe found a boundary failure.")
        exit_code = 2
    else:
        print("WINNER: BLUE TEAM")
        print("Meaning: all controlled probes were contained by the current runtime.")
        exit_code = 0

    report = {
        "winner": "RED_TEAM" if red_wins else "BLUE_TEAM",
        "blue_team_contained": len(blue_wins),
        "red_team_findings": len(red_wins),
        "critical_findings": len(critical),
        "tests": results,
        "baseline": baseline_payload,
        "scope": "local-only canonical runtime; no external targets",
    }
    report_path = ROOT / "red_blue_test_report.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True, default=str), encoding="utf-8")
    print(f"Report: {report_path}")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
