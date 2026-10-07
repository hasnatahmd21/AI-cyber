"""Command-line entry point for the canonical AI-Cyber runtime.

This surface deliberately delegates execution to the canonical HYDRA module;
it does not duplicate phase logic.
"""
from __future__ import annotations

import argparse
import json
import sys
from contextlib import redirect_stdout
from io import StringIO
from typing import Any

from .hydra import run_final_hardening_verification
from .intelligence_hydra import run_hydra_phase, run_all_extended


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ai-cyber",
        description="Run the canonical AI-Cyber HYDRA runtime.",
    )
    parser.add_argument(
        "--phase",
        default="all",
        help="HYDRA phase selector accepted by the canonical runtime (default: all).",
    )
    parser.add_argument(
        "--hardening",
        action="store_true",
        help="Run final adversarial hardening verification after the phase run.",
    )
    parser.add_argument(
        "--extended-all",
        action="store_true",
        help="Run the extended intelligence evaluation in addition to core HYDRA.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON only.",
    )
    return parser




def _result_successful(result: dict[str, Any]) -> bool:
    """Evaluate a phase result without assuming every phase has a summary."""
    if not isinstance(result, dict):
        return False
    if result.get("success") is False or result.get("verified") is False:
        return False
    if result.get("status") in {"FAIL", "FAILED", "EXCEPTION", "NO_RESULT", "ERROR"}:
        return False
    if result.get("failed", 0) or result.get("tests_failed", 0):
        return False
    if result.get("failures"):
        return False
    summary = result.get("summary")
    if isinstance(summary, dict):
        return _result_successful(summary)
    results = result.get("results")
    if isinstance(results, dict):
        return all(
            value in {"PASS", "VERIFIED", True}
            if isinstance(value, (str, bool))
            else _result_successful(value)
            for value in results.values()
        )
    return True

def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    try:
        if args.json:
            runtime_output = StringIO()
            with redirect_stdout(runtime_output):
                phase_result: dict[str, Any] = run_all_extended() if args.extended_all else run_hydra_phase(args.phase)
                payload: dict[str, Any] = {"phase_result": phase_result}
                if args.hardening:
                    payload["hardening_result"] = run_final_hardening_verification()
            diagnostic_output = runtime_output.getvalue()
            if diagnostic_output:
                print(diagnostic_output, file=sys.stderr, end="")
        else:
            phase_result = run_all_extended() if args.extended_all else run_hydra_phase(args.phase)
            payload = {"phase_result": phase_result}
            if args.hardening:
                payload["hardening_result"] = run_final_hardening_verification()

        success = _result_successful(phase_result)
        if args.extended_all:
            success = bool(phase_result.get("summary", {}).get("success", False))
        if args.hardening:
            success = success and bool(payload["hardening_result"].get("verified", False))

        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True, default=str))
        else:
            summary = phase_result.get("summary", {})
            print(
                "AI-Cyber runtime: "
                f"success={success} phases={summary.get('phases', 'n/a')} "
                f"auxiliary_checks={summary.get('auxiliary_checks', 'n/a')}"
            )
            if args.hardening:
                print(
                    "Final hardening: "
                    f"verified={payload['hardening_result'].get('verified', False)} "
                    f"failed={payload['hardening_result'].get('failed', 'n/a')}"
                )

        return 0 if success else 1
    except Exception as exc:
        if args.json:
            print(
                json.dumps(
                    {"success": False, "error": str(exc), "error_type": type(exc).__name__},
                    indent=2,
                    sort_keys=True,
                )
            )
        else:
            print(f"AI-Cyber runtime error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
