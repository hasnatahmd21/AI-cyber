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

from .hydra import run_final_hardening_verification, run_hydra_phase


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
        "--json",
        action="store_true",
        help="Emit machine-readable JSON only.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    try:
        if args.json:
            runtime_output = StringIO()
            with redirect_stdout(runtime_output):
                phase_result: dict[str, Any] = run_hydra_phase(args.phase)
                payload: dict[str, Any] = {"phase_result": phase_result}
                if args.hardening:
                    payload["hardening_result"] = run_final_hardening_verification()
            diagnostic_output = runtime_output.getvalue()
            if diagnostic_output:
                print(diagnostic_output, file=sys.stderr, end="")
        else:
            phase_result = run_hydra_phase(args.phase)
            payload = {"phase_result": phase_result}
            if args.hardening:
                payload["hardening_result"] = run_final_hardening_verification()

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
