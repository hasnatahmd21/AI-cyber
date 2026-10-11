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
    """Route every CLI invocation through the canonical security gate.

    No demo, compatibility, or alternate subcommand may invoke HYDRA directly.
    The secured dispatcher validates the command, checks signed source baselines,
    runs the barrier and independent defence layers, then dispatches to HYDRA.
    """
    from .secured import main as secured_main
    return secured_main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
