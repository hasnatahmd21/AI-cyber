"""Controlled human/agent command gateway.

Only allow-listed operations are accepted. This is intentionally not a shell,
Python evaluator, or arbitrary command executor.
"""
from __future__ import annotations

import re
from typing import Any, Callable

_PHASE_RE = re.compile(r"^run\s+phase\s+(?:0*(\d{1,2}))$", re.I)
_SEARCH_RE = re.compile(r"^search\s+(.+)$", re.I)


def execute(
    command: str,
    *,
    run_phase: Callable[[str, bool], dict[str, Any]],
    search: Callable[[str], dict[str, Any]],
    status: Callable[[], dict[str, Any]],
    regression: Callable[[], dict[str, Any]],
    red_team: Callable[[], dict[str, Any]],
) -> dict[str, Any]:
    if not isinstance(command, str):
        raise ValueError("command must be a string")
    command = command.strip()
    if not command or len(command) > 512:
        raise ValueError("command must be 1-512 characters")

    if command.lower() in {"status", "get status", "show status"}:
        return {"success": True, "command": command, "action": "status", "result": status()}

    if command.lower() in {"run all", "run all phases", "run 27 phases"}:
        return {"success": True, "command": command, "action": "run_all", "result": run_phase("all", False)}

    if command.lower() in {"run all and hardening", "run all + hardening", "run 27 phases and hardening"}:
        return {"success": True, "command": command, "action": "run_all_hardening", "result": run_phase("all", True)}

    m = _PHASE_RE.fullmatch(command)
    if m:
        number = int(m.group(1))
        if not 1 <= number <= 27:
            raise ValueError("phase must be between 1 and 27")
        return {
            "success": True,
            "command": command,
            "action": "run_phase",
            "result": run_phase(f"phase{number}", False),
        }

    m = _SEARCH_RE.fullmatch(command)
    if m:
        return {"success": True, "command": command, "action": "search", "result": search(m.group(1).strip())}

    if command.lower() in {"run regression", "run regression tests"}:
        return {"success": True, "command": command, "action": "regression", "result": regression()}

    if command.lower() in {"run local red-team", "run red-team", "run red team"}:
        return {"success": True, "command": command, "action": "red_team", "result": red_team()}

    raise ValueError(
        "unsupported command; allowed: status, run phase N, run all, "
        "run all and hardening, search <query>, run regression, run local red-team"
    )
