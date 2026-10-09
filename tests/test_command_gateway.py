"""Contract tests for the controlled command gateway."""
from __future__ import annotations

import pytest

from ai_cyber_os.command_gateway import execute


@pytest.fixture
def handlers():
    calls = []

    def run_phase(phase, hardening):
        calls.append(("phase", phase, hardening))
        return {"success": True, "phase": phase}

    def search(query):
        calls.append(("search", query))
        return {"success": True, "query": query, "evidence_only": True}

    def status():
        calls.append(("status",))
        return {"runtime": "online"}

    def regression():
        calls.append(("regression",))
        return {"success": True, "tests": 12}

    def red_team():
        calls.append(("red_team",))
        return {"success": True, "authorized_local_only": True}

    return {
        "calls": calls,
        "run_phase": run_phase,
        "search": search,
        "status": status,
        "regression": regression,
        "red_team": red_team,
    }


def invoke(command, handlers):
    return execute(command, **{k: v for k, v in handlers.items() if k != "calls"})


@pytest.mark.parametrize("command", ["status", "GET STATUS", " show status "])
def test_status_aliases_dispatch_to_status_handler(command, handlers):
    result = invoke(command, handlers)
    assert result["action"] == "status"
    assert result["result"] == {"runtime": "online"}
    assert handlers["calls"] == [("status",)]


@pytest.mark.parametrize(
    ("command", "expected_action", "expected_phase"),
    [
        ("run phase 1", "run_phase", "phase1"),
        ("RUN PHASE 07", "run_phase", "phase7"),
        ("run phase 27", "run_phase", "phase27"),
    ],
)
def test_phase_dispatch_is_allowlisted(command, expected_action, expected_phase, handlers):
    result = invoke(command, handlers)
    assert result["action"] == expected_action
    assert result["result"]["phase"] == expected_phase
    assert handlers["calls"] == [("phase", expected_phase, False)]


@pytest.mark.parametrize(
    ("command", "expected_action"),
    [
        ("run all", "run_all"),
        ("run all and hardening", "run_all_hardening"),
    ],
)
def test_full_run_aliases_dispatch_explicit_hardening(command, expected_action, handlers):
    result = invoke(command, handlers)
    assert result["action"] == expected_action
    assert handlers["calls"] == [
        ("phase", "all", expected_action == "run_all_hardening")
    ]


def test_search_returns_evidence_from_supplied_handler(handlers):
    result = invoke("search  CVE-2025-12345  ", handlers)
    assert result["action"] == "search"
    assert result["result"]["evidence_only"] is True
    assert handlers["calls"] == [("search", "CVE-2025-12345")]


@pytest.mark.parametrize("command", ["", " ", "x" * 513, "run phase 0", "run phase 28",
                                     "search    ", "python import os", "rm -rf /",
                                     "run phase 1; run all"])
def test_invalid_or_shell_like_commands_are_rejected(command, handlers):
    with pytest.raises(ValueError):
        invoke(command, handlers)
    assert handlers["calls"] == []


def test_regression_and_red_team_dispatch_only_to_injected_handlers(handlers):
    regression = invoke("run regression tests", handlers)
    red_team = invoke("run local red-team", handlers)
    assert regression["action"] == "regression"
    assert regression["result"]["tests"] == 12
    assert red_team["action"] == "red_team"
    assert red_team["result"]["authorized_local_only"] is True
    assert handlers["calls"] == [("regression",), ("red_team",)]
