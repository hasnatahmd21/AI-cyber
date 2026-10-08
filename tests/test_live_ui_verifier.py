from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VERIFIER = ROOT / "tools" / "live_ui_verify.py"


def test_live_ui_verifier_is_fail_closed_and_browser_based():
    source = VERIFIER.read_text(encoding="utf-8")
    for marker in (
        "playwright",
        "chromium.launch(headless=True)",
        "networkidle",
        "SYSTEM HEALTHY",
        "CVE-2026-87654",
        "/ui",
        "/health",
        "no browser console errors",
        "no page errors",
        "no cross-origin requests",
        'result": "GREEN"',
    ):
        assert marker in source


def test_live_ui_verifier_checks_both_viewports():
    source = VERIFIER.read_text(encoding="utf-8")
    assert '("desktop", 1440, 900)' in source
    assert '("mobile", 390, 844)' in source


def test_httpx2_is_declared_for_current_starlette_testclient():
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "httpx2>=2.13,<3.0" in pyproject
