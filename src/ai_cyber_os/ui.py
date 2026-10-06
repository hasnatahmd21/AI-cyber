"""Local operational UI for the canonical AI-Cyber runtime.

The UI is a visualization/control surface only. Every execution delegates
directly to the canonical HYDRA runtime; the UI never synthesizes findings.
"""
from __future__ import annotations

import argparse
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .hydra import run_final_hardening_verification, run_hydra_phase

HOST = "127.0.0.1"
PORT = 8765
VALID_PHASES = {"all", *{f"phase{i}" for i in range(1, 28)}}
TEMPLATE = Path(__file__).with_name("ui_template.html").read_text(encoding="utf-8")

STATE_LOCK = threading.Lock()
STATE: dict[str, Any] = {
    "runtime": "online",
    "last_phase": None,
    "last_success": None,
    "last_summary": None,
    "last_hardening": None,
    "failed_phases": [],
}


def _snapshot() -> dict[str, Any]:
    with STATE_LOCK:
        return json.loads(json.dumps(STATE, default=str))


def _execute(phase: str, hardening: bool) -> dict[str, Any]:
    if phase not in VALID_PHASES:
        raise ValueError("invalid phase selector")

    phase_result = run_hydra_phase(phase)

    if isinstance(phase_result, dict):
        summary = phase_result.get("summary", {})
        if isinstance(summary, dict) and "success" in summary:
            success = summary.get("success") is True
        else:
            success = phase_result.get("verified") is True
    else:
        success = False

    hardening_result = None
    if hardening:
        hardening_result = run_final_hardening_verification()
        success = (
            success
            and isinstance(hardening_result, dict)
            and hardening_result.get("verified") is True
        )

    summary = phase_result.get("summary") if isinstance(phase_result, dict) else None
    failed_phases = summary.get("failed_phases", []) if isinstance(summary, dict) else []
    if not isinstance(failed_phases, list):
        failed_phases = []

    with STATE_LOCK:
        STATE.update(
            last_phase=phase,
            last_success=success,
            last_summary=(
                summary
                if isinstance(summary, dict)
                else {
                    "phases": 27 if phase == "all" else 1,
                    "success": success,
                    "failed_phases": failed_phases,
                }
            ),
            last_hardening=hardening_result,
            failed_phases=failed_phases,
        )

    return {
        "phase": phase,
        "phase_result": phase_result,
        "hardening_result": hardening_result,
        "success": success,
        "state": _snapshot(),
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "AI-CYBER-UI/2.0"

    def _send(self, status: int, payload: Any, content_type: str = "application/json") -> None:
        data = (
            payload.encode("utf-8")
            if isinstance(payload, str)
            else json.dumps(payload, default=str).encode("utf-8")
        )
        self.send_response(status)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        path = urlparse(self.path).path

        if path == "/":
            self._send(200, TEMPLATE, "text/html")
            return

        if path == "/api/status":
            state = _snapshot()
            state.update(
                success=True,
                phases=27,
                network_scope="localhost-only",
            )
            self._send(200, state)
            return

        self._send(404, {"success": False, "error": "not found"})

    def do_POST(self) -> None:
        if urlparse(self.path).path != "/api/run":
            self._send(404, {"success": False, "error": "not found"})
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length > 16_384:
                raise ValueError("request too large")

            body = json.loads(self.rfile.read(length) or b"{}")
            if not isinstance(body, dict):
                raise ValueError("JSON object required")

            allowed_fields = {"phase", "hardening"}
            unknown_fields = set(body) - allowed_fields
            if unknown_fields:
                raise ValueError(
                    "unknown request fields: "
                    + ", ".join(sorted(str(field) for field in unknown_fields))
                )

            phase = body.get("phase", "all")
            hardening = body.get("hardening", False)

            if not isinstance(phase, str):
                raise ValueError("phase must be a string")
            if not isinstance(hardening, bool):
                raise ValueError("hardening must be a boolean")

            result = _execute(phase, hardening)
            self._send(200 if result["success"] else 422, result)
        except Exception as exc:
            self._send(
                400,
                {
                    "success": False,
                    "error": f"{type(exc).__name__}: {exc}",
                },
            )

    def log_message(self, fmt: str, *args: Any) -> None:
        return


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Local AI-Cyber HYDRA operations UI")
    parser.add_argument("--host", default=HOST)
    parser.add_argument("--port", type=int, default=PORT)
    args = parser.parse_args(argv)

    if args.host not in {"127.0.0.1", "localhost", "::1"}:
        parser.error("UI is intentionally local-only")

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"AI-CYBER UI: http://{args.host}:{args.port}")
    print("Scope: localhost-only; execution delegates to canonical HYDRA runtime.")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return 0
    finally:
        server.server_close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
