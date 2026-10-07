"""Local operational UI for the canonical AI-Cyber runtime.

The UI is a visualization/control surface only. Every execution delegates
directly to the canonical HYDRA runtime; the UI never synthesizes findings.
Live situation data comes only from runtime/test telemetry.
"""
from __future__ import annotations

import argparse
import json
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from .hydra import run_final_hardening_verification, run_hydra_phase
from .operations import load_report, run_regression, save_report
from .knowledge import DEFAULT_DB, ingest_file, search as knowledge_search, status as knowledge_status
from .runtime_intelligence import analyze as intelligence_analyze
from .dataset_pipeline import ingest_manifest, inspect_dataset
from .threat_intel import ingest_source, PARSERS
from . import telemetry
from .command_gateway import execute as execute_command

HOST = "127.0.0.1"
PORT = 8765
PROJECT_ROOT = Path(__file__).resolve().parents[2]
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
    "last_result": None,
    "events": [],
}


def _snapshot() -> dict[str, Any]:
    with STATE_LOCK:
        return json.loads(json.dumps(STATE, default=str))


def _execute(phase: str, hardening: bool) -> dict[str, Any]:
    if phase not in VALID_PHASES:
        raise ValueError("invalid phase selector")

    telemetry.begin("hydra", phase=phase, message=f"HYDRA {phase} execution started")
    telemetry.emit(
        "phase_started",
        f"Executing canonical HYDRA selector {phase}",
        operation="hydra",
        phase=phase,
        status="RUNNING",
        source="hydra",
    )

    try:
        phase_result = run_hydra_phase(phase)
        if isinstance(phase_result, dict):
            summary = phase_result.get("summary", {})
            if isinstance(summary, dict) and "success" in summary:
                success = summary.get("success") is True
            else:
                success = phase_result.get("verified") is True
        else:
            summary = None
            success = False

        telemetry.emit(
            "phase_completed",
            f"Canonical HYDRA selector {phase} returned",
            operation="hydra",
            phase=phase,
            status="PASS" if success else "FAIL",
            source="hydra",
            evidence=summary if isinstance(summary, dict) else phase_result,
        )

        hardening_result = None
        if hardening:
            telemetry.begin("hardening", phase=phase, message="Final hardening verification started")
            hardening_result = run_final_hardening_verification()
            hardening_success = (
                isinstance(hardening_result, dict)
                and hardening_result.get("verified") is True
            )
            telemetry.emit(
                "hardening_completed",
                "Final hardening verification returned",
                operation="hardening",
                phase=phase,
                status="PASS" if hardening_success else "FAIL",
                source="hardening",
                evidence=hardening_result,
                keep_active=True,
            )
            success = success and hardening_success

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

        result = {
            "phase": phase,
            "phase_result": phase_result,
            "hardening_result": hardening_result,
            "success": success,
        }
        with STATE_LOCK:
            STATE["last_result"] = result
            STATE["events"].append({
                "phase": phase,
                "success": success,
                "hardening": bool(hardening),
                "timestamp": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
            })
            STATE["events"] = STATE["events"][-40:]
            result["state"] = _snapshot()

        telemetry.complete(
            "hydra",
            success=success,
            phase=phase,
            message=f"HYDRA {phase} completed",
            evidence={"failed_phases": failed_phases, "hardening": bool(hardening)},
        )
        save_report("hydra", result)
        return result
    except Exception as exc:
        telemetry.error("hydra", f"HYDRA execution raised {type(exc).__name__}: {exc}", phase=phase)
        raise


def _run_redteam() -> dict[str, Any]:
    from .redteam import run

    telemetry.begin("red-team", message="Authorized localhost red-team harness started")
    try:
        result = run()
        success = isinstance(result, dict) and result.get("success") is True
        telemetry.complete(
            "red-team",
            success=success,
            message="Authorized localhost red-team harness completed",
            evidence=result,
        )
        return save_report("red-team", result)
    except Exception as exc:
        telemetry.error("red-team", f"Red-team harness raised {type(exc).__name__}: {exc}")
        raise


def _run_regression() -> dict[str, Any]:
    telemetry.begin("regression", message="Regression verification started")
    try:
        result = save_report("regression", run_regression(PROJECT_ROOT))
        success = isinstance(result, dict) and result.get("success") is True
        telemetry.complete("regression", success=success, evidence=result)
        return result
    except Exception as exc:
        telemetry.error("regression", f"Regression verification raised {type(exc).__name__}: {exc}")
        raise


def _command_status() -> dict[str, Any]:
    state = _snapshot()
    state["knowledge"] = knowledge_status(db_path=DEFAULT_DB)
    state["live"] = telemetry.snapshot()
    return state


class Handler(BaseHTTPRequestHandler):
    server_version = "AI-CYBER-UI/3.0"

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
                latest_report=load_report(),
                knowledge=knowledge_status(db_path=DEFAULT_DB),
                live=telemetry.snapshot(),
            )
            self._send(200, state)
            return

        if path == "/api/report":
            self._send(200, {"success": True, "report": load_report()})
            return

        if path == "/api/situation":
            state = _command_status()
            state["report"] = load_report()
            self._send(200, state)
            return

        if path == "/api/events":
            params = parse_qs(urlparse(self.path).query)
            try:
                since = int(params.get("since", ["0"])[0])
            except ValueError:
                since = 0
            self._send(200, telemetry.snapshot(since=since))
            return

        if path == "/api/knowledge/status":
            self._send(200, knowledge_status(db_path=DEFAULT_DB))
            return

        self._send(404, {"success": False, "error": "not found"})

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path not in {"/api/run", "/api/test", "/api/knowledge", "/api/command"}:
            self._send(404, {"success": False, "error": "not found"})
            return

        try:
            if path == "/api/command":
                length = int(self.headers.get("Content-Length", "0"))
                if length > 2048:
                    raise ValueError("request too large")
                body = json.loads(self.rfile.read(length) or b"{}")
                if not isinstance(body, dict) or set(body) != {"command"}:
                    raise ValueError("command request must contain only 'command'")
                command = body.get("command")
                if not isinstance(command, str):
                    raise ValueError("command must be a string")
                result = execute_command(
                    command,
                    run_phase=_execute,
                    search=lambda query: intelligence_analyze(query, db_path=DEFAULT_DB, limit=10),
                    status=_command_status,
                    regression=_run_regression,
                    red_team=_run_redteam,
                )
                nested = result.get("result")
                result["success"] = not isinstance(nested, dict) or nested.get("success", True) is not False
                self._send(200 if result["success"] else 422, result)
                return

            if path == "/api/knowledge":
                length = int(self.headers.get("Content-Length", "0"))
                if length > 8192:
                    raise ValueError("request too large")
                body = json.loads(self.rfile.read(length) or b"{}")
                if not isinstance(body, dict):
                    raise ValueError("JSON object required")
                action = body.get("action")

                if action == "search":
                    allowed = {"action", "query", "dataset", "limit"}
                    unknown = set(body) - allowed
                    if unknown:
                        raise ValueError("unknown request fields: " + ", ".join(sorted(str(x) for x in unknown)))
                    query = body.get("query")
                    if not isinstance(query, str):
                        raise ValueError("query must be a string")
                    result = knowledge_search(
                        query, db_path=DEFAULT_DB, dataset=body.get("dataset"), limit=body.get("limit", 10)
                    )
                elif action == "ingest":
                    allowed = {"action", "path", "manifest", "kind", "dataset", "source", "license", "version", "source_uri", "validation_status"}
                    unknown = set(body) - allowed
                    if unknown:
                        raise ValueError("unknown request fields: " + ", ".join(sorted(str(x) for x in unknown)))
                    raw_path = body.get("path")
                    if not isinstance(raw_path, str) or not raw_path:
                        raise ValueError("path must be a non-empty string")
                    candidate = (PROJECT_ROOT / raw_path).resolve()
                    candidate.relative_to(PROJECT_ROOT.resolve())
                    result = ingest_file(
                        candidate,
                        db_path=DEFAULT_DB,
                        dataset=body.get("dataset"),
                        source=body.get("source"),
                        license=body.get("license", ""),
                        version=body.get("version", ""),
                        source_uri=body.get("source_uri", ""),
                        validation_status=body.get("validation_status", "unverified"),
                    )
                elif action == "ingest-manifest":
                    raw_manifest = body.get("manifest")
                    if not isinstance(raw_manifest, str) or not raw_manifest:
                        raise ValueError("manifest must be a non-empty string")
                    manifest_path = (PROJECT_ROOT / raw_manifest).resolve()
                    manifest_path.relative_to(PROJECT_ROOT.resolve())
                    result = ingest_manifest(manifest_path, db_path=DEFAULT_DB)
                elif action == "inspect-manifest":
                    raw_manifest = body.get("manifest")
                    if not isinstance(raw_manifest, str) or not raw_manifest:
                        raise ValueError("manifest must be a non-empty string")
                    manifest_path = (PROJECT_ROOT / raw_manifest).resolve()
                    manifest_path.relative_to(PROJECT_ROOT.resolve())
                    result = inspect_dataset(manifest_path)
                elif action == "ingest-source":
                    kind = body.get("kind")
                    raw_path = body.get("path")
                    if kind not in PARSERS:
                        raise ValueError("unsupported threat-intel source")
                    if not isinstance(raw_path, str) or not raw_path:
                        raise ValueError("path must be a non-empty string")
                    candidate = (PROJECT_ROOT / raw_path).resolve()
                    candidate.relative_to(PROJECT_ROOT.resolve())
                    result = ingest_source(
                        kind,
                        candidate,
                        db_path=DEFAULT_DB,
                        dataset=body.get("dataset"),
                        source=body.get("source"),
                        version=body.get("version", ""),
                        source_uri=body.get("source_uri", ""),
                        license=body.get("license", ""),
                        validation_status=body.get("validation_status", "unverified"),
                    )
                elif action == "status":
                    result = knowledge_status(db_path=DEFAULT_DB)
                else:
                    raise ValueError("invalid knowledge action")

                self._send(200 if result.get("success", True) else 422, result)
                return

            if path == "/api/test":
                length = int(self.headers.get("Content-Length", "0"))
                if length > 4096:
                    raise ValueError("request too large")
                body = json.loads(self.rfile.read(length) or b"{}")
                if not isinstance(body, dict):
                    raise ValueError("JSON object required")
                unknown = set(body) - {"kind"}
                if unknown:
                    raise ValueError("unknown request fields: " + ", ".join(sorted(str(x) for x in unknown)))
                kind = body.get("kind")
                if kind == "full":
                    result = _execute("all", False)
                elif kind == "hardening":
                    result = _execute("all", True)
                elif kind == "regression":
                    result = _run_regression()
                elif kind == "red-team":
                    result = _run_redteam()
                else:
                    raise ValueError("invalid test kind")
                self._send(200 if result.get("success", False) else 422, result)
                return

            length = int(self.headers.get("Content-Length", "0"))
            if length > 16384:
                raise ValueError("request too large")
            body = json.loads(self.rfile.read(length) or b"{}")
            if not isinstance(body, dict):
                raise ValueError("JSON object required")
            unknown_fields = set(body) - {"phase", "hardening"}
            if unknown_fields:
                raise ValueError("unknown request fields: " + ", ".join(sorted(str(field) for field in unknown_fields)))
            phase = body.get("phase", "all")
            hardening = body.get("hardening", False)
            if not isinstance(phase, str):
                raise ValueError("phase must be a string")
            if not isinstance(hardening, bool):
                raise ValueError("hardening must be a boolean")
            result = _execute(phase, hardening)
            self._send(200 if result["success"] else 422, result)
        except Exception as exc:
            self._send(400, {"success": False, "error": f"{type(exc).__name__}: {exc}"})

    def log_message(self, fmt: str, *args: Any) -> None:
        return


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Local AI-Cyber HYDRA operations UI")
    parser.add_argument("--host", default=HOST)
    parser.add_argument("--port", type=int, default=PORT)
    parser.add_argument("--no-browser", action="store_true", help="Do not open the UI automatically.")
    args = parser.parse_args(argv)

    if args.host not in {"127.0.0.1", "localhost", "::1"}:
        parser.error("UI is intentionally local-only")

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    url = f"http://{args.host}:{args.port}"
    print(f"AI-CYBER UI: {url}")
    print("Scope: localhost-only; execution delegates to canonical HYDRA runtime.")
    if not args.no_browser:
        threading.Timer(0.35, lambda: webbrowser.open(url)).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return 0
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
