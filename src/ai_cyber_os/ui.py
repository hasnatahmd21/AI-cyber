"""Local operational UI for the canonical AI-Cyber runtime.

The UI is a visualization/control surface only. Every execution delegates
directly to the canonical HYDRA runtime; the UI never synthesizes findings.
Live situation data comes only from runtime/test telemetry.
"""
from __future__ import annotations

import argparse
import json
import sys
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from .operations import load_report, run_regression, save_report
from .knowledge import DEFAULT_DB, ingest_file, search as knowledge_search, status as knowledge_status
from .rag import build_context as build_rag_context
from .runtime_intelligence import analyze as intelligence_analyze
from .dataset_pipeline import ingest_manifest, inspect_dataset
from .threat_intel import ingest_source, PARSERS
from . import telemetry, live_surface
from .command_gateway import execute as execute_command

HOST = "127.0.0.1"
PORT = 8765
PROJECT_ROOT = Path(__file__).resolve().parents[2]
VALID_PHASES = {"all", *{f"phase{i}" for i in range(1, 28)}}
# The uploaded 3D command centre is the sole production UI. The legacy template is not served.
TEMPLATE_PATH = PROJECT_ROOT / "CYBER_OS_defence.html"
TEMPLATE = TEMPLATE_PATH.read_text(encoding="utf-8")

STATE_LOCK = threading.Lock()
def _assert_inside_project(path: Path, label: str = "path") -> Path:
    try:
        path.relative_to(PROJECT_ROOT.resolve())
    except ValueError as exc:
        raise ValueError(f"{label} must remain inside project") from exc
    return path


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


def run_hydra_phase(*args, **kwargs):
    """Lazy adapter: load the canonical HYDRA implementation only after the guard passes."""
    from .intelligence_hydra import run_hydra_phase as implementation
    return implementation(*args, **kwargs)


def run_final_hardening_verification(*args, **kwargs):
    """Lazy adapter for the existing hardening verifier."""
    from .hydra import run_final_hardening_verification as implementation
    return implementation(*args, **kwargs)



def _guarded_operation(operation: str, payload: Any, action):
    """Run every user-triggered POST operation through the existing integrity/barrier/layer gate."""
    from ._defence import run_guarded

    body = json.dumps(payload, sort_keys=True, default=str, ensure_ascii=False)
    # The gate receives bounded untrusted input, not an arbitrary shell command.
    argv = ["ui-operation", str(operation)[:80], body[:4096]]
    outcome: dict[str, Any] = {}
    def safely_call_action():
        try:
            outcome["result"] = action()
        except Exception as exc:
            # Preserve business/runtime errors; only guard failures become a denial.
            outcome["error"] = exc
        return {"ui_operation_invoked": True}
    try:
        run_guarded(argv, safely_call_action)
    except Exception as exc:
        # A broken/unavailable guard is a deny, never a route to an unguarded action.
        raise PermissionError(f"defence preflight refused operation ({type(exc).__name__})") from None
    finally:
        live_surface.invalidate_status_cache()
    if "error" in outcome:
        raise outcome["error"]
    return outcome.get("result")


def _data_fabric_status() -> dict[str, Any]:
    status = knowledge_status(db_path=DEFAULT_DB)
    manifests: list[dict[str, Any]] = []
    for base in (PROJECT_ROOT / "datasets" / "manifests", PROJECT_ROOT / "docs" / "datasets"):
        try:
            if base.is_dir() and not base.is_symlink():
                for item in sorted(base.glob("*.json")):
                    if item.is_file() and not item.is_symlink():
                        manifests.append({
                            "path": item.relative_to(PROJECT_ROOT).as_posix(),
                            "name": item.name,
                            "bytes": item.stat().st_size,
                        })
        except OSError:
            continue
    # Do not expose the local user's absolute home-directory path in API responses.
    status = dict(status)
    status["db"] = "~/.ai-cyber/knowledge.db"
    status.update(
        source="live",
        timestamp=__import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
        engine="SQLite FTS5",
        retrieval="deterministic lexical retrieval",
        provenance_enabled=True,
        manifests=manifests,
        manifest_count=len(manifests),
    )
    return status


def _hydra_status() -> dict[str, Any]:
    state = _snapshot()
    report = load_report()
    last_phase = state.get("last_phase")
    last_success = state.get("last_success")
    last_summary = state.get("last_summary") if isinstance(state.get("last_summary"), dict) else {}
    live = telemetry.snapshot()
    if last_success is True:
        status = "passed"
    elif last_success is False:
        status = "failed"
    elif live.get("run", {}).get("active"):
        status = "checking"
    else:
        status = "idle"

    # A phase is green only when a run reports it passed or all 27 completed successfully.
    phase_map = last_summary.get("results", last_summary.get("phase_results", {}))
    if isinstance(phase_map, list):
        phase_map = {
            str(item.get("phase", item.get("id", ""))): item
            for item in phase_map if isinstance(item, dict)
        }
    if not isinstance(phase_map, dict):
        phase_map = {}
    raw_failed = last_summary.get("failed_phases", state.get("failed_phases", []))
    if not isinstance(raw_failed, list):
        raw_failed = []
    failed_numbers: set[int] = set()
    for item in raw_failed:
        candidate = item.get("phase", item.get("id", "")) if isinstance(item, dict) else item
        digits = "".join(char for char in str(candidate) if char.isdigit())
        if digits:
            try:
                number = int(digits)
                if 1 <= number <= 27:
                    failed_numbers.add(number)
            except ValueError:
                pass

    phase_count = last_summary.get("phases", 0)
    if isinstance(phase_count, list):
        phase_count = len(phase_count)
    try:
        phase_count = int(phase_count)
    except (TypeError, ValueError):
        phase_count = len(phase_map)
    all_27_passed = (
        last_phase == "all"
        and last_success is True
        and not failed_numbers
        and (phase_count >= 27 or len(phase_map) >= 27)
    )

    phases = []
    for number in range(1, 28):
        phase_name = f"phase{number}"
        candidate = phase_map.get(phase_name, phase_map.get(str(number), phase_map.get(number)))
        phase_status = "unknown"
        if isinstance(candidate, dict):
            if candidate.get("success") is True or candidate.get("verified") is True or candidate.get("status") in {"PASS", "PASSED", "VERIFIED"}:
                phase_status = "passed"
            elif candidate.get("success") is False or candidate.get("verified") is False or candidate.get("status") in {"FAIL", "FAILED", "ERROR", "BLOCKED"}:
                phase_status = "failed"
        elif candidate is True or (isinstance(candidate, str) and candidate.upper() in {"PASS", "PASSED", "VERIFIED"}):
            phase_status = "passed"
        elif candidate is False or (isinstance(candidate, str) and candidate.upper() in {"FAIL", "FAILED", "ERROR", "BLOCKED"}):
            phase_status = "failed"

        if number in failed_numbers:
            phase_status = "failed"
        elif all_27_passed:
            phase_status = "passed"
        elif last_phase == phase_name and last_success is not None:
            phase_status = "passed" if last_success else "failed"
        phases.append({"phase": number, "id": phase_name, "state": phase_status})

    return {
        "source": "live",
        "timestamp": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
        "state": status,
        "available_phases": 27,
        "last_phase": last_phase,
        "last_success": last_success,
        "last_summary": last_summary,
        "latest_report": report,
        "phases": phases,
        "telemetry": live.get("run", {}),
    }


def _live_status_bundle() -> dict[str, Any]:
    state = _snapshot()
    live = telemetry.snapshot()
    fabric = _data_fabric_status()
    defence = live_surface.defence_status(fabric=fabric, runtime_state=state)
    hydra = _hydra_status()
    summary = live_surface.project_summary(
        runtime_state=state, telemetry_state=live, fabric=fabric, defence=defence
    )
    return {
        "success": True,
        "timestamp": summary["timestamp"],
        "project": summary,
        "defence": defence,
        "hydra": hydra,
        "data_fabric": fabric,
        "telemetry": live,
    }


def _execute_runtime(phase: str, hardening: bool) -> dict[str, Any]:
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


def _execute(phase: str, hardening: bool) -> dict[str, Any]:
    """Guard every HYDRA operation before loading or executing the runtime implementation."""
    if phase not in VALID_PHASES:
        raise ValueError("invalid phase selector")
    return _guarded_operation(
        "hydra-run",
        {"phase": phase, "hardening": hardening},
        lambda: _execute_runtime(phase, hardening),
    )


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
            ui_check = live_surface.verify_ui_asset()
            if ui_check.get("state") != "passed":
                self._send(503, {"success": False, "error": "UI integrity verification failed", "ui": ui_check})
                return
            self._send(200, TEMPLATE, "text/html")
            return


        if path in {"/defence/status", "/api/defence/status"}:
            fabric = _data_fabric_status()
            self._send(200, live_surface.defence_status(fabric=fabric, runtime_state=_snapshot()))
            return

        if path == "/api/live/summary":
            self._send(200, _live_status_bundle())
            return

        if path == "/api/hydra/status":
            self._send(200, _hydra_status())
            return

        if path == "/api/hydra/phases":
            self._send(200, {"success": True, **_hydra_status()})
            return

        if path == "/api/data-fabric/status":
            self._send(200, _data_fabric_status())
            return

        if path == "/api/status":
            state = _snapshot()
            state.update(
                success=True,
                phases=27,
                network_scope="localhost-only",
                latest_report=load_report(),
                knowledge=_data_fabric_status(),
                live=telemetry.snapshot(),
                project=_live_status_bundle()["project"],
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
            self._send(200, _data_fabric_status())
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
                result = _guarded_operation(
                    "command",
                    {"command": command},
                    lambda: execute_command(
                        command,
                        run_phase=_execute_runtime,
                        search=lambda query: intelligence_analyze(query, db_path=DEFAULT_DB, limit=10),
                        status=_command_status,
                        regression=_run_regression,
                        red_team=_run_redteam,
                    ),
                )
                nested = result.get("result")
                action = result.get("action")
                if action == "status":
                    # Status has no operation-level success field; a real snapshot is enough.
                    success = isinstance(nested, dict)
                else:
                    # Execution/search handlers must explicitly report success. Missing or
                    # malformed backend results must never be presented as a green result.
                    success = isinstance(nested, dict) and nested.get("success") is True
                result["success"] = success
                self._send(200 if success else 422, result)
                return

            if path == "/api/knowledge":
                length = int(self.headers.get("Content-Length", "0"))
                if length > 8192:
                    raise ValueError("request too large")
                body = json.loads(self.rfile.read(length) or b"{}")
                if not isinstance(body, dict):
                    raise ValueError("JSON object required")
                action = body.get("action")

                if action in {"search", "context"}:
                    allowed = {"action", "query", "dataset", "limit"}
                    unknown = set(body) - allowed
                    if unknown:
                        raise ValueError("unknown request fields: " + ", ".join(sorted(str(x) for x in unknown)))
                    query = body.get("query")
                    if not isinstance(query, str) or not query.strip():
                        raise ValueError("query must be a non-empty string")
                    dataset = body.get("dataset")
                    if dataset is not None and (not isinstance(dataset, str) or not dataset.strip()):
                        raise ValueError("dataset must be a non-empty string when supplied")
                    limit = body.get("limit", 10 if action == "search" else 8)
                    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 50:
                        raise ValueError("limit must be an integer between 1 and 50")
                    if action == "context":
                        result = _guarded_operation(
                            "knowledge-context", body,
                            lambda: build_rag_context(query.strip(), db_path=DEFAULT_DB, dataset=dataset, limit=limit),
                        )
                        result["success"] = True
                    else:
                        result = _guarded_operation(
                            "knowledge-search", body,
                            lambda: knowledge_search(query.strip(), db_path=DEFAULT_DB, dataset=dataset, limit=limit),
                        )
                        if isinstance(result, list):
                            result = {"success": True, "query": query.strip(), "results": result}
                elif action == "ingest":
                    allowed = {"action", "path", "manifest", "kind", "dataset", "source", "license", "version", "source_uri", "validation_status"}
                    unknown = set(body) - allowed
                    if unknown:
                        raise ValueError("unknown request fields: " + ", ".join(sorted(str(x) for x in unknown)))
                    raw_path = body.get("path")
                    if not isinstance(raw_path, str) or not raw_path:
                        raise ValueError("path must be a non-empty string")
                    candidate = (PROJECT_ROOT / raw_path).resolve()
                    _assert_inside_project(candidate, "path")
                    result = _guarded_operation(
                        "knowledge-ingest", body,
                        lambda: ingest_file(
                            candidate,
                            db_path=DEFAULT_DB,
                            dataset=body.get("dataset"),
                            source=body.get("source"),
                            license=body.get("license", ""),
                            version=body.get("version", ""),
                            source_uri=body.get("source_uri", ""),
                            validation_status=body.get("validation_status", "unverified"),
                        ),
                    )
                elif action == "ingest-manifest":
                    raw_manifest = body.get("manifest")
                    if not isinstance(raw_manifest, str) or not raw_manifest:
                        raise ValueError("manifest must be a non-empty string")
                    manifest_path = (PROJECT_ROOT / raw_manifest).resolve()
                    _assert_inside_project(manifest_path, "manifest")
                    result = _guarded_operation(
                        "dataset-ingest-manifest", body,
                        lambda: ingest_manifest(manifest_path, db_path=DEFAULT_DB),
                    )
                elif action == "inspect-manifest":
                    raw_manifest = body.get("manifest")
                    if not isinstance(raw_manifest, str) or not raw_manifest:
                        raise ValueError("manifest must be a non-empty string")
                    manifest_path = (PROJECT_ROOT / raw_manifest).resolve()
                    manifest_path.relative_to(PROJECT_ROOT.resolve())
                    result = _guarded_operation(
                        "dataset-inspect-manifest", body,
                        lambda: inspect_dataset(manifest_path),
                    )
                elif action == "ingest-source":
                    kind = body.get("kind")
                    raw_path = body.get("path")
                    if kind not in PARSERS:
                        raise ValueError("unsupported threat-intel source")
                    if not isinstance(raw_path, str) or not raw_path:
                        raise ValueError("path must be a non-empty string")
                    candidate = (PROJECT_ROOT / raw_path).resolve()
                    candidate.relative_to(PROJECT_ROOT.resolve())
                    result = _guarded_operation(
                        "threat-intel-ingest", body,
                        lambda: ingest_source(
                            kind,
                            candidate,
                            db_path=DEFAULT_DB,
                            dataset=body.get("dataset"),
                            source=body.get("source"),
                            version=body.get("version", ""),
                            source_uri=body.get("source_uri", ""),
                            license=body.get("license", ""),
                            validation_status=body.get("validation_status", "unverified"),
                        ),
                    )
                elif action == "status":
                    result = _guarded_operation(
                        "knowledge-status", body, lambda: _data_fabric_status()
                    )
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
                if kind not in {"full", "hardening", "regression", "red-team"}:
                    raise ValueError("invalid test kind")
                result = _guarded_operation(
                    f"test-{kind}",
                    body,
                    lambda: (
                        _execute_runtime("all", False) if kind == "full" else
                        _execute_runtime("all", True) if kind == "hardening" else
                        _run_regression() if kind == "regression" else
                        _run_redteam()
                    ),
                )
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
        except PermissionError as exc:
            self._send(403, {"success": False, "error": str(exc), "blocked_by": "layered_defence"})
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

    ui_check = live_surface.verify_ui_asset()
    if ui_check.get("state") != "passed":
        print("UI integrity verification failed; refusing to serve the console.", file=sys.stderr)
        return 5

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    url = f"http://{args.host}:{args.port}"
    print(f"AI-CYBER UI: {url}")
    # Run one real guarded preflight at startup. It never runs HYDRA, and failures remain visible in status.
    try:
        _guarded_operation("ui-startup-preflight", {"ui": "CYBER_OS_defence.html"}, lambda: {"success": True})
        with STATE_LOCK:
            STATE["runtime"] = "online"
        telemetry.emit("ui_preflight", "CYBER OS startup preflight passed the layered defence gate",
                       operation="ui", status="PASS", source="ui")
    except Exception as exc:
        with STATE_LOCK:
            STATE["runtime"] = "degraded"
        telemetry.error("ui-preflight", f"CYBER OS startup preflight blocked ({type(exc).__name__})")
    print("Scope: localhost-only; serving CYBER_OS_defence.html; all POST operations pass the layered defence gate.")
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
