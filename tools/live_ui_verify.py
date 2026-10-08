#!/usr/bin/env python3
"""Live-browser verification for the real AI-CYBER UI.

Starts the actual FastAPI/Uvicorn application with deterministic local test
data, then drives it through Chromium. The process is fail-closed: browser
errors, cross-origin requests, contract failures, or failed UI/backend actions
produce a non-zero exit code and a JSON report.
"""
from __future__ import annotations

import argparse
import json
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit


REPO = Path(__file__).resolve().parents[1]
GREEN_RECORD = {
    "record_id": "live-ui-record",
    "family": "vulnerability",
    "title": "Live UI verification evidence",
    "description": "Deterministic browser-verification evidence.",
    "cve_id": "CVE-2026-87654",
    "cwe_ids": ["CWE-79"],
    "capec_ids": [],
    "attack_ids": [],
    "cvss_score": 8.8,
    "cvss_vector": None,
    "severity": "HIGH",
    "evidence_refs": ["live-ui-test:evidence:1"],
    "related_record_ids": [],
    "source_dataset": "live-ui-test",
    "source_artifact": "browser.jsonl",
    "source_version": "1.0",
}
GREEN_EVENT = {
    "event_id": "live-ui-event",
    "event_type": "alert",
    "observed_at": "2026-10-08T10:00:00Z",
    "source": "live-ui-test",
    "severity": "HIGH",
    "subject_type": "asset",
    "subject_id": "live-ui-host",
    "payload": {"signal": "live-browser-verification"},
}
COMMAND_SCRIPT = "print('live-ui-green')"


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_http(url: str, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    last = ""
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                if response.status == 200:
                    return
        except (OSError, urllib.error.URLError) as exc:
            last = str(exc)
        time.sleep(0.25)
    raise RuntimeError(f"server did not become ready: {last}")


def serve(data_dir: Path, port: int) -> int:
    from ai_cyber_os.api import create_app
    from ai_cyber_os.backend import KnowledgeRAGBackend
    from ai_cyber_os.commands import CommandSpec, ControlledCommandGateway
    from ai_cyber_os.security_families import normalize_record
    from ai_cyber_os.situation import SituationStore, TelemetryEvent

    data_dir.mkdir(parents=True, exist_ok=True)
    backend = KnowledgeRAGBackend(
        data_dir / "knowledge.sqlite",
        data_dir / "relationships.sqlite",
    )
    backend.ingest_records([normalize_record(GREEN_RECORD)])

    situation = SituationStore(data_dir / "situation.sqlite")
    situation.ingest(TelemetryEvent(**GREEN_EVENT))

    gateway = ControlledCommandGateway(
        [
            CommandSpec(
                name="live-probe",
                executable=sys.executable,
                allowed_argv=(("-c", COMMAND_SCRIPT),),
                timeout_seconds=10,
                max_output_bytes=4096,
            )
        ],
        workspace_root=data_dir,
        audit_store=situation,
    )

    import uvicorn

    uvicorn.run(
        create_app(
            backend=backend,
            situation=situation,
            command_gateway=gateway,
        ),
        host="127.0.0.1",
        port=port,
        log_level="warning",
    )
    return 0


def browser_verify(base_url: str) -> dict:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise RuntimeError(
            "Playwright is required for live UI verification"
        ) from exc

    checks: list[dict] = []

    def record(name: str, ok: bool, detail: str = "") -> None:
        checks.append(
            {"name": name, "status": "PASS" if ok else "FAIL", "detail": detail}
        )
        if not ok:
            raise AssertionError(f"{name}: {detail}")

    expected_origin = urlsplit(base_url).scheme + "://" + urlsplit(base_url).netloc

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)

        for viewport_name, width, height in (
            ("desktop", 1440, 900),
            ("mobile", 390, 844),
        ):
            context = browser.new_context(
                viewport={"width": width, "height": height},
                locale="en-US",
            )
            console_errors: list[str] = []
            page_errors: list[str] = []
            cross_origin: list[str] = []

            page = context.new_page()
            page.on(
                "console",
                lambda msg: console_errors.append(msg.text)
                if msg.type == "error"
                else None,
            )
            page.on("pageerror", lambda exc: page_errors.append(str(exc)))

            def on_request(req) -> None:
                parsed = urlsplit(req.url)
                if parsed.scheme in {"http", "https"}:
                    origin = parsed.scheme + "://" + parsed.netloc
                    if origin != expected_origin:
                        cross_origin.append(req.url)

            page.on("request", on_request)

            response = page.goto(
                base_url.rstrip("/") + "/ui",
                wait_until="networkidle",
                timeout=30_000,
            )
            record(
                viewport_name + " UI HTTP 200",
                response is not None and response.status == 200,
            )
            headers = response.headers if response is not None else {}
            record(
                viewport_name + " security headers",
                headers.get("x-content-type-options") == "nosniff"
                and headers.get("referrer-policy") == "no-referrer"
                and headers.get("cache-control") == "no-store"
                and headers.get("x-ai-cyber-schema") == "ai_cyber_api.v1"
                and headers.get("x-ai-cyber-ui-schema") == "ai_cyber_ui.v1"
                and "default-src 'self'" in headers.get(
                    "content-security-policy", ""
                ),
            )

            record(
                viewport_name + " static assets loaded",
                page.locator('link[rel="stylesheet"]')
                .count() == 1
                and page.locator("script[src]").count() == 1,
            )
            record(
                viewport_name + " title",
                page.title() == "AI-CYBER Console",
            )
            page.locator("#system-status").wait_for(state="visible")
            record(
                viewport_name + " backend health rendered",
                page.locator("#system-status").inner_text()
                == "SYSTEM HEALTHY",
            )
            record(
                viewport_name + " seeded metrics",
                page.locator("#metric-knowledge").inner_text() == "1"
                and page.locator("#metric-telemetry").inner_text() == "1",
            )

            page.locator("#query").fill("CVE-2026-87654")
            page.locator("#query-form button[type=submit]").click()
            page.locator("#results .result-card").first.wait_for(
                timeout=15_000
            )
            result_text = page.locator("#results").inner_text()
            record(
                viewport_name + " evidence retrieval",
                "Live UI verification evidence" in result_text,
            )
            record(
                viewport_name + " evidence citation",
                "Citation:" in result_text,
            )

            page.locator("#subject-id").fill("live-ui-host")
            page.locator("#situation-form button[type=submit]").click()
            page.locator("#situation-output .result-card").wait_for(
                timeout=15_000
            )
            situation_text = page.locator("#situation-output").inner_text()
            record(
                viewport_name + " situation snapshot",
                "live-ui-host" in situation_text,
            )
            record(
                viewport_name + " evidence-only situation",
                "evidence-only" in situation_text,
            )

            page.once("dialog", lambda dialog: dialog.accept())
            page.locator("#command-form button[type=submit]").click()
            page.locator("#command-output .result-card").wait_for(
                timeout=15_000
            )
            command_text = page.locator("#command-output").inner_text()
            record(
                viewport_name + " approved command execution",
                "live-ui-green" in command_text,
            )

            resources = page.evaluate(
                "() => performance.getEntriesByType('resource').map(x => x.name)"
            )
            bad_resources = []
            for resource in resources:
                parsed = urlsplit(resource)
                if parsed.scheme in {"http", "https"}:
                    origin = parsed.scheme + "://" + parsed.netloc
                    if origin != expected_origin:
                        bad_resources.append(resource)
            record(
                viewport_name + " same-origin runtime resources",
                not bad_resources,
                str(bad_resources),
            )
            record(
                viewport_name + " no browser console errors",
                not console_errors,
                str(console_errors),
            )
            record(
                viewport_name + " no page errors",
                not page_errors,
                str(page_errors),
            )
            record(
                viewport_name + " no cross-origin requests",
                not cross_origin,
                str(cross_origin),
            )
            context.close()

        browser.close()

    return {
        "checks": checks,
        "passed": len(checks),
        "failed": 0,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url")
    parser.add_argument(
        "--report", type=Path, default=Path("live-ui-report.json")
    )
    parser.add_argument("--serve", action="store_true")
    parser.add_argument("--data-dir", type=Path)
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args()

    if args.serve:
        if args.data_dir is None or args.port <= 0:
            raise SystemExit("--serve requires --data-dir and --port")
        return serve(args.data_dir, args.port)

    started = datetime.now(timezone.utc)
    server = None
    try:
        with tempfile.TemporaryDirectory(
            prefix="ai-cyber-live-ui-"
        ) as td:
            data_dir = Path(td)
            port = free_port()
            base_url = args.base_url or f"http://127.0.0.1:{port}"
            server = subprocess.Popen(
                [
                    sys.executable,
                    str(Path(__file__).resolve()),
                    "--serve",
                    "--data-dir",
                    str(data_dir),
                    "--port",
                    str(port),
                ],
                cwd=REPO,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            wait_http(base_url + "/health")
            result = browser_verify(base_url)
            payload = {
                "schema_version": "ai_cyber.live_ui.v1",
                "result": "GREEN",
                "started_at": started.isoformat(),
                "finished_at": datetime.now(timezone.utc).isoformat(),
                **result,
            }
    except Exception as exc:
        payload = {
            "schema_version": "ai_cyber.live_ui.v1",
            "result": "FAIL",
            "started_at": started.isoformat(),
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "passed": 0,
            "failed": 1,
            "error": str(exc),
        }
        if server is not None and server.stderr:
            try:
                payload["server_stderr"] = server.stderr.read()[-8000:]
            except Exception:
                pass
    finally:
        if server is not None and server.poll() is None:
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=5)

    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "result": payload["result"],
                "report": str(args.report),
                "passed": payload.get("passed", 0),
            },
            sort_keys=True,
        )
    )
    return 0 if payload["result"] == "GREEN" else 1


if __name__ == "__main__":
    raise SystemExit(main())
