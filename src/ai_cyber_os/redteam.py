"""Safe localhost-only AI-CYBER UI contract red-team."""
from __future__ import annotations

import json
from http.client import HTTPConnection
from threading import Thread
from typing import Any

from . import ui


def _call(server, method: str, path: str, body: Any = None, raw: bool = False):
    conn = HTTPConnection("127.0.0.1", server.server_port, timeout=30)
    try:
        data = body if raw else (
            None if body is None else json.dumps(body)
        )
        headers = {} if body is None or raw else {"Content-Type": "application/json"}
        conn.request(method, path, body=data, headers=headers)
        response = conn.getresponse()
        text = response.read().decode("utf-8", errors="replace")
        return response.status, text
    finally:
        conn.close()


def run() -> dict[str, Any]:
    server = ui.ThreadingHTTPServer(("127.0.0.1", 0), ui.Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    attacks = [
        ("unknown_fields", "POST", "/api/run",
         {"phase": "phase1", "admin": True}, False, {400}),
        ("hardening_type_confusion", "POST", "/api/run",
         {"phase": "phase1", "hardening": {"bypass": True}}, False, {400}),
        ("phase_type_confusion", "POST", "/api/run",
         {"phase": 1}, False, {400}),
        ("invalid_phase", "POST", "/api/run",
         {"phase": "phase999"}, False, {400}),
        ("privilege_looking_phase", "POST", "/api/run",
         {"phase": "all;admin;execute"}, False, {400}),
        ("oversized_request", "POST", "/api/run",
         b'{"phase":"' + b"A" * 20000 + b'"}', True, {400}),
        ("malformed_json", "POST", "/api/run",
         b'{"phase":"phase1"', True, {400}),
        ("unsupported_delete", "DELETE", "/api/run",
         None, False, {501}),
    ]
    results = []
    try:
        for name, method, path, body, raw, expected in attacks:
            status, response = _call(server, method, path, body, raw)
            results.append({
                "name": name,
                "status": status,
                "expected": sorted(expected),
                "blocked": status in expected,
                "response": response[:1000],
            })
        status, response = _call(server, "GET", "/api/status")
        try:
            state = json.loads(response)
        except json.JSONDecodeError:
            state = {}
        alive = status == 200 and state.get("runtime") == "online"
        return {
            "success": all(x["blocked"] for x in results) and alive,
            "attacks": results,
            "runtime_alive": alive,
            "post_status": state,
        }
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
