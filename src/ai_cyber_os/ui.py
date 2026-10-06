"""Local operational UI for the canonical AI-Cyber runtime.

The UI is intentionally localhost-only and delegates all execution to HYDRA.
It does not contain cyber execution logic, shell execution, or alternate
security controls.
"""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse

from .hydra import run_final_hardening_verification, run_hydra_phase

HOST = "127.0.0.1"
PORT = 8765
VALID_PHASES = {"all", *{f"phase{i}" for i in range(1, 28)}}

HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AI-CYBER | HYDRA Operations</title>
<style>
body{margin:0;background:#0b0f14;color:#d7e0ea;font:14px ui-monospace,SFMono-Regular,Menlo,monospace}
header{padding:18px 22px;border-bottom:1px solid #27313c;background:#10161d}
h1{margin:0;font-size:20px} .sub{color:#8291a1;margin-top:5px}
main{padding:20px;max-width:1200px;margin:auto}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px}
.card{border:1px solid #27313c;background:#10161d;border-radius:8px;padding:15px}
.label{color:#8291a1;font-size:12px}.value{font-size:22px;margin-top:8px}
.ok{color:#74d99b}.bad{color:#ff7373}.warn{color:#f2c66d}
.controls{display:flex;gap:10px;flex-wrap:wrap;margin:18px 0}
select,button{background:#151d26;color:#d7e0ea;border:1px solid #34414e;border-radius:6px;padding:9px 12px}
button{cursor:pointer}button:hover{border-color:#74d99b}
pre{white-space:pre-wrap;overflow:auto;max-height:520px;background:#080b0f;border:1px solid #27313c;padding:14px;border-radius:8px}
.small{color:#8291a1;font-size:12px}
</style>
</head>
<body>
<header><h1>AI-CYBER / HYDRA OPERATIONS</h1><div class="sub">Local canonical runtime control surface · localhost only · no live cyber execution</div></header>
<main>
<div class="grid">
<div class="card"><div class="label">RUNTIME</div><div id="runtime" class="value">CHECKING…</div></div>
<div class="card"><div class="label">PHASES</div><div id="phases" class="value">—</div></div>
<div class="card"><div class="label">HARDENING</div><div id="hardening" class="value">—</div></div>
<div class="card"><div class="label">NETWORK</div><div class="value ok">LOCAL ONLY</div></div>
</div>
<div class="controls">
<select id="phase"></select>
<button onclick="runPhase()">Run selected phase</button>
<button onclick="runAll()">Run all + hardening</button>
<button onclick="refresh()">Refresh status</button>
</div>
<div class="small">Execution uses the canonical <code>run_hydra_phase()</code> and hardening verifier. Results below are live runtime results.</div>
<pre id="output">Ready.</pre>
</main>
<script>
const phase=document.getElementById('phase');
phase.innerHTML='<option value="all">all</option>'+Array.from({length:27},(_,i)=>'<option>phase'+(i+1)+'</option>').join('');
function show(x){document.getElementById('output').textContent=JSON.stringify(x,null,2)}
async function refresh(){
  const r=await fetch('/api/status'); const x=await r.json();
  document.getElementById('runtime').textContent=x.success?'HEALTHY':'FAILED';
  document.getElementById('runtime').className='value '+(x.success?'ok':'bad');
  document.getElementById('phases').textContent=x.phases??'—';
  document.getElementById('hardening').textContent=x.hardening_verified?'VERIFIED':'NOT VERIFIED';
  document.getElementById('hardening').className='value '+(x.hardening_verified?'ok':'warn');
  show(x);
}
async function runPhase(){
  show({status:'RUNNING',phase:phase.value});
  const r=await fetch('/api/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({phase:phase.value,hardening:false})});
  show(await r.json()); await refresh();
}
async function runAll(){
  show({status:'RUNNING',phase:'all',hardening:true});
  const r=await fetch('/api/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({phase:'all',hardening:true})});
  show(await r.json()); await refresh();
}
refresh();
</script>
</body>
</html>
"""


def _execute(phase: str, hardening: bool) -> dict[str, Any]:
    if phase not in VALID_PHASES:
        raise ValueError("invalid phase selector")
    result: dict[str, Any] = {"phase": phase}
    phase_result = run_hydra_phase(phase)
    result["phase_result"] = phase_result
    if hardening:
        result["hardening_result"] = run_final_hardening_verification()
    summary = phase_result.get("summary", {}) if isinstance(phase_result, dict) else {}
    result["success"] = summary.get("success") is True
    if hardening:
        result["success"] = result["success"] and result["hardening_result"].get("verified") is True
    return result


class Handler(BaseHTTPRequestHandler):
    server_version = "AI-CYBER-UI/1.0"

    def _send(self, status: int, payload: Any, content_type: str = "application/json") -> None:
        data = payload.encode("utf-8") if isinstance(payload, str) else json.dumps(payload, indent=2, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/":
            self._send(200, HTML, "text/html")
            return
        if path == "/api/status":
            try:
                result = _execute("all", True)
                summary = result["phase_result"].get("summary", {})
                hardening = result.get("hardening_result", {})
                self._send(200, {
                    "success": result["success"],
                    "phases": summary.get("phases"),
                    "auxiliary_checks": summary.get("auxiliary_checks"),
                    "hardening_verified": hardening.get("verified") is True,
                    "hardening_failed": hardening.get("failed"),
                    "network_scope": "localhost-only",
                })
            except Exception as exc:
                self._send(500, {"success": False, "error": f"{type(exc).__name__}: {exc}"})
            return
        self._send(404, {"error": "not found"})

    def do_POST(self) -> None:
        if urlparse(self.path).path != "/api/run":
            self._send(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length > 16_384:
                raise ValueError("request too large")
            body = json.loads(self.rfile.read(length) or b"{}")
            if not isinstance(body, dict):
                raise ValueError("JSON object required")
            result = _execute(str(body.get("phase", "all")), bool(body.get("hardening", False)))
            self._send(200 if result["success"] else 422, result)
        except Exception as exc:
            self._send(400, {"success": False, "error": f"{type(exc).__name__}: {exc}"})

    def log_message(self, fmt: str, *args: Any) -> None:
        return


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Local AI-Cyber HYDRA operations UI")
    parser.add_argument("--host", default=HOST, help="Bind address; localhost is the safe default.")
    parser.add_argument("--port", type=int, default=PORT)
    args = parser.parse_args(argv)
    if args.host not in {"127.0.0.1", "localhost", "::1"}:
        parser.error("UI is intentionally local-only; use 127.0.0.1/localhost/::1")
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
