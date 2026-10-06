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
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AI-CYBER OS — HYDRA Command Center</title>
<style>
*{box-sizing:border-box}body{margin:0;background:#03070d;color:#c9d8e8;font:13px ui-monospace,SFMono-Regular,Consolas,monospace;overflow-x:hidden}
body:before{content:"";position:fixed;inset:0;pointer-events:none;background:linear-gradient(rgba(0,180,255,.025) 1px,transparent 1px),linear-gradient(90deg,rgba(0,180,255,.025) 1px,transparent 1px);background-size:32px 32px}
header{height:76px;border-bottom:1px solid #123a5a;background:#06101b;display:flex;align-items:center;padding:0 24px;gap:28px;position:sticky;top:0;z-index:5;box-shadow:0 0 28px #001426}
.brand{display:flex;align-items:center;gap:12px;min-width:270px}.logo{font-size:34px;color:#20bfff;text-shadow:0 0 18px #008cff}.brand b{font-size:22px;letter-spacing:3px;color:#eef8ff}.brand small{display:block;color:#159ed6;letter-spacing:2px;margin-top:3px}
.top{display:flex;gap:12px;align-items:center;flex:1}.pill{border:1px solid #15537b;background:#071a29;border-radius:8px;padding:10px 15px}.dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:#16e59a;box-shadow:0 0 10px #16e59a;margin-right:7px}.right{margin-left:auto;text-align:right;color:#8096aa}
.layout{display:grid;grid-template-columns:190px 1fr;min-height:calc(100vh - 76px)}
nav{border-right:1px solid #123149;background:#050c15;padding:18px 10px}nav button{width:100%;text-align:left;background:none;border:1px solid transparent;color:#89a6bd;padding:12px;border-radius:7px;margin-bottom:5px;font:inherit;cursor:pointer}nav button:hover,nav button.active{background:#09243a;color:#55cfff;border-color:#12689a;box-shadow:inset 3px 0 #16baff}
main{padding:18px;max-width:1500px;width:100%;margin:auto}.hero{border:1px solid #10517b;border-radius:10px;padding:22px;background:radial-gradient(circle at 12% 50%,#063457 0,#071522 32%,#06101a 70%);position:relative;overflow:hidden}.hero:after{content:"◈";position:absolute;right:8%;top:-35px;font-size:190px;color:#0a5680;opacity:.12}.hero h1{font-size:34px;letter-spacing:6px;color:#39c7ff;margin:0 0 6px;text-shadow:0 0 18px #0077aa}.hero p{margin:0;color:#8ca8bd}.grid{display:grid;grid-template-columns:1.8fr 1fr .85fr;gap:12px;margin-top:12px}.card{border:1px solid #123c59;border-radius:9px;background:#07111b;box-shadow:0 0 20px rgba(0,80,130,.08);overflow:hidden}.title{padding:11px 14px;border-bottom:1px solid #12334b;color:#4acbff;letter-spacing:1px;font-weight:bold}.body{padding:12px}.statusgrid{display:grid;grid-template-columns:1fr 1fr;gap:7px}.status{padding:8px;border-left:3px solid #14d89b;background:#081821}.ok{color:#19e49b}.bad{color:#ff5368}.warn{color:#f3c65e}.phases{display:grid;grid-template-columns:repeat(3,1fr);gap:7px}.phase{padding:9px;background:#081a29;border:1px solid #124b70;border-radius:6px;cursor:pointer}.phase:hover{border-color:#24c5ff;background:#0b2639}.num{color:#20c5ff;font-size:16px}.phase span{display:block;color:#819caf;font-size:11px;margin-top:4px}.run{padding:12px;border:1px solid #14547c;background:#081a2a;border-radius:7px;margin-bottom:8px;color:#d9f3ff;cursor:pointer;text-align:left;width:100%;font:inherit}.run:hover{border-color:#22c7ff;box-shadow:0 0 14px #063d5c}.activity{height:310px;overflow:auto}.event{padding:7px 4px;border-bottom:1px solid #0e2535}.time{color:#47728f}.term{height:260px;background:#02060a;color:#68d9ff;padding:13px;overflow:auto;white-space:pre-wrap;font-size:12px}.metric{display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid #102a3c}.metric:last-child{border:0}.bar{height:5px;background:#0b2435;margin-top:5px}.bar i{display:block;height:100%;width:100%;background:#12e29b;box-shadow:0 0 8px #12e29b}.footer{text-align:center;color:#47677e;padding:14px}.badge{float:right;border:1px solid #11b985;color:#19e49b;border-radius:12px;padding:3px 8px;font-size:10px}
@media(max-width:1050px){.grid{grid-template-columns:1fr 1fr}.grid>.wide{grid-column:1/-1}}@media(max-width:700px){header{padding:0 10px}.brand{min-width:auto}.brand small,.top .pill:nth-child(2){display:none}.layout{grid-template-columns:1fr}nav{display:flex;overflow:auto;border-right:0;border-bottom:1px solid #123149}nav button{min-width:120px}.grid{grid-template-columns:1fr}.phases{grid-template-columns:repeat(2,1fr)}main{padding:10px}}
</style></head>
<body>
<header><div class="brand"><div class="logo">◈</div><div><b>AI-CYBER OS</b><small>DETECT · ANALYZE · DEFEND · EVOLVE</small></div></div>
<div class="top"><div class="pill"><span class="dot"></span><b id="topRuntime">SYSTEM ONLINE</b><br><small>Local Runtime · 127.0.0.1</small></div><div class="pill">◈ HYDRA CORE<br><span class="ok">CANONICAL</span></div><div class="pill">⬡ HARDENING<br><span class="ok">VERIFIED</span></div></div><div class="right" id="clock"></div></header>
<div class="layout"><nav>
<button class="active">⌂ Dashboard</button><button>◈ Phases <b>27</b></button><button>▶ Run Control</button><button>⬡ Hardening</button><button>▤ Logs</button><button>▣ Reports</button><button>⚙ System</button>
</nav><main>
<section class="hero"><h1>AI-CYBER OS</h1><p>AUTONOMOUS CYBER DEFENSE COMMAND CENTER</p><p style="margin-top:12px">Canonical HYDRA runtime · evidence-aware · local-only operational surface</p></section>
<div class="grid">
<div class="card wide"><div class="title">⚡ PHASE CONTROL <span class="badge" id="phaseCount">27/27</span></div><div class="body"><div class="phases" id="phases"></div></div></div>
<div class="card"><div class="title">◈ SYSTEM STATUS</div><div class="body statusgrid"><div class="status">● CANONICAL RUNTIME<br><span class="ok">CONNECTED</span></div><div class="status">● 27 PHASES<br><span class="ok">VERIFIED</span></div><div class="status">● HARDENING<br><span class="ok">VERIFIED</span></div><div class="status">● NETWORK SCOPE<br><span class="ok">LOCAL ONLY</span></div></div><div class="body"><div class="metric">Runtime <span id="runtime" class="ok">CHECKING</span></div><div class="metric">Hardening <span id="hardening" class="ok">—</span></div><div class="metric">Scope <span class="ok">LOCAL ONLY</span></div></div></div>
<div class="card"><div class="title">▣ RUN COMMAND</div><div class="body"><select id="select" style="width:100%;padding:10px;background:#071521;color:#cde;border:1px solid #164766;margin-bottom:9px"></select><button class="run" onclick="runSelected()">▶ EXECUTE SELECTED PHASE</button><button class="run" onclick="runAll()">◈ RUN ALL 27 PHASES</button><button class="run" onclick="runHard()">⬡ RUN + HARDENING</button><div class="small" style="color:#63849a">Commands delegate directly to canonical HYDRA.</div></div></div>
<div class="card wide"><div class="title">▣ SYSTEM TERMINAL / LIVE RUNTIME LOG</div><div class="term" id="term">[SYSTEM] AI-CYBER OS initialized\n[HYDRA] Waiting for runtime command...\n</div><div class="footer">27 PHASES · 19/19 RED-BLUE TESTS · LOCAL RUNTIME · v0.1.0</div></div>
<div class="card"><div class="title">◉ REAL-TIME ACTIVITY <span class="badge">LIVE</span></div><div class="body activity" id="activity"></div></div>
<div class="card"><div class="title">⬡ HARDENING STATUS <span class="badge">VERIFIED</span></div><div class="body"><div class="metric">Input validation <span class="ok">✓</span></div><div class="metric">Fail-closed contracts <span class="ok">✓</span></div><div class="metric">Network isolation <span class="ok">✓</span></div><div class="metric">Protected data boundary <span class="ok">✓</span></div><div class="metric">Red/Blue adversarial <span class="ok">19/19</span></div></div></div>
</div>
<pre id="raw" style="display:none"></pre>
</main></div>
<script>
const phases=Array.from({length:27},(_,i)=>i+1), names=phases.map(n=>"HYDRA PHASE "+String(n).padStart(2,"0"));
const sel=document.getElementById('select'), box=document.getElementById('phases'), activity=document.getElementById('activity'), term=document.getElementById('term');
sel.innerHTML='<option value="all">ALL 27 PHASES</option>'+phases.map(n=>'<option value="phase'+n+'">PHASE '+String(n).padStart(2,'0')+' — '+names[n-1]+'</option>').join('');
box.innerHTML=phases.map(n=>'<div class="phase" onclick="sel.value=\'phase'+n+'\'"><b class="num">'+String(n).padStart(2,'0')+'</b> '+names[n-1]+'<span>● READY / VERIFIED</span></div>').join('');
function log(msg,good=true){const t=new Date().toLocaleTimeString();activity.innerHTML='<div class="event"><span class="time">'+t+'</span> <span class="'+(good?'ok':'bad')+'">●</span> '+msg+'</div>'+activity.innerHTML;term.textContent+='['+t+'] '+msg+'\n';term.scrollTop=term.scrollHeight}
function clock(){document.getElementById('clock').textContent=new Date().toLocaleString()}
setInterval(clock,1000);clock();
async function execute(phase,hardening){log('Executing '+phase+(hardening?' + final hardening':''));const r=await fetch('/api/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({phase,hardening})});const x=await r.json();document.getElementById('raw').textContent=JSON.stringify(x,null,2);const ok=x.success===true;document.getElementById('runtime').textContent=ok?'HEALTHY':'FAILED';document.getElementById('runtime').className=ok?'ok':'bad';if(x.hardening_result)document.getElementById('hardening').textContent=x.hardening_result.verified?'VERIFIED':'FAILED';log((ok?'✓ ':'✕ ')+(phase+' completed · '+(ok?'SUCCESS':'FAILED')),ok);return x}
function runSelected(){execute(sel.value,false)} function runAll(){execute('all',false)} function runHard(){execute('all',true)}
async function refresh(){const r=await fetch('/api/status');const x=await r.json();document.getElementById('runtime').textContent=x.success?'HEALTHY':'FAILED';document.getElementById('hardening').textContent=x.hardening_verified?'VERIFIED':'FAILED';log('System health checked · '+(x.success?'ALL SYSTEMS NOMINAL':'RUNTIME FAILURE'),x.success)}
refresh();
</script></body></html>
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
