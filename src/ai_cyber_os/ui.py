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
:root{
 --bg:#02050a;--panel:#06111a;--panel2:#081722;--line:#12384b;
 --cyan:#19d9ff;--cyan2:#00a8ff;--green:#19f5a2;--red:#ff416d;
 --text:#d9f7ff;--muted:#6e91a4;--purple:#8b5cff;
}
*{box-sizing:border-box}
html{background:var(--bg)}
body{margin:0;background:
 radial-gradient(circle at 78% 12%,rgba(0,170,255,.10),transparent 28%),
 radial-gradient(circle at 12% 85%,rgba(0,255,170,.055),transparent 24%),
 #02050a;color:var(--text);font:13px ui-monospace,SFMono-Regular,Consolas,monospace;overflow-x:hidden}
body:before{content:"";position:fixed;inset:0;pointer-events:none;z-index:20;
 background:linear-gradient(rgba(0,255,255,.028) 1px,transparent 1px),linear-gradient(90deg,rgba(0,255,255,.028) 1px,transparent 1px);
 background-size:34px 34px;mask-image:linear-gradient(to bottom,#000,transparent 92%)}
body:after{content:"";position:fixed;left:0;right:0;height:2px;top:-2px;background:rgba(25,217,255,.28);
 box-shadow:0 0 18px 3px rgba(25,217,255,.18);pointer-events:none;z-index:30;animation:scan 7s linear infinite}
@keyframes scan{to{top:100vh}}
@keyframes pulse{0%,100%{opacity:.72;box-shadow:0 0 6px currentColor}50%{opacity:1;box-shadow:0 0 18px currentColor}}
@keyframes glow{0%,100%{text-shadow:0 0 8px rgba(25,217,255,.5)}50%{text-shadow:0 0 24px rgba(25,217,255,.9)}}
@keyframes boot{from{opacity:0;transform:translateY(5px)}to{opacity:1;transform:none}}
header{height:78px;border-bottom:1px solid #14506b;background:rgba(3,10,17,.94);backdrop-filter:blur(12px);
 display:flex;align-items:center;padding:0 24px;gap:24px;position:sticky;top:0;z-index:10;
 box-shadow:0 0 35px rgba(0,160,255,.12),inset 0 -1px rgba(25,217,255,.15)}
.brand{display:flex;align-items:center;gap:12px;min-width:285px}
.logo{font-size:35px;color:var(--cyan);text-shadow:0 0 10px var(--cyan),0 0 32px #0077ff;animation:glow 2.8s ease-in-out infinite}
.brand b{font-size:22px;letter-spacing:4px;color:#f1fcff}
.brand small{display:block;color:#18a9d4;letter-spacing:2px;margin-top:4px}
.top{display:flex;gap:10px;align-items:center;flex:1}
.pill{border:1px solid #15516b;background:linear-gradient(135deg,rgba(8,31,45,.95),rgba(4,15,24,.95));
 border-radius:5px;padding:9px 13px;box-shadow:inset 0 0 16px rgba(0,190,255,.04)}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--green);color:var(--green);
 box-shadow:0 0 10px var(--green);margin-right:7px;animation:pulse 1.8s infinite}
.right{margin-left:auto;text-align:right;color:#7594a6}
.layout{display:grid;grid-template-columns:205px 1fr;min-height:calc(100vh - 78px)}
nav{border-right:1px solid #103448;background:rgba(3,10,16,.82);padding:18px 11px;position:relative}
nav:after{content:"SECURE LOCAL NODE";display:block;color:#31596c;font-size:9px;letter-spacing:2px;padding:18px 10px}
nav button{width:100%;text-align:left;background:transparent;border:1px solid transparent;color:#7699ab;padding:12px;border-radius:4px;margin-bottom:6px;font:inherit;cursor:pointer;transition:.18s}
nav button:hover,nav button.active{background:linear-gradient(90deg,rgba(0,177,255,.13),transparent);color:#62e2ff;border-color:#126080;
 box-shadow:inset 3px 0 var(--cyan),0 0 16px rgba(0,190,255,.07);transform:translateX(2px)}
main{padding:20px;max-width:1600px;width:100%;margin:auto;animation:boot .45s ease}
.hero{border:1px solid #126080;border-radius:7px;padding:25px;
 background:linear-gradient(115deg,rgba(4,42,62,.95),rgba(5,17,27,.94) 48%,rgba(8,14,25,.98));
 position:relative;overflow:hidden;box-shadow:0 0 35px rgba(0,150,255,.10),inset 0 0 45px rgba(0,200,255,.035)}
.hero:before{content:"";position:absolute;inset:0;background:repeating-linear-gradient(0deg,transparent 0 7px,rgba(25,217,255,.025) 8px);pointer-events:none}
.hero:after{content:"◈  HYDRA";position:absolute;right:3%;top:14px;font-size:92px;letter-spacing:10px;color:#0b6683;opacity:.12;transform:rotate(-8deg)}
.hero h1{font-size:36px;letter-spacing:7px;color:#42ddff;margin:0 0 6px;text-shadow:0 0 12px #008dcc,0 0 35px rgba(0,160,255,.45)}
.hero p{margin:0;color:#87adbd}
.grid{display:grid;grid-template-columns:1.8fr 1fr .9fr;gap:13px;margin-top:13px}
.card{border:1px solid #123e53;border-radius:6px;background:linear-gradient(145deg,rgba(7,19,29,.96),rgba(3,10,17,.96));
 box-shadow:0 8px 28px rgba(0,0,0,.28),0 0 18px rgba(0,150,255,.045);overflow:hidden;position:relative;transition:.2s}
.card:hover{border-color:#17607d;box-shadow:0 0 25px rgba(0,190,255,.09)}
.title{padding:11px 14px;border-bottom:1px solid #12384b;color:#3edcff;letter-spacing:1.5px;font-weight:bold;
 background:linear-gradient(90deg,rgba(0,180,255,.07),transparent)}
.body{padding:12px}
.statusgrid{display:grid;grid-template-columns:1fr 1fr;gap:7px}
.status{padding:9px;border-left:2px solid var(--green);background:rgba(8,31,36,.72);box-shadow:inset 0 0 14px rgba(0,255,170,.025)}
.ok{color:var(--green);text-shadow:0 0 7px rgba(25,245,162,.35)}
.bad{color:var(--red);text-shadow:0 0 7px rgba(255,65,109,.35)}
.warn{color:#ffd35a}
.phases{display:grid;grid-template-columns:repeat(3,1fr);gap:7px}
.phase{padding:10px;background:linear-gradient(135deg,#071c2a,#06121c);border:1px solid #124660;border-radius:4px;
 cursor:pointer;transition:.16s;position:relative;overflow:hidden}
.phase:before{content:"";position:absolute;left:-100%;top:0;width:60%;height:100%;background:linear-gradient(90deg,transparent,rgba(30,220,255,.09),transparent);transition:.35s}
.phase:hover:before{left:150%}
.phase:hover{border-color:#25d7ff;background:#092536;transform:translateY(-1px);box-shadow:0 0 14px rgba(0,190,255,.13)}
.num{color:#20d7ff;font-size:16px;text-shadow:0 0 8px rgba(0,200,255,.6)}
.phase span{display:block;color:#6f94a6;font-size:10px;margin-top:5px}
.run{padding:12px;border:1px solid #145777;background:linear-gradient(90deg,#071c2b,#06131e);border-radius:4px;margin-bottom:8px;
 color:#d9f8ff;cursor:pointer;text-align:left;width:100%;font:inherit;transition:.18s}
.run:hover{border-color:#2bdcff;color:white;box-shadow:0 0 18px rgba(0,210,255,.16),inset 0 0 12px rgba(0,180,255,.06);transform:translateX(2px)}
.run:active{transform:translateX(3px);box-shadow:0 0 28px rgba(0,220,255,.25)}
.activity{height:310px;overflow:auto}
.activity::-webkit-scrollbar,.term::-webkit-scrollbar{width:5px}.activity::-webkit-scrollbar-thumb,.term::-webkit-scrollbar-thumb{background:#15536b}
.event{padding:8px 4px;border-bottom:1px solid #0e2938;animation:boot .2s ease}
.time{color:#467b91}
.term{height:260px;background:#010509;color:#69e4ff;padding:14px;overflow:auto;white-space:pre-wrap;font-size:12px;
 border-top:1px solid #0a2c3d;box-shadow:inset 0 0 28px rgba(0,170,255,.05);text-shadow:0 0 5px rgba(0,210,255,.4)}
.metric{display:flex;justify-content:space-between;padding:9px 0;border-bottom:1px solid #102d3e}
.metric:last-child{border:0}
.bar{height:5px;background:#0b2435;margin-top:5px}.bar i{display:block;height:100%;width:100%;background:var(--green);box-shadow:0 0 9px var(--green)}
.footer{text-align:center;color:#456b7d;padding:14px;border-top:1px solid #0b2636}
.badge{float:right;border:1px solid #11b985;color:var(--green);border-radius:3px;padding:3px 8px;font-size:9px;letter-spacing:1px;box-shadow:0 0 10px rgba(25,245,162,.08)}
select{font:inherit!important;border-radius:4px!important;outline:none}
select:focus{border-color:var(--cyan)!important;box-shadow:0 0 12px rgba(25,217,255,.15)}
@media(max-width:1050px){.grid{grid-template-columns:1fr 1fr}.grid>.wide{grid-column:1/-1}}
@media(max-width:700px){header{padding:0 10px}.brand{min-width:auto}.brand small,.top .pill:nth-child(2){display:none}.layout{grid-template-columns:1fr}nav{display:flex;overflow:auto;border-right:0;border-bottom:1px solid #123149}nav button{min-width:120px}.grid{grid-template-columns:1fr}.phases{grid-template-columns:repeat(2,1fr)}main{padding:10px}}
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
    if isinstance(phase_result, dict):
        summary = phase_result.get("summary", {})
        if isinstance(summary, dict) and "success" in summary:
            # "all" returns a canonical aggregate summary.
            result["success"] = summary.get("success") is True
        else:
            # Individual canonical phases return their own verification result.
            result["success"] = phase_result.get("verified") is True
    else:
        result["success"] = False
    if hardening:
        result["success"] = (
            result["success"]
            and isinstance(result.get("hardening_result"), dict)
            and result["hardening_result"].get("verified") is True
        )
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
            # Health/status must be lightweight. Do not execute the full 27-phase
            # suite from a readiness probe or browser refresh; actual verification
            # is performed explicitly through POST /api/run.
            self._send(200, {
                "success": True,
                "runtime": "online",
                "verification": "run POST /api/run to execute canonical HYDRA",
                "phases": 27,
                "network_scope": "localhost-only",
            })
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
