"""Local-first Knowledge/RAG operator UI assets.

The UI is a thin same-origin client for the #8 API. It contains no backend
logic, no external asset/CDN dependency, and no arbitrary command construction.
"""
from __future__ import annotations

SCHEMA_VERSION = "ai_cyber_ui.v1"

INDEX_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="dark">
  <meta name="description" content="AI-CYBER local-first security intelligence console">
  <title>AI-CYBER Console</title>
  <link rel="stylesheet" href="/ui/assets/app.css">
  <script defer src="/ui/assets/app.js"></script>
</head>
<body>
  <header class="topbar">
    <div>
      <div class="eyebrow">LOCAL-FIRST SECURITY INTELLIGENCE</div>
      <h1>AI-CYBER Console</h1>
      <p class="subtitle">Evidence retrieval, connected knowledge, telemetry, and policy-bound operations.</p>
    </div>
    <div id="system-status" class="status status-pending" aria-live="polite">Checking system…</div>
  </header>

  <main class="shell">
    <section class="grid grid-3">
      <article class="panel metric"><span>Schema</span><strong id="metric-schema">—</strong></article>
      <article class="panel metric"><span>Knowledge records</span><strong id="metric-knowledge">—</strong></article>
      <article class="panel metric"><span>Telemetry events</span><strong id="metric-telemetry">—</strong></article>
    </section>

    <section class="grid grid-main">
      <article class="panel">
        <div class="panel-head">
          <div>
            <div class="eyebrow">KNOWLEDGE</div>
            <h2>Evidence retrieval</h2>
          </div>
          <div id="query-meta" class="muted">No query yet.</div>
        </div>

        <form id="query-form" class="stack">
          <label for="query">Query</label>
          <div class="query-row">
            <input id="query" name="query" autocomplete="off" required maxlength="4096"
                   placeholder="Search vulnerabilities, weaknesses, attacks, evidence…">
            <button type="submit">Retrieve</button>
          </div>
          <div class="controls">
            <label>Top K <input id="top-k" type="number" min="1" max="100" value="5"></label>
            <label>Graph depth <input id="graph-depth" type="number" min="0" max="8" value="3"></label>
            <label>Graph limit <input id="graph-limit" type="number" min="1" max="5000" value="100"></label>
            <label>Context chars <input id="context-limit" type="number" min="256" max="1000000" value="12000"></label>
          </div>
        </form>

        <div id="query-error" class="notice error" hidden></div>
        <div id="results" class="results" aria-live="polite">
          <div class="empty">Run a retrieval query to see traceable evidence.</div>
        </div>
      </article>

      <aside class="stack">
        <article class="panel">
          <div class="panel-head">
            <div>
              <div class="eyebrow">TELEMETRY</div>
              <h2>Situation snapshot</h2>
            </div>
          </div>
          <form id="situation-form" class="stack compact">
            <label>Subject type
              <select id="subject-type">
                <option value="asset">asset</option>
                <option value="user">user</option>
                <option value="process">process</option>
                <option value="ip">ip</option>
                <option value="domain">domain</option>
                <option value="account">account</option>
                <option value="service">service</option>
                <option value="session">session</option>
                <option value="other">other</option>
              </select>
            </label>
            <label>Subject ID <input id="subject-id" maxlength="512" placeholder="host-01"></label>
            <div class="two">
              <label>Start <input id="start" value="2026-01-01T00:00:00Z"></label>
              <label>End <input id="end" value="2027-01-01T00:00:00Z"></label>
            </div>
            <button type="submit" class="secondary">Load situation</button>
          </form>
          <div id="situation-output" class="results">
            <div class="empty">No situation loaded.</div>
          </div>
        </article>

        <article class="panel">
          <div class="panel-head">
            <div>
              <div class="eyebrow">CONTROLLED OPERATIONS</div>
              <h2>Command gateway</h2>
            </div>
          </div>
          <div id="command-boundary" class="notice">
            Commands are available only when an explicitly injected #7 gateway is enabled.
          </div>
          <form id="command-form" class="stack compact" hidden>
            <label>Approved command
              <select id="command-name"></select>
            </label>
            <label>Exact approved argv
              <select id="command-argv"></select>
            </label>
            <button type="submit" class="danger">Execute approved command</button>
          </form>
          <div id="command-output" class="results">
            <div class="empty">No command execution.</div>
          </div>
        </article>
      </aside>
    </section>
  </main>

  <footer class="footer">
    <span>AI-CYBER UI <code>ai_cyber_ui.v1</code></span>
    <span>Same-origin • evidence-preserving • no external assets</span>
  </footer>
</body>
</html>
"""

APP_CSS = r"""
:root {
  color-scheme: dark;
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  --bg:#070b12; --panel:#0e1520; --panel-2:#111c29; --text:#e6edf7;
  --muted:#8fa1b7; --border:#223044; --accent:#66d9ef; --good:#71e5a3;
  --bad:#ff7b8b; --shadow:0 12px 30px rgba(0,0,0,.25);
}
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--text); line-height:1.5; }
.topbar { display:flex; justify-content:space-between; gap:24px; align-items:flex-start; padding:28px 4vw 22px; border-bottom:1px solid var(--border); background:linear-gradient(180deg,#0a1019,#080d15); }
h1,h2,p { margin:0; } h1 { font-size:clamp(1.7rem,3vw,2.5rem); letter-spacing:-.04em; }
h2 { font-size:1.05rem; margin-top:3px; } .subtitle { color:var(--muted); max-width:760px; margin-top:7px; }
.eyebrow { color:var(--accent); font-size:.7rem; font-weight:800; letter-spacing:.14em; }
.shell { max-width:1500px; margin:0 auto; padding:22px 4vw 40px; }
.grid { display:grid; gap:16px; } .grid-3 { grid-template-columns:repeat(3,minmax(0,1fr)); }
.grid-main { grid-template-columns:minmax(0,1.8fr) minmax(320px,.85fr); align-items:start; margin-top:16px; }
.panel { background:var(--panel); border:1px solid var(--border); border-radius:14px; box-shadow:var(--shadow); padding:18px; }
.metric { display:flex; flex-direction:column; gap:5px; } .metric span,.muted { color:var(--muted); font-size:.82rem; }
.metric strong { font-size:1.2rem; } .panel-head { display:flex; justify-content:space-between; gap:16px; align-items:flex-start; margin-bottom:16px; }
.stack { display:flex; flex-direction:column; gap:12px; } .compact { gap:9px; }
label { color:var(--muted); font-size:.82rem; } input,select,button { width:100%; border-radius:10px; border:1px solid var(--border); font:inherit; }
input,select { background:var(--panel-2); color:var(--text); padding:10px 11px; margin-top:5px; outline:none; }
input:focus,select:focus { border-color:var(--accent); } button { background:var(--text); color:#09111d; padding:10px 14px; cursor:pointer; font-weight:800; }
button.secondary { background:var(--panel-2); color:var(--text); } button.danger { background:rgba(255,123,139,.12); color:#ffb3bd; border-color:rgba(255,123,139,.4); }
.query-row { display:grid; grid-template-columns:1fr auto; gap:10px; } .query-row button { width:auto; min-width:130px; }
.controls { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:10px; } .two { display:grid; grid-template-columns:1fr 1fr; gap:9px; }
.results { display:flex; flex-direction:column; gap:10px; margin-top:16px; } .empty { color:var(--muted); border:1px dashed var(--border); border-radius:10px; padding:15px; }
.result-card { border:1px solid var(--border); border-radius:11px; padding:14px; background:#0b121b; }
.result-title { font-weight:800; margin-bottom:5px; } .result-meta { display:flex; flex-wrap:wrap; gap:7px; margin-bottom:8px; }
.chip { border:1px solid var(--border); border-radius:999px; padding:2px 8px; color:var(--muted); font-size:.72rem; }
.result-body { color:#c8d3e2; white-space:pre-wrap; overflow-wrap:anywhere; }
.citation { font-size:.76rem; color:var(--accent); margin-top:9px; }
.notice { border:1px solid var(--border); border-radius:10px; padding:10px 12px; color:var(--muted); background:#0a111a; font-size:.82rem; }
.notice.error { border-color:rgba(255,123,139,.35); color:#ffb3bd; }
.status { border-radius:999px; padding:7px 12px; font-size:.75rem; font-weight:800; white-space:nowrap; }
.status-pending { background:#141d28; color:var(--muted); } .status-good { background:rgba(113,229,163,.12); color:var(--good); }
.status-bad { background:rgba(255,123,139,.12); color:var(--bad); }
.footer { display:flex; justify-content:space-between; gap:12px; color:var(--muted); border-top:1px solid var(--border); padding:14px 4vw 22px; font-size:.72rem; }
code { color:var(--accent); } @media (max-width:980px) { .grid-main { grid-template-columns:1fr; } }
@media (max-width:720px) { .grid-3,.controls { grid-template-columns:1fr 1fr; } .topbar { flex-direction:column; } .query-row,.two { grid-template-columns:1fr; } .footer { flex-direction:column; } }
"""

APP_JS = r"""
const state = { commands: [] };

function el(id) { return document.getElementById(id); }

function setStatus(ok, text) {
  const node = el("system-status");
  node.textContent = text;
  node.className = "status " + (ok ? "status-good" : "status-bad");
}

function showError(targetId, message) {
  const node = el(targetId);
  node.hidden = false;
  node.textContent = message;
}

function clearError(targetId) {
  const node = el(targetId);
  node.hidden = true;
  node.textContent = "";
}

async function requestJson(url, options = {}) {
  const response = await fetch(url, {
    ...options,
    headers: { "Accept": "application/json", ...(options.headers || {}) },
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detail = body.detail || body;
    throw new Error(detail.error || detail.message || ("HTTP " + response.status));
  }
  return body;
}

function addText(parent, tag, text, className = "") {
  const node = document.createElement(tag);
  node.textContent = String(text ?? "");
  if (className) node.className = className;
  parent.appendChild(node);
  return node;
}

function addChip(parent, text) { addText(parent, "span", text, "chip"); }

function renderQuery(packet) {
  const target = el("results");
  target.replaceChildren();
  if (!packet.hits || packet.hits.length === 0) {
    addText(target, "div", "No evidence matched this query.", "empty");
    el("query-meta").textContent = "0 hits";
    return;
  }

  el("query-meta").textContent =
    packet.hits.length + " bounded hits • " + (packet.graph_expanded_hits || 0) + " graph-expanded";

  for (const hit of packet.hits) {
    const card = addText(target, "article", "", "result-card");
    addText(card, "div", hit.title || hit.record_id || "Untitled evidence", "result-title");
    const meta = addText(card, "div", "", "result-meta");
    addChip(meta, hit.retrieval_source || "retrieval");
    if (hit.dataset_id) addChip(meta, hit.dataset_id);
    if (hit.artifact_path) addChip(meta, hit.artifact_path);
    if (hit.record_id) addChip(meta, hit.record_id);
    if (hit.graph_depth !== undefined) addChip(meta, "depth " + hit.graph_depth);
    addText(card, "div", hit.snippet || JSON.stringify(hit.payload || hit, null, 2), "result-body");
    const cite = Array.isArray(packet.citations)
      ? packet.citations.find(c => c.doc_id === hit.doc_id)
      : null;
    if (cite) addText(card, "div", "Citation: " + JSON.stringify(cite), "citation");
  }
}

async function loadHealth() {
  try {
    const body = await requestJson("/health");
    setStatus(true, "SYSTEM HEALTHY");
    el("metric-schema").textContent = body.schema_version || "—";
    el("metric-knowledge").textContent = body.backend?.knowledge_records ?? "—";
    el("metric-telemetry").textContent = body.situation?.event_count ?? "—";
    await loadCommands();
  } catch (error) {
    setStatus(false, "SYSTEM DEGRADED");
    showError("query-error", error.message);
  }
}

async function loadCommands() {
  const body = await requestJson("/v1/commands");
  state.commands = body.commands || [];
  const form = el("command-form");
  const boundary = el("command-boundary");
  const select = el("command-name");
  select.replaceChildren();

  if (!body.enabled || state.commands.length === 0) {
    form.hidden = true;
    boundary.textContent = body.enabled
      ? "Gateway is enabled but no commands are registered."
      : "Command execution is disabled. Inject an explicit #7 gateway to enable policy-bound execution.";
    return;
  }

  form.hidden = false;
  boundary.textContent = "Only exact pre-registered argv sets from the #7 gateway can be executed.";
  for (const spec of state.commands) {
    const option = document.createElement("option");
    option.value = spec.name;
    option.textContent = spec.name + " • " + spec.executable;
    select.appendChild(option);
  }
  updateArgvChoices();
}

function updateArgvChoices() {
  const selected = state.commands.find(x => x.name === el("command-name").value);
  const target = el("command-argv");
  target.replaceChildren();
  for (const argv of (selected?.allowed_argv || [])) {
    const option = document.createElement("option");
    option.value = JSON.stringify(argv);
    option.textContent = argv.length ? argv.join("  ") : "(no arguments)";
    target.appendChild(option);
  }
}

el("query-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  clearError("query-error");
  try {
    const params = new URLSearchParams({
      q: el("query").value,
      top_k: el("top-k").value,
      graph_depth: el("graph-depth").value,
      graph_limit: el("graph-limit").value,
      max_context_chars: el("context-limit").value,
    });
    renderQuery(await requestJson("/v1/knowledge/query?" + params));
  } catch (error) {
    showError("query-error", error.message);
  }
});

el("situation-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const out = el("situation-output");
  out.replaceChildren();
  try {
    const params = new URLSearchParams({
      subject_type: el("subject-type").value,
      subject_id: el("subject-id").value,
      start: el("start").value,
      end: el("end").value,
      limit: "500",
    });
    const body = await requestJson("/v1/telemetry/situation?" + params);
    const card = addText(out, "article", "", "result-card");
    addText(card, "div", body.subject_type + ":" + body.subject_id, "result-title");
    const meta = addText(card, "div", "", "result-meta");
    addChip(meta, body.event_count + " events");
    addChip(meta, body.evidence_only ? "evidence-only" : "review");
    addText(card, "div",
      "Severity counts: " + JSON.stringify(body.severity_counts) +
      "\nEvent types: " + JSON.stringify(body.event_type_counts),
      "result-body");
    addText(card, "div", "Latest observed: " + (body.latest_event_at || "none"), "citation");
  } catch (error) {
    addText(out, "div", error.message, "notice error");
  }
});

el("command-name").addEventListener("change", updateArgvChoices);

el("command-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const out = el("command-output");
  out.replaceChildren();
  const selected = el("command-name").value;
  const argv = JSON.parse(el("command-argv").value || "[]");
  if (!confirm("Execute approved command \"" + selected + "\" with exact argv?\n\n" + argv.join(" "))) {
    addText(out, "div", "Execution cancelled by operator.", "empty");
    return;
  }
  try {
    const body = await requestJson("/v1/commands/execute", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ command_name: selected, argv }),
    });
    const card = addText(out, "article", "", "result-card");
    addText(card, "div", body.command_name + " • " + body.status, "result-title");
    addText(card, "div", JSON.stringify({
      request_id: body.request_id,
      returncode: body.returncode,
      duration_ms: body.duration_ms,
      stdout: body.stdout,
      stderr: body.stderr,
      audited: body.audit_event_ids?.length > 0,
    }, null, 2), "result-body");
  } catch (error) {
    addText(out, "div", error.message, "notice error");
  }
});

loadHealth();
"""
