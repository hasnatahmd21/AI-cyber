# Knowledge/RAG UI Integration

## Scope

#9 provides a local-first operator console over the verified #8 API. The UI is deliberately thin: it contains presentation and interaction code only, while retrieval, graph expansion, telemetry, integrity, and command policy remain owned by the backend components.

The console exposes three operator areas:

- Evidence retrieval — queries #5 through the #8 API and displays bounded hits with dataset/artifact/record identity, retrieval source, graph depth, and citations.
- Situation snapshot — queries #6 evidence-only snapshots for a selected subject and time window.
- Controlled operations — reads the #7 command catalog and only presents exact pre-registered argv sets. It never builds a shell command string.

## Same-origin security model

The UI is served by the same FastAPI application and calls relative /v1/... paths. There are no external scripts, stylesheets, fonts, images, analytics, or CDN dependencies.

The HTTP layer adds a restrictive Content Security Policy, disables MIME sniffing, sends a no-referrer policy, and uses no-store caching for the operator surface. CSS and JavaScript are served as separate local assets so the policy does not need inline script/style allowances.

Dynamic data is inserted with DOM textContent rather than HTML interpretation. Dataset strings, command output, telemetry payload values, and record titles therefore remain text.

## Command safety

The UI does not allow the operator to type arbitrary argv for execution. It loads the exact allowed_argv sets returned by #7 and submits the selected tuple unchanged to /v1/commands/execute. The #7 gateway remains the authoritative policy enforcement point.

The confirmation dialog is an additional operator check, not a security boundary.

## Trust model

The console presents retrieved records as evidence, not as newly inferred truth. Graph-expanded records retain their retrieval source and relationship path. Situation snapshots preserve evidence_only=true. No autonomous remediation, attacker attribution, or LLM generation is implemented in #9.

## Deployment

The default app remains local-first and can be served with:

    uvicorn --factory ai_cyber_os.api:create_default_app --host 127.0.0.1 --port 8000

Then open /ui.

For non-loopback exposure, authentication, authorization, network policy, TLS, and deployment hardening must be supplied by a later perimeter/deployment layer; this UI does not pretend to provide those controls.

## Test gate

The #9 CI suite compiles the UI/API surface, verifies the UI static security contract, exercises all #1–#8 regressions, checks the canonical runtime, and runs an integrated same-origin UI/API/command-catalog gate.
