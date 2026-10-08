# Live UI Verification

Stage #12 verifies the currently implemented AI-CYBER operator UI through a real Uvicorn server and headless Chromium.

The live gate seeds one deterministic knowledge record, one telemetry event, and one explicitly allowlisted command. It then starts the real Uvicorn application and verifies the served UI in both desktop and mobile viewports:

- UI HTTP response and API/UI schema headers
- CSP, no-store, nosniff, and referrer policy
- CSS/JS asset loading
- backend health state rendered into the page
- knowledge retrieval and traceable citation rendering
- telemetry situation snapshot and evidence-only marker
- approved command execution through the #7 gateway
- same-origin runtime resource loading
- no browser console errors
- no page errors
- no cross-origin HTTP(S) requests

The server is created from the actual application factory; no mock frontend server is used.

A failure in any browser check returns a non-zero process exit and prevents the stage from being considered GREEN.

## Local command

After installing the package and Playwright/Chromium:

```bash
python tools/live_ui_verify.py --report live-ui-report.json
```

## CI

GitHub Actions workflow:

`.github/workflows/live-ui-verification.yml`
