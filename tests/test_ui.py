from __future__ import annotations

import re

from fastapi.testclient import TestClient

from ai_cyber_os.api import SCHEMA_VERSION as API_SCHEMA_VERSION, create_app
from ai_cyber_os.backend import KnowledgeRAGBackend
from ai_cyber_os.situation import SituationStore
from ai_cyber_os.ui import APP_CSS, APP_JS, INDEX_HTML, SCHEMA_VERSION


def _client(tmp_path):
    backend = KnowledgeRAGBackend(tmp_path / "k.sqlite", tmp_path / "g.sqlite")
    situation = SituationStore(tmp_path / "s.sqlite")
    return TestClient(create_app(backend=backend, situation=situation))


def test_ui_routes_and_security_headers(tmp_path):
    with _client(tmp_path) as c:
        page = c.get("/ui")
        css = c.get("/ui/assets/app.css")
        js = c.get("/ui/assets/app.js")
    assert page.status_code == 200
    assert css.status_code == 200
    assert js.status_code == 200
    assert "text/html" in page.headers["content-type"]
    assert "text/css" in css.headers["content-type"]
    assert "javascript" in js.headers["content-type"]
    assert page.headers["content-security-policy"] == (
        "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; "
        "img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
    )
    assert page.headers["x-content-type-options"] == "nosniff"
    assert page.headers["referrer-policy"] == "no-referrer"
    assert page.headers["x-ai-cyber-ui-schema"] == SCHEMA_VERSION
    assert '<script defer src="/ui/assets/app.js"></script>' in page.text
    assert '<link rel="stylesheet" href="/ui/assets/app.css">' in page.text


def test_ui_has_no_external_runtime_dependencies_or_unsafe_dom_injection():
    assert "https://" not in INDEX_HTML
    assert "https://" not in APP_JS
    assert "http://" not in APP_JS
    assert "innerHTML" not in APP_JS
    assert "outerHTML" not in APP_JS
    assert "document.write" not in APP_JS
    assert "eval(" not in APP_JS
    assert "new Function(" not in APP_JS
    assert "textContent" in APP_JS


def test_ui_schema_does_not_duplicate_api_schema_contract():
    assert API_SCHEMA_VERSION == "ai_cyber_api.v1"
    assert SCHEMA_VERSION == "ai_cyber_ui.v1"


def test_ui_contains_core_operator_surfaces():
    for marker in (
        "Evidence retrieval",
        "Situation snapshot",
        "Command gateway",
        "/v1/knowledge/query",
        "/v1/telemetry/situation",
        "/v1/commands/execute",
    ):
        assert marker in INDEX_HTML + APP_JS
    assert re.search(r"Only exact pre-registered argv sets", APP_JS)
    assert re.search(r"approved argv", INDEX_HTML, re.I)
    assert "confirm(" in APP_JS
