from __future__ import annotations

import importlib.util
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "build_permanent_knowledge_db.py"
SPEC = importlib.util.spec_from_file_location("knowledge_db_builder", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

PAYLOAD = bytes((i % 251 for i in range(64 * 1024 + 37)))


class RangeHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def do_GET(self):
        server = self.server
        server.calls += 1
        range_header = self.headers.get("Range")
        if server.ignore_range:
            self.send_response(200)
            self.send_header("Content-Length", str(len(PAYLOAD)))
            self.end_headers()
            self.wfile.write(PAYLOAD)
            return
        if not range_header:
            self.send_response(200)
            self.send_header("Content-Length", str(len(PAYLOAD)))
            self.end_headers()
            self.wfile.write(PAYLOAD[:8192])
            self.wfile.flush()
            self.close_connection = True
            return
        start = int(range_header.removeprefix("bytes=").split("-", 1)[0])
        body = PAYLOAD[start:]
        self.send_response(206)
        self.send_header("Content-Range", f"bytes {start}-{len(PAYLOAD)-1}/{len(PAYLOAD)}")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


def serve(ignore_range=False):
    server = ThreadingHTTPServer(("127.0.0.1", 0), RangeHandler)
    server.calls = 0
    server.ignore_range = ignore_range
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, f"http://127.0.0.1:{server.server_port}/feed"


def test_resumes_truncated_http_transfer(tmp_path: Path):
    server, thread, url = serve()
    try:
        target = tmp_path / "feed.bin"
        MODULE.resumable_download_to(url, target, retries=3, timeout=5)
        assert target.read_bytes() == PAYLOAD
        assert not target.with_name(target.name + ".part").exists()
        assert server.calls >= 2
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_server_ignoring_range_restarts_without_duplicate_append(tmp_path: Path):
    server, thread, url = serve(ignore_range=True)
    try:
        target = tmp_path / "feed.bin"
        target.with_name(target.name + ".part").write_bytes(PAYLOAD[:777])
        MODULE.resumable_download_to(url, target, retries=2, timeout=5)
        assert target.read_bytes() == PAYLOAD
        assert not target.with_name(target.name + ".part").exists()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

def test_nvd_metadata_download_uses_short_bounded_timeout(monkeypatch, tmp_path: Path):
    calls = []

    def fake_download(url, target, *, retries=5, timeout=180):
        calls.append((url, target, retries, timeout))

    monkeypatch.setattr(MODULE, "resumable_download_to", fake_download)
    MODULE._nvd_download_to("https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2025.meta",
                            tmp_path / "feed.meta")
    MODULE._nvd_download_to("https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2025.json.gz",
                            tmp_path / "feed.json.gz")

    assert [(item[2], item[3]) for item in calls] == [(2, 20), (5, 180)]

