from __future__ import annotations

import io
from pathlib import Path

import pytest

from scripts import kaggle_nvd_feed_readiness as readiness


class FakeResponse:
    def __init__(self, body: bytes, *, status: int, headers: dict[str, str]):
        self._stream = io.BytesIO(body)
        self.status = status
        self.headers = headers

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self._stream.close()

    def read(self, size: int = -1) -> bytes:
        return self._stream.read(size)

    def getcode(self) -> int:
        return self.status


def test_download_to_resumes_partial_feed_with_valid_range(monkeypatch, tmp_path: Path):
    target = tmp_path / "feed.json.gz"
    partial = target.with_name(target.name + ".part")
    partial.write_bytes(b"abc")
    calls = []

    def fake_urlopen(request, *, timeout):
        calls.append((request.get_header("Range"), timeout))
        return FakeResponse(
            b"def",
            status=206,
            headers={"Content-Range": "bytes 3-5/6", "Content-Length": "3"},
        )

    monkeypatch.setattr(readiness.urllib.request, "urlopen", fake_urlopen)
    readiness.download_to("https://example.invalid/feed.json.gz", target, retries=1, timeout=7)

    assert calls == [("bytes=3-", 7)]
    assert target.read_bytes() == b"abcdef"
    assert not partial.exists()


def test_download_to_restarts_when_server_ignores_range(monkeypatch, tmp_path: Path):
    target = tmp_path / "feed.json.gz"
    target.with_name(target.name + ".part").write_bytes(b"abc")
    calls = []

    def fake_urlopen(request, *, timeout):
        calls.append(request.get_header("Range"))
        # A server may ignore Range and return the entire representation with 200.
        return FakeResponse(b"abcdef", status=200, headers={"Content-Length": "6"})

    monkeypatch.setattr(readiness.urllib.request, "urlopen", fake_urlopen)
    readiness.download_to("https://example.invalid/feed.json.gz", target, retries=1)

    assert calls == ["bytes=3-"]
    assert target.read_bytes() == b"abcdef"
    assert target.stat().st_size == 6


def test_download_to_rejects_mismatched_content_range(monkeypatch, tmp_path: Path):
    target = tmp_path / "feed.json.gz"
    partial = target.with_name(target.name + ".part")
    partial.write_bytes(b"abc")

    def fake_urlopen(request, *, timeout):
        return FakeResponse(
            b"def",
            status=206,
            headers={"Content-Range": "bytes 2-4/6", "Content-Length": "3"},
        )

    monkeypatch.setattr(readiness.urllib.request, "urlopen", fake_urlopen)
    with pytest.raises(RuntimeError, match="download failed"):
        readiness.download_to("https://example.invalid/feed.json.gz", target, retries=1)

    assert not target.exists()
    assert partial.read_bytes() == b"abc"


def test_nvd_metadata_gets_short_bounded_timeout_but_feed_gets_resume_budget(monkeypatch, tmp_path: Path):
    calls = []

    def fake_download(url, target, *, retries=5, timeout=180):
        calls.append((url, retries, timeout))

    monkeypatch.setattr(readiness, "download_to", fake_download)
    readiness._download_nvd_source(
        "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2025.meta",
        tmp_path / "feed.meta",
    )
    readiness._download_nvd_source(
        "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2025.json.gz",
        tmp_path / "feed.json.gz",
    )

    assert [(row[1], row[2]) for row in calls] == [(2, 20), (5, 180)]
