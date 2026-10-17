from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from tools import kaggle_acquire_datasets as runner


def verified_manifest() -> dict:
    return {
        "manifest_format": 1,
        "dataset": "nvd_cve",
        "version": "NVD-2.0-snapshot-test",
        "source": "NIST National Vulnerability Database (NVD)",
        "source_uri": "https://nvd.nist.gov/vuln/data-feeds",
        "license": "NVD data feed terms; preserve source attribution",
        "license_basis": "Official NVD data-feed provenance; retain NVD attribution",
        "local_path": "datasets/raw/nvd_cve",
        "artifact_set_sha256": "a" * 64,
        "artifact_set_sha256_scheme": "fixture",
        "byte_size": 123,
        "record_count": 2,
        "unique_cve_id_count": 2,
        "duplicate_feed_record_occurrences": 0,
        "schema": {
            "format": "NVD JSON 2.0 compressed feeds",
            "parser_kind": "nvd",
            "count_semantics": "fixture",
        },
        "ingestion_status": "not-started",
        "validation_status": "local-integrity-verified",
        "acquisition_method": "NVD official JSON 2.0 yearly feeds",
        "feed_range": {"year_start": 2002, "year_end": 2026, "includes_updates": True},
        "artifacts": [
            {
                "path": "datasets/raw/nvd_cve/nvdcve-2.0-2025.json.gz",
                "role": "data",
                "format": "NVD JSON 2.0 gzip",
                "count_kind": "nvd-feed",
                "record_count": 2,
                "byte_size": 123,
                "sha256": "b" * 64,
                "uncompressed_byte_size": 456,
                "uncompressed_sha256": "c" * 64,
                "source_uri": "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2025.json.gz",
                "version": "NVD-2.0-2025",
                "upstream_meta": {
                    "path": "datasets/raw/nvd_cve/nvdcve-2.0-2025.meta",
                    "sha256": "d" * 64,
                    "byte_size": 70,
                    "last_modified_date": "2026-10-17",
                    "declared_gzip_size": 123,
                    "declared_uncompressed_size": 456,
                    "declared_uncompressed_sha256": "c" * 64,
                },
            }
        ],
    }


def test_nvd_records_require_verified_nvd_parser_contract():
    manifest = verified_manifest()

    records = runner._nvd_records_from_manifest(manifest)

    assert len(records) == 1
    assert records[0]["dataset"] == "nvd_cve"
    assert records[0]["local_path"] == manifest["artifacts"][0]["path"]
    assert records[0]["count_kind"] == "nvd-feed"
    assert records[0]["record_count"] == 2
    assert records[0]["upstream_meta"] == manifest["artifacts"][0]["upstream_meta"]

    invalid = verified_manifest()
    invalid["schema"]["parser_kind"] = "generic"
    with pytest.raises(ValueError, match="verified NVD"):
        runner._nvd_records_from_manifest(invalid)


def test_nvd_family_uses_existing_official_manifest_builder_and_writes_report(monkeypatch, tmp_path: Path):
    project = tmp_path / "AI-cyber"
    monkeypatch.setattr(runner, "CHECKOUT", project)
    monkeypatch.setattr(runner, "RAW", project / "datasets" / "raw")
    monkeypatch.setattr(runner, "MANIFESTS", project / "datasets" / "manifests")
    monkeypatch.setattr(runner, "REPORTS", project / "datasets" / "acquisition_reports")
    monkeypatch.setattr(runner, "STAMP", "20261017T000000Z")

    payload = verified_manifest()
    calls = {}

    def fake_build(root, year_start, year_end, *, include_updates, project_root):
        calls.update({
            "root": root,
            "year_start": year_start,
            "year_end": year_end,
            "include_updates": include_updates,
            "project_root": project_root,
        })
        return payload

    def fake_write_json_atomic(path: Path, value: dict):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")

    monkeypatch.setattr(
        runner,
        "_load_nvd_readiness_module",
        lambda: SimpleNamespace(build_manifest=fake_build, write_json_atomic=fake_write_json_atomic),
    )

    records = runner.nvd_family()

    assert calls["root"] == project / "datasets" / "raw" / "nvd_cve"
    assert calls["year_start"] == 2002
    assert calls["year_end"] >= calls["year_start"]
    assert calls["include_updates"] is True
    assert calls["project_root"] == project
    assert records[0]["count_kind"] == "nvd-feed"
    saved = project / "datasets" / "manifests" / "nvd_cve.json"
    assert json.loads(saved.read_text(encoding="utf-8"))["artifact_set_sha256"] == "a" * 64
    report = project / "datasets" / "acquisition_reports" / "nvd-readiness-20261017T000000Z.json"
    report_payload = json.loads(report.read_text(encoding="utf-8"))
    assert report_payload["overall"] == "SOURCE_INTEGRITY_PASS"
    assert report_payload["ingestion_performed"] is False
    assert report_payload["database_created"] is False


def test_generic_manifest_writer_never_fabricates_missing_nvd_manifest(monkeypatch, tmp_path: Path):
    manifests = tmp_path / "manifests"
    manifests.mkdir()
    monkeypatch.setattr(runner, "MANIFESTS", manifests)

    with pytest.raises(RuntimeError, match="official NVD readiness pipeline"):
        runner.write_family_manifests({"nvd_cve": [{"dataset": "nvd_cve"}]})

    assert not (manifests / "nvd_cve.json").exists()


def test_generic_manifest_writer_preserves_official_nvd_manifest(monkeypatch, tmp_path: Path):
    manifests = tmp_path / "manifests"
    manifests.mkdir()
    monkeypatch.setattr(runner, "MANIFESTS", manifests)
    payload = verified_manifest()
    target = manifests / "nvd_cve.json"
    target.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    before = target.read_bytes()

    runner.write_family_manifests({
        "nvd_cve": [{"dataset": "nvd_cve", "validation_status": "downloaded-integrity-hashed"}],
        "cwe": [{"dataset": "cwe", "version": "fixture"}],
    })

    assert target.read_bytes() == before
    generic = json.loads((manifests / "cwe.json").read_text(encoding="utf-8"))
    assert generic["source_of_truth"] == "acquisition-report"
