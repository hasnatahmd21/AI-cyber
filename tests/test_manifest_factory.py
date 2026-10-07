from pathlib import Path
import hashlib
import json

import pytest

from ai_cyber_os.manifest_factory import build_batch, build_manifest, write_manifests


META = {
    "cve": {
        "dataset": "cve",
        "version": "2026",
        "source": "NVD",
        "source_uri": "https://nvd.nist.gov/",
        "license": "NIST data terms",
        "schema": {"type": "object"},
        "validation_status": "validated-local",
    }
}


def test_build_manifest_counts_and_hashes(tmp_path: Path):
    root = tmp_path / "project"
    data = root / "datasets" / "cve.jsonl"
    data.parent.mkdir(parents=True)
    data.write_text('{"id":"CVE-2026-0001","description":"test"}\n', encoding="utf-8")
    manifest = build_manifest(data, project_root=root, metadata=META["cve"])
    assert manifest["local_path"] == "datasets/cve.jsonl"
    assert manifest["record_count"] == 1
    assert manifest["sha256"] == hashlib.sha256(data.read_bytes()).hexdigest()
    assert manifest["ingestion_status"] == "pending"


def test_batch_is_deterministic_and_writes_idempotently(tmp_path: Path):
    root = tmp_path / "project"
    data = root / "datasets" / "cve.jsonl"
    data.parent.mkdir(parents=True)
    data.write_text('{"id":"CVE-2026-0001","description":"test"}\n', encoding="utf-8")
    first = build_batch(data.parent, project_root=root, metadata_by_dataset=META)
    second = build_batch(data.parent, project_root=root, metadata_by_dataset=META)
    assert first == second
    out = root / "manifests"
    paths = write_manifests(first, output_dir=out)
    assert paths[0].exists()
    assert write_manifests(first, output_dir=out) == paths


def test_missing_metadata_fails_closed(tmp_path: Path):
    root = tmp_path / "project"
    data = root / "datasets" / "cve.jsonl"
    data.parent.mkdir(parents=True)
    data.write_text('{"id":"CVE-2026-0001"}\n', encoding="utf-8")
    with pytest.raises(ValueError, match="missing metadata"):
        build_batch(data.parent, project_root=root, metadata_by_dataset={})


def test_path_escape_fails(tmp_path: Path):
    root = tmp_path / "project"
    outside = tmp_path / "outside.jsonl"
    outside.write_text('{"id":"CVE-2026-0001"}\n', encoding="utf-8")
    with pytest.raises(ValueError, match="outside project root"):
        build_manifest(outside, project_root=root, metadata=META["cve"])


def test_invalid_json_fails_closed(tmp_path: Path):
    root = tmp_path / "project"
    data = root / "datasets" / "cve.jsonl"
    data.parent.mkdir(parents=True)
    data.write_text("{bad json}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="invalid JSON"):
        build_manifest(data, project_root=root, metadata=META["cve"])


def test_changed_manifest_is_not_overwritten(tmp_path: Path):
    root = tmp_path / "project"
    data = root / "datasets" / "cve.jsonl"
    data.parent.mkdir(parents=True)
    data.write_text('{"id":"CVE-2026-0001"}\n', encoding="utf-8")
    manifest = build_manifest(data, project_root=root, metadata=META["cve"])
    out = root / "manifests"
    write_manifests([manifest], output_dir=out)
    target = out / "cve.manifest.json"
    target.write_text("{}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="refusing to overwrite"):
        write_manifests([manifest], output_dir=out)
