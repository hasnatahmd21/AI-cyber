from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools import kaggle_acquire_datasets as runner


EXPECTED_FAMILIES = (
    "capec", "cisa_kev", "cpe", "cwe", "epss", "mitre_attack",
    "mitre_d3fend", "mitre_mbc", "sigma", "suricata", "zeek_intel",
)


def test_default_acquisition_scope_is_exactly_eleven_existing_sources():
    assert tuple(runner.LOCKED) == EXPECTED_FAMILIES
    assert len(runner.LOCKED) == 11
    assert "nvd_cve" not in runner.LOCKED
    assert "cvss" not in runner.LOCKED
    assert "nvd_cve" not in runner.FAMILIES
    assert "cvss" not in runner.FAMILIES


def test_acquisition_routes_use_canonical_dataset_ids(monkeypatch):
    routes = {
        "capec": "capec_family",
        "cisa_kev": "kev_family",
        "cpe": "cpe_family",
        "cwe": "cwe_family",
        "epss": "epss_family",
        "mitre_attack": "attack_family",
        "mitre_d3fend": "d3fend_family",
        "mitre_mbc": "mbc_family",
        "sigma": "sigma_family",
        "suricata": "suricata_family",
        "zeek_intel": "zeek_family",
    }
    for dataset, function_name in routes.items():
        monkeypatch.setattr(runner, function_name, lambda dataset=dataset: [{"dataset": dataset}])
        assert runner.acquire_family(dataset) == [{"dataset": dataset}]

    with pytest.raises(ValueError, match="approved 11-source set"):
        runner.acquire_family("nvd_cve")
    with pytest.raises(ValueError, match="approved 11-source set"):
        runner.acquire_family("cvss")


def test_manifest_writer_emits_only_canonical_eleven_manifest_names(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(runner, "MANIFESTS", tmp_path)
    by_family = {name: [{"dataset": name, "path": f"datasets/raw/{name}/fixture.dat"}]
                 for name in EXPECTED_FAMILIES}

    runner.write_family_manifests(by_family)

    files = sorted(path.name for path in tmp_path.glob("*.json"))
    assert files == sorted(f"{name}.json" for name in EXPECTED_FAMILIES)
    for name in EXPECTED_FAMILIES:
        payload = json.loads((tmp_path / f"{name}.json").read_text(encoding="utf-8"))
        assert payload["dataset"] == name
        assert payload["artifacts"][0]["dataset"] == name


def test_manifest_writer_refuses_out_of_scope_nvd_or_cvss_manifests(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(runner, "MANIFESTS", tmp_path)
    for name in ("nvd_cve", "cvss"):
        with pytest.raises(ValueError, match="out-of-scope"):
            runner.write_family_manifests({name: [{"dataset": name}]})
    assert list(tmp_path.glob("*.json")) == []
