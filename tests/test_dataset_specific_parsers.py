import json
from pathlib import Path

import pytest

from ai_cyber_os.knowledge import iter_records
from ai_cyber_os.threat_intel import (
    PARSERS,
    parse_attack_stix,
    parse_d3fend_jsonld,
    parse_mbc_stix,
    parse_suricata_rules,
)


def test_jsonld_graph_is_counted_as_nodes(tmp_path: Path):
    path = tmp_path / "d3fend.json"
    payload = {
        "@context": {"rdfs": "http://www.w3.org/2000/01/rdf-schema#"},
        "@graph": [
            {"@id": "d3f:Technique-A", "rdfs:label": {"@value": "Hardening", "@language": "en"}},
            {"@id": "d3f:Technique-B", "rdfs:label": {"@value": "Isolation", "@language": "en"}},
        ],
    }
    path.write_text(json.dumps(payload), encoding="utf-8")

    generic = list(iter_records(path, dataset="d3fend-fixture"))
    parsed = parse_d3fend_jsonld(path, validation_status="fixture-validated")

    assert len(generic) == 2
    assert [item["record_id"] for item in generic] == ["d3f:Technique-A", "d3f:Technique-B"]
    assert len(parsed) == 2
    assert parsed[0]["title"] == "Hardening"
    assert parsed[1]["record_id"] == "d3f:Technique-B"


def test_mbc_directory_counts_objects_not_bundle_files(tmp_path: Path):
    bundles = tmp_path / "bundles"
    bundles.mkdir()
    (bundles / "bundle-001.json").write_text(json.dumps({
        "type": "bundle",
        "id": "bundle--1",
        "objects": [
            {"type": "malware", "id": "malware--1", "name": "Example one"},
            {"type": "attack-pattern", "id": "attack-pattern--1", "name": "Example behavior"},
        ],
    }), encoding="utf-8")
    (bundles / "bundle-002.json").write_text(json.dumps({
        "type": "bundle",
        "id": "bundle--2",
        "objects": [{"type": "x-mbc-behavior", "id": "x-mbc-behavior--2", "name": "Example two"}],
    }), encoding="utf-8")
    (bundles / "manifest.json").write_text(json.dumps({"catalog": "metadata only"}), encoding="utf-8")

    records = parse_mbc_stix(bundles, validation_status="fixture-validated")

    assert len(list(bundles.glob("*.json"))) == 3
    assert len(records) == 3
    assert {record["record_id"] for record in records} == {
        "malware--1", "attack-pattern--1", "x-mbc-behavior--2"
    }
    assert all(record["source"] == "MITRE Malware Behavior Catalog" for record in records)
    assert {json.loads(record["metadata_json"])["bundle_file"] for record in records} == {
        "bundle-001.json", "bundle-002.json"
    }


def test_suricata_rules_separate_active_disabled_and_comments(tmp_path: Path):
    path = tmp_path / "test.rules"
    path.write_text(
        "alert tcp any any -> any 80 (msg:\"active-one\"; sid:1; rev:1;)\n"
        "# alert tcp any any -> any 81 (msg:\"disabled-one\"; sid:2; rev:1;)\n"
        "# a normal explanatory comment, not a rule\n"
        "drop http any any -> any any (msg:\"active-two\"; sid:3; rev:1;)\n"
        "# drop http any any -> any any (msg:\"disabled-two\"; sid:4; rev:1;)\n",
        encoding="utf-8",
    )

    records = parse_suricata_rules(path, validation_status="fixture-validated")
    active = [record for record in records if json.loads(record["metadata_json"])["status"] == "active"]
    disabled = [record for record in records if json.loads(record["metadata_json"])["status"] == "disabled"]

    assert len(active) == 2
    assert len(disabled) == 2
    assert all(record["record_id"].startswith("suricata:active:") for record in active)
    assert all(record["record_id"].startswith("suricata:disabled:") for record in disabled)
    assert "normal explanatory comment" not in " ".join(record["content"] for record in records)


def test_all_new_source_parser_kinds_are_registered():
    assert {"d3fend-jsonld", "mbc-stix", "suricata-rules"} <= set(PARSERS)


def test_lfs_pointer_is_never_parsed_as_attack_json(tmp_path: Path):
    path = tmp_path / "enterprise-attack.json"
    path.write_text(
        "version https://git-lfs.github.com/spec/v1\n"
        "oid sha256:" + "a" * 64 + "\n"
        "size 123456\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Git LFS pointer"):
        parse_attack_stix(path)



def test_readiness_gate_passes_integrity_checked_manifest(tmp_path: Path):
    import hashlib
    from ai_cyber_os.dataset_readiness import readiness_report

    project = tmp_path / "project"
    datasets = project / "datasets"
    manifests = datasets / "manifests"
    manifests.mkdir(parents=True)
    payload = '{"id":"READY-1","content":"readiness fixture"}\\n'
    data_path = datasets / "ready.jsonl"
    data_path.write_text(payload, encoding="utf-8")
    manifest = manifests / "ready.json"
    manifest.write_text(json.dumps({
        "dataset": "ready-fixture",
        "version": "test-1",
        "source": "fixture",
        "source_uri": "https://example.invalid/fixture",
        "license": "CC0",
        "local_path": "datasets/ready.jsonl",
        "sha256": hashlib.sha256(payload.encode("utf-8")).hexdigest(),
        "record_count": 1,
        "schema": {"type": "jsonl"},
        "ingestion_status": "not-started",
        "validation_status": "fixture-validated",
    }), encoding="utf-8")

    report = readiness_report(manifests, required_datasets=["ready-fixture"])

    assert report["overall"] == "PASS"
    assert report["pass"] == 1
    assert report["ingestion_performed"] is False
    assert report["datasets"][0]["inspection"]["records"] == 1


def test_readiness_gate_blocks_lfs_pointer_and_missing_required_source(tmp_path: Path):
    import hashlib
    from ai_cyber_os.dataset_readiness import readiness_report

    datasets = tmp_path / "datasets"
    manifests = datasets / "manifests"
    manifests.mkdir(parents=True)
    pointer = (
        "version https://git-lfs.github.com/spec/v1\\n"
        "oid sha256:" + "b" * 64 + "\\n"
        "size 456789\\n"
    )
    data_path = datasets / "enterprise-attack.json"
    data_path.write_text(pointer, encoding="utf-8")
    manifest = manifests / "attack.json"
    manifest.write_text(json.dumps({
        "dataset": "mitre-attack-enterprise",
        "version": "19.2",
        "source": "MITRE ATT&CK",
        "source_uri": "https://example.invalid/attack",
        "license": "CC BY 4.0",
        "local_path": "datasets/enterprise-attack.json",
        "sha256": hashlib.sha256(pointer.encode("utf-8")).hexdigest(),
        "record_count": 1,
        "schema": {"type": "json"},
        "ingestion_status": "not-started",
        "validation_status": "unverified",
    }), encoding="utf-8")

    report = readiness_report(
        manifests,
        required_datasets=["mitre-attack-enterprise", "missing-required-fixture"],
    )

    assert report["overall"] == "BLOCKED"
    by_name = {row["dataset"]: row for row in report["datasets"]}
    assert by_name["mitre-attack-enterprise"]["status"] == "BLOCKED"
    assert "Git LFS pointer" in by_name["mitre-attack-enterprise"]["evidence"]
    assert by_name["missing-required-fixture"]["status"] == "BLOCKED"
    assert report["ingestion_performed"] is False


def test_mbc_tarball_counts_bundle_files_separately_from_stix_objects(tmp_path: Path):
    import io
    import tarfile
    from ai_cyber_os.threat_intel import parse_mbc_stix

    archive_path = tmp_path / "mbc.tar.gz"
    payloads = {
        "bundle-a.json": {"type": "bundle", "id": "bundle--a", "objects": [
            {"type": "malware", "id": "malware--a"},
            {"type": "attack-pattern", "id": "attack-pattern--a"},
        ]},
        "bundle-b.json": {"type": "bundle", "id": "bundle--b", "objects": [
            {"type": "x-mbc-behavior", "id": "x-mbc-behavior--b"},
        ]},
    }
    with tarfile.open(archive_path, "w:gz") as archive:
        for name, payload in payloads.items():
            raw = json.dumps(payload).encode("utf-8")
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            archive.addfile(info, io.BytesIO(raw))

    records = parse_mbc_stix(archive_path, validation_status="fixture-validated")

    assert len(payloads) == 2  # bundle files
    assert len(records) == 3  # STIX objects inside those files
    assert {json.loads(record["metadata_json"])["bundle_file"] for record in records} == set(payloads)


def test_suricata_tarball_classifies_active_disabled_and_ignores_comments(tmp_path: Path):
    import io
    import tarfile
    from ai_cyber_os.threat_intel import parse_suricata_rules

    archive_path = tmp_path / "suricata.tar.gz"
    rule_text = (
        "alert tcp any any -> any 80 (msg:\"active-in-archive\"; sid:101; rev:1;)\n"
        "# alert tcp any any -> any 81 (msg:\"disabled-in-archive\"; sid:102; rev:1;)\n"
        "# document comment, not a rule\n"
    )
    raw = rule_text.encode("utf-8")
    with tarfile.open(archive_path, "w:gz") as archive:
        info = tarfile.TarInfo("rules/example.rules")
        info.size = len(raw)
        archive.addfile(info, io.BytesIO(raw))

    records = parse_suricata_rules(archive_path, validation_status="fixture-validated")
    states = [json.loads(record["metadata_json"])["status"] for record in records]

    assert states.count("active") == 1
    assert states.count("disabled") == 1
    assert len(records) == 2


def test_lfs_pointer_is_rejected_by_generic_json_and_text_ingestion(tmp_path: Path):
    path = tmp_path / "attack.json"
    path.write_text(
        "version https://git-lfs.github.com/spec/v1\\n"
        "oid sha256:" + "c" * 64 + "\\nsize 789\\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="Git LFS pointer"):
        list(iter_records(path, dataset="attack-pointer-fixture"))


def test_mbc_deduplicates_catalog_bundle_and_per_object_json_by_stix_id(tmp_path: Path):
    import io
    import tarfile
    from ai_cyber_os.threat_intel import parse_mbc_stix

    archive_path = tmp_path / "mbc-duplicates.tar.gz"
    one = {"type": "malware", "id": "malware--same", "name": "Same exact object"}
    two = {"type": "indicator", "id": "indicator--same", "name": "Second object"}
    payloads = {
        "catalog/bundle.json": {"type": "bundle", "id": "bundle--catalog", "objects": [one, two]},
        "objects/malware.json": one,
        "objects/indicator.json": two,
        "metadata.json": {"catalog": "metadata only"},
    }
    with tarfile.open(archive_path, "w:gz") as archive:
        for name, payload in payloads.items():
            raw = json.dumps(payload).encode("utf-8")
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            archive.addfile(info, io.BytesIO(raw))

    records = parse_mbc_stix(archive_path, validation_status="fixture-validated")

    assert len(payloads) == 4  # three STIX-bearing JSON files + metadata JSON
    assert len(records) == 2  # exact repeated STIX IDs counted once
    assert {record["record_id"] for record in records} == {"malware--same", "indicator--same"}


def test_mbc_conflicting_duplicate_stix_id_fails_closed(tmp_path: Path):
    import io
    import tarfile
    from ai_cyber_os.threat_intel import parse_mbc_stix

    archive_path = tmp_path / "mbc-conflict.tar.gz"
    one = {"type": "malware", "id": "malware--duplicate", "name": "Original"}
    altered = {"type": "malware", "id": "malware--duplicate", "name": "Conflicting"}
    with tarfile.open(archive_path, "w:gz") as archive:
        for name, payload in (
            ("objects/original.json", one),
            ("objects/conflicting.json", altered),
        ):
            raw = json.dumps(payload).encode("utf-8")
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            archive.addfile(info, io.BytesIO(raw))

    with pytest.raises(ValueError, match="Conflicting STIX payloads"):
        parse_mbc_stix(archive_path, validation_status="fixture-validated")


def test_nvd_gzip_feed_parser_and_readiness_count_match_actual_cve_ids(tmp_path: Path):
    import gzip
    import hashlib
    from ai_cyber_os.dataset_pipeline import inspect_dataset
    from ai_cyber_os.threat_intel import parse_nvd

    project = tmp_path
    raw_dir = project / "datasets" / "raw" / "nvd_cve"
    manifest_dir = project / "datasets" / "manifests"
    raw_dir.mkdir(parents=True)
    manifest_dir.mkdir(parents=True)

    payload = {
        "resultsPerPage": 2,
        "startIndex": 0,
        "totalResults": 2,
        "format": "NVD_CVE",
        "version": "2.0",
        "vulnerabilities": [
            {"cve": {
                "id": "CVE-2024-10001",
                "sourceIdentifier": "test@example.invalid",
                "published": "2024-01-01T00:00:00.000",
                "lastModified": "2024-01-02T00:00:00.000",
                "descriptions": [{"lang": "en", "value": "first compressed CVE fixture"}],
                "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": 7.5}}]},
            }},
            {"cve": {
                "id": "CVE-2024-10002",
                "sourceIdentifier": "test@example.invalid",
                "published": "2024-01-03T00:00:00.000",
                "lastModified": "2024-01-04T00:00:00.000",
                "descriptions": [{"lang": "en", "value": "second compressed CVE fixture"}],
                "metrics": {},
            }},
        ],
    }
    feed = raw_dir / "nvdcve-2.0-2024.json.gz"
    with gzip.open(feed, "wt", encoding="utf-8") as handle:
        json.dump(payload, handle)

    records = parse_nvd(
        feed, dataset="nvd_cve", version="NVD-2.0-2024",
        source_uri="https://nvd.nist.gov/vuln/data-feeds",
        validation_status="fixture-validated",
    )
    assert len(records) == 2
    assert {record["record_id"] for record in records} == {
        "CVE-2024-10001", "CVE-2024-10002"
    }
    assert "first compressed CVE fixture" in next(
        record["content"] for record in records if record["record_id"] == "CVE-2024-10001"
    )

    manifest = manifest_dir / "nvd_cve.json"
    manifest.write_text(json.dumps({
        "dataset": "nvd_cve",
        "version": "NVD-2.0-2024",
        "source": "NVD",
        "source_uri": "https://nvd.nist.gov/vuln/data-feeds",
        "license": "NVD data feed terms; preserve source attribution",
        "local_path": "datasets/raw/nvd_cve",
        "sha256": hashlib.sha256(feed.read_bytes()).hexdigest(),
        "record_count": 2,
        "schema": {"format": "NVD 2.0 gzip JSON", "parser_kind": "nvd"},
        "ingestion_status": "not-started",
        "validation_status": "fixture-validated",
        "artifacts": [{
            "path": "datasets/raw/nvd_cve/nvdcve-2.0-2024.json.gz",
            "role": "data",
            "sha256": hashlib.sha256(feed.read_bytes()).hexdigest(),
            "byte_size": feed.stat().st_size,
            "record_count": 2,
            "count_kind": "nvd-feed",
            "source_uri": "https://nvd.nist.gov/vuln/data-feeds",
            "version": "NVD-2.0-2024",
        }],
    }), encoding="utf-8")

    inspection = inspect_dataset(manifest)
    assert inspection["ready"] is True
    assert inspection["records"] == 2
    assert inspection["artifacts"][0]["byte_size_matches"] is True
    assert inspection["artifacts"][0]["record_count_matches"] is True


def test_nvd_meta_verification_checks_compressed_and_uncompressed_bytes(tmp_path: Path):
    import gzip
    import hashlib
    from scripts.kaggle_nvd_feed_readiness import parse_meta, verified_against_meta

    feed = tmp_path / "nvdcve-2.0-2024.json.gz"
    raw = json.dumps({
        "vulnerabilities": [{"cve": {"id": "CVE-2024-19001"}}],
        "totalResults": 1,
    }, separators=(",", ":")).encode("utf-8")
    with gzip.open(feed, "wb") as handle:
        handle.write(raw)

    metadata = chr(10).join([
        "lastModifiedDate:2026-10-15T00:00:00Z",
        f"size:{len(raw)}",
        f"gzSize:{feed.stat().st_size}",
        f"sha256:{hashlib.sha256(raw).hexdigest()}",
    ]) + chr(10)
    parsed = parse_meta(metadata)
    evidence = verified_against_meta(feed, parsed)

    assert evidence["uncompressed_size"] == len(raw)
    assert evidence["uncompressed_sha256"] == hashlib.sha256(raw).hexdigest()
    assert evidence["compressed_size"] == feed.stat().st_size

    bad_meta = dict(parsed)
    bad_meta["sha256"] = "0" * 64
    with pytest.raises(ValueError, match="uncompressed SHA-256 mismatch"):
        verified_against_meta(feed, bad_meta)


def test_nvd_meta_parser_rejects_missing_or_malformed_integrity_fields():
    from scripts.kaggle_nvd_feed_readiness import parse_meta

    incomplete = chr(10).join([
        "lastModifiedDate:2026-10-15T00:00:00Z",
        "size:100",
    ]) + chr(10)
    with pytest.raises(ValueError, match="missing required fields"):
        parse_meta(incomplete)

    malformed = chr(10).join([
        "size:100",
        "gzSize:50",
        "sha256:not-a-digest",
    ]) + chr(10)
    with pytest.raises(ValueError, match="sha256 must be"):
        parse_meta(malformed)


def test_cwe_xml_parser_canonicalizes_weakness_ids_and_streams_catalog_types(tmp_path: Path):
    import zipfile
    from ai_cyber_os.threat_intel import iter_parse_cwe_xml, parse_cwe_xml

    xml = """<Weakness_Catalog>
      <Weaknesses>
        <Weakness ID="79" Name="Improper Neutralization of Input During Web Page Generation">
          <Description><Description_Summary>Cross-site scripting</Description_Summary></Description>
        </Weakness>
        <Weakness ID="89" Name="SQL Injection">
          <Description><Description_Summary>SQL injection weakness</Description_Summary></Description>
        </Weakness>
      </Weaknesses>
      <Categories><Category ID="C1" Name="Input Validation"><Summary>Input group</Summary></Category></Categories>
      <Views><View ID="1000" Name="Research Concepts"><Objective>View objective</Objective></View></Views>
    </Weakness_Catalog>"""
    plain = tmp_path / "cwec_fixture.xml"
    plain.write_text(xml, encoding="utf-8")
    archive_path = tmp_path / "cwec_fixture.xml.zip"
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("cwec_fixture.xml", xml)

    rows = list(iter_parse_cwe_xml(
        archive_path,
        dataset="cwe",
        source="MITRE CWE fixture",
        version="fixture-4",
        source_uri="https://example.invalid/cwe",
        license="fixture license",
        validation_status="fixture-validated",
    ))
    assert len(rows) == 4
    by_id = {row["record_id"]: row for row in rows}
    assert {"CWE-79", "CWE-89", "cwe-category-C1", "cwe-view-1000"} == set(by_id)
    assert by_id["CWE-79"]["title"].startswith("CWE-79:")
    assert "Cross-site scripting" in by_id["CWE-79"]["content"]
    assert by_id["CWE-79"]["source_uri"] == "https://example.invalid/cwe"
    assert by_id["CWE-79"]["validation_status"] == "fixture-validated"
    assert len(parse_cwe_xml(plain, dataset="cwe", validation_status="fixture-validated")) == 4


def test_sigma_zip_parser_preserves_rule_ids_detection_and_provenance(tmp_path: Path):
    import zipfile
    from ai_cyber_os.threat_intel import iter_parse_sigma_rules

    archive_path = tmp_path / "sigma-fixture.zip"
    rule = """title: Suspicious PowerShell
id: 11111111-2222-4333-8444-555555555555
status: stable
description: Detects encoded PowerShell commands
references:
  - https://example.invalid/sigma-rule
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\\\\powershell.exe'
  condition: selection
"""
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("rules/windows/process_creation/suspicious_powershell.yml", rule)
        archive.writestr("README.md", "not a Sigma rule")

    records = list(iter_parse_sigma_rules(
        archive_path,
        dataset="sigma",
        source="Sigma fixture",
        version="fixture-v1",
        source_uri="https://example.invalid/sigma",
        license="fixture license",
        validation_status="fixture-validated",
    ))
    assert len(records) == 1
    row = records[0]
    assert row["record_id"] == "11111111-2222-4333-8444-555555555555"
    assert row["title"] == "Suspicious PowerShell"
    assert "attack.t1059.001" in row["content"]
    assert "process_creation" in row["content"]
    assert row["source_uri"] == "https://example.invalid/sigma"
    assert row["validation_status"] == "fixture-validated"
