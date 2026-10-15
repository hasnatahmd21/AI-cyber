import hashlib
import json
from pathlib import Path

import pytest

from ai_cyber_os.dataset_pipeline import ingest_manifest, inspect_dataset
from ai_cyber_os.intelligence import correlate, extract_identifiers


def _manifest(root: Path, payload: str, *, sha256: str | None = None, count: int = 2) -> Path:
    data = root / "datasets" / "fixtures.jsonl"
    data.parent.mkdir(parents=True)
    data.write_text(payload, encoding="utf-8")
    digest = sha256 or hashlib.sha256(payload.encode("utf-8")).hexdigest()
    manifest_dir = root / "datasets" / "manifests"
    manifest_dir.mkdir(parents=True)
    manifest = manifest_dir / "fixture.json"
    manifest.write_text(json.dumps({
        "dataset": "fixture-threat-intel",
        "version": "test-1",
        "source": "local-test",
        "source_uri": "https://example.invalid/test",
        "license": "CC0",
        "local_path": "datasets/fixtures.jsonl",
        "sha256": digest,
        "record_count": count,
        "schema": {"type": "jsonl"},
        "ingestion_status": "ready",
        "validation_status": "fixture-validated",
    }), encoding="utf-8")
    return manifest


def test_manifest_pipeline_verifies_integrity(tmp_path: Path):
    payload = (
        '{"id":"CVE-2026-1000","title":"Example","description":"CVE-2026-1000 '
        'maps to CWE-79 and ATT&CK T1059.001"}\n'
        '{"id":"CVE-2026-1001","description":"second evidence"}\n'
    )
    manifest = _manifest(tmp_path, payload)
    inspected = inspect_dataset(manifest)
    assert inspected["ready"] is True
    result = ingest_manifest(manifest, db_path=tmp_path / "knowledge.db")
    assert result["ready"] is True
    assert result["inserted"] == 2


def test_manifest_pipeline_rejects_bad_checksum(tmp_path: Path):
    payload = '{"id":"X","content":"evidence"}\n'
    manifest = _manifest(tmp_path, payload, sha256="0" * 64, count=1)
    assert inspect_dataset(manifest)["sha256_matches"] is False
    with pytest.raises(ValueError, match="SHA-256"):
        ingest_manifest(manifest, db_path=tmp_path / "knowledge.db")


def test_identifier_extraction_and_relation_correlation(tmp_path: Path):
    payload = '{"id":"CVE-2026-2000","content":"CVE-2026-2000 CWE-89 ATT&CK T1059.001"}\n'
    manifest = _manifest(tmp_path, payload, count=1)
    db = tmp_path / "knowledge.db"
    ingest_manifest(manifest, db_path=db)
    ids = extract_identifiers(payload)
    assert ids["cve"] == ["CVE-2026-2000"]
    result = correlate("CVE-2026-2000", db_path=str(db))
    assert result["evidence_only"] is True
    assert result["related"]["CVE-2026-2000"][0]["record_id"] == "CVE-2026-2000"



def test_manifest_rejects_boolean_and_string_record_counts(tmp_path: Path):
    payload = '{"id":"fixture","content":"evidence"}\n'
    manifest = _manifest(tmp_path, payload, count=1)
    data = json.loads(manifest.read_text(encoding="utf-8"))
    data["record_count"] = True
    manifest.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match="record_count must be an integer"):
        inspect_dataset(manifest)


def test_manifest_rejects_symlink_escape(tmp_path: Path):
    payload = '{"id":"fixture","content":"evidence"}\n'
    manifest = _manifest(tmp_path, payload, count=1)
    outside = tmp_path.parent / f"{tmp_path.name}-outside.jsonl"
    outside.write_text(payload, encoding="utf-8")
    link = tmp_path / "datasets" / "escape.jsonl"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is unavailable on this platform")
    data = json.loads(manifest.read_text(encoding="utf-8"))
    data["local_path"] = "datasets/escape.jsonl"
    manifest.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match="remain inside the project"):
        inspect_dataset(manifest)


def test_checksum_can_be_explicitly_skipped_but_count_cannot(tmp_path: Path):
    payload = '{"id":"fixture-checksum-optout","content":"evidence"}\n'
    manifest = _manifest(tmp_path, payload, sha256="0" * 64, count=1)
    result = ingest_manifest(
        manifest, db_path=tmp_path / "knowledge.db", require_checksum=False
    )
    assert result["ready"] is True
    assert result["inspection"]["sha256_matches"] is False

    data = json.loads(manifest.read_text(encoding="utf-8"))
    data["record_count"] = 99
    manifest.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match="record count"):
        ingest_manifest(
            manifest, db_path=tmp_path / "knowledge-count.db",
            require_checksum=False
        )


def test_multi_artifact_manifest_rejects_non_integer_record_count(tmp_path: Path):
    data_dir = tmp_path / "datasets"
    data_dir.mkdir()
    payload = '{"id":"fixture","content":"evidence"}\n'
    artifact = data_dir / "one.jsonl"
    artifact.write_text(payload, encoding="utf-8")
    manifest_dir = data_dir / "manifests"
    manifest_dir.mkdir()
    manifest = manifest_dir / "multi.json"
    manifest.write_text(json.dumps({
        "dataset": "multi-fixture",
        "version": "1",
        "artifacts": [{
            "path": "datasets/one.jsonl",
            "sha256": hashlib.sha256(payload.encode("utf-8")).hexdigest(),
            "record_count": 1.5,
        }],
    }), encoding="utf-8")
    with pytest.raises(ValueError, match="record_count must be an integer"):
        inspect_dataset(manifest)



def test_multi_artifact_manifest_rejects_path_escape(tmp_path: Path):
    outside = tmp_path.parent / f"{tmp_path.name}-outside-artifact.jsonl"
    payload = '{"id":"fixture","content":"evidence"}\n'
    outside.write_text(payload, encoding="utf-8")
    manifest_dir = tmp_path / "datasets" / "manifests"
    manifest_dir.mkdir(parents=True)
    manifest = manifest_dir / "multi.json"
    manifest.write_text(json.dumps({
        "dataset": "multi-fixture",
        "version": "1",
        "artifacts": [{
            "path": "../" + outside.name,
            "sha256": hashlib.sha256(payload.encode("utf-8")).hexdigest(),
            "record_count": 1,
        }],
    }), encoding="utf-8")
    with pytest.raises(ValueError, match="remain inside the project"):
        inspect_dataset(manifest)



def test_xml_catalog_counts_only_manifest_entity_elements(tmp_path: Path):
    from ai_cyber_os.knowledge import iter_records

    xml = """<Catalog><Attack_Patterns>
      <Attack_Pattern ID="1"><Name>one</Name><Description><Text>details</Text></Description></Attack_Pattern>
      <Attack_Pattern ID="2"><Name>two</Name></Attack_Pattern>
    </Attack_Patterns><Categories><Category ID="C1"><Name>cat</Name></Category></Categories>
    </Catalog>"""
    path = tmp_path / "catalog.xml"
    path.write_text(xml, encoding="utf-8")
    rows = list(iter_records(path, record_elements=["Attack_Pattern", "Category"]))
    assert len(rows) == 3
    assert all("Attack_Pattern" in row["content"] or "Category" in row["content"]
               for row in rows)
    assert "details" in rows[0]["content"]


def test_gzip_csv_skips_leading_metadata_and_counts_data_rows(tmp_path: Path):
    import gzip
    from ai_cyber_os.knowledge import iter_records

    path = tmp_path / "scores.csv.gz"
    with gzip.open(path, "wt", encoding="utf-8") as handle:
        handle.write("#model_version:v1,score_date:2026-10-01\n")
        handle.write("cve,epss,percentile\n")
        handle.write("CVE-2026-1,0.1,0.9\n")
        handle.write("CVE-2026-2,0.2,0.8\n")
    rows = list(iter_records(path))
    assert len(rows) == 2
    assert "CVE-2026-1" in rows[0]["content"]


def test_sigma_archive_schema_excludes_version_text(tmp_path: Path):
    import zipfile
    from ai_cyber_os.knowledge import iter_records

    path = tmp_path / "rules.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("rules/one.yml", "title: one\n")
        archive.writestr("rules/two.yml", "title: two\n")
        archive.writestr("version.txt", "r1\n")
    rows = list(iter_records(path, record_extensions={".yml", ".yaml"}))
    assert len(rows) == 2


def test_license_artifact_is_hash_checked_but_not_ingested(tmp_path: Path):
    data_dir = tmp_path / "datasets"
    raw_dir = data_dir / "raw"
    manifest_dir = data_dir / "manifests"
    raw_dir.mkdir(parents=True)
    manifest_dir.mkdir()
    data = '{"items":[{"id":"K-1","title":"fixture"}]}'
    license_text = "license text"
    (raw_dir / "data.json").write_text(data, encoding="utf-8")
    (raw_dir / "LICENSE.txt").write_text(license_text, encoding="utf-8")
    manifest = manifest_dir / "fixture.json"
    manifest.write_text(json.dumps({
        "dataset": "fixture", "version": "1", "source": "test",
        "source_uri": "fixture://source", "license": "test",
        "schema": {"format": "json"},
        "artifacts": [
            {"path": "datasets/raw/data.json",
             "sha256": hashlib.sha256(data.encode()).hexdigest(),
             "record_count": 1, "role": "data"},
            {"path": "datasets/raw/LICENSE.txt",
             "sha256": hashlib.sha256(license_text.encode()).hexdigest(),
             "record_count": None, "role": "license"}
        ]
    }), encoding="utf-8")
    inspected = inspect_dataset(manifest)
    assert inspected["ready"] is True
    assert inspected["records"] == 1
    assert inspected["artifacts"][1]["sha256_matches"] is True
    assert inspected["artifacts"][1]["records"] == 0
    db = tmp_path / "knowledge.db"
    result = ingest_manifest(manifest, db_path=db)
    assert result["inserted"] == 1
    from ai_cyber_os.knowledge import status
    assert status(db_path=db)["records"] == 1


def test_jsonld_graph_is_counted_as_individual_records(tmp_path: Path):
    from ai_cyber_os.knowledge import iter_records

    path = tmp_path / "ontology.json"
    path.write_text(json.dumps({
        "@context": {},
        "@graph": [
            {"@id": "https://example.invalid/A", "@type": "Thing", "label": "A"},
            {"@id": "https://example.invalid/B", "@type": "Thing", "label": "B"},
        ],
    }), encoding="utf-8")
    rows = list(iter_records(path, dataset="d3fend-fixture", record_format="ontology_jsonld"))
    assert len(rows) == 2
    assert {row["record_id"] for row in rows} == {
        "https://example.invalid/A", "https://example.invalid/B"
    }


def test_stix_tarball_excludes_repo_manifest_and_yields_bundle_objects(tmp_path: Path):
    import io
    import tarfile
    from ai_cyber_os.knowledge import iter_records

    path = tmp_path / "mbc.tar.gz"
    members = {
        "project/manifest.json": json.dumps({"repository": "metadata-only"}),
        "project/a.json": json.dumps({"type": "bundle", "objects": [
            {"type": "indicator", "id": "indicator--one", "name": "one"},
            {"type": "malware", "id": "malware--two", "name": "two"},
        ]}),
    }
    with tarfile.open(path, "w:gz") as archive:
        for name, text in members.items():
            payload = text.encode("utf-8")
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))

    rows = list(iter_records(
        path, dataset="mbc-fixture", record_format="mbc_stix_repo_tarball"
    ))
    assert len(rows) == 2
    assert {json.loads(row["metadata_json"])["type"] for row in rows} == {
        "indicator", "malware"
    }


def test_suricata_parser_preserves_active_disabled_and_sid_fields(tmp_path: Path):
    import io
    import tarfile
    from ai_cyber_os.knowledge import iter_records

    path = tmp_path / "suricata.tar.gz"
    rules = (
        'alert tcp any any -> any 80 (msg:"active rule"; sid:1001; rev:1;)\n'
        '# alert tcp any any -> any 443 (msg:"disabled rule"; sid:1002; rev:2;)\n'
        '# just a comment\n\n'
    ).encode("utf-8")
    with tarfile.open(path, "w:gz") as archive:
        info = tarfile.TarInfo("rules/test.rules")
        info.size = len(rules)
        archive.addfile(info, io.BytesIO(rules))

    rows = list(iter_records(path, dataset="suricata-fixture",
                             record_format="suricata_rules_tar_gz"))
    assert len(rows) == 2
    active, disabled = [json.loads(row["metadata_json"]) for row in rows]
    assert active["enabled"] is True and active["sid"] == "1001"
    assert disabled["enabled"] is False and disabled["sid"] == "1002"


def test_gzip_jsonl_records_are_streamed_and_counted(tmp_path: Path):
    import gzip
    from ai_cyber_os.knowledge import iter_records

    path = tmp_path / "cpe.jsonl.gz"
    with gzip.open(path, "wt", encoding="utf-8") as handle:
        handle.write('{"id":"cpe-1","title":"one"}\n')
        handle.write('{"id":"cpe-2","title":"two"}\n')
    rows = list(iter_records(path, dataset="cpe-fixture"))
    assert [row["record_id"] for row in rows] == ["cpe-1", "cpe-2"]


def test_multi_artifact_stats_are_part_of_readiness(tmp_path: Path):
    import io
    import tarfile

    data_dir = tmp_path / "datasets"
    raw_dir = data_dir / "raw"
    manifest_dir = data_dir / "manifests"
    raw_dir.mkdir(parents=True)
    manifest_dir.mkdir()
    artifact = raw_dir / "rules.tar.gz"
    rules = (
        'alert tcp any any -> any 80 (msg:"active"; sid:1; rev:1;)\n'
        '# alert tcp any any -> any 443 (msg:"disabled"; sid:2; rev:1;)\n'
    ).encode()
    with tarfile.open(artifact, "w:gz") as archive:
        info = tarfile.TarInfo("rules/a.rules")
        info.size = len(rules)
        archive.addfile(info, io.BytesIO(rules))
    manifest = manifest_dir / "suricata-fixture.json"
    manifest.write_text(json.dumps({
        "dataset": "suricata-fixture", "version": "test-1",
        "source": "fixture", "source_uri": "fixture://rules", "license": "test",
        "artifact_type": "suricata_rules_tar_gz",
        "schema": {"format": ".rules text inside tar.gz"},
        "artifacts": [{
            "path": "datasets/raw/rules.tar.gz",
            "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
            "record_count": 2, "role": "data",
            "artifact_type": "suricata_rules_tar_gz",
            "stats": {"active_rules": 1, "disabled_rules": 1,
                      "duplicate_sid_lines": 0, "rule_files": 1},
        }],
    }), encoding="utf-8")
    assert inspect_dataset(manifest)["ready"] is True

    data = json.loads(manifest.read_text(encoding="utf-8"))
    data["artifacts"][0]["stats"]["active_rules"] = 2
    manifest.write_text(json.dumps(data), encoding="utf-8")
    result = inspect_dataset(manifest)
    assert result["ready"] is False
    assert result["artifacts"][0]["stat_checks"]["active_rules"]["matches"] is False


def test_git_lfs_pointer_is_blocked_without_trying_to_parse_as_json(tmp_path: Path):
    data_dir = tmp_path / "datasets"
    manifest_dir = data_dir / "manifests"
    raw_dir = data_dir / "raw"
    manifest_dir.mkdir(parents=True)
    raw_dir.mkdir()
    pointer = (
        "version https://git-lfs.github.com/spec/v1\\n"
        "oid sha256:" + "a" * 64 + "\\n"
        "size 1234\\n"
    )
    artifact = raw_dir / "large.json"
    artifact.write_text(pointer, encoding="utf-8")
    manifest = manifest_dir / "large.json"
    manifest.write_text(json.dumps({
        "dataset": "large-fixture",
        "version": "1",
        "source": "fixture",
        "source_uri": "https://example.invalid/large.json",
        "license": "test",
        "artifact_type": "stix_2_1_bundle",
        "schema": {"format": "STIX 2.1 bundle JSON"},
        "artifacts": [{
            "path": "datasets/raw/large.json",
            "sha256": "a" * 64,
            "record_count": 1,
            "role": "data",
            "artifact_type": "stix_2_1_bundle",
        }],
    }), encoding="utf-8")
    result = inspect_dataset(manifest)
    assert result["ready"] is False
    assert result["artifacts"][0]["git_lfs_pointer"] is True
    assert "Git LFS pointer" in result["artifacts"][0]["blocked_reason"]


def test_explicitly_unverified_license_blocks_readiness_and_ingestion(tmp_path: Path):
    payload = '{"id":"license-fixture","content":"evidence"}\\n'
    manifest = _manifest(tmp_path, payload, count=1)
    data = json.loads(manifest.read_text(encoding="utf-8"))
    data["license_verified"] = False
    manifest.write_text(json.dumps(data), encoding="utf-8")

    inspected = inspect_dataset(manifest)
    assert inspected["ready"] is False
    assert inspected["manifest_checks"]["checks"]["license_verified"] is False
    with pytest.raises(ValueError, match="metadata validation failed"):
        ingest_manifest(manifest, db_path=tmp_path / "knowledge.db")


def test_stix_object_type_statistics_are_enforced(tmp_path: Path):
    data_dir = tmp_path / "datasets"
    raw_dir = data_dir / "raw"
    manifest_dir = data_dir / "manifests"
    raw_dir.mkdir(parents=True)
    manifest_dir.mkdir()
    artifact = raw_dir / "bundle.json"
    artifact.write_text(json.dumps({"type": "bundle", "objects": [
        {"type": "indicator", "id": "indicator--1", "name": "one"},
        {"type": "indicator", "id": "indicator--2", "name": "two"},
    ]}), encoding="utf-8")
    manifest = manifest_dir / "stix.json"
    manifest.write_text(json.dumps({
        "dataset": "stix-fixture", "version": "1", "source": "fixture",
        "source_uri": "https://example.invalid/stix", "license": "test",
        "artifact_type": "stix_2_1_bundle",
        "schema": {"format": "STIX 2.1 bundle JSON"},
        "artifacts": [{
            "path": "datasets/raw/bundle.json",
            "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
            "record_count": 2, "role": "data",
            "artifact_type": "stix_2_1_bundle",
            "stats": {"object_types": {"indicator": 2}},
        }],
    }), encoding="utf-8")
    assert inspect_dataset(manifest)["ready"] is True

    data = json.loads(manifest.read_text(encoding="utf-8"))
    data["artifacts"][0]["stats"]["object_types"]["indicator"] = 1
    manifest.write_text(json.dumps(data), encoding="utf-8")
    result = inspect_dataset(manifest)
    assert result["ready"] is False
    assert result["artifacts"][0]["stat_checks"]["object_types"]["matches"] is False
