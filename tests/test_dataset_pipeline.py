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


def test_nvd_manifest_ingestion_uses_nvd_parser_and_checkpoint(tmp_path: Path):
    import gzip
    from ai_cyber_os.dataset_pipeline import ingest_manifest
    from ai_cyber_os.knowledge import search, status

    project = tmp_path
    raw_dir = project / "datasets" / "raw" / "nvd_cve"
    manifest_dir = project / "datasets" / "manifests"
    raw_dir.mkdir(parents=True)
    manifest_dir.mkdir(parents=True)
    feed = raw_dir / "nvdcve-2.0-2024.json.gz"
    payload = {
        "totalResults": 1,
        "vulnerabilities": [{
            "cve": {
                "id": "CVE-2024-76543",
                "descriptions": [{"lang": "en", "value": "A remotely exploitable test vulnerability"}],
                "metrics": {"cvssMetricV31": [{
                    "type": "Primary",
                    "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"},
                }]},
            },
        }],
    }
    with gzip.open(feed, "wt", encoding="utf-8") as handle:
        json.dump(payload, handle)
    raw_hash = hashlib.sha256(feed.read_bytes()).hexdigest()
    manifest = manifest_dir / "nvd_cve.json"
    manifest.write_text(json.dumps({
        "dataset": "nvd_cve",
        "version": "NVD-2.0-2024",
        "source": "NIST NVD",
        "source_uri": "https://nvd.nist.gov/vuln/data-feeds",
        "license": "NVD data-feed terms",
        "schema": {"parser_kind": "nvd"},
        "artifacts": [{
            "path": "datasets/raw/nvd_cve/nvdcve-2.0-2024.json.gz",
            "role": "data",
            "sha256": raw_hash,
            "byte_size": feed.stat().st_size,
            "record_count": 1,
            "count_kind": "nvd-feed",
            "version": "NVD-2.0-2024",
        }],
    }), encoding="utf-8")

    db = project / "knowledge-v1.sqlite3"
    first = ingest_manifest(manifest, db_path=db)
    second = ingest_manifest(manifest, db_path=db)

    hits = search("CVE-2024-76543", db_path=db)
    assert first["inserted"] == 1
    assert first["artifact_results"][0]["checkpoint_status"] == "complete"
    assert second["inserted"] == 0
    assert second["skipped_artifacts"] == 1
    assert hits and hits[0]["record_id"] == "CVE-2024-76543"
    assert hits[0]["source"] == "NIST NVD"
    assert status(db_path=db)["database_version"] == "ai-cyber-knowledge-v1"
    assert status(db_path=db)["checkpoints"]["complete"] == 1


def test_mbc_manifest_ingestion_deduplicates_stix_ids_and_resumes(tmp_path: Path):
    import io
    import tarfile
    from ai_cyber_os.dataset_pipeline import ingest_manifest
    from ai_cyber_os.knowledge import open_store, status

    project = tmp_path
    raw_dir = project / "datasets" / "raw" / "mitre_mbc"
    manifest_dir = project / "datasets" / "manifests"
    raw_dir.mkdir(parents=True)
    manifest_dir.mkdir(parents=True)
    archive_path = raw_dir / "mbc.tar.gz"
    malware = {"type": "malware", "id": "malware--same", "name": "Same malware object"}
    behavior = {"type": "x-mbc-behavior", "id": "x-mbc-behavior--one", "name": "Test behavior"}
    documents = {
        "catalog/bundle.json": {"type": "bundle", "id": "bundle--catalog", "objects": [malware, behavior]},
        "objects/malware.json": malware,
    }
    with tarfile.open(archive_path, "w:gz") as archive:
        for name, document in documents.items():
            raw = json.dumps(document).encode("utf-8")
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            archive.addfile(info, io.BytesIO(raw))
    manifest = manifest_dir / "mitre_mbc.json"
    manifest.write_text(json.dumps({
        "dataset": "mitre_mbc",
        "version": "fixture-1",
        "source": "MITRE MBC fixture",
        "source_uri": "https://example.invalid/mbc",
        "license": "fixture",
        "schema": {"format": "STIX archive"},
        "artifacts": [{
            "path": "datasets/raw/mitre_mbc/mbc.tar.gz",
            "role": "data",
            "sha256": hashlib.sha256(archive_path.read_bytes()).hexdigest(),
            "byte_size": archive_path.stat().st_size,
            "record_count": 2,
            "count_kind": "mbc",
        }],
    }), encoding="utf-8")

    db_path = project / "knowledge-v1.sqlite3"
    result = ingest_manifest(manifest, db_path=db_path)
    db = open_store(db_path)
    try:
        ids = {row["record_id"] for row in db.execute(
            "SELECT record_id FROM knowledge_records WHERE dataset='mitre_mbc'"
        )}
    finally:
        db.close()

    resumed = ingest_manifest(manifest, db_path=db_path)
    assert result["inserted"] == 2
    assert ids == {"malware--same", "x-mbc-behavior--one"}
    assert resumed["skipped_artifacts"] == 1
    assert status(db_path=db_path)["records"] == 2
    assert status(db_path=db_path)["checkpoints"]["complete"] == 1


def test_suricata_manifest_ingestion_persists_active_and_disabled_state(tmp_path: Path):
    import io
    import tarfile
    from ai_cyber_os.dataset_pipeline import ingest_manifest
    from ai_cyber_os.knowledge import open_store

    project = tmp_path
    raw_dir = project / "datasets" / "raw" / "suricata"
    manifest_dir = project / "datasets" / "manifests"
    raw_dir.mkdir(parents=True)
    manifest_dir.mkdir(parents=True)
    archive_path = raw_dir / "rules.tar.gz"
    rules = (
        "alert tcp any any -> any 80 (msg:\"active-rule\"; sid:7001; rev:1;)\n"
        "# drop http any any -> any any (msg:\"disabled-rule\"; sid:7002; rev:1;)\n"
    ).encode("utf-8")
    with tarfile.open(archive_path, "w:gz") as archive:
        info = tarfile.TarInfo("rules/example.rules")
        info.size = len(rules)
        archive.addfile(info, io.BytesIO(rules))
    manifest = manifest_dir / "suricata.json"
    manifest.write_text(json.dumps({
        "dataset": "suricata",
        "version": "fixture-1",
        "source": "Suricata test rules",
        "source_uri": "https://example.invalid/suricata",
        "license": "fixture",
        "schema": {"format": "Suricata archive"},
        "artifacts": [{
            "path": "datasets/raw/suricata/rules.tar.gz",
            "role": "data",
            "sha256": hashlib.sha256(archive_path.read_bytes()).hexdigest(),
            "byte_size": archive_path.stat().st_size,
            "record_count": 2,
            "count_kind": "suricata",
        }],
    }), encoding="utf-8")

    db_path = project / "knowledge-v1.sqlite3"
    result = ingest_manifest(manifest, db_path=db_path)
    db = open_store(db_path)
    try:
        metadata = [
            json.loads(row["metadata_json"])
            for row in db.execute("SELECT metadata_json FROM knowledge_records WHERE dataset='suricata'")
        ]
    finally:
        db.close()
    assert result["inserted"] == 2
    assert {row["status"] for row in metadata} == {"active", "disabled"}


def test_manifest_directory_preflight_blocks_before_database_creation_and_ignores_example(tmp_path: Path):
    from ai_cyber_os.dataset_pipeline import ingest_manifest_directory
    from ai_cyber_os.knowledge import status

    payload = (
        '{"id":"READY-1","title":"ready fixture","content":"citation-backed security evidence"}\n'
        '{"id":"READY-2","title":"second fixture","content":"another verified security record"}\n'
    )
    manifest = _manifest(tmp_path, payload, count=2)
    manifests_dir = manifest.parent
    (manifests_dir / "example.json").write_text(json.dumps({
        "dataset": "missing-required-dataset",
        "local_path": "datasets/does-not-exist.json",
    }), encoding="utf-8")
    db_path = tmp_path / "persistent" / "knowledge-v1.sqlite3"

    blocked = ingest_manifest_directory(
        manifests_dir,
        db_path=db_path,
        required_datasets=["fixture-threat-intel", "missing-required-dataset"],
    )
    assert blocked["overall"] == "BLOCKED"
    assert blocked["ingestion_performed"] is False
    assert blocked["missing_required_datasets"] == ["missing-required-dataset"]
    assert not db_path.exists(), "preflight blockers must not create an empty/partial database"

    ready = ingest_manifest_directory(
        manifests_dir,
        db_path=db_path,
        required_datasets=["fixture-threat-intel"],
    )
    assert ready["overall"] == "PASS"
    assert ready["success"] is True
    assert ready["ingestion_performed"] is True
    assert ready["inserted"] == 2
    assert status(db_path=db_path)["records"] == 2
    assert status(db_path=db_path)["database_version"] == "ai-cyber-knowledge-v1"
