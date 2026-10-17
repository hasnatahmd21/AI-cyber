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


def test_manifest_directory_derives_provenance_backed_cvss_with_checkpoints(tmp_path: Path):
    import gzip
    from ai_cyber_os.dataset_pipeline import ingest_manifest_directory
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
                "sourceIdentifier": "nvd-fixture",
                "published": "2024-01-01T00:00:00Z",
                "lastModified": "2024-01-02T00:00:00Z",
                "descriptions": [{"lang": "en", "value": "A CVSS-backed fixture vulnerability"}],
                "metrics": {
                    "cvssMetricV31": [{
                        "source": "nvd-fixture",
                        "type": "Primary",
                        "cvssData": {
                            "version": "3.1",
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            "baseScore": 9.8,
                            "baseSeverity": "CRITICAL",
                        },
                    }],
                },
            },
        }],
    }
    with gzip.open(feed, "wt", encoding="utf-8") as handle:
        json.dump(payload, handle)
    digest = hashlib.sha256(feed.read_bytes()).hexdigest()
    manifest = manifest_dir / "nvd_cve.json"
    manifest.write_text(json.dumps({
        "dataset": "nvd_cve",
        "version": "NVD-2.0-2024",
        "source": "NIST NVD fixture",
        "source_uri": "https://nvd.nist.gov/vuln/data-feeds",
        "license": "NVD data-feed terms",
        "schema": {"format": "NVD JSON 2.0", "parser_kind": "nvd"},
        "artifacts": [{
            "path": "datasets/raw/nvd_cve/nvdcve-2.0-2024.json.gz",
            "role": "data",
            "sha256": digest,
            "byte_size": feed.stat().st_size,
            "record_count": 1,
            "count_kind": "nvd-feed",
            "version": "NVD-2.0-2024",
        }],
    }), encoding="utf-8")

    db_path = project / "persistent" / "knowledge-v1.sqlite3"
    first = ingest_manifest_directory(
        manifest_dir, db_path=db_path, required_datasets=["nvd_cve"]
    )
    assert first["overall"] == "PASS"
    assert first["derived_datasets"][0]["status"] == "PASS"
    assert first["derived_datasets"][0]["derivation"]["derived_records_in_database"] == 1
    cvss_hits = search("CVSS", db_path=db_path, dataset="cvss")
    assert cvss_hits and cvss_hits[0]["record_id"].startswith("cvss:CVE-2024-76543:")
    assert cvss_hits[0]["source_uri"] == "https://nvd.nist.gov/vuln/data-feeds"
    assert cvss_hits[0]["validation_status"] == "fixture-validated" or cvss_hits[0]["validation_status"] == "unverified"
    assert status(db_path=db_path)["checkpoints"]["complete"] >= 2

    second = ingest_manifest_directory(
        manifest_dir, db_path=db_path, required_datasets=["nvd_cve"]
    )
    assert second["overall"] == "PASS"
    assert second["derived_datasets"][0]["derivation"]["checkpoint_batches_skipped"] == 1
    assert len(search("CVSS", db_path=db_path, dataset="cvss")) == 1


def test_private_kaggle_db_persistence_checks_sqlite_hash_and_never_sets_public(tmp_path: Path, monkeypatch):
    import hashlib
    from types import SimpleNamespace

    import scripts.kaggle_build_knowledge_db as builder
    from ai_cyber_os.knowledge import ingest_file

    source = tmp_path / "evidence.jsonl"
    source.write_text(
        '{"id":"CVE-2021-44228","content":"CVSS critical vulnerability evidence",'
        '"source":"fixture","source_uri":"https://example.invalid/source",'
        '"license":"fixture license","validation_status":"fixture-validated"}\n',
        encoding="utf-8",
    )
    db_path = tmp_path / "persistent" / "knowledge-v1.sqlite3"
    ingest_file(source, db_path=db_path, dataset="cisa_kev", source="fixture",
                source_uri="https://example.invalid/source", license="fixture license",
                validation_status="fixture-validated")
    report_path = tmp_path / "build-report.json"
    source_manifests = tmp_path / "source-manifests"
    source_manifests.mkdir()
    real_manifest = source_manifests / "cisa_kev.json"
    real_manifest.write_text(json.dumps({
        "dataset": "cisa_kev",
        "version": "fixture-feed-1",
        "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "record_count": 1,
    }), encoding="utf-8")
    (source_manifests / "example.json").write_text(
        '{"dataset":"not-real"}', encoding="utf-8"
    )
    source_readiness_report = tmp_path / "parser-readiness.json"
    source_readiness_report.write_text(
        '{"overall":"PASS","ingestion_performed":false}', encoding="utf-8"
    )
    report_data = {
        "overall": "PASS",
        "database_version": "ai-cyber-knowledge-v1",
        "manifests_dir": str(source_manifests),
        "source_readiness_report": str(source_readiness_report),
    }

    monkeypatch.setattr(builder, "_kaggle_credentials", lambda: {
        "KAGGLE_USERNAME": "fixture-user",
        "KAGGLE_KEY": "never-include-this-in-output",
    })
    monkeypatch.setattr(builder.shutil, "which", lambda command: "/mock/kaggle")
    calls = []
    restart_calls = []
    core_query_calls = []

    def fake_run(command, **kwargs):
        calls.append((list(command), kwargs))
        if command[1:3] == ["datasets", "download"]:
            import shutil
            target = Path(command[command.index("-p") + 1])
            target.mkdir(parents=True, exist_ok=True)
            shutil.copy2(db_path, target / "knowledge-v1.sqlite3")
        return SimpleNamespace(returncode=0, stdout="verified fixture status", stderr="")

    def fake_restart(db, cve_id):
        restart_calls.append((Path(db), cve_id))
        return {"success": True, "evidence_only": True, "count": 1, "has_citations": True}

    def fake_core_queries(db, cve_id, cwe_id, attack_id):
        core_query_calls.append((Path(db), cve_id, cwe_id, attack_id))
        return {"default_db": str(Path(db).resolve()), "queries": {
            "cve": {"count": 1}, "cwe": {"count": 1}, "attack": {"count": 1},
        }}

    monkeypatch.setattr(builder.subprocess, "run", fake_run)
    monkeypatch.setattr(builder, "restart_smoke_test", fake_restart)
    monkeypatch.setattr(builder, "core_query_smoke_test", fake_core_queries)
    result = builder.persist_via_kaggle_dataset(
        db_path, report_path, report_data,
        "fixture-user/ai-cyber-knowledge-db", "create",
    )

    assert result["status"] == "published-restored-hash-and-restart-verified"
    assert result["restored_hash_matches"] is True
    assert result["restore_restart_test"]["success"] is True
    assert restart_calls and restart_calls[0][1] == builder.PROBE_CVE
    assert result["restore_core_query_test"]["queries"]["cwe"]["count"] == 1
    assert core_query_calls and core_query_calls[0][1:] == (
        builder.PROBE_CVE, builder.PROBE_CWE, builder.PROBE_ATTACK
    )
    assert result["access"] == "private; public flag was not used"
    create_call = next(call[0] for call in calls if "create" in call[0])
    assert create_call[:3] == ["/mock/kaggle", "datasets", "create"]
    assert "--public" not in create_call
    assert "--dir-mode" in create_call and "skip" in create_call
    status_call = next(call[0] for call in calls if call[0][1:3] == ["datasets", "status"])
    assert status_call[-1] == "fixture-user/ai-cyber-knowledge-db"
    download_call = next(call[0] for call in calls if call[0][1:3] == ["datasets", "download"])
    assert "--unzip" in download_call

    upload_dir = Path(result["upload_dir"])
    try:
        assert Path(restart_calls[0][0]).name == "knowledge-v1.sqlite3"
        assert result["restore_directory_cleaned"] is True
        metadata = json.loads((upload_dir / "dataset-metadata.json").read_text(encoding="utf-8"))
        artifact = json.loads((upload_dir / "database-artifact-manifest.json").read_text(encoding="utf-8"))
        uploaded_report = (upload_dir / "knowledge-db-build-report.json").read_text(encoding="utf-8")
        assert metadata["id"] == "fixture-user/ai-cyber-knowledge-db"
        assert metadata["licenses"] == [{"name": "other"}]
        assert artifact["sha256"] == hashlib.sha256((upload_dir / "knowledge-v1.sqlite3").read_bytes()).hexdigest()
        assert artifact["source_manifest_count"] == 1
        assert artifact["source_manifest_sha256"]["cisa_kev.json"] == hashlib.sha256(real_manifest.read_bytes()).hexdigest()
        copied_manifest_name = artifact["source_manifest_files"]["cisa_kev.json"]
        assert copied_manifest_name.startswith("source-manifest-")
        assert json.loads((upload_dir / copied_manifest_name).read_text())["dataset"] == "cisa_kev"
        assert not (upload_dir / "source-manifest-example.json").exists()
        assert (upload_dir / "source-readiness-report.json").read_text() == source_readiness_report.read_text()
        assert artifact["source_readiness_report_sha256"] == hashlib.sha256(source_readiness_report.read_bytes()).hexdigest()
        assert "never-include-this-in-output" not in uploaded_report
    finally:
        import shutil
        shutil.rmtree(upload_dir, ignore_errors=True)


def test_kaggle_persistence_checks_metadata_and_sqlite_before_credentials(tmp_path: Path, monkeypatch):
    import sqlite3
    from scripts import kaggle_build_knowledge_db as builder

    with pytest.raises(ValueError, match="Kaggle dataset ID"):
        builder.persist_via_kaggle_dataset(
            tmp_path / "does-not-exist.sqlite3",
            tmp_path / "report.json",
            {},
            "invalid dataset id",
            "create",
        )

    db_path = tmp_path / "knowledge.sqlite3"
    db = sqlite3.connect(db_path)
    try:
        db.execute("CREATE TABLE knowledge_records(record_id TEXT PRIMARY KEY)")
        db.execute("CREATE TABLE knowledge_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        db.execute("INSERT INTO knowledge_records(record_id) VALUES ('fixture-record')")
        db.execute("INSERT INTO knowledge_meta(key,value) VALUES ('database_version','ai-cyber-knowledge-v1')")
        db.commit()
    finally:
        db.close()

    monkeypatch.setattr(
        builder,
        "_kaggle_credentials",
        lambda: (_ for _ in ()).throw(RuntimeError("stubbed credential check")),
    )
    with pytest.raises(RuntimeError, match="stubbed credential check"):
        builder.persist_via_kaggle_dataset(
            db_path, tmp_path / "report.json", {},
            "test-owner/ai-cyber-db", "create",
        )


def test_restart_smoke_test_uses_configured_db_and_returns_cited_evidence(tmp_path: Path):
    from scripts.kaggle_build_knowledge_db import restart_smoke_test
    from ai_cyber_os.knowledge import ingest_file

    source = tmp_path / "known-cve.jsonl"
    source.write_text(
        '{"id":"CVE-2021-44228","title":"Fixture CVE","content":"critical remote code execution vulnerability",'
        '"source":"CISA KEV fixture","source_uri":"https://example.invalid/cisa-kev",'
        '"license":"fixture","version":"nvd-fixture-1",'
        '"validation_status":"fixture-validated"}\n',
        encoding="utf-8",
    )
    db_path = tmp_path / "knowledge-v1.sqlite3"
    ingest_file(
        source,
        db_path=db_path,
        dataset="cisa_kev",
        source="CISA KEV fixture",
        source_uri="https://example.invalid/cisa-kev",
        license="fixture",
        version="cisa-kev-fixture-1",
        validation_status="fixture-validated",
    )

    result = restart_smoke_test(db_path, "CVE-2021-44228")

    assert Path(result["default_db"]).resolve() == db_path.resolve()
    assert result["status"]["database_version"] == "ai-cyber-knowledge-v1"
    assert result["status"]["records"] == 1
    assert result["hits"][0]["record_id"] == "CVE-2021-44228"
    assert result["analysis"]["success"] is True
    assert result["analysis"]["evidence_only"] is True
    assert result["analysis"]["has_citations"] is True


def test_manifest_directory_pins_source_snapshot_and_blocks_changed_manifest(tmp_path: Path):
    import hashlib
    from ai_cyber_os.dataset_pipeline import ingest_manifest_directory

    payload = '{"id":"PINNED-1","content":"one versioned evidence record"}\n'
    manifest = _manifest(tmp_path, payload, count=1)
    db_path = tmp_path / "knowledge-v1.sqlite3"

    first = ingest_manifest_directory(
        manifest.parent, db_path=db_path, required_datasets=["fixture-threat-intel"]
    )
    assert first["overall"] == "PASS"
    assert first["database_resume_status"] == "NEW_SOURCE_SNAPSHOT"
    assert first["source_manifest_digests"]["fixture-threat-intel"] == hashlib.sha256(
        manifest.read_bytes()
    ).hexdigest()

    before = hashlib.sha256(db_path.read_bytes()).hexdigest()
    data = json.loads(manifest.read_text(encoding="utf-8"))
    data["version"] = "test-2"
    manifest.write_text(json.dumps(data), encoding="utf-8")
    blocked = ingest_manifest_directory(
        manifest.parent, db_path=db_path, required_datasets=["fixture-threat-intel"]
    )

    assert blocked["overall"] == "BLOCKED"
    assert blocked["database_resume_status"] == "BLOCKED"
    assert blocked["ingestion_performed"] is False
    assert "Source-manifest digests differ" in blocked["evidence"]
    assert hashlib.sha256(db_path.read_bytes()).hexdigest() == before


def test_manifest_directory_rejects_duplicate_dataset_manifests(tmp_path: Path):
    from ai_cyber_os.dataset_pipeline import ingest_manifest_directory

    payload = '{"id":"DUP-1","content":"duplicate manifest fixture"}\n'
    manifest = _manifest(tmp_path, payload, count=1)
    duplicate = manifest.parent / "fixture_duplicate.json"
    duplicate.write_text(manifest.read_text(encoding="utf-8"), encoding="utf-8")
    db_path = tmp_path / "knowledge-v1.sqlite3"

    result = ingest_manifest_directory(
        manifest.parent, db_path=db_path, required_datasets=["fixture-threat-intel"]
    )

    assert result["overall"] == "FAIL"
    assert result["ingestion_performed"] is False
    assert not db_path.exists()
    assert any("duplicate manifest" in row.get("evidence", "").casefold()
               for row in result.get("preflight_failures", []))


def test_cwe_manifest_ingestion_indexes_canonical_ids_and_provenance(tmp_path: Path):
    import zipfile
    from ai_cyber_os.dataset_pipeline import ingest_manifest
    from ai_cyber_os.knowledge import search, status

    raw_dir = tmp_path / "datasets" / "raw" / "cwe"
    manifest_dir = tmp_path / "datasets" / "manifests"
    raw_dir.mkdir(parents=True)
    manifest_dir.mkdir(parents=True)
    xml = """<Weakness_Catalog>
      <Weaknesses>
        <Weakness ID="79" Name="Improper Neutralization of Input During Web Page Generation">
          <Description><Description_Summary>Cross-site scripting weakness</Description_Summary></Description>
        </Weakness>
        <Weakness ID="89" Name="SQL Injection">
          <Description><Description_Summary>SQL injection weakness</Description_Summary></Description>
        </Weakness>
      </Weaknesses>
      <Categories><Category ID="C1" Name="Input Validation"><Summary>Input group</Summary></Category></Categories>
      <Views><View ID="1000" Name="Research Concepts"><Objective>View objective</Objective></View></Views>
    </Weakness_Catalog>"""
    archive = raw_dir / "cwec_fixture.xml.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as handle:
        handle.writestr("cwec_fixture.xml", xml)
    manifest = manifest_dir / "cwe.json"
    manifest.write_text(json.dumps({
        "dataset": "cwe",
        "version": "fixture-4",
        "source": "MITRE CWE fixture",
        "source_uri": "https://example.invalid/cwe",
        "license": "fixture license",
        "schema": {"format": "xml(zip)", "elements": ["Weakness", "Category", "View"]},
        "artifacts": [{
            "path": "datasets/raw/cwe/cwec_fixture.xml.zip",
            "role": "data",
            "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
            "byte_size": archive.stat().st_size,
            "record_count": 4,
            "count_kind": "xml_cwe",
        }],
    }), encoding="utf-8")
    db_path = tmp_path / "knowledge-v1.sqlite3"

    first = ingest_manifest(manifest, db_path=db_path)
    hits = search("CWE-79", db_path=db_path, dataset="cwe")
    assert first["inserted"] == 4
    assert hits and hits[0]["record_id"] == "CWE-79"
    assert hits[0]["source_uri"] == "https://example.invalid/cwe"
    assert hits[0]["validation_status"] == "unverified"
    assert status(db_path=db_path)["checkpoints"]["complete"] == 1

    resumed = ingest_manifest(manifest, db_path=db_path)
    assert resumed["skipped_artifacts"] == 1
    assert len(search("CWE-79", db_path=db_path, dataset="cwe")) == 1


def test_core_query_smoke_test_checks_cve_cwe_attack_and_citations_in_new_process(tmp_path: Path):
    from scripts.kaggle_build_knowledge_db import core_query_smoke_test
    from ai_cyber_os.knowledge import ingest_file

    source = tmp_path / "core-evidence.jsonl"
    records = [
        {
            "id": "CVE-2021-44228",
            "title": "Log4Shell CVE fixture",
            "content": "Critical remote code execution vulnerability evidence",
            "source": "CISA KEV fixture",
            "source_uri": "https://example.invalid/kev",
            "license": "fixture",
            "version": "nvd-fixture",
            "validation_status": "fixture-validated",
        },
        {
            "id": "CWE-79",
            "title": "CWE-79 cross-site scripting",
            "content": "Improper neutralization of input during web page generation",
            "source": "CWE fixture",
            "source_uri": "https://example.invalid/cwe",
            "license": "fixture",
            "version": "cwe-fixture",
            "validation_status": "fixture-validated",
        },
        {
            "id": "T1059.001",
            "title": "PowerShell",
            "content": "ATT&CK technique T1059.001 PowerShell command and scripting interpreter",
            "source": "ATT&CK fixture",
            "source_uri": "https://example.invalid/attack",
            "license": "fixture",
            "version": "attack-fixture",
            "validation_status": "fixture-validated",
        },
    ]
    source.write_text("".join(json.dumps(row) + "\n" for row in records), encoding="utf-8")
    db_path = tmp_path / "knowledge-v1.sqlite3"
    for dataset, record in zip(("cisa_kev", "cwe", "mitre_attack"), records):
        one = tmp_path / f"{dataset}.jsonl"
        one.write_text(json.dumps(record) + "\n", encoding="utf-8")
        ingest_file(
            one,
            db_path=db_path,
            dataset=dataset,
            source=record["source"],
            source_uri=record["source_uri"],
            license=record["license"],
            version=record["version"],
            validation_status=record["validation_status"],
        )

    result = core_query_smoke_test(
        db_path, "CVE-2021-44228", "CWE-79", "T1059.001"
    )
    assert Path(result["default_db"]).resolve() == db_path.resolve()
    assert result["status"]["records"] == 3
    assert set(result["queries"]) == {"cve", "cwe", "attack"}
    assert result["queries"]["cve"]["dataset"] == "cisa_kev"
    for family in ("cve", "cwe", "attack"):
        query = result["queries"][family]
        assert query["count"] == 1
        assert query["success"] is True
        assert query["evidence_only"] is True
        assert query["has_citations"] is True
        assert query["evidence"][0]["source_uri"].startswith("https://example.invalid/")


def test_manifest_directory_blocks_unexpected_dataset_before_ingestion(tmp_path: Path):
    from ai_cyber_os.dataset_pipeline import ingest_manifest_directory

    payload = '{"id":"LOCKED-1","content":"only locked dataset should ingest"}\n'
    manifest = _manifest(tmp_path, payload, count=1)
    unexpected = json.loads(manifest.read_text(encoding="utf-8"))
    unexpected["dataset"] = "unsupported_scope_dataset"
    unexpected_path = manifest.parent / "unsupported_scope_dataset.json"
    unexpected_path.write_text(json.dumps(unexpected), encoding="utf-8")
    db_path = tmp_path / "knowledge-v1.sqlite3"

    result = ingest_manifest_directory(
        manifest.parent, db_path=db_path, required_datasets=["fixture-threat-intel"]
    )

    assert result["overall"] == "BLOCKED"
    assert result["unexpected_dataset_names"] == ["unsupported_scope_dataset"]
    assert result["ingestion_performed"] is False
    assert not db_path.exists()
    assert any(row["dataset"] == "unsupported_scope_dataset" and row["status"] == "BLOCKED"
               for row in result["preflight"])


def test_attack_manifest_ingestion_indexes_external_ids_for_full_stix_bundle(tmp_path: Path):
    from ai_cyber_os.dataset_pipeline import ingest_manifest
    from ai_cyber_os.knowledge import open_store, search, status

    raw_dir = tmp_path / "datasets" / "raw" / "mitre_attack"
    manifest_dir = tmp_path / "datasets" / "manifests"
    raw_dir.mkdir(parents=True)
    manifest_dir.mkdir(parents=True)
    bundle = raw_dir / "enterprise-attack-fixture.json"
    objects = [
        {
            "type": "attack-pattern",
            "id": "attack-pattern--11111111-1111-4111-8111-111111111111",
            "name": "PowerShell",
            "description": "Command and scripting interpreter using PowerShell.",
            "external_references": [{
                "source_name": "mitre-attack",
                "external_id": "T1059.001",
                "url": "https://attack.mitre.org/techniques/T1059/001/",
            }],
            "kill_chain_phases": [{"phase_name": "execution", "kill_chain_name": "mitre-attack"}],
        },
        {
            "type": "relationship",
            "id": "relationship--22222222-2222-4222-8222-222222222222",
            "relationship_type": "related-to",
            "source_ref": "attack-pattern--11111111-1111-4111-8111-111111111111",
            "target_ref": "attack-pattern--11111111-1111-4111-8111-111111111111",
        },
    ]
    bundle.write_text(json.dumps({
        "type": "bundle",
        "id": "bundle--aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "objects": objects,
    }), encoding="utf-8")
    manifest = manifest_dir / "mitre_attack.json"
    manifest.write_text(json.dumps({
        "dataset": "mitre_attack",
        "version": "v19.2-fixture",
        "source": "MITRE ATT&CK fixture",
        "source_uri": "https://github.com/mitre-attack/attack-stix-data",
        "license": "MITRE ATT&CK fixture terms",
        "validation_status": "fixture-validated",
        "schema": {"format": "STIX 2.1 bundle JSON"},
        "artifacts": [{
            "path": "datasets/raw/mitre_attack/enterprise-attack-fixture.json",
            "role": "data",
            "sha256": hashlib.sha256(bundle.read_bytes()).hexdigest(),
            "byte_size": bundle.stat().st_size,
            "record_count": 2,
            "count_kind": "stix_bundle",
            "source_uri": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/v19.2/enterprise-attack/enterprise-attack.json",
            "version": "v19.2-fixture",
        }],
    }), encoding="utf-8")

    db_path = tmp_path / "knowledge-v1.sqlite3"
    result = ingest_manifest(manifest, db_path=db_path)
    hits = search("T1059.001", db_path=db_path, dataset="mitre_attack")
    assert result["inserted"] == 2
    assert hits and hits[0]["record_id"] == "attack-pattern--11111111-1111-4111-8111-111111111111"
    assert "T1059.001" in hits[0]["content"]
    assert hits[0]["title"] == "PowerShell"
    assert hits[0]["source_uri"].endswith("enterprise-attack/enterprise-attack.json")
    assert hits[0]["version"] == "v19.2-fixture"
    assert hits[0]["validation_status"] == "fixture-validated"
    assert status(db_path=db_path)["checkpoints"]["complete"] == 1
    db = open_store(db_path)
    try:
        metadata = json.loads(db.execute(
            "SELECT metadata_json FROM knowledge_records WHERE record_id=?",
            ("attack-pattern--11111111-1111-4111-8111-111111111111",),
        ).fetchone()["metadata_json"])
    finally:
        db.close()
    assert "external_references" in metadata
    assert metadata["external_references"][0]["external_id"] == "T1059.001"


def test_sigma_manifest_ingestion_indexes_rule_id_and_detection(tmp_path: Path):
    import zipfile
    from ai_cyber_os.knowledge import search, status

    raw_dir = tmp_path / "datasets" / "raw" / "sigma"
    manifest_dir = tmp_path / "datasets" / "manifests"
    raw_dir.mkdir(parents=True)
    manifest_dir.mkdir(parents=True)
    archive_path = raw_dir / "sigma-fixture.zip"
    rule = """title: Suspicious PowerShell
id: 11111111-2222-4333-8444-555555555555
status: stable
description: Detects encoded PowerShell commands
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
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as handle:
        handle.writestr("rules/windows/process_creation/suspicious_powershell.yml", rule)
    manifest = manifest_dir / "sigma.json"
    manifest.write_text(json.dumps({
        "dataset": "sigma",
        "version": "fixture-v1",
        "source": "Sigma fixture",
        "source_uri": "https://example.invalid/sigma",
        "license": "fixture license",
        "schema": {"format": "YAML rules inside archive"},
        "artifacts": [{
            "path": "datasets/raw/sigma/sigma-fixture.zip",
            "role": "data",
            "sha256": hashlib.sha256(archive_path.read_bytes()).hexdigest(),
            "byte_size": archive_path.stat().st_size,
            "record_count": 1,
            "count_kind": "sigma",
        }],
    }), encoding="utf-8")
    db_path = tmp_path / "knowledge-v1.sqlite3"

    result = ingest_manifest(manifest, db_path=db_path)
    hits = search("11111111-2222-4333-8444-555555555555", db_path=db_path, dataset="sigma")

    assert result["inserted"] == 1
    assert len(hits) == 1
    assert hits[0]["record_id"] == "11111111-2222-4333-8444-555555555555"
    assert "attack.t1059.001" in hits[0]["content"]
    assert hits[0]["source_uri"] == "https://example.invalid/sigma"
    assert status(db_path=db_path)["checkpoints"]["complete"] == 1



def test_default_build_scope_is_eleven_and_skips_out_of_scope_nvd_cvss_manifests(tmp_path: Path):
    from ai_cyber_os.dataset_pipeline import DEFAULT_REQUIRED_DATASETS, ingest_manifest_directory
    from ai_cyber_os.dataset_readiness import readiness_report
    from scripts import kaggle_dataset_parser_readiness_gate as source_gate

    assert len(DEFAULT_REQUIRED_DATASETS) == 11
    assert tuple(source_gate.REQUIRED_DATASET_NAMES) == tuple(DEFAULT_REQUIRED_DATASETS)
    assert len(source_gate.REQUIRED_DATASET_NAMES) == 11
    assert "nvd_cve" not in source_gate.REQUIRED_DATASET_NAMES
    assert "nvd_cve" not in DEFAULT_REQUIRED_DATASETS
    assert "cvss" not in DEFAULT_REQUIRED_DATASETS

    manifest = _manifest(
        tmp_path,
        '{"id":"SCOPE-1","title":"scope fixture","content":"eleven source scope"}\n',
        count=1,
    )
    manifests_dir = manifest.parent
    (manifests_dir / "nvd_cve.json").write_text("{ invalid legacy NVD manifest", encoding="utf-8")
    (manifests_dir / "cvss.json").write_text("{ invalid legacy CVSS manifest", encoding="utf-8")

    ready = readiness_report(
        manifests_dir,
        required_datasets=["fixture-threat-intel"],
        excluded_datasets=["nvd_cve", "cvss"],
    )
    assert ready["overall"] == "PASS"
    assert ready["count"] == 1
    assert set(ready["excluded_datasets"]) == {"nvd_cve", "cvss"}

    db_path = tmp_path / "knowledge-v1.sqlite3"
    ingested = ingest_manifest_directory(
        manifests_dir,
        db_path=db_path,
        required_datasets=["fixture-threat-intel"],
    )
    assert ingested["overall"] == "PASS"
    assert ingested["ingestion_performed"] is True
    assert {row["dataset"] for row in ingested["excluded_manifests_skipped"]} == {
        "nvd_cve", "cvss"
    }
