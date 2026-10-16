from __future__ import annotations

import gzip
import hashlib
import importlib.util
import json
import tarfile
from pathlib import Path

from ai_cyber_os.knowledge import ingest_file, open_store

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "package_knowledge_db_release.py"
SPEC = importlib.util.spec_from_file_location("package_knowledge_db_release", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

DATASETS = (
    "capec", "cisa_kev", "cpe", "cwe", "epss", "mitre_attack",
    "mitre_d3fend", "mitre_mbc", "sigma", "suricata", "zeek_intel", "nvd_cve",
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def make_fixture(tmp_path: Path):
    manifests = tmp_path / "manifests"
    manifests.mkdir()
    for dataset in DATASETS:
        (manifests / f"{dataset}.json").write_text(
            json.dumps({"dataset": dataset, "version": "fixture-v1"}) + "\n",
            encoding="utf-8",
        )
    (manifests / "example.json").write_text(
        json.dumps({"dataset": "example", "version": "REPLACE_WITH_VERSION"}) + "\n",
        encoding="utf-8",
    )
    digests = {
        dataset: sha256_file(manifests / f"{dataset}.json")
        for dataset in DATASETS
    }

    db_path = tmp_path / "knowledge.sqlite3"
    for dataset in (*DATASETS, "cvss"):
        source = tmp_path / f"{dataset}.jsonl"
        source.write_text(
            json.dumps({
                "id": f"{dataset.upper()}-FIXTURE-1",
                "title": f"{dataset} fixture evidence",
                "content": f"verified {dataset} fixture evidence",
            }) + "\n",
            encoding="utf-8",
        )
        assert ingest_file(
            source, db_path=db_path, dataset=dataset, source=f"{dataset} fixture",
            source_uri=f"https://example.invalid/{dataset}", license="CC0",
            version="fixture-v1", validation_status="fixture-validated",
        )["success"] is True

    connection = open_store(db_path)
    try:
        connection.execute(
            "INSERT INTO knowledge_meta(key,value) VALUES('source_manifest_digests',?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (json.dumps(digests, sort_keys=True, separators=(",", ":")),),
        )
        connection.commit()
        integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
        assert integrity == "ok"
        records = connection.execute("SELECT COUNT(*) FROM knowledge_records").fetchone()[0]
        fts = connection.execute("SELECT COUNT(*) FROM knowledge_fts").fetchone()[0]
        chunks = connection.execute("SELECT COUNT(*) FROM knowledge_chunks").fetchone()[0]
        chunk_fts = connection.execute("SELECT COUNT(*) FROM knowledge_chunks_fts").fetchone()[0]
        counts = dict(connection.execute(
            "SELECT dataset, COUNT(*) FROM knowledge_records GROUP BY dataset"
        ))
        meta = dict(connection.execute("SELECT key,value FROM knowledge_meta"))
        fingerprints = MODULE._stable_table_fingerprints(connection)
    finally:
        connection.close()

    verification = {
        "pass": True, "db_bytes": db_path.stat().st_size,
        "db_sha256": sha256_file(db_path), "sqlite_integrity": "ok",
        "foreign_key_issues": 0, "missing_tables": [],
        "records": records, "fts_records": fts, "chunks": chunks, "chunk_fts": chunk_fts,
        "dataset_counts": dict(sorted(counts.items())),
        "schema_version": int(meta["schema_version"]),
        "database_version": meta["database_version"],
        **fingerprints,
        "rag_smoke_probes": [{"pass": True}] * 4,
    }
    build = tmp_path / "knowledge-db-build-report.json"
    build.write_text(json.dumps({
        "overall": "PASS", "success": True, "database_verification": verification,
    }, indent=2), encoding="utf-8")
    live = tmp_path / "live-rag-api-report.json"
    live.write_text(json.dumps({
        "overall": "PASS", "success": True,
        "tests": [{"pass": True, "dataset": dataset} for dataset in (*DATASETS[:3], "cvss")],
    }, indent=2), encoding="utf-8")
    return db_path, manifests, build, live, verification


def test_release_packager_refuses_a_failed_database_build(tmp_path: Path):
    db, manifests, build, live, _ = make_fixture(tmp_path)
    report = json.loads(build.read_text(encoding="utf-8"))
    report["overall"] = "FAIL"
    build.write_text(json.dumps(report), encoding="utf-8")
    try:
        MODULE.package_release(
            db_path=db, build_report_path=build, live_rag_report_path=live,
            manifest_dir=manifests, output_dir=tmp_path / "out",
            repository="example/AI-cyber", commit_sha="deadbeef",
            run_number=1, run_attempt=1,
        )
    except RuntimeError as exc:
        assert "build report is not PASS" in str(exc)
    else:
        raise AssertionError("failed DB build was incorrectly packaged")


def test_verified_db_release_bundle_and_split_assets_are_reproducible(tmp_path: Path):
    db, manifests, build, live, expected = make_fixture(tmp_path)
    pre_api_sha = sha256_file(db)
    # Exercise a documented open-store side effect without changing indexed records.
    connection = sqlite3.connect(db)
    try:
        connection.execute(
            "UPDATE knowledge_meta SET value='post-rag-probe-timestamp' WHERE key='last_opened_at'"
        )
        connection.commit()
    finally:
        connection.close()
    assert sha256_file(db) != pre_api_sha
    output = tmp_path / "out"
    result = MODULE.package_release(
        db_path=db, build_report_path=build, live_rag_report_path=live,
        manifest_dir=manifests, output_dir=output,
        repository="example/AI-cyber", commit_sha="deadbeef",
        run_number=1, run_attempt=1, max_asset_bytes=1024,
    )
    assert result["overall"] == "PASS"
    assert result["manifest_count"] == 12
    assert result["database_sha256"] == sha256_file(db)
    assert result["records"] == expected["records"]
    plan = json.loads((output / "release-assets.json").read_text(encoding="utf-8"))
    assert plan["release_tag"] == "ai-cyber-knowledge-db-1-1"
    assert plan["chunked_database"] is True
    parts = [output / name for name in plan["database_asset_files"]]
    assert len(parts) > 1
    assert all(p.is_file() and p.stat().st_size <= 1024 for p in parts)

    rebuilt_gzip = tmp_path / "rebuilt.sqlite3.gz"
    with rebuilt_gzip.open("wb") as destination:
        for part in parts:
            destination.write(part.read_bytes())
    rebuilt_db = tmp_path / "rebuilt.sqlite3"
    with gzip.open(rebuilt_gzip, "rb") as source, rebuilt_db.open("wb") as destination:
        destination.write(source.read())
    assert sha256_file(rebuilt_db) == sha256_file(db)

    manifest = json.loads((output / "knowledge-db-release-manifest.json").read_text(encoding="utf-8"))
    assert manifest["verification"]["sqlite_integrity"] == "ok"
    assert manifest["database"]["uncompressed_sha256"] == sha256_file(db)
    with tarfile.open(output / "source-manifests.tar.gz", "r:gz") as archive:
        members = archive.getnames()
    assert not any(name.endswith("example.json") for name in members)
    assert len([name for name in members if name.endswith(".json")]) == 12



def test_release_packager_detects_knowledge_record_mutation(tmp_path: Path):
    db, manifests, build, live, _ = make_fixture(tmp_path)
    connection = sqlite3.connect(db)
    try:
        connection.execute(
            "UPDATE knowledge_records SET content='tampered evidence' "
            "WHERE record_id='NVD_CVE-FIXTURE-1'"
        )
        connection.commit()
    finally:
        connection.close()
    try:
        MODULE.package_release(
            db_path=db, build_report_path=build, live_rag_report_path=live,
            manifest_dir=manifests, output_dir=tmp_path / "out",
            repository="example/AI-cyber", commit_sha="deadbeef",
            run_number=1, run_attempt=1,
        )
    except RuntimeError as exc:
        assert "record_table_sha256 differs" in str(exc)
    else:
        raise AssertionError("modified knowledge records were incorrectly packaged")

def test_release_packager_refuses_failed_live_rag_probes(tmp_path: Path):
    db, manifests, build, live, _ = make_fixture(tmp_path)
    report = json.loads(live.read_text(encoding="utf-8"))
    report["tests"][0]["pass"] = False
    live.write_text(json.dumps(report), encoding="utf-8")
    try:
        MODULE.package_release(
            db_path=db, build_report_path=build, live_rag_report_path=live,
            manifest_dir=manifests, output_dir=tmp_path / "out",
            repository="example/AI-cyber", commit_sha="deadbeef",
            run_number=1, run_attempt=1,
        )
    except RuntimeError as exc:
        assert "live RAG/API report has missing or failed probes" in str(exc)
    else:
        raise AssertionError("failed RAG probes were incorrectly packaged")
