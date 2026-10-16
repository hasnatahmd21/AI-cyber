#!/usr/bin/env python3
"""Verify and package a populated AI-CYBER Knowledge DB for durable release."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import shutil
import sqlite3
import tarfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REQUIRED_DATASETS = {
    "capec", "cisa_kev", "cpe", "cwe", "epss", "mitre_attack",
    "mitre_d3fend", "mitre_mbc", "sigma", "suricata", "zeek_intel", "nvd_cve",
}
REQUIRED_TABLES = {
    "knowledge_records", "knowledge_relations", "knowledge_fts",
    "knowledge_chunks", "knowledge_chunks_fts", "knowledge_meta",
    "knowledge_ingestion_checkpoints",
}
DEFAULT_MAX_ASSET_BYTES = 1_800_000_000


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected a JSON object: {path}")
    return value


def _manifest_snapshot(manifest_dir: Path) -> dict[str, str]:
    snapshot: dict[str, str] = {}
    for path in sorted(manifest_dir.glob("*.json")):
        if path.name.casefold() == "example.json":
            continue
        manifest = _read_json(path)
        dataset = manifest.get("dataset")
        if not isinstance(dataset, str) or not dataset.strip():
            raise ValueError(f"manifest has no valid dataset name: {path}")
        if dataset in snapshot:
            raise ValueError(f"duplicate source manifest for dataset {dataset!r}")
        snapshot[dataset] = sha256_file(path)
    missing = sorted(REQUIRED_DATASETS - set(snapshot))
    unexpected = sorted(set(snapshot) - REQUIRED_DATASETS)
    if missing or unexpected:
        raise RuntimeError(
            f"source manifest set must be exactly the locked 12 datasets; "
            f"missing={missing}, unexpected={unexpected}"
        )
    return dict(sorted(snapshot.items()))


def _stable_table_fingerprints(conn: sqlite3.Connection) -> dict[str, str]:
    """Hash stable knowledge tables, excluding volatile open/access metadata."""
    queries = {
        "record_table_sha256": (
            "SELECT record_id,dataset,source,source_uri,license,validation_status,version,"
            "title,content,content_sha256,metadata_json,schema_version,ingested_at "
            "FROM knowledge_records ORDER BY record_id"
        ),
        "relations_table_sha256": (
            "SELECT record_id,relation_type,target_id FROM knowledge_relations "
            "ORDER BY record_id,relation_type,target_id"
        ),
        "chunks_table_sha256": (
            "SELECT chunk_id,record_id,chunk_index,content,content_sha256 "
            "FROM knowledge_chunks ORDER BY chunk_id"
        ),
    }
    fingerprints: dict[str, str] = {}
    for name, query in queries.items():
        digest = hashlib.sha256()
        cursor = conn.execute(query)
        while True:
            rows = cursor.fetchmany(1000)
            if not rows:
                break
            for row in rows:
                encoded = json.dumps(
                    list(row), ensure_ascii=False, separators=(",", ":"), default=str
                ).encode("utf-8")
                digest.update(encoded)
                digest.update(b"\\n")
        fingerprints[name] = digest.hexdigest()
    return fingerprints


def _inspect_database(db_path: Path, expected_source_digests: dict[str, str]) -> dict[str, Any]:
    if not db_path.is_file() or db_path.stat().st_size <= 0:
        raise FileNotFoundError(f"Knowledge DB missing or empty: {db_path}")
    wal = Path(str(db_path) + "-wal")
    if wal.is_file() and wal.stat().st_size:
        raise RuntimeError("refusing to package a DB with a non-empty WAL sidecar")

    connection = sqlite3.connect(f"{db_path.resolve().as_uri()}?mode=ro", uri=True)
    try:
        integrity = str(connection.execute("PRAGMA integrity_check").fetchone()[0])
        foreign_key_issues = connection.execute("PRAGMA foreign_key_check").fetchall()
        tables = {
            str(row[0]) for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type IN ('table','view')"
            )
        }
        missing_tables = sorted(REQUIRED_TABLES - tables)
        if missing_tables:
            records = fts_records = chunks = chunk_fts = 0
            dataset_counts: dict[str, int] = {}
        else:
            records = int(connection.execute("SELECT COUNT(*) FROM knowledge_records").fetchone()[0])
            fts_records = int(connection.execute("SELECT COUNT(*) FROM knowledge_fts").fetchone()[0])
            chunks = int(connection.execute("SELECT COUNT(*) FROM knowledge_chunks").fetchone()[0])
            chunk_fts = int(connection.execute("SELECT COUNT(*) FROM knowledge_chunks_fts").fetchone()[0])
            dataset_counts = {
                str(name): int(count) for name, count in connection.execute(
                    "SELECT dataset, COUNT(*) FROM knowledge_records GROUP BY dataset"
                )
            }
        meta = {
            str(key): str(value) for key, value in connection.execute(
                "SELECT key, value FROM knowledge_meta"
            )
        } if "knowledge_meta" in tables else {}
        stable_fingerprints = (
            _stable_table_fingerprints(connection)
            if not missing_tables else {}
        )
    finally:
        connection.close()

    raw_digests = meta.get("source_manifest_digests")
    if not raw_digests:
        raise RuntimeError("database has no pinned source-manifest digest ledger")
    try:
        db_source_digests = json.loads(raw_digests)
    except json.JSONDecodeError as exc:
        raise RuntimeError("database source-manifest digest ledger is malformed JSON") from exc

    problems = []
    if integrity != "ok":
        problems.append(f"SQLite integrity_check={integrity!r}")
    if foreign_key_issues:
        problems.append(f"foreign-key issues={len(foreign_key_issues)}")
    if missing_tables:
        problems.append(f"missing tables={missing_tables}")
    if records <= 0:
        problems.append("database has no knowledge records")
    if fts_records != records:
        problems.append(f"record FTS count {fts_records} != records {records}")
    if chunk_fts != chunks:
        problems.append(f"chunk FTS count {chunk_fts} != chunks {chunks}")
    missing_data = sorted(name for name in REQUIRED_DATASETS if dataset_counts.get(name, 0) <= 0)
    if missing_data:
        problems.append(f"required datasets without records={missing_data}")
    if dataset_counts.get("cvss", 0) <= 0:
        problems.append("derived CVSS dataset has no records")
    if db_source_digests != expected_source_digests:
        problems.append("DB-pinned source-manifest hashes do not match the manifests being released")
    if problems:
        raise RuntimeError("pre-release DB verification failed: " + "; ".join(problems))

    return {
        "sqlite_integrity": integrity,
        "foreign_key_issues": len(foreign_key_issues),
        "missing_tables": missing_tables,
        "records": records,
        "fts_records": fts_records,
        "chunks": chunks,
        "chunk_fts": chunk_fts,
        "dataset_counts": dict(sorted(dataset_counts.items())),
        "schema_version": int(meta.get("schema_version", "0")),
        "database_version": meta.get("database_version", ""),
        **stable_fingerprints,
        "source_manifest_digests": dict(sorted(db_source_digests.items())),
    }


def _compress_database(source_path: Path, output_path: Path) -> None:
    with source_path.open("rb") as source, output_path.open("wb") as raw_output:
        with gzip.GzipFile(
            filename="", fileobj=raw_output, mode="wb", compresslevel=1, mtime=0
        ) as destination:
            shutil.copyfileobj(source, destination, length=1024 * 1024)


def _split_if_needed(path: Path, max_bytes: int) -> list[Path]:
    for stale in path.parent.glob(path.name + ".part-*"):
        stale.unlink(missing_ok=True)
    if path.stat().st_size <= max_bytes:
        return [path]
    parts: list[Path] = []
    with path.open("rb") as source:
        index = 0
        while True:
            block = source.read(max_bytes)
            if not block:
                break
            part = path.with_name(f"{path.name}.part-{index:03d}")
            part.write_bytes(block)
            parts.append(part)
            index += 1
    if len(parts) < 2 or any(p.stat().st_size > max_bytes for p in parts):
        raise RuntimeError("failed to split compressed DB into safe-sized release assets")
    return parts


def _bundle_manifests(manifest_dir: Path, archive_path: Path) -> None:
    with tarfile.open(archive_path, "w:gz") as archive:
        readme = manifest_dir / "README.md"
        if readme.is_file():
            archive.add(readme, arcname="manifests/README.md", recursive=False)
        for path in sorted(manifest_dir.glob("*.json")):
            if path.name.casefold() != "example.json":
                archive.add(path, arcname=f"manifests/{path.name}", recursive=False)


def package_release(
    *,
    db_path: str | Path,
    build_report_path: str | Path,
    live_rag_report_path: str | Path,
    manifest_dir: str | Path,
    output_dir: str | Path,
    repository: str,
    commit_sha: str,
    run_number: str | int,
    run_attempt: str | int,
    max_asset_bytes: int = DEFAULT_MAX_ASSET_BYTES,
) -> dict[str, Any]:
    if max_asset_bytes <= 0:
        raise ValueError("max_asset_bytes must be positive")
    db = Path(db_path).expanduser().resolve()
    build_path = Path(build_report_path).expanduser().resolve()
    live_path = Path(live_rag_report_path).expanduser().resolve()
    manifests = Path(manifest_dir).expanduser().resolve()
    output = Path(output_dir).expanduser().resolve()
    output.mkdir(parents=True, exist_ok=True)

    build_report = _read_json(build_path)
    live_report = _read_json(live_path)
    verification = build_report.get("database_verification")
    if build_report.get("overall") != "PASS" or build_report.get("success") is not True:
        raise RuntimeError("refusing release: full database build report is not PASS")
    if not isinstance(verification, dict) or verification.get("pass") is not True:
        raise RuntimeError("refusing release: full SQLite/FTS/RAG verification is not PASS")
    probes = live_report.get("tests")
    if live_report.get("overall") != "PASS" or live_report.get("success") is not True:
        raise RuntimeError("refusing release: live RAG/API report is not PASS")
    if not isinstance(probes, list) or not probes or any(
        not isinstance(row, dict) or row.get("pass") is not True for row in probes
    ):
        raise RuntimeError("refusing release: live RAG/API report has missing or failed probes")

    source_digests = _manifest_snapshot(manifests)
    if verification.get("source_manifest_digests") not in (None, source_digests):
        raise RuntimeError("build report's source-manifest snapshot differs from current manifests")
    db_sha = sha256_file(db)
    db_bytes = db.stat().st_size
    # The live API intentionally updates knowledge_meta.last_opened_at. The raw
    # SQLite file hash can therefore change without any knowledge evidence being
    # modified. Pin the stable content tables and compare those after RAG probes.
    actual = _inspect_database(db, source_digests)
    for field in (
        "records", "fts_records", "chunks", "chunk_fts", "schema_version",
        "database_version", "record_table_sha256", "relations_table_sha256",
        "chunks_table_sha256",
    ):
        if not verification.get(field):
            raise RuntimeError(f"build report lacks required stable verification field: {field}")
        if actual.get(field) != verification.get(field):
            raise RuntimeError(
                f"DB {field} differs from build report: "
                f"report={verification.get(field)!r}, actual={actual.get(field)!r}"
            )
    if actual["dataset_counts"] != verification.get("dataset_counts"):
        raise RuntimeError("per-dataset record counts differ from the full build report")

    tag = f"ai-cyber-knowledge-db-{run_number}-{run_attempt}"
    compressed = output / "ai_cyber_knowledge.sqlite3.gz"
    _compress_database(db, compressed)
    compressed_sha = sha256_file(compressed)
    compressed_bytes = compressed.stat().st_size
    recovered_digest = hashlib.sha256()
    recovered_bytes = 0
    with gzip.open(compressed, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            recovered_digest.update(block)
            recovered_bytes += len(block)
    if recovered_digest.hexdigest() != db_sha or recovered_bytes != db_bytes:
        raise RuntimeError("compressed package does not reconstruct the exact verified DB")
    db_assets = _split_if_needed(compressed, max_asset_bytes)

    bundle = output / "source-manifests.tar.gz"
    _bundle_manifests(manifests, bundle)
    checksums_path = output / "knowledge-db-release-checksums.txt"
    checksum_lines = [
        f"{db_sha}  ai_cyber_knowledge.sqlite3",
        f"{compressed_sha}  ai_cyber_knowledge.sqlite3.gz",
    ]
    for path in db_assets + [bundle, build_path, live_path]:
        checksum_lines.append(f"{sha256_file(path)}  {path.name}")
    checksums_path.write_text("\n".join(checksum_lines) + "\n", encoding="utf-8")

    release_manifest = {
        "format_version": 1,
        "release_tag": tag,
        "repository": repository,
        "source_commit": commit_sha,
        "workflow_run_number": str(run_number),
        "workflow_run_attempt": str(run_attempt),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "database": {
            "uncompressed_filename": "ai_cyber_knowledge.sqlite3",
            "uncompressed_bytes": db_bytes,
            "uncompressed_sha256": db_sha,
            "compression": "gzip level 1, deterministic gzip mtime=0",
            "compressed_bytes": compressed_bytes,
            "compressed_sha256": compressed_sha,
            "release_asset_files": [path.name for path in db_assets],
            "chunked": len(db_assets) > 1,
            "max_asset_bytes": max_asset_bytes,
        },
        "verification": actual,
        "build_validation_db_sha256": verification.get("db_sha256"),
        "build_validation_db_bytes": verification.get("db_bytes"),
        "note": (
            "Final database SHA-256 below is measured after localhost RAG/API probes. "
            "SQLite open metadata such as last_opened_at may legitimately change the raw "
            "database hash; stable knowledge records, relations, chunks and counts are "
            "compared against the full-build report before publication."
        ),
        "source_manifests": source_digests,
        "source_manifest_bundle": {
            "filename": bundle.name,
            "bytes": bundle.stat().st_size,
            "sha256": sha256_file(bundle),
        },
        "reports": {
            "database_build": build_path.name,
            "live_rag_api": live_path.name,
            "live_rag_probe_count": len(probes),
        },
    }
    manifest_path = output / "knowledge-db-release-manifest.json"
    manifest_path.write_text(
        json.dumps(release_manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    asset_names = [p.name for p in db_assets] + [
        manifest_path.name, checksums_path.name, bundle.name,
        build_path.name, live_path.name, "release-assets.json",
    ]
    plan = {
        "release_tag": tag,
        "asset_files": asset_names,
        "database_asset_files": [p.name for p in db_assets],
        "chunked_database": len(db_assets) > 1,
    }
    (output / "release-assets.json").write_text(
        json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return {
        "success": True,
        "overall": "PASS",
        "release_tag": tag,
        "database_bytes": db_bytes,
        "database_sha256": db_sha,
        "compressed_bytes": compressed_bytes,
        "compressed_sha256": compressed_sha,
        "database_asset_files": [p.name for p in db_assets],
        "asset_files": asset_names,
        "dataset_counts": actual["dataset_counts"],
        "manifest_count": len(source_digests),
        "records": actual["records"],
        "chunks": actual["chunks"],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db-path", type=Path, required=True)
    parser.add_argument("--build-report", type=Path, required=True)
    parser.add_argument("--live-rag-report", type=Path, required=True)
    parser.add_argument("--manifest-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--commit-sha", required=True)
    parser.add_argument("--run-number", required=True)
    parser.add_argument("--run-attempt", required=True)
    parser.add_argument("--max-asset-bytes", type=int, default=DEFAULT_MAX_ASSET_BYTES)
    args = parser.parse_args(argv)
    try:
        result = package_release(
            db_path=args.db_path,
            build_report_path=args.build_report,
            live_rag_report_path=args.live_rag_report,
            manifest_dir=args.manifest_dir,
            output_dir=args.output_dir,
            repository=args.repository,
            commit_sha=args.commit_sha,
            run_number=args.run_number,
            run_attempt=args.run_attempt,
            max_asset_bytes=args.max_asset_bytes,
        )
    except Exception as exc:
        print(json.dumps({"success": False, "overall": "FAIL",
                          "error": f"{type(exc).__name__}: {exc}"}, indent=2))
        return 2
    print(json.dumps(result, indent=2, ensure_ascii=False))
    print(f"RELEASE_MANIFEST={Path(args.output_dir).expanduser().resolve() / 'knowledge-db-release-manifest.json'}")
    print(f"RELEASE_ASSET_PLAN={Path(args.output_dir).expanduser().resolve() / 'release-assets.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
