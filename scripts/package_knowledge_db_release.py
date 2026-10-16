#!/usr/bin/env python3
"""Verify and package a populated AI-CYBER Knowledge DB for durable release."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import re
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
        if manifest.get("license_verified") is not True:
            raise RuntimeError(f"refusing public release: licence/terms not verified for dataset {dataset!r}")
        license_text = manifest.get("license")
        license_url = manifest.get("license_url")
        if not isinstance(license_text, str) or not license_text.strip():
            raise RuntimeError(f"refusing public release: dataset {dataset!r} has no license description")
        if not isinstance(license_url, str) or not license_url.startswith("https://"):
            raise RuntimeError(f"refusing public release: dataset {dataset!r} has no HTTPS source-terms URL")
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


def _assert_no_etpro_suricata_records(conn: sqlite3.Connection) -> None:
    """Block public redistribution of the upstream ETPRO-only Suricata SID range."""
    pattern = re.compile(r"\bsid\s*:\s*(\d+)\b", re.IGNORECASE)
    for record_id, content in conn.execute(
        "SELECT record_id, content FROM knowledge_records WHERE lower(dataset)='suricata'"
    ):
        for match in pattern.finditer(str(content or "")):
            sid = int(match.group(1))
            if 2_800_000 <= sid <= 2_900_000:
                raise RuntimeError(
                    "public Knowledge DB release blocked: Suricata record "
                    f"{record_id!r} contains ETPRO-only SID {sid}; remove/re-license "
                    "the rule before publishing. The upstream ET Open notice is SID-specific."
                )


def _project_root_for_manifests(manifest_dir: Path) -> Path:
    # Production path is <repo>/datasets/manifests. Keep fixture tests self-contained.
    if manifest_dir.parent.name == "datasets":
        return manifest_dir.parent.parent.resolve()
    return manifest_dir.parent.resolve()


def _license_guidance(dataset: str) -> str:
    guidance = {
        "capec": "MITRE CAPEC terms require preserving MITRE's copyright designation and terms notice when distributing copies.",
        "cwe": "MITRE CWE terms require preserving MITRE's copyright designation and terms notice; CWE is a MITRE trademark.",
        "mitre_attack": "Preserve the upstream ATT&CK copyright designation and license. Required designation: © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.",
        "cpe": "Credit NIST/NVD for the public CPE Dictionary. Public availability is not a blanket licence for unrelated third-party material embedded in metadata.",
        "nvd_cve": "Credit NIST/NVD and retain record references. Individual CVE descriptions, references or third-party contributions may have separate rights; this notice does not relicense them.",
        "epss": "Credit FIRST/EPSS when scores are used in products, reports or publications, as requested by the upstream EPSS project.",
        "cisa_kev": "Retain the pinned upstream licence text and identify the CISA KEV catalog as the source. Linked third-party material may have separate terms.",
        "mitre_d3fend": "Preserve the bundled MIT licence and MITRE D3FEND attribution. Follow separate upstream terms for third-party material included in the ontology.",
        "mitre_mbc": "Preserve the bundled Apache-2.0 licence and all upstream notices.",
        "sigma": "Preserve each rule's author field, author attribution, the rule/source URI and the DRL 1.1 notice. Attribution also applies when a rule match is shown in output.",
        "suricata": "The upstream notice identifies SID-scoped GPLv2 and BSD-style terms plus a separate ETPRO-only range. This release gate blocks SIDs 2800000–2900000; do not describe all rules as BSD-only.",
        "zeek_intel": "Preserve the bundled Zeek BSD-style copyright, redistribution conditions and disclaimer; some upstream files may carry additional notices.",
    }
    return guidance.get(
        dataset,
        "Preserve source identity, links and upstream copyright/licence notices; examine item-specific terms where present.",
    )


def _write_third_party_notices(manifest_dir: Path, output_path: Path) -> list[dict[str, Any]]:
    manifests = [
        _read_json(path) for path in sorted(manifest_dir.glob("*.json"))
        if path.name.casefold() != "example.json"
    ]
    missing = sorted(REQUIRED_DATASETS - {m.get("dataset") for m in manifests})
    if missing:
        raise RuntimeError(f"cannot write third-party notices; missing manifests: {missing}")
    lines = [
        "# AI-CYBER Knowledge DB — Third-Party Data Notices",
        "",
        f"Generated at {datetime.now(timezone.utc).isoformat()} from the pinned source-manifest snapshot.",
        "",
        "This notice ledger is provenance and attribution guidance, not legal advice and not a new licence. "
        "Each upstream licence or terms page controls its own content. A dataset-level review does not "
        "relicense third-party text, references, rule authorship, or other embedded material. Preserve "
        "original record identifiers, source URIs, author fields and notices when displaying or exporting evidence.",
        "",
    ]
    for manifest in sorted(manifests, key=lambda m: str(m.get("dataset", ""))):
        dataset = str(manifest.get("dataset", "unknown"))
        lines.extend([
            f"## {dataset}",
            "",
            f"- Source: {manifest.get('source', 'not declared')}",
            f"- Version: {manifest.get('version', 'not declared')}",
            f"- Source data: {manifest.get('source_uri', 'not declared')}",
            f"- Licence / terms recorded in manifest: {manifest.get('license', 'not declared')}",
            f"- Official terms URL: {manifest.get('license_url', 'not declared')}",
            f"- Source terms reviewed: {'yes' if manifest.get('license_verified') is True else 'NO — release blocked'}",
            f"- Attribution / redistribution notes: {_license_guidance(dataset)}",
        ])
        declared = list(manifest.get("license_files", []) or [])
        for item in manifest.get("artifacts", []) or []:
            if isinstance(item, dict) and str(item.get("role", "")).lower() == "license":
                declared.append(item.get("path"))
        declared = sorted({str(value) for value in declared if isinstance(value, str) and value.strip()})
        if declared:
            lines.append(f"- Bundled upstream notice/licence files: {', '.join(declared)}")
        lines.append("")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return [
        {"dataset": str(m.get("dataset")), "license_url": m.get("license_url"),
         "license_verified": m.get("license_verified") is True}
        for m in sorted(manifests, key=lambda m: str(m.get("dataset", "")))
    ]


def _bundle_manifests(
    manifest_dir: Path, archive_path: Path, notices_path: Path
) -> list[dict[str, Any]]:
    root = _project_root_for_manifests(manifest_dir)
    manifests = [
        _read_json(path) for path in sorted(manifest_dir.glob("*.json"))
        if path.name.casefold() != "example.json"
    ]
    by_path: dict[str, dict[str, Any]] = {}
    for manifest in manifests:
        declared = list(manifest.get("license_files", []) or [])
        for item in manifest.get("artifacts", []) or []:
            if isinstance(item, dict) and str(item.get("role", "")).lower() == "license":
                declared.append(item.get("path"))
        artifact_hashes = {
            str(item.get("path")): str(item.get("sha256", "")).lower()
            for item in manifest.get("artifacts", []) or []
            if isinstance(item, dict) and str(item.get("role", "")).lower() == "license"
        }
        for value in declared:
            if not isinstance(value, str) or not value.strip():
                continue
            relative = Path(value)
            if relative.is_absolute() or ".." in relative.parts or "\\" in value:
                raise RuntimeError(f"unsafe third-party notice path in manifest: {value!r}")
            local = (root / relative).resolve()
            try:
                local.relative_to(root.resolve())
            except ValueError as exc:
                raise RuntimeError(f"third-party notice path escapes repository root: {value!r}") from exc
            if not local.is_file():
                raise FileNotFoundError(f"declared licence/notice file is missing: {value}")
            actual_sha = sha256_file(local)
            expected_sha = artifact_hashes.get(value)
            if expected_sha and actual_sha != expected_sha:
                raise RuntimeError(f"declared licence-file SHA-256 mismatch: {value}")
            by_path[relative.as_posix()] = {
                "path": relative.as_posix(), "sha256": actual_sha,
                "bytes": local.stat().st_size, "local": local,
            }

    authored_notice = root / "datasets" / "licenses" / "THIRD_PARTY_NOTICES.md"
    if authored_notice.is_file():
        path = Path("datasets/licenses/THIRD_PARTY_NOTICES.md")
        by_path[path.as_posix()] = {
            "path": path.as_posix(), "sha256": sha256_file(authored_notice),
            "bytes": authored_notice.stat().st_size, "local": authored_notice,
        }

    archive_path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive_path, "w:gz") as archive:
        readme = manifest_dir / "README.md"
        if readme.is_file():
            archive.add(readme, arcname="manifests/README.md", recursive=False)
        for path in sorted(manifest_dir.glob("*.json")):
            if path.name.casefold() != "example.json":
                archive.add(path, arcname=f"manifests/{path.name}", recursive=False)
        for rel, row in sorted(by_path.items()):
            archive.add(row["local"], arcname=f"source-licenses/{rel}", recursive=False)
        archive.add(notices_path, arcname="THIRD_PARTY_NOTICES.md", recursive=False)
    return [
        {key: value for key, value in row.items() if key != "local"}
        for _, row in sorted(by_path.items())
    ]


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
        if not missing_tables:
            _assert_no_etpro_suricata_records(connection)
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

    notices_path = output / "THIRD_PARTY_NOTICES.md"
    notice_ledger = _write_third_party_notices(manifests, notices_path)
    bundle = output / "source-manifests.tar.gz"
    bundled_license_files = _bundle_manifests(manifests, bundle, notices_path)
    checksums_path = output / "knowledge-db-release-checksums.txt"
    checksum_lines = [
        f"{db_sha}  ai_cyber_knowledge.sqlite3",
        f"{compressed_sha}  ai_cyber_knowledge.sqlite3.gz",
    ]
    for path in db_assets + [bundle, notices_path, build_path, live_path]:
        checksum_lines.append(f"{sha256_file(path)}  {path.name}")
    for item in bundled_license_files:
        checksum_lines.append(f"{item['sha256']}  source-licenses/{item['path']}")
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
        "third_party_notices": {
            "filename": notices_path.name,
            "bytes": notices_path.stat().st_size,
            "sha256": sha256_file(notices_path),
            "datasets": notice_ledger,
        },
        "bundled_source_license_files": bundled_license_files,
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
        manifest_path.name, checksums_path.name, bundle.name, notices_path.name,
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
