"""Read-only verification and runtime gating for the permanent Knowledge DB.

This module never creates or upgrades a database. It is safe to use before
starting the RAG/API service, including when the configured file is missing.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
from pathlib import Path
from typing import Any

from .knowledge import DATABASE_VERSION, DEFAULT_DB, SCHEMA_VERSION

APPROVED_DATASETS = (
    "capec",
    "cisa_kev",
    "cpe",
    "cwe",
    "epss",
    "mitre_attack",
    "mitre_d3fend",
    "mitre_mbc",
    "sigma",
    "suricata",
    "zeek_intel",
)
REQUIRED_TABLES = {
    "knowledge_records",
    "knowledge_relations",
    "knowledge_fts",
    "knowledge_chunks",
    "knowledge_chunks_fts",
    "knowledge_meta",
    "knowledge_ingestion_checkpoints",
}
_SHA256 = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)


class KnowledgeRuntimeBlocked(RuntimeError):
    """Raised when strict runtime mode has no verified populated DB."""


def configured_database_path() -> Path:
    """Resolve the configured DB dynamically so late env setup is not ignored."""
    value = os.environ.get("AI_CYBER_KNOWLEDGE_DB", "").strip()
    return Path(value).expanduser() if value else DEFAULT_DB.expanduser()


def require_verified_db_enabled() -> bool:
    """Strict mode prevents missing/wrong configured DBs from being auto-created."""
    return os.environ.get("AI_CYBER_REQUIRE_VERIFIED_DB", "").strip().lower() in {
        "1", "true", "yes", "on",
    }


def verify_database(
    db_path: str | Path | None = None,
    *,
    deep: bool = True,
    required_datasets: tuple[str, ...] = APPROVED_DATASETS,
) -> dict[str, Any]:
    """Verify a populated 11-dataset SQLite store without writing to it.

    With deep=True this performs SQLite integrity, FTS parity, and checkpoint
    checks. With deep=False it performs a fast runtime gate suitable for API
    requests; it still checks schema/version, 11-source scope, and manifest pins.
    """
    path = Path(db_path).expanduser() if db_path is not None else configured_database_path()
    path = path.resolve()
    report: dict[str, Any] = {
        "success": False,
        "overall": "BLOCKED",
        "database_file": path.name,
        "database_bytes": 0,
        "deep_check": bool(deep),
        "required_dataset_count": len(required_datasets),
        "required_datasets": list(required_datasets),
        "errors": [],
    }
    if not path.is_file():
        report["errors"].append("configured Knowledge DB file does not exist; no file was created")
        return report
    report["database_bytes"] = path.stat().st_size
    if report["database_bytes"] <= 0:
        report["overall"] = "FAIL"
        report["errors"].append("configured Knowledge DB file is empty")
        return report

    try:
        uri = path.as_uri() + "?mode=ro"
        connection = sqlite3.connect(uri, uri=True, timeout=60)
        connection.row_factory = sqlite3.Row
    except (OSError, sqlite3.Error, ValueError) as exc:
        report["overall"] = "FAIL"
        report["errors"].append(f"cannot open Knowledge DB read-only: {type(exc).__name__}: {exc}")
        return report

    try:
        table_names = {
            str(row[0]) for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type IN ('table','view')"
            )
        }
        missing_tables = sorted(REQUIRED_TABLES - table_names)
        if missing_tables:
            report["overall"] = "FAIL"
            report["errors"].append(f"required tables missing: {missing_tables}")
            return report

        metadata = {
            str(row["key"]): str(row["value"])
            for row in connection.execute("SELECT key, value FROM knowledge_meta")
        }
        dataset_counts = {
            str(row["dataset"]): int(row["records"])
            for row in connection.execute(
                "SELECT dataset, COUNT(*) AS records FROM knowledge_records "
                "GROUP BY dataset ORDER BY dataset"
            )
        }
        record_count = int(
            connection.execute("SELECT COUNT(*) FROM knowledge_records").fetchone()[0]
        )
        report.update({
            "database_version": metadata.get("database_version"),
            "schema_version": metadata.get("schema_version"),
            "records": record_count,
            "datasets": dataset_counts,
            "missing_datasets": sorted(set(required_datasets) - set(dataset_counts)),
            "unexpected_datasets": sorted(set(dataset_counts) - set(required_datasets)),
        })

        if metadata.get("database_version") != DATABASE_VERSION:
            report["errors"].append(
                f"database version must be {DATABASE_VERSION!r}, got {metadata.get('database_version')!r}"
            )
        try:
            actual_schema_version = int(metadata.get("schema_version", "0"))
        except (TypeError, ValueError):
            actual_schema_version = 0
        if actual_schema_version != SCHEMA_VERSION:
            report["errors"].append(
                f"schema version must be {SCHEMA_VERSION}, got {actual_schema_version}"
            )

        if record_count <= 0:
            report["errors"].append("Knowledge DB has no records")
        empty_required = sorted(
            name for name in required_datasets if dataset_counts.get(name, 0) <= 0
        )
        if empty_required:
            report["errors"].append(f"required datasets have no records: {empty_required}")
        unexpected = sorted(set(dataset_counts) - set(required_datasets))
        if unexpected:
            report["errors"].append(
                f"database contains datasets outside the approved scope: {unexpected}"
            )

        ledger_text = metadata.get("source_manifest_digests", "")
        try:
            ledger = json.loads(ledger_text)
            if not isinstance(ledger, dict):
                raise ValueError("manifest digest ledger must be a JSON object")
        except (json.JSONDecodeError, ValueError) as exc:
            ledger = {}
            report["errors"].append(f"source manifest digest ledger is invalid: {exc}")
        ledger_names = set(str(name) for name in ledger)
        if ledger_names != set(required_datasets):
            report["errors"].append(
                "source manifest digest ledger does not exactly cover the approved set; "
                f"missing={sorted(set(required_datasets) - ledger_names)}, "
                f"unexpected={sorted(ledger_names - set(required_datasets))}"
            )
        bad_digests = sorted(
            str(name) for name, digest in ledger.items()
            if not isinstance(digest, str) or not _SHA256.fullmatch(digest)
        )
        if bad_digests:
            report["errors"].append(f"invalid pinned manifest SHA-256 values: {bad_digests}")
        report["source_manifest_ledger_verified"] = not any(
            "ledger" in error or "manifest SHA-256" in error for error in report["errors"]
        )

        if deep:
            integrity_rows = [
                str(row[0]) for row in connection.execute("PRAGMA integrity_check")
            ]
            report["sqlite_integrity_check"] = (
                integrity_rows[0] if len(integrity_rows) == 1 else "; ".join(integrity_rows)
            )
            if integrity_rows != ["ok"]:
                report["errors"].append(
                    f"SQLite integrity_check failed: {integrity_rows[:10]}"
                )

            fk_issues = connection.execute("PRAGMA foreign_key_check").fetchall()
            report["foreign_key_issues"] = len(fk_issues)
            if fk_issues:
                report["errors"].append(f"SQLite foreign-key issues: {len(fk_issues)}")

            fts_count = int(
                connection.execute("SELECT COUNT(*) FROM knowledge_fts").fetchone()[0]
            )
            chunk_count = int(
                connection.execute("SELECT COUNT(*) FROM knowledge_chunks").fetchone()[0]
            )
            chunk_fts_count = int(
                connection.execute("SELECT COUNT(*) FROM knowledge_chunks_fts").fetchone()[0]
            )
            checkpoint_rows = {
                str(row["status"]): int(row["count"])
                for row in connection.execute(
                    "SELECT status, COUNT(*) AS count FROM knowledge_ingestion_checkpoints "
                    "GROUP BY status ORDER BY status"
                )
            }
            unfinished = {
                name: count for name, count in checkpoint_rows.items()
                if name != "complete" and count
            }
            report.update({
                "knowledge_fts_rows": fts_count,
                "chunks": chunk_count,
                "chunk_fts_rows": chunk_fts_count,
                "checkpoint_status_counts": checkpoint_rows,
                "unfinished_checkpoints": unfinished,
            })
            if fts_count != record_count:
                report["errors"].append(
                    f"knowledge_fts rows {fts_count} do not match records {record_count}"
                )
            if chunk_fts_count != chunk_count:
                report["errors"].append(
                    f"knowledge_chunks_fts rows {chunk_fts_count} do not match chunks {chunk_count}"
                )
            if unfinished:
                report["errors"].append(
                    f"unfinished or failed ingestion checkpoints remain: {unfinished}"
                )
    except (sqlite3.Error, OSError, ValueError) as exc:
        report["overall"] = "FAIL"
        report["errors"].append(f"{type(exc).__name__}: {exc}")
        return report
    finally:
        connection.close()

    report["success"] = not report["errors"]
    report["overall"] = "PASS" if report["success"] else "FAIL"
    return report


def require_runtime_database(db_path: str | Path | None = None) -> Path:
    """Fail closed in strict mode before knowledge APIs can create an empty store."""
    path = Path(db_path).expanduser() if db_path is not None else configured_database_path()
    path = path.resolve()
    if require_verified_db_enabled():
        report = verify_database(path, deep=False)
        if report.get("success") is not True:
            errors = "; ".join(str(item) for item in report.get("errors", []))
            raise KnowledgeRuntimeBlocked(
                f"configured Knowledge DB is not runtime-ready: {errors or report.get('overall')}"
            )
    return path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, default=None, help="SQLite path; defaults to AI_CYBER_KNOWLEDGE_DB")
    parser.add_argument("--quick", action="store_true", help="Skip full SQLite/FTS integrity scan")
    parser.add_argument("--report", type=Path, default=None, help="Optional JSON report destination")
    args = parser.parse_args(argv)
    report = verify_database(args.db, deep=not args.quick)
    payload = json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True)
    print(payload)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(payload + "\n", encoding="utf-8")
    return 0 if report["success"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
