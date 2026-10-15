"""Manifest-driven dataset ingestion for AI-CYBER."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .knowledge import ingest_file, iter_records, open_store, status

MANIFEST_REQUIRED = {
    "dataset",
    "version",
    "source",
    "source_uri",
    "license",
    "local_path",
    "sha256",
    "record_count",
    "schema",
    "ingestion_status",
    "validation_status",
}


def sha256_file(path: str | Path, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as fh:
        for chunk in iter(lambda: fh.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()


def load_manifest(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    data = json.loads(p.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("manifest must be a JSON object")
    if "artifacts" in data:
        if not isinstance(data["artifacts"], list) or not data["artifacts"]:
            raise ValueError("manifest artifacts must be a non-empty list")
        for index, item in enumerate(data["artifacts"]):
            if not isinstance(item, dict):
                raise ValueError(f"manifest artifact {index} must be an object")
            if not isinstance(item.get("path"), str) or not item["path"].strip():
                raise ValueError(f"manifest artifact {index} path must be a non-empty string")
            if not isinstance(item.get("sha256"), str) or not item["sha256"].strip():
                raise ValueError(f"manifest artifact {index} sha256 must be a non-empty string")
            digest = item["sha256"].strip().lower()
            if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
                raise ValueError(f"manifest artifact {index} has invalid SHA-256")
            role = str(item.get("role", "data")).lower()
            if "record_count" not in item:
                raise ValueError(f"manifest artifact {index} is missing record_count")
            raw_count = item["record_count"]
            if role == "license" and raw_count is None:
                continue
            if isinstance(raw_count, bool) or not isinstance(raw_count, int):
                raise ValueError(f"manifest artifact {index} record_count must be an integer")
            count = raw_count
            if count < 0:
                raise ValueError(f"manifest artifact {index} record_count must be non-negative")
        return data
    missing = sorted(MANIFEST_REQUIRED - set(data))
    if missing:
        raise ValueError(f"manifest missing required fields: {', '.join(missing)}")
    if not isinstance(data["schema"], (dict, list, str)):
        raise ValueError("manifest schema must be an object, list, or string")
    if not isinstance(data["sha256"], str):
        raise ValueError("manifest sha256 must be a string")
    digest = data["sha256"].strip().lower()
    if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
        raise ValueError("manifest sha256 must be a 64-character hexadecimal SHA-256")
    raw_record_count = data["record_count"]
    if isinstance(raw_record_count, bool) or not isinstance(raw_record_count, int):
        raise ValueError("manifest record_count must be an integer")
    record_count = raw_record_count
    if record_count < 0:
        raise ValueError("manifest record_count must be non-negative")
    if not str(data["dataset"]).strip():
        raise ValueError("manifest dataset must not be empty")
    if not isinstance(data["local_path"], str) or not data["local_path"].strip():
        raise ValueError("manifest local_path must be a non-empty string")
    for field in ("dataset", "version", "source", "source_uri", "license",
                  "ingestion_status", "validation_status"):
        if not isinstance(data[field], str):
            raise ValueError(f"manifest {field} must be a string")
    return data


def _project_root(manifest_path: str | Path) -> Path:
    """Resolve repository/project root from a manifest path."""
    p = Path(manifest_path).resolve()
    for parent in (p.parent, *p.parents):
        if parent.name == "datasets":
            return parent.parent.resolve()
    return p.parent.resolve()


def _count_artifact_records(
    local: Path,
    *,
    manifest: dict[str, Any],
    item: dict[str, Any],
    manifest_path: str | Path,
) -> int:
    """Count logical records with format-aware parsers for special source archives."""
    count_kind = str(item.get("count_kind", "")).casefold()
    common = {
        "dataset": manifest.get("dataset", Path(manifest_path).stem),
        "source": item.get("source", manifest.get("source", "")),
        "version": item.get("version", manifest.get("version", "")),
        "source_uri": item.get("source_uri", manifest.get("source_uri", "")),
        "license": item.get("license", manifest.get("license", "")),
        "validation_status": item.get("validation_status", manifest.get("validation_status", "unverified")),
    }
    if count_kind in {"nvd", "nvd-feed", "nvd_cve"}:
        from .threat_intel import parse_nvd
        return len(parse_nvd(local, **common))
    if count_kind == "mbc":
        from .threat_intel import parse_mbc_stix
        return len(parse_mbc_stix(local, **common))
    if count_kind == "suricata":
        from .threat_intel import parse_suricata_rules
        return len(parse_suricata_rules(local, **common))

    schema = manifest.get("schema", {})
    record_elements = schema.get("elements") if isinstance(schema, dict) else None
    schema_format = str(schema.get("format", "")).lower() if isinstance(schema, dict) else ""
    record_extensions = {".yml", ".yaml"} if "yaml rules inside archive" in schema_format else None
    return sum(
        1
        for _ in iter_records(
            local,
            dataset=common["dataset"],
            source=common["source"],
            license=common["license"],
            version=common["version"],
            source_uri=common["source_uri"],
            validation_status=common["validation_status"],
            record_elements=record_elements,
            record_extensions=record_extensions,
        )
    )


def _artifact_inspection(
    manifest_path: str | Path, manifest: dict[str, Any]
) -> dict[str, Any]:
    root = _project_root(manifest_path)
    artifacts: list[dict[str, Any]] = []

    for item in manifest["artifacts"]:
        if not isinstance(item, dict) or "path" not in item:
            raise ValueError("each manifest artifact must contain a path")

        local = (root / str(item["path"])).resolve()
        try:
            local.relative_to(root)
        except ValueError as exc:
            raise ValueError(
                "manifest artifact path must remain inside the project"
            ) from exc

        if not local.is_file():
            raise FileNotFoundError(local)

        actual_sha = sha256_file(local)
        expected_sha = str(item["sha256"]).lower().strip()
        actual_size = local.stat().st_size
        declared_size = item.get("byte_size")
        size_matches = declared_size is None or (
            isinstance(declared_size, int) and not isinstance(declared_size, bool)
            and actual_size == declared_size
        )

        role = str(item.get("role", "data")).lower()
        if role == "license":
            # License text is integrity-checked but is not a knowledge record.
            count = 0
            count_matches = True
            declared_count = None
        else:
            count = _count_artifact_records(
                local, manifest=manifest, item=item, manifest_path=manifest_path
            )
            declared_count = item["record_count"]
            count_matches = count == declared_count

        artifacts.append({
            "path": str(local),
            "role": role,
            "sha256": actual_sha,
            "sha256_matches": actual_sha == expected_sha,
            "byte_size": actual_size,
            "declared_byte_size": declared_size,
            "byte_size_matches": size_matches,
            "records": count,
            "declared_record_count": declared_count,
            "record_count_matches": count_matches,
            "count_kind": item.get("count_kind"),
        })

    return {
        "dataset": manifest.get("dataset", Path(manifest_path).stem),
        "version": manifest.get("version", ""),
        "artifacts": artifacts,
        "records": sum(a["records"] for a in artifacts),
        "ready": all(
            a["sha256_matches"] and a["byte_size_matches"] and a["record_count_matches"]
            for a in artifacts
        ),
    }


def inspect_dataset(manifest_path: str | Path) -> dict[str, Any]:
    manifest = load_manifest(manifest_path)

    if "artifacts" in manifest:
        return _artifact_inspection(manifest_path, manifest)

    root = _project_root(manifest_path)
    local = (root / manifest["local_path"]).resolve()
    try:
        local.relative_to(root)
    except ValueError as exc:
        raise ValueError("manifest local_path must remain inside the project") from exc

    if not local.is_file():
        raise FileNotFoundError(local)

    actual_sha = sha256_file(local)
    expected_sha = manifest["sha256"].lower().strip()
    actual_size = local.stat().st_size
    declared_size = manifest.get("byte_size")
    size_matches = declared_size is None or (
        isinstance(declared_size, int) and not isinstance(declared_size, bool)
        and actual_size == declared_size
    )
    records = sum(
        1 for _ in iter_records(
            local,
            dataset=manifest["dataset"],
            source=manifest["source"],
            license=manifest["license"],
            version=manifest["version"],
            source_uri=manifest["source_uri"],
            validation_status=manifest["validation_status"],
            record_elements=(manifest.get("schema", {}).get("elements")
                             if isinstance(manifest.get("schema"), dict) else None),
        )
    )
    declared = manifest["record_count"]

    return {
        "dataset": manifest["dataset"],
        "version": manifest["version"],
        "path": str(local),
        "sha256": actual_sha,
        "sha256_matches": actual_sha == expected_sha,
        "byte_size": actual_size,
        "declared_byte_size": declared_size,
        "byte_size_matches": size_matches,
        "records": records,
        "declared_record_count": declared,
        "record_count_matches": records == declared,
        "manifest_validation_status": manifest["validation_status"],
        "ready": actual_sha == expected_sha and size_matches and records == declared,
    }


def _checkpoint_read(
    db_path: str | Path,
    *,
    manifest_path: str,
    manifest_sha256: str,
    artifact_path: str,
    artifact_sha256: str,
) -> dict[str, Any] | None:
    db = open_store(db_path)
    try:
        row = db.execute(
            """SELECT * FROM knowledge_ingestion_checkpoints
               WHERE manifest_path=? AND manifest_sha256=?
                 AND artifact_path=? AND artifact_sha256=?""",
            (manifest_path, manifest_sha256, artifact_path, artifact_sha256),
        ).fetchone()
        return dict(row) if row else None
    finally:
        db.close()


def _checkpoint_write(
    db_path: str | Path,
    *,
    manifest_path: str,
    manifest_sha256: str,
    artifact_path: str,
    artifact_sha256: str,
    dataset: str,
    status_value: str,
    expected_records: int,
    processed_records: int = 0,
    inserted_records: int = 0,
    updated_records: int = 0,
    duplicate_records: int = 0,
    error: str | None = None,
) -> None:
    now = datetime.now(timezone.utc).isoformat()
    db = open_store(db_path)
    try:
        db.execute(
            """INSERT INTO knowledge_ingestion_checkpoints
               (manifest_path,manifest_sha256,artifact_path,artifact_sha256,dataset,status,
                expected_records,processed_records,inserted_records,updated_records,
                duplicate_records,started_at,updated_at,error)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(manifest_path,manifest_sha256,artifact_path,artifact_sha256)
               DO UPDATE SET
                dataset=excluded.dataset,status=excluded.status,
                expected_records=excluded.expected_records,
                processed_records=excluded.processed_records,
                inserted_records=excluded.inserted_records,
                updated_records=excluded.updated_records,
                duplicate_records=excluded.duplicate_records,
                updated_at=excluded.updated_at,error=excluded.error""",
            (
                manifest_path, manifest_sha256, artifact_path, artifact_sha256, dataset,
                status_value, expected_records, processed_records, inserted_records,
                updated_records, duplicate_records, now, now, error[:2000] if error else None,
            ),
        )
        db.commit()
    finally:
        db.close()


def _specialized_records(
    local: Path,
    *,
    kind: str,
    dataset: str,
    source: str,
    version: str,
    source_uri: str,
    license: str,
    validation_status: str,
) -> list[dict[str, Any]] | None:
    common = {
        "dataset": dataset,
        "source": source,
        "version": version,
        "source_uri": source_uri,
        "license": license,
        "validation_status": validation_status,
    }
    if kind in {"nvd", "nvd-feed", "nvd_cve"}:
        from .threat_intel import parse_nvd
        return parse_nvd(local, **common)
    if kind in {"kev", "cisa-kev", "cisa_kev"}:
        from .threat_intel import parse_cisa_kev
        return parse_cisa_kev(local, **common)
    if kind in {"d3fend", "d3fend-jsonld"}:
        from .threat_intel import parse_d3fend_jsonld
        return parse_d3fend_jsonld(local, **common)
    if kind == "mbc":
        from .threat_intel import parse_mbc_stix
        return parse_mbc_stix(local, **common)
    if kind == "suricata":
        from .threat_intel import parse_suricata_rules
        return parse_suricata_rules(local, **common)
    return None


def _ingest_one_artifact(
    manifest: dict[str, Any],
    item: dict[str, Any],
    item_inspection: dict[str, Any],
    *,
    manifest_path: str | Path,
    manifest_sha256: str,
    db_path: str | Path,
) -> dict[str, Any]:
    if str(item.get("role", "data")).casefold() == "license":
        return {"skipped": True, "reason": "license artifact", "inserted": 0, "updated": 0, "duplicates": 0}

    root = _project_root(manifest_path)
    local = (root / str(item["path"] if "artifacts" in manifest else manifest["local_path"])).resolve()
    try:
        local.relative_to(root)
    except ValueError as exc:
        raise ValueError("manifest artifact path must remain inside the project") from exc

    dataset = str(manifest.get("dataset") or Path(manifest_path).stem)
    source = str(item.get("source", manifest.get("source", "")))
    version = str(item.get("version", manifest.get("version", "")))
    source_uri = str(item.get("source_uri", manifest.get("source_uri", "")))
    license_text = str(item.get("license", manifest.get("license", "")))
    validation_status = str(item.get("validation_status", manifest.get("validation_status", "unverified")))
    expected_records = int(item_inspection["records"])
    observed_sha256 = str(item_inspection["sha256"])
    artifact_label = str(item.get("path", manifest.get("local_path", local.name)))
    kind = str(item.get("count_kind") or manifest.get("schema", {}).get("parser_kind", "")
               if isinstance(manifest.get("schema"), dict) else item.get("count_kind") or "").casefold()
    manifest_label = str(Path(manifest_path).resolve())

    old = _checkpoint_read(
        db_path,
        manifest_path=manifest_label,
        manifest_sha256=manifest_sha256,
        artifact_path=artifact_label,
        artifact_sha256=observed_sha256,
    )
    if (old and old["status"] == "complete"
            and int(old["processed_records"]) == expected_records
            and int(old["expected_records"]) == expected_records):
        return {
            "skipped": True,
            "reason": "completed checkpoint matches manifest and artifact digests",
            "inserted": 0,
            "updated": 0,
            "duplicates": 0,
            "records": expected_records,
            "checkpoint_status": "complete",
        }

    _checkpoint_write(
        db_path,
        manifest_path=manifest_label,
        manifest_sha256=manifest_sha256,
        artifact_path=artifact_label,
        artifact_sha256=observed_sha256,
        dataset=dataset,
        status_value="running",
        expected_records=expected_records,
    )
    schema = manifest.get("schema", {})
    record_elements = schema.get("elements") if isinstance(schema, dict) else None
    schema_format = str(schema.get("format", "")).casefold() if isinstance(schema, dict) else ""
    record_extensions = (
        {".yml", ".yaml"}
        if "yaml rules inside archive" in schema_format or kind == "sigma"
        else None
    )

    try:
        records = _specialized_records(
            local, kind=kind, dataset=dataset, source=source, version=version,
            source_uri=source_uri, license=license_text,
            validation_status=validation_status,
        )
        if records is not None:
            from .threat_intel import ingest_parsed
            result = ingest_parsed(records, db_path=db_path)
            processed = int(result.get("records", 0))
        else:
            result = ingest_file(
                local, db_path=db_path, dataset=dataset, source=source,
                license=license_text, version=version, source_uri=source_uri,
                validation_status=validation_status, record_elements=record_elements,
                record_extensions=record_extensions,
            )
            processed = int(result.get("records_seen", 0))

        if processed != expected_records:
            raise ValueError(
                f"ingestion parser counted {processed} records but readiness counted "
                f"{expected_records} for {artifact_label}"
            )
        inserted = int(result.get("inserted", 0))
        updated = int(result.get("updated", 0))
        duplicates = int(result.get("duplicates", 0))
        _checkpoint_write(
            db_path,
            manifest_path=manifest_label,
            manifest_sha256=manifest_sha256,
            artifact_path=artifact_label,
            artifact_sha256=observed_sha256,
            dataset=dataset,
            status_value="complete",
            expected_records=expected_records,
            processed_records=processed,
            inserted_records=inserted,
            updated_records=updated,
            duplicate_records=duplicates,
        )
        return {
            "skipped": False, "inserted": inserted, "updated": updated,
            "duplicates": duplicates, "records": processed, "checkpoint_status": "complete",
        }
    except Exception as exc:
        _checkpoint_write(
            db_path,
            manifest_path=manifest_label,
            manifest_sha256=manifest_sha256,
            artifact_path=artifact_label,
            artifact_sha256=observed_sha256,
            dataset=dataset,
            status_value="failed",
            expected_records=expected_records,
            error=f"{type(exc).__name__}: {exc}",
        )
        raise


def ingest_manifest(
    manifest_path: str | Path,
    *,
    db_path: str | Path,
    require_checksum: bool = True,
) -> dict[str, Any]:
    """Verify then ingest one manifest through its format-specific parser.

    Each artifact is checkpointed by manifest SHA-256 plus observed artifact
    SHA-256. Completed artifacts are skipped on restart; interrupted artifacts
    are safely reprocessed with deterministic, idempotent record IDs.
    """
    path = Path(manifest_path).resolve()
    manifest = load_manifest(path)
    inspection = inspect_dataset(path)

    if "artifacts" not in manifest:
        if require_checksum and not inspection["sha256_matches"]:
            raise ValueError("dataset SHA-256 does not match manifest")
        if not inspection["byte_size_matches"]:
            raise ValueError("dataset byte size does not match manifest")
        if not inspection["record_count_matches"]:
            raise ValueError("dataset record count does not match manifest")
        integrity_ok = inspection["byte_size_matches"] and inspection["record_count_matches"] and (
            inspection["sha256_matches"] or not require_checksum
        )
        if not integrity_ok:
            raise ValueError("dataset manifest integrity/count validation failed")
        item = {
            "path": manifest["local_path"],
            "sha256": inspection["sha256"],
            "byte_size": inspection["byte_size"],
            "record_count": inspection["records"],
            "role": "data",
            "count_kind": (
                manifest.get("schema", {}).get("parser_kind", "")
                if isinstance(manifest.get("schema"), dict) else ""
            ),
        }
        item_inspection = {
            "sha256": inspection["sha256"],
            "records": inspection["records"],
            "byte_size": inspection["byte_size"],
        }
        manifest_sha256 = sha256_file(path)
        result = _ingest_one_artifact(
            manifest, item, item_inspection, manifest_path=path,
            manifest_sha256=manifest_sha256, db_path=db_path,
        )
        return {
            "success": True, "ready": True, "records": inspection["records"],
            "inserted": result["inserted"], "updated": result["updated"],
            "duplicates": result["duplicates"], "skipped_artifacts": int(result["skipped"]),
            "artifacts": 1, "artifact_results": [result], "inspection": inspection,
            "manifest": str(path), "db_path": str(Path(db_path).expanduser().resolve()),
        }

    for artifact in inspection["artifacts"]:
        if require_checksum and not artifact["sha256_matches"]:
            raise ValueError("dataset SHA-256 does not match manifest")
        if not artifact["byte_size_matches"]:
            raise ValueError("dataset byte size does not match manifest")
        if not artifact["record_count_matches"]:
            raise ValueError("dataset record count does not match manifest")

    manifest_sha256 = sha256_file(path)
    total_inserted = total_updated = total_duplicates = skipped = processed_total = 0
    artifact_results: list[dict[str, Any]] = []
    for item, item_inspection in zip(manifest["artifacts"], inspection["artifacts"]):
        result = _ingest_one_artifact(
            manifest, item, item_inspection, manifest_path=path,
            manifest_sha256=manifest_sha256, db_path=db_path,
        )
        artifact_results.append({"path": item.get("path"), **result})
        total_inserted += int(result.get("inserted", 0))
        total_updated += int(result.get("updated", 0))
        total_duplicates += int(result.get("duplicates", 0))
        skipped += int(result.get("skipped", False))
        processed_total += int(result.get("records", 0))

    return {
        "success": True, "ready": True, "records": inspection["records"],
        "processed_records": processed_total,
        "inserted": total_inserted, "updated": total_updated,
        "duplicates": total_duplicates, "skipped_artifacts": skipped,
        "artifacts": len(manifest["artifacts"]), "artifact_results": artifact_results,
        "inspection": inspection, "manifest": str(path),
        "db_path": str(Path(db_path).expanduser().resolve()),
    }


DEFAULT_REQUIRED_DATASETS = (
    "capec", "cisa_kev", "cpe", "cwe", "epss", "mitre_attack",
    "mitre_d3fend", "mitre_mbc", "sigma", "suricata", "zeek_intel", "nvd_cve",
)


def ingest_manifest_directory(
    manifests_dir: str | Path,
    *,
    db_path: str | Path,
    required_datasets: tuple[str, ...] | list[str] = DEFAULT_REQUIRED_DATASETS,
    require_checksum: bool = True,
) -> dict[str, Any]:
    """Preflight every requested dataset before creating/modifying the DB.

    The example.json placeholder is always ignored. If even one required
    manifest or artifact is missing or fails integrity/count checks, ingestion
    does not start. Once preflight passes, artifacts are ingested with
    checkpoints and can be resumed idempotently after a restart.
    """
    root = Path(manifests_dir).expanduser().resolve()
    db_file = Path(db_path).expanduser().resolve()
    report: dict[str, Any] = {
        "success": False,
        "ready": False,
        "ingestion_performed": False,
        "database_created_before_run": db_file.exists(),
        "manifests_dir": str(root),
        "db_path": str(db_file),
        "required_datasets": sorted(set(str(x) for x in required_datasets)),
        "preflight": [],
        "results": [],
        "missing_required_datasets": [],
    }
    if not root.is_dir():
        report["overall"] = "BLOCKED"
        report["evidence"] = f"Manifest directory does not exist: {root}"
        return report

    files = sorted(
        path for path in root.rglob("*.json")
        if path.is_file() and path.name.casefold() != "example.json"
    )
    loaded: list[tuple[Path, dict[str, Any]]] = []
    preflight_failures: list[dict[str, Any]] = []
    names: set[str] = set()
    for manifest_path in files:
        try:
            manifest = load_manifest(manifest_path)
            dataset = str(manifest.get("dataset") or manifest_path.stem)
            names.add(dataset)
            inspection = inspect_dataset(manifest_path)
            row = {
                "dataset": dataset,
                "manifest": str(manifest_path),
                "status": "PASS" if inspection.get("ready") is True else "FAIL",
                "inspection": inspection,
            }
            if row["status"] != "PASS":
                row["evidence"] = "SHA-256, byte-size and/or record-count validation failed."
                preflight_failures.append(row)
            loaded.append((manifest_path, manifest))
            report["preflight"].append(row)
        except FileNotFoundError as exc:
            row = {
                "dataset": manifest_path.stem,
                "manifest": str(manifest_path),
                "status": "BLOCKED",
                "evidence": f"Required artifact missing: {exc}",
            }
            preflight_failures.append(row)
            report["preflight"].append(row)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            message = f"{type(exc).__name__}: {exc}"
            blocked = "missing" in str(exc).casefold() or "git lfs pointer" in str(exc).casefold()
            row = {
                "dataset": manifest_path.stem,
                "manifest": str(manifest_path),
                "status": "BLOCKED" if blocked else "FAIL",
                "evidence": message,
            }
            preflight_failures.append(row)
            report["preflight"].append(row)

    required = set(str(x) for x in required_datasets)
    missing = sorted(required - names)
    report["missing_required_datasets"] = missing
    for dataset in missing:
        row = {
            "dataset": dataset,
            "manifest": "",
            "status": "BLOCKED",
            "evidence": "Required dataset has no real manifest; example.json does not satisfy this requirement.",
        }
        preflight_failures.append(row)
        report["preflight"].append(row)

    if preflight_failures:
        report["overall"] = "FAIL" if any(row["status"] == "FAIL" for row in preflight_failures) else "BLOCKED"
        report["evidence"] = "Preflight failed; no manifest was ingested and the target database was not opened."
        report["preflight_failures"] = preflight_failures
        return report

    report["ready"] = True
    report["preflight_passed"] = len(loaded)
    total_inserted = total_updated = total_duplicates = 0
    for manifest_path, manifest in loaded:
        dataset = str(manifest.get("dataset") or manifest_path.stem)
        try:
            result = ingest_manifest(
                manifest_path, db_path=db_file, require_checksum=require_checksum
            )
            report["results"].append({"dataset": dataset, **result})
            total_inserted += int(result.get("inserted", 0))
            total_updated += int(result.get("updated", 0))
            total_duplicates += int(result.get("duplicates", 0))
        except Exception as exc:
            report["results"].append({
                "dataset": dataset,
                "success": False,
                "error": f"{type(exc).__name__}: {exc}",
            })
            report["overall"] = "FAIL"
            report["evidence"] = (
                "Ingestion failed after preflight. Completed artifacts are checkpointed; "
                "rerun the same command to resume safely."
            )
            report["ingestion_performed"] = True
            report["inserted"] = total_inserted
            report["updated"] = total_updated
            report["duplicates"] = total_duplicates
            report["store_status"] = status(db_path=db_file) if db_file.exists() else None
            return report

    report.update({
        "success": True,
        "overall": "PASS",
        "ingestion_performed": True,
        "inserted": total_inserted,
        "updated": total_updated,
        "duplicates": total_duplicates,
        "evidence": "All required sources passed preflight and ingestion completed through the configured DB path.",
        "store_status": status(db_path=db_file),
    })
    return report


def verify_store(db_path: str | Path) -> dict[str, Any]:
    return status(db_path=db_path)
