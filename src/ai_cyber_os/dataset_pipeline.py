"""Manifest-driven dataset ingestion for AI-CYBER."""
from __future__ import annotations

import hashlib
import json
import sqlite3
import time
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
        from .threat_intel import iter_parse_nvd
        return sum(1 for _ in iter_parse_nvd(local, **common))
    if count_kind == "stix_bundle" and common["dataset"] == "mitre_attack":
        from .threat_intel import iter_parse_attack_bundle
        return sum(1 for _ in iter_parse_attack_bundle(local, **common))
    if count_kind == "mbc":
        from .threat_intel import parse_mbc_stix
        return len(parse_mbc_stix(local, **common))
    if count_kind == "suricata":
        from .threat_intel import parse_suricata_rules
        return len(parse_suricata_rules(local, **common))
    if count_kind in {"xml_cwe", "cwe"}:
        from .threat_intel import iter_parse_cwe_xml
        return sum(1 for _ in iter_parse_cwe_xml(local, **common))
    if count_kind == "sigma":
        from .threat_intel import iter_parse_sigma_rules
        return sum(1 for _ in iter_parse_sigma_rules(local, **common))

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
    manifest_path: str | Path, manifest: dict[str, Any], *, count_records: bool = True
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
        elif count_records:
            count = _count_artifact_records(
                local, manifest=manifest, item=item, manifest_path=manifest_path
            )
            declared_count = item["record_count"]
            count_matches = count == declared_count
        else:
            # Fast path only after a fresh full readiness gate passed. SHA-256 and size are still checked.
            count = item["record_count"]
            declared_count = item["record_count"]
            count_matches = True

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


def inspect_dataset(manifest_path: str | Path, *, count_records: bool = True) -> dict[str, Any]:
    manifest = load_manifest(manifest_path)

    if "artifacts" in manifest:
        return _artifact_inspection(manifest_path, manifest, count_records=count_records)

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
    declared = manifest["record_count"]
    if count_records:
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
    else:
        records = declared

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
) -> Any:
    common = {
        "dataset": dataset,
        "source": source,
        "version": version,
        "source_uri": source_uri,
        "license": license,
        "validation_status": validation_status,
    }
    if kind in {"nvd", "nvd-feed", "nvd_cve"}:
        from .threat_intel import iter_parse_nvd
        return iter_parse_nvd(local, **common)
    if kind == "stix_bundle" and dataset == "mitre_attack":
        from .threat_intel import iter_parse_attack_bundle
        return iter_parse_attack_bundle(local, **common)
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
    if kind in {"xml_cwe", "cwe"}:
        from .threat_intel import iter_parse_cwe_xml
        return iter_parse_cwe_xml(local, **common)
    if kind == "sigma":
        from .threat_intel import iter_parse_sigma_rules
        return iter_parse_sigma_rules(local, **common)
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

    artifact_started = time.monotonic()
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

    print("ARTIFACT START dataset={} artifact={} expected_records={} bytes={}".format(
        dataset, artifact_label, expected_records, local.stat().st_size), flush=True)
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
        print("ARTIFACT SKIP dataset={} artifact={} reason=checkpoint-complete elapsed_s={:.1f}".format(
            dataset, artifact_label, time.monotonic()-artifact_started), flush=True)
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
        print("ARTIFACT END dataset={} artifact={} elapsed_s={:.1f} processed={} inserted={} updated={} duplicates={}".format(
            dataset, artifact_label, time.monotonic()-artifact_started, processed, inserted, updated, duplicates), flush=True)
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
    inspection: dict[str, Any] | None = None,
    prevalidated_counts: bool = False,
) -> dict[str, Any]:
    """Verify then ingest one manifest through its format-specific parser.

    Each artifact is checkpointed by manifest SHA-256 plus observed artifact
    SHA-256. Completed artifacts are skipped on restart; interrupted artifacts
    are safely reprocessed with deterministic, idempotent record IDs.
    """
    path = Path(manifest_path).resolve()
    manifest = load_manifest(path)
    if inspection is None:
        inspection = inspect_dataset(path, count_records=not prevalidated_counts)

    # Apply policy-aware integrity checks below. A single generic ready gate here
    # would incorrectly reject the documented require_checksum=False override,
    # and would hide the specific checksum/count error expected by callers.

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


def derive_cvss_from_nvd_database(
    db_path: str | Path,
    *,
    manifest_path: str | Path,
    batch_size: int = 2000,
) -> dict[str, Any]:
    """Create deterministic CVSS metric records from ingested NVD CVE records.

    Records are derived only from the NVD evidence already indexed in this DB.
    Keyset pagination bounds memory use; each page is checkpointed by the source
    manifest digest and the exact page's content hashes, so restarts skip pages
    already derived from the same source evidence.
    """
    if isinstance(batch_size, bool) or not isinstance(batch_size, int) or batch_size < 1:
        raise ValueError("batch_size must be a positive integer")
    from .knowledge import _normalize
    from .threat_intel import ingest_parsed

    manifest_file = Path(manifest_path).resolve()
    if not manifest_file.is_file():
        raise FileNotFoundError(manifest_file)
    manifest_sha = sha256_file(manifest_file)
    db_file = Path(db_path).expanduser().resolve()
    counts = {
        "source_records_scanned": 0,
        "cvss_metrics_found": 0,
        "inserted": 0,
        "updated": 0,
        "duplicates": 0,
        "checkpoint_batches_skipped": 0,
        "checkpoint_batches_completed": 0,
    }
    last_record_id = ""
    while True:
        db = open_store(db_file)
        try:
            rows = db.execute(
                """SELECT record_id, dataset, source, source_uri, license, version,
                          validation_status, content_sha256, metadata_json
                   FROM knowledge_records
                   WHERE dataset='nvd_cve' AND record_id>?
                   ORDER BY record_id LIMIT ?""",
                (last_record_id, batch_size),
            ).fetchall()
            page = [dict(row) for row in rows]
        finally:
            db.close()
        if not page:
            break

        source_hash_material = "\n".join(
            f"{row['record_id']}\0{row['content_sha256']}" for row in page
        )
        page_sha = hashlib.sha256(source_hash_material.encode("utf-8")).hexdigest()
        first_id = str(page[0]["record_id"])
        final_id = str(page[-1]["record_id"])
        checkpoint_path = f"derived:cvss:{first_id}:{final_id}"

        derived: list[dict[str, Any]] = []
        for row in page:
            counts["source_records_scanned"] += 1
            try:
                metadata = json.loads(row["metadata_json"])
            except (TypeError, json.JSONDecodeError) as exc:
                raise ValueError(f"invalid NVD metadata_json for {row['record_id']}: {exc}") from exc
            cve_id = str(
                metadata.get("id")
                or metadata.get("external_id")
                or row["record_id"].rsplit(":", 1)[-1]
            )
            metrics = metadata.get("metrics") or {}
            if not isinstance(metrics, dict):
                continue
            for metric_key in sorted(metrics):
                if not str(metric_key).casefold().startswith("cvssmetric"):
                    continue
                metric_rows = metrics[metric_key]
                if isinstance(metric_rows, dict):
                    metric_rows = [metric_rows]
                if not isinstance(metric_rows, list):
                    continue
                for metric in metric_rows:
                    if not isinstance(metric, dict):
                        continue
                    cvss_data = metric.get("cvssData")
                    if not isinstance(cvss_data, dict) or not cvss_data:
                        continue
                    suffix = str(metric_key).casefold().replace("cvssmetricv", "")
                    fallback_version = {
                        "2": "2.0", "20": "2.0", "30": "3.0",
                        "31": "3.1", "40": "4.0",
                    }.get(suffix, suffix)
                    cvss_version = str(cvss_data.get("version") or fallback_version)
                    metric_type = str(metric.get("type") or "unspecified").casefold()
                    metric_source = str(metric.get("source") or metric.get("sourceIdentifier") or "unspecified")
                    vector = str(cvss_data.get("vectorString") or "")
                    stable_identity = json.dumps(
                        [metric_key, cvss_version, metric_type, metric_source],
                        ensure_ascii=False, separators=(",", ":"), default=str,
                    )
                    fingerprint = hashlib.sha256(stable_identity.encode("utf-8")).hexdigest()[:16]
                    # Keep identity stable across metric score/vector updates so a
                    # changed upstream metric replaces the prior evidence record.
                    record_id = f"cvss:{cve_id}:{cvss_version}:{fingerprint}"
                    evidence = {
                        "cve_id": cve_id,
                        "cvss_version": cvss_version,
                        "metric_type": metric_type,
                        "metric_source": metric_source,
                        "base_score": cvss_data.get("baseScore"),
                        "base_severity": cvss_data.get("baseSeverity"),
                        "vector_string": vector,
                        "cvss_data": cvss_data,
                        "metric_summary": {
                            key: metric.get(key)
                            for key in ("exploitabilityScore", "impactScore", "source", "type", "version")
                            if key in metric
                        },
                        "derived_from_dataset": "nvd_cve",
                        "derived_from_record_id": row["record_id"],
                        "derived_from_content_sha256": row["content_sha256"],
                    }
                    raw = {
                        "id": record_id,
                        "title": f"{cve_id} CVSS {cvss_version} {metric_type}",
                        "content": json.dumps(
                            evidence, ensure_ascii=False, sort_keys=True, default=str
                        ),
                        "cve_id": cve_id,
                        "cvss_version": cvss_version,
                        "metric_type": metric_type,
                        "metric_source": metric_source,
                        "base_score": cvss_data.get("baseScore"),
                        "base_severity": cvss_data.get("baseSeverity"),
                        "vector_string": vector,
                        "derived_from_record_id": row["record_id"],
                        "derived_from_content_sha256": row["content_sha256"],
                    }
                    derived.append(_normalize(
                        raw,
                        dataset="cvss",
                        source="NVD CVSS metrics derived from NVD CVE 2.0",
                        source_uri=str(row.get("source_uri") or ""),
                        license=str(row.get("license") or ""),
                        version=str(row.get("version") or ""),
                        validation_status=str(row.get("validation_status") or "unverified"),
                    ))
        counts["cvss_metrics_found"] += len(derived)
        expected_ids_by_cve: dict[str, set[str]] = {}
        for record in derived:
            metadata = json.loads(record["metadata_json"])
            expected_ids_by_cve.setdefault(str(metadata.get("cve_id") or ""), set()).add(
                str(record["record_id"])
            )
        # Even a CVE whose newest NVD record no longer has CVSS metrics must
        # be visited; its expected set is empty so stale derived rows are removed.
        if page:
            from .knowledge import open_store as _open_store
            db = _open_store(db_file)
            try:
                for source_row in page:
                    source_meta = json.loads(source_row["metadata_json"])
                    canonical_cve = str(
                        source_meta.get("id")
                        or source_meta.get("external_id")
                        or source_row["record_id"].rsplit(":", 1)[-1]
                    )
                    expected = expected_ids_by_cve.get(canonical_cve, set())
                    # Use the record_id primary-key index to avoid a full scan of every
                    # CVSS record for each of the hundreds of thousands of source CVEs.
                    prefix = f"cvss:{canonical_cve}:"
                    # Keep the range predicate on record_id alone so SQLite uses
                    # its primary-key index instead of scanning the whole CVSS dataset index.
                    stale_rows = db.execute(
                        "SELECT record_id, dataset FROM knowledge_records "
                        "WHERE record_id >= ? AND record_id < ?",
                        (prefix, prefix + "\U0010ffff"),
                    ).fetchall()
                    for stale in stale_rows:
                        # IDs are globally unique, but another dataset may supply a
                        # colliding literal ID; only delete derived CVSS evidence.
                        if str(stale["dataset"]) != "cvss":
                            continue
                        stale_id = str(stale["record_id"])
                        if stale_id in expected:
                            continue
                        db.execute("DELETE FROM knowledge_fts WHERE record_id=?", (stale_id,))
                        db.execute("DELETE FROM knowledge_chunks_fts WHERE record_id=?", (stale_id,))
                        db.execute("DELETE FROM knowledge_chunks WHERE record_id=?", (stale_id,))
                        db.execute("DELETE FROM knowledge_relations WHERE record_id=?", (stale_id,))
                        db.execute("DELETE FROM knowledge_records WHERE record_id=?", (stale_id,))
                db.commit()
            finally:
                db.close()

        existing = _checkpoint_read(
            db_file,
            manifest_path=str(manifest_file),
            manifest_sha256=manifest_sha,
            artifact_path=checkpoint_path,
            artifact_sha256=page_sha,
        )
        if (
            existing
            and existing["status"] == "complete"
            and int(existing["expected_records"]) == len(derived)
            and int(existing["processed_records"]) == len(derived)
        ):
            counts["checkpoint_batches_skipped"] += 1
            last_record_id = final_id
            continue

        _checkpoint_write(
            db_file,
            manifest_path=str(manifest_file),
            manifest_sha256=manifest_sha,
            artifact_path=checkpoint_path,
            artifact_sha256=page_sha,
            dataset="cvss",
            status_value="running",
            expected_records=len(derived),
        )
        try:
            outcome = ingest_parsed(derived, db_path=db_file) if derived else {
                "records": 0, "processed_records": 0, "inserted": 0, "updated": 0, "duplicates": 0,
            }
            if int(outcome.get("processed_records", outcome.get("records", 0))) != len(derived):
                raise ValueError(
                    f"CVSS derivation ingested {outcome.get('processed_records')} records, "
                    f"expected {len(derived)}"
                )
            _checkpoint_write(
                db_file,
                manifest_path=str(manifest_file),
                manifest_sha256=manifest_sha,
                artifact_path=checkpoint_path,
                artifact_sha256=page_sha,
                dataset="cvss",
                status_value="complete",
                expected_records=len(derived),
                processed_records=len(derived),
                inserted_records=int(outcome.get("inserted", 0)),
                updated_records=int(outcome.get("updated", 0)),
                duplicate_records=int(outcome.get("duplicates", 0)),
            )
            counts["inserted"] += int(outcome.get("inserted", 0))
            counts["updated"] += int(outcome.get("updated", 0))
            counts["duplicates"] += int(outcome.get("duplicates", 0))
            counts["checkpoint_batches_completed"] += 1
        except Exception as exc:
            _checkpoint_write(
                db_file,
                manifest_path=str(manifest_file),
                manifest_sha256=manifest_sha,
                artifact_path=checkpoint_path,
                artifact_sha256=page_sha,
                dataset="cvss",
                status_value="failed",
                expected_records=len(derived),
                error=f"{type(exc).__name__}: {exc}",
            )
            raise
        last_record_id = final_id

    db = open_store(db_file)
    try:
        derived_count = int(db.execute(
            "SELECT COUNT(*) FROM knowledge_records WHERE dataset='cvss'"
        ).fetchone()[0])
        db.execute(
            "INSERT INTO knowledge_meta(key,value) VALUES('cvss_derivation_status','complete') "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value"
        )
        db.execute(
            "INSERT INTO knowledge_meta(key,value) VALUES('cvss_derived_records',?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (str(derived_count),),
        )
        db.commit()
    finally:
        db.close()
    counts["derived_records_in_database"] = derived_count
    return counts


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
    prevalidated_counts: bool = False,
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
        "database_resume_status": None,
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
    for manifest_index, manifest_path in enumerate(files, 1):
        started = time.monotonic()
        print("PREFLIGHT START [{}/{}] {} count_parser={}".format(manifest_index, len(files), manifest_path.name, "SKIP_PREVALIDATED" if prevalidated_counts else "FULL"), flush=True)
        try:
            manifest = load_manifest(manifest_path)
            dataset = str(manifest.get("dataset") or manifest_path.stem)
            if dataset in names:
                raise ValueError(f"duplicate manifest for dataset {dataset!r}; keep one authoritative manifest per dataset")
            names.add(dataset)
            inspection = inspect_dataset(manifest_path, count_records=not prevalidated_counts)
            row = {
                "dataset": dataset,
                "manifest": str(manifest_path),
                "status": "PASS" if inspection.get("ready") is True else "FAIL",
                "inspection": inspection,
                "_inspection": inspection,
            }
            if row["status"] != "PASS":
                row["evidence"] = "SHA-256, byte-size and/or record-count validation failed."
                preflight_failures.append(row)
            loaded.append((manifest_path, manifest))
            report["preflight"].append(row)
            print("PREFLIGHT END {} status={} elapsed_s={:.1f}".format(dataset, row["status"], time.monotonic()-started), flush=True)
        except FileNotFoundError as exc:
            row = {
                "dataset": manifest_path.stem,
                "manifest": str(manifest_path),
                "status": "BLOCKED",
                "evidence": f"Required artifact missing: {exc}",
            }
            preflight_failures.append(row)
            report["preflight"].append(row)
            print("PREFLIGHT END {} status=BLOCKED elapsed_s={:.1f} error={}".format(manifest_path.name, time.monotonic()-started, exc), flush=True)
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
            print("PREFLIGHT END {} status={} elapsed_s={:.1f} error={}".format(manifest_path.name, row["status"], time.monotonic()-started, message), flush=True)

    required = set(str(x) for x in required_datasets)
    missing = sorted(required - names)
    unexpected = sorted(names - required)
    report["missing_required_datasets"] = missing
    report["unexpected_dataset_names"] = unexpected
    for dataset in missing:
        row = {
            "dataset": dataset,
            "manifest": "",
            "status": "BLOCKED",
            "evidence": "Required dataset has no real manifest; example.json does not satisfy this requirement.",
        }
        preflight_failures.append(row)
        report["preflight"].append(row)

    for dataset in unexpected:
        row = {
            "dataset": dataset,
            "manifest": "",
            "status": "BLOCKED",
            "evidence": (
                "Dataset is outside the locked first-wave raw-source set. CVSS must be derived "
                "from NVD in the database build, not ingested from an independent raw manifest."
            ),
        }
        preflight_failures.append(row)
        report["preflight"].append(row)

    if preflight_failures:
        report["overall"] = "FAIL" if any(row["status"] == "FAIL" for row in preflight_failures) else "BLOCKED"
        report["evidence"] = "Preflight failed; no manifest was ingested and the target database was not opened."
        report["preflight_failures"] = preflight_failures
        return report

    manifest_digests = {
        str(manifest.get("dataset") or manifest_path.stem): sha256_file(manifest_path)
        for manifest_path, manifest in sorted(loaded, key=lambda row: str(row[0]))
    }
    manifest_digest_json = json.dumps(manifest_digests, sort_keys=True, separators=(",", ":"))

    # Pin the exact source snapshot into the DB. Reuse is permitted only for
    # resumptions with identical manifests; silently mixing a newer manifest
    # into an older DB could retain removed records and make the snapshot
    # irreproducible.
    if db_file.is_file() and db_file.stat().st_size > 0:
        try:
            existing_db = sqlite3.connect(f"file:{db_file.as_posix()}?mode=ro", uri=True)
            try:
                tables = {
                    str(row[0]) for row in existing_db.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    )
                }
                if not {"knowledge_meta", "knowledge_records"}.issubset(tables):
                    raise ValueError("existing target is not an AI-CYBER Knowledge DB")
                meta_values = {
                    str(row[0]): str(row[1])
                    for row in existing_db.execute("SELECT key,value FROM knowledge_meta")
                }
                existing_records = int(
                    existing_db.execute("SELECT COUNT(*) FROM knowledge_records").fetchone()[0]
                )
            finally:
                existing_db.close()
        except (sqlite3.DatabaseError, OSError, ValueError) as exc:
            report.update({
                "overall": "BLOCKED",
                "evidence": f"Existing DB cannot be safely resumed: {type(exc).__name__}: {exc}",
                "database_resume_status": "BLOCKED",
                "ingestion_performed": False,
            })
            return report

        if meta_values.get("database_version") not in {None, "ai-cyber-knowledge-v1"}:
            report.update({
                "overall": "BLOCKED",
                "evidence": (
                    "Existing DB has an unknown database_version. Use a new --db-path "
                    "instead of overwriting a different Knowledge DB."
                ),
                "database_resume_status": "BLOCKED",
                "ingestion_performed": False,
            })
            return report
        pinned = meta_values.get("source_manifest_digests")
        if existing_records > 0 and not pinned:
            report.update({
                "overall": "BLOCKED",
                "evidence": (
                    "Existing DB has records but no pinned source-manifest digest ledger. "
                    "Use a new DB path to prevent mixing untracked source snapshots."
                ),
                "database_resume_status": "BLOCKED",
                "ingestion_performed": False,
            })
            return report
        if pinned and pinned != manifest_digest_json:
            report.update({
                "overall": "BLOCKED",
                "evidence": (
                    "Source-manifest digests differ from the existing DB snapshot. "
                    "Use a new versioned --db-path; resuming into this file could retain stale records."
                ),
                "database_resume_status": "BLOCKED",
                "existing_source_manifest_digests": json.loads(pinned),
                "current_source_manifest_digests": manifest_digests,
                "ingestion_performed": False,
            })
            return report

    db = open_store(db_file)
    try:
        db.execute(
            "INSERT INTO knowledge_meta(key,value) VALUES('source_manifest_digests',?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (manifest_digest_json,),
        )
        db.execute(
            "INSERT INTO knowledge_meta(key,value) VALUES('source_manifest_set_sha256',?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (hashlib.sha256(manifest_digest_json.encode("utf-8")).hexdigest(),),
        )
        db.commit()
    finally:
        db.close()

    report["source_manifest_digests"] = manifest_digests
    report["source_manifest_set_sha256"] = hashlib.sha256(
        manifest_digest_json.encode("utf-8")
    ).hexdigest()
    report["database_resume_status"] = (
        "RESUME_SAME_SOURCE_SNAPSHOT" if report["database_created_before_run"]
        else "NEW_SOURCE_SNAPSHOT"
    )
    report["ready"] = True
    report["preflight_passed"] = len(loaded)
    total_inserted = total_updated = total_duplicates = 0
    inspection_by_dataset = {str(row.get("dataset")): row.get("_inspection") for row in report["preflight"]}
    for ingest_index, (manifest_path, manifest) in enumerate(loaded, 1):
        dataset = str(manifest.get("dataset") or manifest_path.stem)
        ingest_started = time.monotonic()
        print("INGEST START [{}/{}] {}".format(ingest_index, len(loaded), dataset), flush=True)
        try:
            result = ingest_manifest(
                manifest_path, db_path=db_file, require_checksum=require_checksum,
                inspection=inspection_by_dataset.get(dataset),
                prevalidated_counts=prevalidated_counts,
            )
            print("INGEST END {} elapsed_s={:.1f} records={}".format(
                dataset, time.monotonic()-ingest_started,
                result.get("records", result.get("processed_records", 0))), flush=True)
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

    report["ingestion_performed"] = True
    nvd_manifest = next(
        (
            (manifest_path, manifest)
            for manifest_path, manifest in loaded
            if str(manifest.get("dataset") or manifest_path.stem) == "nvd_cve"
        ),
        None,
    )
    if nvd_manifest is not None:
        try:
            cvss_result = derive_cvss_from_nvd_database(
                db_file, manifest_path=nvd_manifest[0]
            )
            report["derived_datasets"] = [{
                "dataset": "cvss",
                "status": "PASS" if cvss_result["derived_records_in_database"] > 0 else "FAIL",
                "source_dataset": "nvd_cve",
                "derivation": cvss_result,
                "evidence": (
                    "CVSS metrics were extracted from the verified NVD records and persisted with source provenance."
                    if cvss_result["derived_records_in_database"] > 0
                    else "NVD source records contained no derivable CVSS metric records."
                ),
            }]
            if cvss_result["derived_records_in_database"] < 1:
                report.update({
                    "success": False,
                    "overall": "FAIL",
                    "inserted": total_inserted,
                    "updated": total_updated,
                    "duplicates": total_duplicates,
                    "evidence": "Raw dataset ingestion passed, but the derived CVSS dataset produced no records.",
                    "store_status": status(db_path=db_file),
                })
                return report
        except Exception as exc:
            report.update({
                "success": False,
                "overall": "FAIL",
                "inserted": total_inserted,
                "updated": total_updated,
                "duplicates": total_duplicates,
                "derived_datasets": [{
                    "dataset": "cvss",
                    "status": "FAIL",
                    "evidence": f"{type(exc).__name__}: {exc}",
                }],
                "evidence": "Raw dataset ingestion completed but the CVSS derivation stage failed; rerun to resume from checkpoints.",
                "store_status": status(db_path=db_file),
            })
            return report

    report.update({
        "success": True,
        "overall": "PASS",
        "inserted": total_inserted,
        "updated": total_updated,
        "duplicates": total_duplicates,
        "evidence": (
            "All required raw sources passed preflight, parser-aware ingestion completed, "
            "and derived CVSS records were verified in the same configured database."
            if nvd_manifest is not None else
            "All required sources passed preflight and ingestion completed through the configured DB path."
        ),
        "store_status": status(db_path=db_file),
    })
    return report


def verify_store(db_path: str | Path) -> dict[str, Any]:
    return status(db_path=db_path)
