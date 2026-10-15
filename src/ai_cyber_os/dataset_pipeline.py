"""Manifest-driven dataset ingestion for AI-CYBER."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .knowledge import ingest_file, iter_records, status

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


def _is_git_lfs_pointer(path: str | Path) -> bool:
    try:
        with Path(path).open("rb") as handle:
            return handle.read(256).startswith(b"version https://git-lfs.github.com/spec/v1")
    except OSError:
        return False


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


def _manifest_quality_checks(manifest: dict[str, Any]) -> dict[str, Any]:
    """Check provenance/placeholder metadata without inventing missing claims."""
    checks: dict[str, bool] = {}
    placeholder_tokens = ("REPLACE_WITH_", "TODO_FILL_", "YOUR_SOURCE_URI")
    for field in ("dataset", "version", "source", "source_uri", "license"):
        if field not in manifest:
            continue
        value = manifest.get(field)
        checks[field] = (
            isinstance(value, str)
            and bool(value.strip())
            and not any(token in value for token in placeholder_tokens)
        )
    # If a manifest explicitly says the license has not been verified, keep the
    # artifact blocked even when its bytes and parser counts are otherwise valid.
    if "license_verified" in manifest:
        checks["license_verified"] = manifest.get("license_verified") is True
    return {"checks": checks, "all_pass": all(checks.values())}


def _project_root(manifest_path: str | Path) -> Path:
    """Resolve repository/project root from a manifest path."""
    p = Path(manifest_path).resolve()
    for parent in (p.parent, *p.parents):
        if parent.name == "datasets":
            return parent.parent.resolve()
    return p.parent.resolve()


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
        expected_sha = item["sha256"].lower().strip()
        role = str(item.get("role", "data")).lower()
        is_lfs_pointer = _is_git_lfs_pointer(local)
        format_key = str(
            item.get("artifact_type") or manifest.get("artifact_type")
            or (manifest.get("schema", {}).get("format", "")
                if isinstance(manifest.get("schema"), dict) else "")
        )
        declared_stats = item.get("stats", {}) if isinstance(item.get("stats"), dict) else {}

        if role == "license":
            count = 0
            declared = None
            count_matches = True
            observed_stats: dict[str, Any] = {}
            stat_checks: dict[str, Any] = {}
        elif is_lfs_pointer:
            # Never try to JSON-parse or ingest the three-line LFS pointer as
            # though it were the dataset payload.
            count = 0
            declared = item["record_count"]
            count_matches = False
            observed_stats = {}
            stat_checks = {
                "payload_available": {
                    "declared": "complete dataset payload",
                    "observed": "Git LFS pointer only",
                    "matches": False,
                }
            }
        else:
            schema = manifest.get("schema", {})
            record_elements = schema.get("elements") if isinstance(schema, dict) else None
            schema_format = str(schema.get("format", "")).lower() if isinstance(schema, dict) else ""
            record_extensions = {".yml", ".yaml"} if "yaml rules inside archive" in schema_format else None

            count = 0
            object_types: dict[str, int] = {}
            active_rules = 0
            disabled_rules = 0
            active_sid_counts: dict[str, int] = {}
            active_without_sid = 0
            rule_sources: set[str] = set()

            for record in iter_records(
                local,
                dataset=manifest.get("dataset", Path(manifest_path).stem),
                source=item.get("source", manifest.get("source", "")),
                license=item.get("license", manifest.get("license", "")),
                version=item.get("version", manifest.get("version", "")),
                source_uri=item.get("source_uri", manifest.get("source_uri", "")),
                validation_status=item.get(
                    "validation_status", manifest.get("validation_status", "unverified")
                ),
                record_elements=record_elements,
                record_extensions=record_extensions,
                record_format=format_key,
            ):
                count += 1
                try:
                    metadata = json.loads(record.get("metadata_json", "{}"))
                except (TypeError, json.JSONDecodeError):
                    metadata = {}
                object_type = metadata.get("type")
                if isinstance(object_type, str) and object_type:
                    object_types[object_type] = object_types.get(object_type, 0) + 1

                if "suricata" in format_key.lower():
                    if metadata.get("enabled") is True:
                        active_rules += 1
                        sid = metadata.get("sid")
                        if sid is None or str(sid).strip() == "":
                            active_without_sid += 1
                        else:
                            key = str(sid)
                            active_sid_counts[key] = active_sid_counts.get(key, 0) + 1
                        rule_sources.add(str(record.get("source", "")))
                    elif metadata.get("enabled") is False:
                        disabled_rules += 1
                        rule_sources.add(str(record.get("source", "")))

            declared = item["record_count"]
            count_matches = count == declared
            observed_stats = {}
            stat_checks = {}

            expected_types = declared_stats.get("object_types")
            if isinstance(expected_types, dict):
                normalized_expected = {str(k): int(v) for k, v in expected_types.items()}
                normalized_observed = dict(sorted(object_types.items()))
                stat_checks["object_types"] = {
                    "declared": normalized_expected,
                    "observed": normalized_observed,
                    "matches": normalized_observed == dict(sorted(normalized_expected.items())),
                }
                observed_stats["object_types"] = normalized_observed

            if "suricata" in format_key.lower():
                duplicate_sid_lines = sum(max(0, n - 1) for n in active_sid_counts.values())
                observed_rules = {
                    "active_rules": active_rules,
                    "disabled_rules": disabled_rules,
                    "duplicate_sid_lines": duplicate_sid_lines,
                    "rule_files": len(rule_sources),
                    "active_rules_without_sid": active_without_sid,
                }
                observed_stats.update(observed_rules)
                for key in ("active_rules", "disabled_rules", "duplicate_sid_lines", "rule_files"):
                    if key in declared_stats:
                        stat_checks[key] = {
                            "declared": declared_stats[key],
                            "observed": observed_rules[key],
                            "matches": observed_rules[key] == declared_stats[key],
                        }
                stat_checks["active_rules_without_sid"] = {
                    "declared": 0,
                    "observed": active_without_sid,
                    "matches": active_without_sid == 0,
                }

        artifacts.append(
            {
                "path": str(local),
                "role": role,
                "artifact_type": format_key,
                "sha256": actual_sha,
                "sha256_matches": actual_sha == expected_sha,
                "git_lfs_pointer": is_lfs_pointer,
                "blocked_reason": "Git LFS pointer detected; payload has not been downloaded" if is_lfs_pointer else None,
                "records": count,
                "record_count_matches": count_matches,
                "declared_stats": declared_stats,
                "observed_stats": observed_stats,
                "stat_checks": stat_checks,
                "stats_match": all(check.get("matches", False) for check in stat_checks.values()),
            }
        )

    metadata_quality = _manifest_quality_checks(manifest)
    artifact_integrity = all(
        a["sha256_matches"] and a["record_count_matches"] and a["stats_match"]
        for a in artifacts
    )
    return {
        "dataset": manifest.get("dataset", Path(manifest_path).stem),
        "version": manifest.get("version", ""),
        "artifacts": artifacts,
        "records": sum(a["records"] for a in artifacts),
        "manifest_checks": metadata_quality,
        "artifact_integrity": artifact_integrity,
        "ready": artifact_integrity and metadata_quality["all_pass"],
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

    metadata_quality = _manifest_quality_checks(manifest)
    actual_sha = sha256_file(local)
    expected_sha = manifest["sha256"].lower().strip()
    if _is_git_lfs_pointer(local):
        return {
            "dataset": manifest["dataset"],
            "version": manifest["version"],
            "path": str(local),
            "sha256": actual_sha,
            "sha256_matches": actual_sha == expected_sha,
            "records": 0,
            "record_count_matches": False,
            "manifest_validation_status": manifest["validation_status"],
            "git_lfs_pointer": True,
            "blocked_reason": "Git LFS pointer detected; download and verify the real artifact",
            "ready": False,
        }
    records = sum(
        1
        for _ in iter_records(
            local,
            dataset=manifest["dataset"],
            source=manifest["source"],
            license=manifest["license"],
            version=manifest["version"],
            source_uri=manifest["source_uri"],
            validation_status=manifest["validation_status"],
            record_elements=(manifest.get("schema", {}).get("elements")
                             if isinstance(manifest.get("schema"), dict) else None),
            record_format=(manifest.get("artifact_type") or
                           (manifest.get("schema", {}).get("format", "")
                            if isinstance(manifest.get("schema"), dict) else "")),
        )
    )
    declared = int(manifest["record_count"])

    return {
        "dataset": manifest["dataset"],
        "version": manifest["version"],
        "path": str(local),
        "sha256": actual_sha,
        "sha256_matches": actual_sha == expected_sha,
        "records": records,
        "record_count_matches": records == declared,
        "manifest_validation_status": manifest["validation_status"],
        "manifest_checks": metadata_quality,
        "ready": (actual_sha == expected_sha and records == declared
                  and metadata_quality["all_pass"]),
    }


def ingest_manifest(
    manifest_path: str | Path,
    *,
    db_path: str | Path,
    require_checksum: bool = True,
) -> dict[str, Any]:
    manifest = load_manifest(manifest_path)
    inspection = inspect_dataset(manifest_path)

    # Report deterministic integrity failures before the aggregate readiness
    # check so callers/tests can distinguish checksum failures from record-count
    # failures. A bad checksum must never be hidden behind a generic error.
    if "artifacts" not in manifest:
        if require_checksum and not inspection["sha256_matches"]:
            raise ValueError("dataset SHA-256 does not match manifest")
        if not inspection["record_count_matches"]:
            raise ValueError("dataset record count does not match manifest")
    else:
        for artifact in inspection["artifacts"]:
            if require_checksum and not artifact["sha256_matches"]:
                raise ValueError("dataset SHA-256 does not match manifest")
            if not artifact["record_count_matches"]:
                raise ValueError("dataset record count does not match manifest")

    manifest_checks = inspection.get("manifest_checks", {"all_pass": True})
    if not manifest_checks.get("all_pass", True):
        failed = [
            key for key, passed in manifest_checks.get("checks", {}).items()
            if not passed
        ]
        raise ValueError(
            "dataset manifest metadata validation failed: " + ", ".join(failed)
        )

    # Checksum enforcement is optional only when explicitly requested; counts
    # and path containment remain mandatory in either mode.
    integrity_ok = (
        all(a["record_count_matches"] and
            (a["sha256_matches"] or not require_checksum)
            for a in inspection["artifacts"])
        if "artifacts" in manifest
        else inspection["record_count_matches"] and
             (inspection["sha256_matches"] or not require_checksum)
    )
    if not integrity_ok:
        raise ValueError("dataset manifest integrity/count validation failed")

    if "artifacts" in manifest:
        total = 0
        for item in manifest["artifacts"]:
            if str(item.get("role", "data")).lower() == "license":
                continue
            local = (_project_root(manifest_path) / str(item["path"])).resolve()
            schema = manifest.get("schema", {})
            record_elements = schema.get("elements") if isinstance(schema, dict) else None
            schema_format = str(schema.get("format", "")).lower() if isinstance(schema, dict) else ""
            record_extensions = {".yml", ".yaml"} if "yaml rules inside archive" in schema_format else None
            result = ingest_file(
                local,
                db_path=db_path,
                dataset=manifest.get(
                    "dataset", Path(manifest_path).stem
                ),
                source=item.get("source", manifest.get("source", "")),
                license=item.get("license", manifest.get("license", "")),
                version=item.get("version", manifest.get("version", "")),
                source_uri=item.get(
                    "source_uri", manifest.get("source_uri", "")
                ),
                validation_status=item.get(
                    "validation_status",
                    manifest.get("validation_status", "unverified"),
                ),
                record_elements=record_elements,
                record_extensions=record_extensions,
                record_format=(item.get("artifact_type") or manifest.get("artifact_type")
                               or schema_format),
            )
            total += int(result.get("inserted", 0))

        return {
            "success": True,
            "ready": True,
            "records": inspection["records"],
            "artifacts": len(manifest["artifacts"]),
            "inserted": total,
            "inspection": inspection,
            "manifest": str(Path(manifest_path)),
        }

    result = ingest_file(
        inspection["path"],
        db_path=db_path,
        dataset=manifest["dataset"],
        source=manifest["source"],
        license=manifest["license"],
        version=manifest["version"],
        source_uri=manifest["source_uri"],
        validation_status=manifest["validation_status"],
        record_elements=(manifest.get("schema", {}).get("elements")
                         if isinstance(manifest.get("schema"), dict) else None),
        record_format=(manifest.get("artifact_type") or
                       (manifest.get("schema", {}).get("format", "")
                        if isinstance(manifest.get("schema"), dict) else "")),
    )
    result["inspection"] = inspection
    result["manifest"] = str(Path(manifest_path))
    result["ready"] = True
    return result


def verify_store(db_path: str | Path) -> dict[str, Any]:
    return status(db_path=db_path)
