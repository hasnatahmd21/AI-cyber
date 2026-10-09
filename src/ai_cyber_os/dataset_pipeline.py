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
            if "record_count" not in item:
                raise ValueError(f"manifest artifact {index} is missing record_count")
            raw_count = item["record_count"]
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

        count = sum(
            1
            for _ in iter_records(
                local,
                dataset=manifest.get("dataset", Path(manifest_path).stem),
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
            )
        )

        declared = int(item["record_count"])
        artifacts.append(
            {
                "path": str(local),
                "sha256": actual_sha,
                "sha256_matches": actual_sha == expected_sha,
                "records": count,
                "record_count_matches": count == declared,
            }
        )

    return {
        "dataset": manifest.get("dataset", Path(manifest_path).stem),
        "version": manifest.get("version", ""),
        "artifacts": artifacts,
        "records": sum(a["records"] for a in artifacts),
        "ready": all(
            a["sha256_matches"] and a["record_count_matches"]
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
        "ready": actual_sha == expected_sha and records == declared,
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
            local = (_project_root(manifest_path) / str(item["path"])).resolve()
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
    )
    result["inspection"] = inspection
    result["manifest"] = str(Path(manifest_path))
    result["ready"] = True
    return result


def verify_store(db_path: str | Path) -> dict[str, Any]:
    return status(db_path=db_path)
