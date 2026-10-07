"""Manifest-driven dataset ingestion for AI-CYBER."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .knowledge import ingest_file, iter_records, status

MANIFEST_REQUIRED = {
    "dataset", "version", "source", "source_uri", "license", "local_path",
    "sha256", "record_count", "schema", "ingestion_status", "validation_status",
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
    if isinstance(data.get("artifacts"), list):
        if not data["artifacts"]:
            raise ValueError("manifest artifacts must not be empty")
        return data
    missing = sorted(MANIFEST_REQUIRED - set(data))
    if missing:
        raise ValueError(f"manifest missing required fields: {', '.join(missing)}")
    if not isinstance(data["schema"], (dict, list, str)):
        raise ValueError("manifest schema must be an object, list, or string")
    return data

def _artifact_inspection(manifest_path: str | Path, manifest: dict[str, Any]) -> dict[str, Any]:
    root = _project_root(manifest_path)
    artifacts = []
    for item in manifest["artifacts"]:
        local = (root / item["path"]).resolve()
        try:
            local.relative_to(root)
        except ValueError as exc:
            raise ValueError("manifest artifact path must remain inside the project") from exc
        if not local.is_file():
            raise FileNotFoundError(local)
        actual_sha = sha256_file(local)
        expected_sha = str(item.get("sha256", "")).lower().strip()
        count = sum(1 for _ in iter_records(local, dataset=manifest.get("dataset", Path(manifest_path).stem),
            source=item.get("source", manifest.get("source", "")), license=item.get("license", manifest.get("license", "")),
            version=item.get("version", manifest.get("version", "")), source_uri=item.get("source_uri", manifest.get("source_uri", "")),
            validation_status=item.get("validation_status", manifest.get("validation_status", "unverified"))))
        declared = int(item.get("record_count", -1))
        artifacts.append({"path": str(local), "sha256": actual_sha,
            "sha256_matches": actual_sha == expected_sha if expected_sha else True,
            "records": count, "record_count_matches": count == declared if declared >= 0 else True})
    return {"dataset": manifest.get("dataset", Path(manifest_path).stem), "version": manifest.get("version", ""),
            "artifacts": artifacts, "records": sum(a["records"] for a in artifacts),
            "ready": all(a["sha256_matches"] and a["record_count_matches"] for a in artifacts)}

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
    expected_sha = str(manifest["sha256"]).lower().strip()
    records = sum(1 for _ in iter_records(local, dataset=manifest["dataset"], source=manifest["source"],
        license=manifest["license"], version=manifest["version"], source_uri=manifest["source_uri"],
        validation_status=manifest["validation_status"]))
    declared = int(manifest["record_count"])
    return {"dataset": manifest["dataset"], "version": manifest["version"], "path": str(local),
        "sha256": actual_sha, "sha256_matches": actual_sha == expected_sha if expected_sha else True,
        "records": records, "record_count_matches": records == declared if declared >= 0 else True,
        "manifest_validation_status": manifest["validation_status"],
        "ready": (actual_sha == expected_sha if expected_sha else True) and (records == declared if declared >= 0 else True)}

def ingest_manifest(manifest_path: str | Path, *, db_path: str | Path, require_checksum: bool = True) -> dict[str, Any]:
    manifest = load_manifest(manifest_path)
    inspection = inspect_dataset(manifest_path)
    if not inspection["ready"]:
        raise ValueError("dataset manifest integrity/count validation failed")
    if "artifacts" in manifest:
        total = 0
        for item in manifest["artifacts"]:
            local = (_project_root(manifest_path) / item["path"]).resolve()
            result = ingest_file(local, db_path=db_path, dataset=manifest.get("dataset", Path(manifest_path).stem),
                source=item.get("source", manifest.get("source", "")), license=item.get("license", manifest.get("license", "")),
                version=item.get("version", manifest.get("version", "")), source_uri=item.get("source_uri", manifest.get("source_uri", "")),
                validation_status=item.get("validation_status", manifest.get("validation_status", "unverified")))
            total += int(result.get("inserted", 0))
        return {"success": True, "ready": True, "records": inspection["records"], "artifacts": len(manifest["artifacts"]),
                "inserted": total, "inspection": inspection, "manifest": str(Path(manifest_path))}
    if require_checksum and not inspection["sha256_matches"]:
        raise ValueError("dataset SHA-256 does not match manifest")
    if not inspection["record_count_matches"]:
        raise ValueError("dataset record count does not match manifest")
    result = ingest_file(inspection["path"], db_path=db_path, dataset=manifest["dataset"], source=manifest["source"],
        license=manifest["license"], version=manifest["version"], source_uri=manifest["source_uri"],
        validation_status=manifest["validation_status"])
    result["inspection"] = inspection; result["manifest"] = str(Path(manifest_path)); result["ready"] = True
    return result
def verify_store(db_path: str | Path) -> dict[str, Any]:
    return status(db_path=db_path)
