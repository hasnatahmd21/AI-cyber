"""Deterministic batch manifest factory for real local AI-CYBER datasets.

This module never downloads data and never claims external verification. It creates
ingestion manifests only from files already present on disk and explicit metadata.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .knowledge import iter_records

SUPPORTED_SUFFIXES = {".jsonl", ".ndjson", ".json", ".csv", ".txt", ".md"}

REQUIRED_METADATA = {
    "dataset", "version", "source", "source_uri", "license",
    "schema", "validation_status",
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_relative(path: Path, root: Path) -> str:
    resolved = path.resolve()
    base = root.resolve()
    try:
        return resolved.relative_to(base).as_posix()
    except ValueError as exc:
        raise ValueError(f"path is outside project root: {path}") from exc


def _record_count(path: Path, metadata: dict[str, Any]) -> int:
    return sum(
        1
        for _ in iter_records(
            path,
            dataset=metadata["dataset"],
            source=metadata["source"],
            license=metadata["license"],
            version=metadata["version"],
            source_uri=metadata["source_uri"],
            validation_status=metadata["validation_status"],
        )
    )


def build_manifest(
    data_path: str | Path,
    *,
    project_root: str | Path,
    metadata: dict[str, Any],
) -> dict[str, Any]:
    """Build one fail-closed manifest from one local dataset file."""
    path = Path(data_path).resolve()
    root = Path(project_root).resolve()
    if not path.is_file():
        raise FileNotFoundError(path)
    if path.suffix.lower() not in SUPPORTED_SUFFIXES:
        raise ValueError(f"unsupported dataset format: {path.suffix}")
    missing = sorted(REQUIRED_METADATA - set(metadata))
    if missing:
        raise ValueError(f"metadata missing required fields: {', '.join(missing)}")
    for key in REQUIRED_METADATA - {"schema"}:
        value = metadata.get(key)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"metadata field {key!r} must be a non-empty string")
    relative = _safe_relative(path, root)
    count = _record_count(path, metadata)
    return {
        "dataset": metadata["dataset"].strip(),
        "version": metadata["version"].strip(),
        "source": metadata["source"].strip(),
        "source_uri": metadata["source_uri"].strip(),
        "license": metadata["license"].strip(),
        "local_path": relative,
        "sha256": _sha256(path),
        "record_count": count,
        "schema": metadata["schema"],
        "ingestion_status": "pending",
        "validation_status": metadata["validation_status"].strip(),
    }


def build_batch(
    dataset_root: str | Path,
    *,
    project_root: str | Path,
    metadata_by_dataset: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """Discover supported files and build deterministic manifests.

    Metadata is keyed by the exact dataset name. Duplicate dataset identities or
    duplicate local files are rejected rather than silently merged.
    """
    root = Path(dataset_root).resolve()
    project = Path(project_root).resolve()
    if not root.is_dir():
        raise FileNotFoundError(root)
    manifests: list[dict[str, Any]] = []
    seen_paths: set[str] = set()
    seen_datasets: set[str] = set()

    for path in sorted(p for p in root.rglob("*") if p.is_file() and p.suffix.lower() in SUPPORTED_SUFFIXES):
        relative = _safe_relative(path, project)
        if relative in seen_paths:
            raise ValueError(f"duplicate dataset path: {relative}")
        seen_paths.add(relative)
        dataset = Path(path).stem
        metadata = metadata_by_dataset.get(dataset)
        if metadata is None:
            raise ValueError(f"missing metadata for dataset file: {dataset}")
        identity = str(metadata.get("dataset", "")).strip()
        if identity in seen_datasets:
            raise ValueError(f"duplicate dataset identity: {identity}")
        seen_datasets.add(identity)
        manifests.append(build_manifest(path, project_root=project, metadata=metadata))
    if not manifests:
        raise ValueError(f"no supported dataset files found under {root}")
    return manifests


def write_manifests(
    manifests: list[dict[str, Any]],
    *,
    output_dir: str | Path,
) -> list[Path]:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for manifest in manifests:
        name = str(manifest["dataset"]).strip()
        if not name or Path(name).name != name:
            raise ValueError(f"unsafe manifest dataset name: {name!r}")
        target = out / f"{name}.manifest.json"
        payload = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
        if target.exists() and target.read_text(encoding="utf-8") != payload:
            raise ValueError(f"refusing to overwrite changed manifest: {target}")
        target.write_text(payload, encoding="utf-8")
        written.append(target)
    return written
