#!/usr/bin/env python3
"""Restore manifest-pinned Git LFS payloads without trusting unverified downloads."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from typing import Any

LFS_SIGNATURE = b"version https://git-lfs.github.com/spec/v1"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
CHUNK_SIZE = 1024 * 1024


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_lfs_pointer(path: Path) -> dict[str, Any] | None:
    with path.open("rb") as handle:
        head = handle.read(4096)
    if not head.startswith(LFS_SIGNATURE):
        return None
    text = head.decode("ascii", errors="strict")
    fields: dict[str, Any] = {}
    for line in text.splitlines():
        if line.startswith("oid sha256:"):
            fields["sha256"] = line.removeprefix("oid sha256:").strip().lower()
        elif line.startswith("size "):
            try:
                fields["size"] = int(line.removeprefix("size ").strip())
            except ValueError as exc:
                raise ValueError(f"invalid LFS pointer size in {path}") from exc
    if not SHA256_RE.fullmatch(str(fields.get("sha256", ""))):
        raise ValueError(f"invalid or missing sha256 OID in LFS pointer: {path}")
    if not isinstance(fields.get("size"), int) or fields["size"] < 0:
        raise ValueError(f"invalid or missing size in LFS pointer: {path}")
    return fields


def project_root(manifest_path: Path) -> Path:
    resolved = manifest_path.resolve()
    for parent in (resolved.parent, *resolved.parents):
        if parent.name == "datasets":
            return parent.parent
    return resolved.parent


def _safe_local_path(root: Path, raw_path: str) -> Path:
    local = (root / raw_path).resolve()
    try:
        local.relative_to(root.resolve())
    except ValueError as exc:
        raise ValueError(f"artifact path escapes project root: {raw_path}") from exc
    return local


def _artifact_specs(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    if isinstance(manifest.get("artifacts"), list):
        return [item for item in manifest["artifacts"]
                if isinstance(item, dict) and str(item.get("role", "data")).lower() != "license"]
    return [{
        "path": manifest["local_path"],
        "sha256": manifest["sha256"],
        "source_uri": manifest["source_uri"],
        "byte_size": manifest.get("byte_size"),
        "role": "data",
    }]


def restore_one(root: Path, item: dict[str, Any], manifest: dict[str, Any]) -> dict[str, Any]:
    raw_path = item.get("path") or manifest.get("local_path")
    if not isinstance(raw_path, str) or not raw_path.strip():
        raise ValueError("manifest artifact path is missing")
    destination = _safe_local_path(root, raw_path)
    if not destination.is_file():
        raise FileNotFoundError(f"artifact is missing locally: {destination}")

    expected_sha = str(item.get("sha256") or manifest.get("sha256") or "").lower().strip()
    if not SHA256_RE.fullmatch(expected_sha):
        raise ValueError(f"manifest has invalid SHA-256 for {raw_path}")

    actual_sha = sha256_file(destination)
    if actual_sha == expected_sha:
        return {"path": raw_path, "status": "ALREADY_VERIFIED", "sha256": actual_sha,
                "bytes": destination.stat().st_size}

    pointer = parse_lfs_pointer(destination)
    if pointer is None:
        raise ValueError(
            f"{raw_path} is not a Git LFS pointer and does not match its manifest; "
            "refusing to overwrite an unrecognized file"
        )
    if pointer["sha256"] != expected_sha:
        raise ValueError(
            f"LFS pointer OID does not match manifest for {raw_path}: "
            f"pointer={pointer['sha256']} manifest={expected_sha}"
        )

    expected_size_raw = item.get("byte_size", manifest.get("byte_size", pointer["size"]))
    if isinstance(expected_size_raw, bool):
        raise ValueError(f"invalid byte_size in manifest for {raw_path}")
    try:
        expected_size = int(expected_size_raw)
    except (TypeError, ValueError) as exc:
        expected_size = pointer["size"]
    if expected_size != pointer["size"]:
        raise ValueError(
            f"LFS pointer size does not match manifest for {raw_path}: "
            f"pointer={pointer['size']} manifest={expected_size}"
        )

    source_uri = item.get("source_uri") or manifest.get("source_uri")
    parsed = urlparse(str(source_uri or ""))
    if parsed.scheme != "https" or not parsed.netloc:
        raise ValueError(f"refusing non-HTTPS or missing source URI for {raw_path}")

    destination.parent.mkdir(parents=True, exist_ok=True)
    temp_path: Path | None = None
    digest = hashlib.sha256()
    written = 0
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", prefix=f".{destination.name}.restore-", suffix=".tmp",
            dir=destination.parent, delete=False
        ) as temporary:
            temp_path = Path(temporary.name)
            request = Request(str(source_uri), headers={"User-Agent": "AI-CYBER-dataset-restore/1.0"})
            with urlopen(request, timeout=90) as response:
                while True:
                    chunk = response.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > expected_size:
                        raise ValueError(
                            f"download exceeded expected size for {raw_path}: "
                            f"more than {expected_size} bytes"
                        )
                    digest.update(chunk)
                    temporary.write(chunk)
            temporary.flush()
            os.fsync(temporary.fileno())

        downloaded_sha = digest.hexdigest()
        if written != expected_size:
            raise ValueError(
                f"download size mismatch for {raw_path}: expected {expected_size}, got {written}"
            )
        if downloaded_sha != expected_sha:
            raise ValueError(
                f"download SHA-256 mismatch for {raw_path}: "
                f"expected {expected_sha}, got {downloaded_sha}"
            )

        # Atomic replacement only occurs after exact byte-size and checksum checks.
        os.replace(temp_path, destination)
        temp_path = None
        return {
            "path": raw_path,
            "status": "RESTORED_AND_VERIFIED",
            "source_uri": str(source_uri),
            "sha256": downloaded_sha,
            "bytes": written,
        }
    finally:
        if temp_path is not None:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass


def restore_manifest(manifest_path: Path) -> dict[str, Any]:
    manifest_path = manifest_path.resolve()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict):
        raise ValueError("manifest must be a JSON object")
    root = project_root(manifest_path)
    results = []
    for item in _artifact_specs(manifest):
        raw_path = item.get("path", manifest.get("local_path"))
        local = _safe_local_path(root, str(raw_path))
        if not local.is_file():
            results.append({"path": raw_path, "status": "BLOCKED_MISSING"})
            continue
        try:
            if parse_lfs_pointer(local) is None and sha256_file(local) != str(
                item.get("sha256") or manifest.get("sha256") or ""
            ).lower().strip():
                results.append({
                    "path": raw_path,
                    "status": "BLOCKED_UNRECOGNIZED_MISMATCH",
                    "reason": "file is not an LFS pointer and fails the expected checksum; left unchanged",
                })
                continue
            results.append(restore_one(root, item, manifest))
        except Exception as exc:
            results.append({
                "path": raw_path,
                "status": "BLOCKED",
                "error": f"{type(exc).__name__}: {exc}",
            })

    return {
        "manifest": str(manifest_path),
        "dataset": manifest.get("dataset", manifest_path.stem),
        "results": results,
        "success": bool(results) and all(
            row.get("status") in {"ALREADY_VERIFIED", "RESTORED_AND_VERIFIED"}
            for row in results
        ),
        "database_created": False,
        "ingestion_performed": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Restore only manifest-pinned Git LFS placeholders and verify bytes before replacement"
    )
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()
    try:
        result = restore_manifest(args.manifest)
    except Exception as exc:
        result = {"success": False, "error": f"{type(exc).__name__}: {exc}"}
    payload = json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True)
    print(payload)
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(payload + "\n", encoding="utf-8")
    return 0 if result.get("success") else 1


if __name__ == "__main__":
    raise SystemExit(main())
