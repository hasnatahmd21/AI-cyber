#!/usr/bin/env python3
"""Independently verify the integrity and reproducibility of a Stage 0 report.

This verifier reads repository files but never imports or executes repository code.
It reports discrepancies as a non-zero exit status and never prints file contents.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from collections import defaultdict
from pathlib import Path, PurePosixPath
from typing import Any


SCHEMA = "ai-cyber.deep-forensic-audit.v1"
HEX_SHA256_LENGTH = 64


def _safe_path(root: Path, relative: str) -> tuple[Path | None, str | None]:
    """Resolve a report path without allowing absolute paths or symlink traversal."""
    pure = PurePosixPath(relative)
    if (
        not relative
        or pure.is_absolute()
        or pure.as_posix() != relative
        or any(part in {"", ".", ".."} for part in pure.parts)
    ):
        return None, f"unsafe or non-canonical repository-relative path: {relative!r}"

    candidate = root.joinpath(*pure.parts)
    parent = root
    for part in pure.parts[:-1]:
        parent = parent / part
        if parent.is_symlink():
            return None, f"path descends through a symlink: {relative}"
    return candidate, None


def _digest_and_size(path: Path) -> tuple[str, int]:
    """Hash regular file bytes or the symlink target text; never follow a symlink."""
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode):
        data = os.readlink(path).encode("utf-8", errors="surrogateescape")
        return hashlib.sha256(data).hexdigest(), metadata.st_size
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError("inventory path is not a regular file or symlink")

    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest(), metadata.st_size


def verify_report(
    report: dict[str, Any],
    root: Path,
    expected_commit: str | None = None,
) -> list[str]:
    """Return integrity failures; an empty list means all checks passed."""
    root = root.resolve()
    errors: list[str] = []

    if report.get("schema") != SCHEMA:
        errors.append(f"unexpected report schema: {report.get('schema')!r}")

    actual_commit = report.get("commit_sha")
    if expected_commit and actual_commit != expected_commit:
        errors.append(
            f"commit identity mismatch: report={actual_commit!r}, expected={expected_commit!r}"
        )

    inventory = report.get("repository_inventory")
    if not isinstance(inventory, dict):
        return errors + ["repository_inventory is missing or not an object"]
    inventory_files = inventory.get("files")
    if not isinstance(inventory_files, list):
        return errors + ["repository_inventory.files is missing or not a list"]

    inventory_paths: list[str] = []
    for item in inventory_files:
        if not isinstance(item, dict):
            errors.append("repository inventory contains a non-object file record")
            continue
        relative = item.get("path")
        if not isinstance(relative, str):
            errors.append("inventory record has no string path")
            continue
        inventory_paths.append(relative)
    if len(inventory_paths) != len(set(inventory_paths)):
        errors.append("repository inventory contains duplicate path records")
    if inventory_paths != sorted(inventory_paths):
        errors.append("repository inventory paths are not sorted deterministically")

    by_path: dict[str, dict[str, Any]] = {}
    observed_hashes: dict[str, list[str]] = defaultdict(list)
    for item in inventory_files:
        if not isinstance(item, dict):
            continue
        relative = item.get("path")
        if not isinstance(relative, str):
            errors.append("inventory record has no string path")
            continue
        by_path[relative] = item
        path, path_error = _safe_path(root, relative)
        if path_error:
            errors.append(path_error)
            continue
        assert path is not None
        try:
            digest, size = _digest_and_size(path)
        except FileNotFoundError:
            errors.append(f"inventory path is missing: {relative}")
            continue
        except (OSError, ValueError) as exc:
            errors.append(f"cannot safely verify {relative}: {type(exc).__name__}: {exc}")
            continue

        if digest != item.get("sha256"):
            errors.append(f"SHA-256 mismatch for {relative}")
        if size != item.get("bytes"):
            errors.append(f"byte-size mismatch for {relative}")
        is_link = path.is_symlink()
        if (item.get("category") == "symlink") != is_link:
            errors.append(f"symlink classification mismatch for {relative}")
        observed_hashes[digest].append(relative)

        if not isinstance(item.get("sha256"), str) or len(item["sha256"]) != HEX_SHA256_LENGTH:
            errors.append(f"invalid SHA-256 field for {relative}")

    summary = report.get("summary", {})
    if not isinstance(summary, dict):
        errors.append("summary is missing or not an object")
        summary = {}
    if summary.get("repository_file_count") != len(inventory_files):
        errors.append("repository_file_count does not match inventory length")

    expected_duplicate_groups = [
        {"sha256": digest, "paths": sorted(paths)}
        for digest, paths in sorted(observed_hashes.items())
        if len(paths) > 1
    ]
    reported_duplicate_groups = inventory.get("duplicate_content_groups", [])

    def normalize_groups(groups: Any) -> list[dict[str, Any]] | None:
        if not isinstance(groups, list):
            return None
        normalized: list[dict[str, Any]] = []
        for group in groups:
            if not isinstance(group, dict):
                return None
            paths = group.get("paths")
            if not isinstance(paths, list) or not all(isinstance(path, str) for path in paths):
                return None
            normalized.append({"sha256": group.get("sha256"), "paths": sorted(paths)})
        return sorted(normalized, key=lambda group: (str(group["sha256"]), group["paths"]))

    if normalize_groups(reported_duplicate_groups) != normalize_groups(expected_duplicate_groups):
        errors.append("duplicate-content groups do not match recomputed inventory hashes")
    if summary.get("duplicate_content_groups") != len(expected_duplicate_groups):
        errors.append("duplicate_content_groups count does not match recomputed inventory")

    expected_python_paths = {
        path for path, item in by_path.items()
        if PurePosixPath(path).suffix.lower() == ".py" and item.get("category") != "symlink"
    }
    python_records = report.get("files")
    if not isinstance(python_records, list):
        return errors + ["files (Python AST records) is missing or not a list"]
    python_paths: list[str] = []
    for item in python_records:
        if not isinstance(item, dict):
            errors.append("Python AST inventory contains a non-object record")
            continue
        relative = item.get("path")
        if not isinstance(relative, str):
            errors.append("Python AST record has no string path")
            continue
        python_paths.append(relative)
    if len(python_paths) != len(set(python_paths)):
        errors.append("Python AST inventory contains duplicate path records")
    if set(python_paths) != expected_python_paths:
        missing = sorted(expected_python_paths - set(python_paths))
        extra = sorted(set(python_paths) - expected_python_paths)
        errors.append(f"Python AST path coverage mismatch: missing={missing[:10]}, extra={extra[:10]}")

    ast_by_path = {
        item["path"]: item for item in python_records
        if isinstance(item, dict) and isinstance(item.get("path"), str)
    }
    for relative, record in ast_by_path.items():
        inv_item = by_path.get(relative)
        if inv_item is None:
            errors.append(f"Python AST record is absent from repository inventory: {relative}")
            continue
        if record.get("sha256") != inv_item.get("sha256"):
            errors.append(f"AST/inventory SHA-256 mismatch for {relative}")
        if record.get("bytes") != inv_item.get("bytes"):
            errors.append(f"AST/inventory byte-size mismatch for {relative}")
        if record.get("syntax_ok") is True and record.get("syntax_error") is not None:
            errors.append(f"syntax status contradicts syntax_error for {relative}")
        if record.get("syntax_ok") is False and not isinstance(record.get("syntax_error"), dict):
            errors.append(f"syntax failure lacks structured details for {relative}")

    if summary.get("python_file_count") != len(expected_python_paths):
        errors.append("python_file_count does not match non-symlink Python inventory")

    manifest = hashlib.sha256()
    can_recompute_manifest = True
    for relative in sorted(expected_python_paths):
        path, path_error = _safe_path(root, relative)
        if path_error or path is None:
            errors.append(path_error or f"cannot safely resolve {relative}")
            can_recompute_manifest = False
            continue
        if path.is_symlink() or not path.is_file():
            errors.append(f"Python manifest entry is not a regular file: {relative}")
            can_recompute_manifest = False
            continue
        manifest.update(relative.encode("utf-8") + b"\0")
        try:
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    manifest.update(chunk)
        except OSError as exc:
            errors.append(f"cannot hash Python source {relative}: {type(exc).__name__}: {exc}")
            can_recompute_manifest = False
            continue
        manifest.update(b"\0")

    claimed_manifest = summary.get("file_content_manifest_sha256")
    if not isinstance(claimed_manifest, str) or len(claimed_manifest) != HEX_SHA256_LENGTH:
        errors.append("file_content_manifest_sha256 is missing or malformed")
    elif can_recompute_manifest and manifest.hexdigest() != claimed_manifest:
        errors.append(
            "Python-source content manifest mismatch: "
            f"report={claimed_manifest}, recomputed={manifest.hexdigest()}"
        )

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path, help="path to generated deep-audit JSON")
    parser.add_argument("--root", type=Path, default=Path("."), help="repository root")
    parser.add_argument(
        "--expected-commit",
        default=os.environ.get("GITHUB_SHA"),
        help="expected commit SHA (defaults to GITHUB_SHA when set)",
    )
    args = parser.parse_args()

    try:
        report = json.loads(args.report.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        print(f"FAIL: cannot read audit JSON: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    if not isinstance(report, dict):
        print("FAIL: audit JSON root must be an object", file=sys.stderr)
        return 2

    failures = verify_report(report, args.root, args.expected_commit)
    if failures:
        print(f"FAIL: {len(failures)} forensic evidence integrity check(s) failed:")
        for failure in failures:
            print(f"- {failure}")
        return 1

    print(
        "PASS: report schema, commit identity, all inventory hashes and sizes, "
        "duplicate groups, Python AST coverage, and source-manifest hash verified."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
