#!/usr/bin/env python3
"""Audit the tracked AI-CYBER project ZIP without extracting untrusted paths."""
from __future__ import annotations

import argparse
import hashlib
import json
import stat
import sys
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _normalise_member(raw: str) -> tuple[str | None, str | None]:
    if "\\\\" in raw:
        return None, "backslash in ZIP member path"
    name = raw
    while name.startswith("./"):
        name = name[2:]
    name = name.rstrip("/")
    if not name:
        return None, None
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        return None, "absolute or traversal ZIP member path"
    if path.parts and ":" in path.parts[0]:
        return None, "drive-qualified ZIP member path"
    return path.as_posix(), None


def inspect_archive(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(f"Project ZIP not found: {path}")
    names: list[str] = []
    errors: list[dict[str, str]] = []
    seen: set[str] = set()
    duplicate_names: list[str] = []
    symlink_names: list[str] = []
    bad_member: str | None = None
    total_uncompressed = 0

    with zipfile.ZipFile(path, "r") as archive:
        infos = archive.infolist()
        for info in infos:
            total_uncompressed += info.file_size
            normalised, error = _normalise_member(info.filename)
            if error:
                errors.append({"member": info.filename, "error": error})
                continue
            if normalised is None:
                continue
            names.append(normalised)
            if normalised in seen:
                duplicate_names.append(normalised)
            seen.add(normalised)
            mode = (info.external_attr >> 16) & 0xFFFF
            if stat.S_ISLNK(mode):
                symlink_names.append(normalised)
        try:
            bad_member = archive.testzip()
        except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
            errors.append({"member": "<archive>", "error": f"{type(exc).__name__}: {exc}"})

    # Match by suffix so an optional containing directory in the ZIP is harmless.
    def matches(*suffixes: str) -> list[str]:
        return sorted({
            name for name in names
            if any(name == suffix or name.endswith("/" + suffix) for suffix in suffixes)
        })

    components = {
        "it_tech_monolith": matches("IT_tech__MERGED_ALL_FIXES_APPLIED.py"),
        "hydra_runtime_or_legacy": matches(
            "src/ai_cyber_os/hydra.py",
            "ai_cyber_os/hydra.py",
            "HYDRA_FINAL_CLIENT_HANDOVER_FIXED.py",
            "HYDRA_MASTER_RECONSTRUCTED_v2.py",
            "HYDRA_patched-3.py",
        ),
        "dataset_pipeline": matches("dataset_pipeline.py"),
        "knowledge_or_rag_module": matches("knowledge.py", "rag.py"),
        "runtime_ui": matches("src/ai_cyber_os/ui.py", "ai_cyber_os/ui.py", "ui.py"),
        "package_manifest": matches("pyproject.toml", "requirements.txt"),
        "knowledge_tests": matches("tests/test_knowledge.py", "test_knowledge.py"),
        "dataset_tests": matches("tests/test_dataset_pipeline.py", "test_dataset_pipeline.py"),
    }
    return {
        "archive": str(path),
        "archive_bytes": path.stat().st_size,
        "archive_sha256": _sha256(path),
        "zip_member_count": len(infos),
        "unique_normalised_member_count": len(seen),
        "uncompressed_bytes": total_uncompressed,
        "crc_integrity": "FAIL" if bad_member else "PASS",
        "first_corrupt_member": bad_member,
        "unsafe_member_errors": errors,
        "duplicate_member_paths": sorted(set(duplicate_names)),
        "symlink_members": sorted(set(symlink_names)),
        "component_matches": components,
        "member_paths_sample": sorted(names)[:160],
        "member_paths_truncated": len(names) > 160,
        "safe_archive": not (bad_member or errors or duplicate_names or symlink_names),
        "note": (
            "Component matches describe archive contents only; they do not establish "
            "that the ZIP's runtime behavior passes tests."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("zip_path", nargs="?", default="ai_cyber_project.zip")
    args = parser.parse_args(argv)
    try:
        report = inspect_archive(Path(args.zip_path))
    except (OSError, zipfile.BadZipFile) as exc:
        print(json.dumps({"safe_archive": False, "error": f"{type(exc).__name__}: {exc}"}, indent=2))
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["safe_archive"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
