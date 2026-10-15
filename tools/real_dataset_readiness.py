#!/usr/bin/env python3
"""Evidence-based inventory and manifest readiness gate; does not download or ingest."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if SRC_ROOT.is_dir() and str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from ai_cyber_os.dataset_pipeline import inspect_dataset, sha256_file

SUPPORTED = {
    ".json", ".jsonl", ".ndjson", ".xml", ".csv", ".txt", ".log",
    ".md", ".yaml", ".yml", ".rules", ".zeek", ".gz", ".zip", ".tgz", ".tar",
}
LFS_SIGNATURE = b"version https://git-lfs.github.com/spec/v1"
PLACEHOLDER_MARKERS = ("REPLACE_WITH_", "TODO_FILL_", "YOUR_SOURCE_URI")


def _contains_placeholder(value: Any) -> bool:
    if isinstance(value, str):
        return any(marker in value for marker in PLACEHOLDER_MARKERS)
    if isinstance(value, dict):
        return any(_contains_placeholder(k) or _contains_placeholder(v) for k, v in value.items())
    if isinstance(value, list):
        return any(_contains_placeholder(item) for item in value)
    return False


def _is_lfs_pointer(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            head = handle.read(256)
    except OSError:
        return False
    return head.startswith(LFS_SIGNATURE)


def _manifest_paths(root: Path) -> list[Path]:
    candidates = (root / "datasets" / "manifests", root / "manifests")
    found: set[Path] = set()
    for directory in candidates:
        if directory.is_dir():
            found.update(p.resolve() for p in directory.glob("*.json") if p.is_file())
    return sorted(found)


def inspect(root: Path, *, deep: bool = True) -> dict[str, Any]:
    root = root.resolve()
    if not root.is_dir():
        raise FileNotFoundError(f"dataset root not found: {root}")

    files: list[dict[str, Any]] = []
    lfs_paths: list[str] = []
    total_bytes = 0
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in SUPPORTED:
            continue
        if any(part in {".git", "__pycache__", ".pytest_cache"} for part in path.parts):
            continue
        size = path.stat().st_size
        pointer = _is_lfs_pointer(path)
        digest = sha256_file(path)
        total_bytes += size
        rel = str(path.relative_to(root))
        if pointer:
            lfs_paths.append(rel)
        files.append({
            "path": rel,
            "bytes": size,
            "sha256": digest,
            "git_lfs_pointer": pointer,
            "status": "BLOCKED_LFS_POINTER" if pointer else ("EMPTY" if size == 0 else "PRESENT"),
        })

    manifest_results: list[dict[str, Any]] = []
    for manifest_path in _manifest_paths(root):
        rel = str(manifest_path.relative_to(root))
        try:
            parsed = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            manifest_results.append({
                "manifest": rel, "dataset": manifest_path.stem, "status": "FAIL",
                "ready": False, "error": f"manifest parse error: {exc}",
            })
            continue

        if _contains_placeholder(parsed):
            manifest_results.append({
                "manifest": rel,
                "dataset": parsed.get("dataset", manifest_path.stem) if isinstance(parsed, dict) else manifest_path.stem,
                "status": "TEMPLATE_EXCLUDED",
                "ready": False,
                "reason": "placeholder manifest is a template, not an ingestible dataset",
            })
            continue

        if not deep:
            manifest_results.append({
                "manifest": rel,
                "dataset": parsed.get("dataset", manifest_path.stem) if isinstance(parsed, dict) else manifest_path.stem,
                "status": "NOT_DEEP_CHECKED",
                "ready": False,
                "reason": "re-run with --deep to verify SHA-256, parser counts, and format statistics",
            })
            continue

        try:
            result = inspect_dataset(manifest_path)
            ready = bool(result.get("ready"))
            manifest_results.append({
                "manifest": rel,
                "dataset": result.get("dataset", manifest_path.stem),
                "status": "PASS" if ready else "BLOCKED",
                "ready": ready,
                "records": result.get("records", 0),
                "sha256_matches": result.get("sha256_matches"),
                "record_count_matches": result.get("record_count_matches"),
                "manifest_checks": result.get("manifest_checks"),
                "artifact_integrity": result.get("artifact_integrity"),
                "artifacts": result.get("artifacts", []),
                "error": None,
            })
        except Exception as exc:
            manifest_results.append({
                "manifest": rel,
                "dataset": parsed.get("dataset", manifest_path.stem) if isinstance(parsed, dict) else manifest_path.stem,
                "status": "BLOCKED",
                "ready": False,
                "error": f"{type(exc).__name__}: {exc}",
            })

    eligible = [row for row in manifest_results if row["status"] != "TEMPLATE_EXCLUDED"]
    readiness = bool(eligible) and all(row["ready"] for row in eligible) and not lfs_paths
    inventory = {"files": len(files), "bytes": total_bytes, "files_detail": files}
    # Compatibility keys retained for callers of the original inventory-only API.
    return {
        "root": str(root),
        "files": len(files),
        "bytes": total_bytes,
        "files_detail": files,
        "inventory": inventory,
        "git_lfs_pointer_paths": lfs_paths,
        "manifests": {
            "found": len(manifest_results),
            "eligible": len(eligible),
            "passing": sum(row["ready"] for row in eligible),
            "blocked": sum(not row["ready"] for row in eligible),
            "details": manifest_results,
        },
        "deep_check": deep,
        "ready_for_ingestion": readiness,
        "ingestion_performed": False,
        "database_created": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Read-only AI-CYBER dataset integrity, parser-count, and readiness checks"
    )
    parser.add_argument("root", type=Path, help="repository or dataset project root")
    parser.add_argument("--json-out", type=Path)
    parser.add_argument(
        "--no-deep", action="store_true",
        help="inventory files only; does not qualify as an ingestion readiness PASS",
    )
    args = parser.parse_args()
    result = inspect(args.root, deep=not args.no_deep)
    payload = json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False, default=str)
    print(payload)
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(payload + "\n", encoding="utf-8")
    return 0 if result["ready_for_ingestion"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
