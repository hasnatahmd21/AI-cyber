"""Evidence-based dataset readiness gate. This module inspects only; it never ingests data."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Iterable, Any

from .dataset_pipeline import inspect_dataset, load_manifest


def inspect_manifest_readiness(manifest_path: str | Path) -> dict[str, Any]:
    """Return PASS/BLOCKED/FAIL plus inspectable evidence for one manifest."""
    path = Path(manifest_path)
    if path.name.casefold() == "example.json":
        return {
            "dataset": path.stem,
            "manifest": str(path),
            "status": "BLOCKED",
            "evidence": "Placeholder example.json is explicitly excluded from real dataset readiness and ingestion.",
        }
    try:
        manifest = load_manifest(path)
    except FileNotFoundError as exc:
        return {
            "dataset": path.stem,
            "manifest": str(path),
            "status": "BLOCKED",
            "evidence": f"Manifest file is missing: {exc}",
        }
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return {
            "dataset": path.stem,
            "manifest": str(path),
            "status": "FAIL",
            "evidence": f"Manifest validation failed: {type(exc).__name__}: {exc}",
        }

    dataset = str(manifest.get("dataset") or path.stem)
    try:
        inspection = inspect_dataset(path)
    except FileNotFoundError as exc:
        return {
            "dataset": dataset,
            "manifest": str(path),
            "status": "BLOCKED",
            "evidence": f"Required artifact is missing: {exc}",
        }
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        message = f"{type(exc).__name__}: {exc}"
        blocked = "git lfs pointer" in str(exc).casefold() or "missing" in str(exc).casefold()
        return {
            "dataset": dataset,
            "manifest": str(path),
            "status": "BLOCKED" if blocked else "FAIL",
            "evidence": message,
        }

    return {
        "dataset": dataset,
        "manifest": str(path),
        "status": "PASS" if inspection.get("ready") is True else "FAIL",
        "evidence": "SHA-256 and record-count checks passed." if inspection.get("ready") is True
                    else "SHA-256 and/or record-count check did not match the manifest.",
        "inspection": inspection,
    }


def readiness_report(
    manifests_dir: str | Path,
    *,
    required_datasets: Iterable[str] = (),
) -> dict[str, Any]:
    """Inspect every JSON manifest and flag required datasets with no manifest."""
    root = Path(manifests_dir)
    if not root.is_dir():
        return {
            "overall": "BLOCKED",
            "manifests_dir": str(root),
            "count": 0,
            "datasets": [],
            "missing_required_datasets": sorted(set(required_datasets)),
            "evidence": f"Manifest directory is unavailable: {root}",
        }

    rows = [
        inspect_manifest_readiness(path)
        for path in sorted(root.rglob("*.json"))
        if path.name.casefold() != "example.json"
    ]
    names = {str(row.get("dataset") or "") for row in rows}
    missing = sorted(set(str(name) for name in required_datasets) - names)
    for name in missing:
        rows.append({
            "dataset": name,
            "manifest": "",
            "status": "BLOCKED",
            "evidence": "Required dataset has no manifest under the configured manifest directory.",
        })

    if not rows:
        overall = "BLOCKED"
        evidence = "No real dataset manifests were found; nothing is declared ready."
    elif any(row["status"] == "FAIL" for row in rows):
        overall = "FAIL"
        evidence = "At least one dataset manifest or integrity/count check failed."
    elif any(row["status"] == "BLOCKED" for row in rows):
        overall = "BLOCKED"
        evidence = "At least one required source/artifact is unavailable or intentionally excluded."
    else:
        overall = "PASS"
        evidence = "Every discovered dataset passed manifest, checksum, and record-count inspection."

    return {
        "overall": overall,
        "manifests_dir": str(root.resolve()),
        "count": len(rows),
        "pass": sum(row["status"] == "PASS" for row in rows),
        "blocked": sum(row["status"] == "BLOCKED" for row in rows),
        "fail": sum(row["status"] == "FAIL" for row in rows),
        "missing_required_datasets": missing,
        "datasets": rows,
        "evidence": evidence,
        "ingestion_performed": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Inspect AI-CYBER dataset readiness without ingestion")
    parser.add_argument("--manifests-dir", required=True)
    parser.add_argument("--require", action="append", default=[], metavar="DATASET")
    args = parser.parse_args(argv)
    report = readiness_report(args.manifests_dir, required_datasets=args.require)
    print(json.dumps(report, indent=2, ensure_ascii=False, default=str))
    return 0 if report["overall"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
