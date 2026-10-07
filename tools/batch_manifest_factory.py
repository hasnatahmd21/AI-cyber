#!/usr/bin/env python3
"""Create deterministic ingestion manifests from local real datasets."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from ai_cyber_os.manifest_factory import build_batch, write_manifests


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("dataset_root", type=Path)
    ap.add_argument("--project-root", type=Path, required=True)
    ap.add_argument("--metadata-json", type=Path, required=True)
    ap.add_argument("--output-dir", type=Path, required=True)
    args = ap.parse_args()
    metadata = json.loads(args.metadata_json.read_text(encoding="utf-8"))
    if not isinstance(metadata, dict):
        raise SystemExit("metadata JSON must be an object keyed by dataset filename stem")
    manifests = build_batch(
        args.dataset_root,
        project_root=args.project_root,
        metadata_by_dataset=metadata,
    )
    paths = write_manifests(manifests, output_dir=args.output_dir)
    print(json.dumps({"ready": True, "manifests": [str(p) for p in paths], "count": len(paths)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
