#!/usr/bin/env python3
"""Generate a complete dataset manifest from a local evidence file.

The tool computes the file SHA-256 and normalized record count. It never
downloads or labels an upstream source as trusted; provenance fields remain
operator-supplied.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from ai_cyber_os.dataset_pipeline import sha256_file
from ai_cyber_os.knowledge import iter_records


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("dataset_path", type=Path)
    p.add_argument("--dataset", required=True)
    p.add_argument("--source", required=True)
    p.add_argument("--source-uri", required=True)
    p.add_argument("--license", required=True)
    p.add_argument("--version", required=True)
    p.add_argument("--validation-status", default="unverified")
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()

    data = args.dataset_path.resolve()
    root = args.output.resolve().parents[2]
    try:
        local_path = data.relative_to(root).as_posix()
    except ValueError as exc:
        raise SystemExit("dataset_path must be inside the repository root") from exc

    count = sum(1 for _ in iter_records(data, dataset=args.dataset, source=args.source,
                                         license=args.license, version=args.version,
                                         source_uri=args.source_uri,
                                         validation_status=args.validation_status))
    manifest = {
        "dataset": args.dataset,
        "version": args.version,
        "source": args.source,
        "source_uri": args.source_uri,
        "license": args.license,
        "local_path": local_path,
        "sha256": sha256_file(data),
        "record_count": count,
        "schema": {"format": data.suffix.lower().lstrip("."), "record_contract": "ai-cyber-evidence-v1"},
        "ingestion_status": "pending",
        "validation_status": args.validation_status,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
