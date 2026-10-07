#!/usr/bin/env python3
"""Inspect or ingest an AI-CYBER dataset from its manifest."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from ai_cyber_os.dataset_pipeline import ingest_manifest, inspect_dataset


def main() -> int:
    parser = argparse.ArgumentParser(description="AI-CYBER manifest-driven dataset pipeline")
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--db", required=True)
    parser.add_argument("--inspect", action="store_true")
    parser.add_argument("--no-checksum", action="store_true")
    args = parser.parse_args()

    if args.inspect:
        result = inspect_dataset(args.manifest)
    else:
        result = ingest_manifest(
            args.manifest,
            db_path=args.db,
            require_checksum=not args.no_checksum,
        )
    print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
