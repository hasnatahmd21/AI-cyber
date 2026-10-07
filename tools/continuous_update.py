#!/usr/bin/env python3
"""Apply verified local dataset manifests incrementally."""
from __future__ import annotations
import argparse, json
from pathlib import Path
from ai_cyber_os.continuous_update import update_from_manifests

def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("manifests", nargs="+", type=Path)
    p.add_argument("--db", required=True)
    p.add_argument("--state", required=True)
    p.add_argument("--force", action="store_true")
    args = p.parse_args()
    result = update_from_manifests(args.manifests, db_path=args.db, state_path=args.state, force=args.force)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["success"] else 1

if __name__ == "__main__":
    raise SystemExit(main())
