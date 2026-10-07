"""Command-line interface for the local AI-CYBER knowledge store."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .knowledge import DEFAULT_DB, ingest_file, search, status


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="AI-CYBER evidence/RAG knowledge store")
    p.add_argument("--db", default=str(DEFAULT_DB))
    sub = p.add_subparsers(dest="command", required=True)

    ing = sub.add_parser("ingest")
    ing.add_argument("path")
    ing.add_argument("--dataset")
    ing.add_argument("--source")
    ing.add_argument("--license", default="")
    ing.add_argument("--version", default="")
    ing.add_argument("--source-uri", default="")
    ing.add_argument("--validation-status", default="unverified")

    q = sub.add_parser("search")
    q.add_argument("query")
    q.add_argument("--dataset")
    q.add_argument("--limit", type=int, default=10)

    sub.add_parser("status")
    args = p.parse_args(argv)

    if args.command == "ingest":
        result = ingest_file(args.path, db_path=args.db, dataset=args.dataset,
                             source=args.source, license=args.license, version=args.version,
                             source_uri=args.source_uri, validation_status=args.validation_status)
    elif args.command == "search":
        result = {"success": True, "results": search(args.query, db_path=args.db,
                                                       dataset=args.dataset, limit=args.limit)}
    else:
        result = status(db_path=args.db)
    print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
    return 0 if result.get("success", True) else 1


if __name__ == "__main__":
    raise SystemExit(main())
