#!/usr/bin/env python3
"""Inspect real dataset trees before ingestion; never downloads or fabricates data."""
from __future__ import annotations
import argparse,json,hashlib
from pathlib import Path

SUPPORTED={".json",".jsonl",".ndjson",".xml",".csv",".txt",".log"}

def inspect(root:Path)->dict:
    rows=[]; total_bytes=0
    for p in sorted(root.rglob("*")):
        if p.is_file() and p.suffix.lower() in SUPPORTED:
            b=p.read_bytes(); total_bytes+=len(b)
            rows.append({"path":str(p.relative_to(root)),"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest()})
    return {"root":str(root),"files":len(rows),"bytes":total_bytes,"files_detail":rows}

def main()->int:
    ap=argparse.ArgumentParser()
    ap.add_argument("root",type=Path)
    ap.add_argument("--json-out",type=Path)
    a=ap.parse_args()
    if not a.root.exists(): raise SystemExit(f"dataset root not found: {a.root}")
    result=inspect(a.root)
    result["ready"]=result["files"]>0
    payload=json.dumps(result,indent=2,sort_keys=True)
    print(payload)
    if a.json_out: a.json_out.write_text(payload+"\n",encoding="utf-8")
    return 0 if result["ready"] else 1
if __name__=="__main__": raise SystemExit(main())
