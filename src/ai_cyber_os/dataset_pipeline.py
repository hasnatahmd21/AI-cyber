"""Canonical dataset manifest, integrity, provenance and SQLite ingestion layer."""
from __future__ import annotations
import argparse, hashlib, json, sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

SCHEMA = "ai-cyber.dataset-manifest.v1"

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def count_records(path: Path) -> int:
    if path.suffix.lower() in {".jsonl", ".ndjson"}:
        return sum(1 for line in path.open(encoding="utf-8") if line.strip())
    if path.suffix.lower() == ".json":
        value = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(value, list): return len(value)
        if isinstance(value, dict):
            for key in ("records", "data", "items", "examples", "rows", "entries"):
                if isinstance(value.get(key), list): return len(value[key])
        return 1
    raise ValueError(f"Unsupported dataset format: {path.suffix}")

def iter_records(path: Path) -> Iterable[dict[str, Any]]:
    if path.suffix.lower() in {".jsonl", ".ndjson"}:
        with path.open(encoding="utf-8") as f:
            for line_no, line in enumerate(f, 1):
                if not line.strip(): continue
                value = json.loads(line)
                if not isinstance(value, dict): raise ValueError(f"{path}:{line_no} is not a JSON object")
                yield value
        return
    if path.suffix.lower() == ".json":
        value = json.loads(path.read_text(encoding="utf-8"))
        rows = value if isinstance(value, list) else next((value[k] for k in ("records","data","items","examples","rows","entries") if isinstance(value,dict) and isinstance(value.get(k),list)), None)
        if rows is None: rows = [value]
        for row in rows:
            if not isinstance(row, dict): raise ValueError(f"{path} contains a non-object record")
            yield row
        return
    raise ValueError(f"Unsupported dataset format: {path.suffix}")

def validate_manifest(manifest: dict[str, Any], root: Path) -> dict[str, Any]:
    if manifest.get("schema") != SCHEMA: raise ValueError("Unsupported dataset manifest schema")
    if not manifest.get("dataset_id") or not manifest.get("version"): raise ValueError("dataset_id/version required")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts: raise ValueError("manifest.artifacts must be non-empty")
    seen=set(); checked=[]
    root=root.resolve()
    for a in artifacts:
        rel=a.get("path"); expected=a.get("sha256"); count=a.get("records")
        if not isinstance(rel,str) or rel in seen: raise ValueError(f"invalid/duplicate artifact path: {rel}")
        seen.add(rel)
        if not isinstance(expected,str) or len(expected)!=64: raise ValueError(f"invalid sha256: {rel}")
        if not isinstance(count,int) or count<0: raise ValueError(f"invalid record count: {rel}")
        path=(root/rel).resolve()
        if not path.is_file(): raise FileNotFoundError(path)
        actual=sha256_file(path); actual_count=count_records(path)
        if actual != expected: raise ValueError(f"SHA256 mismatch for {rel}")
        if actual_count != count: raise ValueError(f"record count mismatch for {rel}")
        checked.append({"path":rel,"sha256":actual,"records":actual_count})
    return {"dataset_id":manifest["dataset_id"],"version":manifest["version"],"artifact_count":len(checked),"record_count":sum(x["records"] for x in checked),"artifacts":checked}

def init_store(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS dataset_catalog(dataset_id TEXT PRIMARY KEY, version TEXT NOT NULL, manifest_path TEXT NOT NULL, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS artifacts(dataset_id TEXT NOT NULL, artifact_path TEXT NOT NULL, format TEXT NOT NULL, record_count INTEGER NOT NULL, sha256 TEXT NOT NULL, PRIMARY KEY(dataset_id,artifact_path));
        CREATE TABLE IF NOT EXISTS provenance(dataset_id TEXT NOT NULL, artifact_path TEXT, source TEXT, version TEXT, origin TEXT, acquired_at TEXT);
        CREATE TABLE IF NOT EXISTS records(dataset_id TEXT NOT NULL, artifact_path TEXT NOT NULL, record_id TEXT NOT NULL, payload_json TEXT NOT NULL, PRIMARY KEY(dataset_id,artifact_path,record_id));
        """)

def ingest_manifest(manifest_path: Path, root: Path, db_path: Path) -> dict[str, Any]:
    manifest=json.loads(manifest_path.read_text(encoding="utf-8")); result=validate_manifest(manifest,root); init_store(db_path); root=root.resolve(); ds=manifest["dataset_id"]; now=datetime.now(timezone.utc).isoformat()
    with sqlite3.connect(db_path) as conn:
        conn.execute("INSERT OR REPLACE INTO dataset_catalog VALUES (?,?,?,?)",(ds,manifest["version"],manifest_path.resolve().relative_to(root).as_posix(),now))
        for a in manifest["artifacts"]:
            rel=a["path"]; p=a.get("provenance",{}); mp=manifest.get("provenance",{})
            conn.execute("INSERT OR REPLACE INTO artifacts VALUES (?,?,?,?,?)",(ds,rel,a.get("format",""),a["records"],a["sha256"]))
            conn.execute("DELETE FROM provenance WHERE dataset_id=? AND artifact_path=?",(ds,rel))
            conn.execute("INSERT INTO provenance VALUES (?,?,?,?,?,?)",(ds,rel,p.get("source"),p.get("version"),mp.get("origin"),mp.get("acquired_at")))
            conn.execute("DELETE FROM records WHERE dataset_id=? AND artifact_path=?",(ds,rel))
            for i,row in enumerate(iter_records(root/rel),1):
                rid=str(row.get("record_id") or row.get("id") or row.get("uid") or f"{rel}:{i}")
                conn.execute("INSERT INTO records VALUES (?,?,?,?)",(ds,rel,rid,json.dumps(row,sort_keys=True)))
    return result

def ingest_and_verify(manifest_path: str|Path, root: str|Path, db_path: str|Path)->dict[str,Any]:
    return ingest_manifest(Path(manifest_path),Path(root),Path(db_path))

def _main()->int:
    p=argparse.ArgumentParser(); p.add_argument("--manifest",required=True); p.add_argument("--root",required=True); p.add_argument("--db",required=True); a=p.parse_args(); print(json.dumps(ingest_and_verify(a.manifest,a.root,a.db),indent=2)); return 0

if __name__ == "__main__": raise SystemExit(_main())
