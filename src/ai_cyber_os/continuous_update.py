"""Manifest-driven continuous dataset update mechanism."""
from __future__ import annotations
import hashlib, json, os, tempfile
from pathlib import Path
from typing import Any
from .dataset_pipeline import inspect_dataset, ingest_manifest, load_manifest

def _load_state(path: Path) -> dict[str, Any]:
    if not path.exists(): return {"version": 1, "datasets": {}}
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("datasets", {}), dict): raise ValueError("invalid continuous-update state")
    return data

def _atomic_write(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, sort_keys=True); fh.write("\n")
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)

def update_from_manifests(manifest_paths: list[str | Path], *, db_path: str | Path, state_path: str | Path, force: bool = False) -> dict[str, Any]:
    state_file = Path(state_path); state = _load_state(state_file); results = []
    for manifest_path in manifest_paths:
        mf = Path(manifest_path); manifest = load_manifest(mf); inspection = inspect_dataset(mf)
        key = str(manifest.get("dataset") or mf)
        if "sha256" in inspection:
            dataset_digest = inspection["sha256"]
        else:
            dataset_digest = hashlib.sha256(
                json.dumps(
                    [
                        {
                            "path": artifact["path"],
                            "sha256": artifact["sha256"],
                            "records": artifact["records"],
                        }
                        for artifact in inspection["artifacts"]
                    ],
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest()
        fingerprint = f"{dataset_digest}:{inspection['records']}:{manifest.get('version', '')}"
        previous = state["datasets"].get(key, {}).get("fingerprint")
        if not force and previous == fingerprint:
            results.append({"dataset": key, "status": "UNCHANGED", "fingerprint": fingerprint}); continue
        result = ingest_manifest(mf, db_path=db_path, require_checksum=True)
        state["datasets"][key] = {"fingerprint": fingerprint, "version": manifest.get("version", ""), "sha256": dataset_digest, "record_count": inspection["records"], "manifest": str(mf)}
        results.append({"dataset": key, "status": "INGESTED", "fingerprint": fingerprint, "ingestion": result})
    _atomic_write(state_file, state)
    return {"success": all(r["status"] in {"UNCHANGED", "INGESTED"} for r in results), "datasets_checked": len(results), "ingested": sum(r["status"]=="INGESTED" for r in results), "unchanged": sum(r["status"]=="UNCHANGED" for r in results), "results": results, "state": str(state_file)}
