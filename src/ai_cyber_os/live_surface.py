"""Read-only, evidence-backed live status adapters for the CYBER OS console.

This module never starts HYDRA or performs recovery as a side effect of a status
poll. Mutating/operational requests remain behind the existing defence gate.
"""
from __future__ import annotations

import hashlib
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[2]
STATE_ROOT = PROJECT_ROOT / ".ai_cyber"
AUDIT_ROOT = STATE_ROOT / "audit"
HYDRA_ROOT = PROJECT_ROOT / "src" / "ai_cyber_os"
DEFENCE_ROOT = PROJECT_ROOT / "layered_defense" / "ai_cyber"
UI_ASSET_PATH = PROJECT_ROOT / "CYBER_OS_defence.html"
# Pin the uploaded UI to the reviewed HTML; updating the design requires updating this value too.
UI_ASSET_SHA256 = "fe8795cc2000c30353bdeec8337768d77386af732004731ef7aa7713e7a95dbe"
_SERVICE_STARTED = time.monotonic()
_CACHE_TTL_S = 8.0
_integrity_cache: dict[str, Any] = {"until": 0.0, "value": None}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _state(state: str, evidence: str, **extra: Any) -> dict[str, Any]:
    return {"state": state, "evidence": str(evidence)[:240], **extra}


def verify_ui_asset() -> dict[str, Any]:
    """Verify the exact UI bytes before serving the page; fail closed on a mismatch."""
    try:
        if UI_ASSET_PATH.is_symlink() or not UI_ASSET_PATH.is_file():
            return _state("failed", "Canonical UI asset is missing or is a symbolic link.")
        digest = hashlib.sha256(UI_ASSET_PATH.read_bytes()).hexdigest()
        if digest != UI_ASSET_SHA256:
            return _state("failed", "Canonical UI SHA-256 differs from the reviewed pin.", sha256=digest)
        return _state("passed", "Canonical CYBER OS UI matches its reviewed SHA-256.", sha256=digest)
    except OSError as exc:
        return _state("failed", f"Canonical UI could not be verified ({type(exc).__name__}).")


def _audit_file_list() -> list[Path]:
    try:
        if AUDIT_ROOT.is_symlink() or not AUDIT_ROOT.is_dir():
            return []
        files = [p for p in AUDIT_ROOT.glob("*.json.enc") if p.is_file() and not p.is_symlink()]
        return sorted(files, key=lambda p: (p.stat().st_mtime_ns, p.name), reverse=True)
    except OSError:
        return []


def _latest_audit() -> dict[str, Any]:
    files = _audit_file_list()
    if not files:
        return {
            "available": False,
            "encrypted": False,
            "chainOk": None,
            "records": 0,
            "timestamp": None,
            "records_data": [],
            "evidence": "No encrypted defence audit has been recorded in this runtime yet.",
        }
    path = files[0]
    try:
        # Never create a new key during a read-only status request.
        key_env = os.environ.get("AI_CYBER_KEY_DEFAULT")
        key_path = STATE_ROOT / "key"
        if not key_env and (key_path.is_symlink() or not key_path.is_file()):
            raise RuntimeError("signing key unavailable")
        defence_root = str(PROJECT_ROOT / "layered_defense")
        if defence_root not in sys.path:
            sys.path.insert(0, defence_root)
        from ai_cyber.adapters.audit_store import load_verified_encrypted
        from ai_cyber.crypto_encryption import AeadCipher
        from ai_cyber.keystore import DefaultKeyProvider

        records = load_verified_encrypted(
            str(path),
            AeadCipher(DefaultKeyProvider(str(STATE_ROOT))),
        )
        stamp = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat()
        return {
            "available": True,
            "encrypted": True,
            "chainOk": True,
            "records": len(records),
            "timestamp": stamp,
            "records_data": records,
            "evidence": "Latest encrypted audit decrypted and its hash chain verified.",
        }
    except Exception as exc:
        try:
            stamp = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat()
        except OSError:
            stamp = None
        return {
            "available": True,
            "encrypted": True,
            "chainOk": False,
            "records": 0,
            "timestamp": stamp,
            "records_data": [],
            "evidence": f"Latest encrypted audit could not be verified ({type(exc).__name__}).",
        }


def _integrity_check(*, force: bool = False) -> dict[str, Any]:
    now = time.monotonic()
    cached = _integrity_cache.get("value")
    if not force and cached is not None and now < float(_integrity_cache.get("until", 0.0)):
        return dict(cached)

    hydra_baseline = STATE_ROOT / "hydra_baseline.json"
    defence_baseline = STATE_ROOT / "defence_baseline.json"
    has_env_key = bool(os.environ.get("AI_CYBER_KEY_DEFAULT"))
    key_path = STATE_ROOT / "key"
    has_key = has_env_key or (key_path.is_file() and not key_path.is_symlink())
    if not hydra_baseline.is_file() or hydra_baseline.is_symlink() or not defence_baseline.is_file() or defence_baseline.is_symlink():
        value = _state("unknown", "Signed HYDRA/defence baselines have not both been initialised; no baseline was created by this read-only check.", checked_at=_now())
    elif not has_key:
        value = _state("failed", "Signing key is missing; integrity verification cannot authenticate the baselines.", checked_at=_now())
    else:
        try:
            defence_root = str(PROJECT_ROOT / "layered_defense")
            if defence_root not in sys.path:
                sys.path.insert(0, defence_root)
            from ai_cyber.crypto_integrity import Integrity
            from ai_cyber.integrity_gate import check
            from ai_cyber.keystore import DefaultKeyProvider
            from ai_cyber.launcher import default_defence_paths, default_paths
            from ai_cyber.runtime import build_system

            provider = DefaultKeyProvider(str(STATE_ROOT))
            system = build_system(key_provider=provider)
            try:
                hydra_dir, baseline_path = default_paths()
                defence_dir, defence_baseline_path = default_defence_paths(baseline_path)
                result = check(
                    system,
                    hydra_dir,
                    baseline_path,
                    Integrity(provider),
                    None,
                    defence_dir=defence_dir,
                    defence_baseline_path=defence_baseline_path,
                    defence_clean_source=None,
                )
                value = _state(
                    "passed" if result.ok else "failed",
                    "Both signed code trees and HYDRA split integrity verified."
                    if result.ok else result.reason,
                    checked_at=_now(),
                )
            finally:
                system.shutdown()
        except Exception as exc:
            value = _state("failed", f"Integrity check failed closed ({type(exc).__name__}).", checked_at=_now())

    _integrity_cache.update({"until": now + _CACHE_TTL_S, "value": value})
    return dict(value)


def invalidate_status_cache() -> None:
    """Invalidate cached read-only integrity results after a guarded operation."""
    _integrity_cache.update({"until": 0.0, "value": None})


def _trace_map(records: list[dict[str, Any]]) -> tuple[dict[str, str], dict[str, Any] | None]:
    trace_states: dict[str, str] = {}
    decision_record = None
    for record in reversed(records):
        if not isinstance(record, dict):
            continue
        fields = record.get("fields")
        if not isinstance(fields, dict):
            continue
        event = record.get("event")
        if event == "decision" and decision_record is None:
            decision_record = record
            trace = fields.get("trace")
            if isinstance(trace, list):
                for item in trace:
                    if isinstance(item, str) and ":" in item:
                        name, state = item.split(":", 1)
                        trace_states[name] = state.lower()
        if trace_states and decision_record is not None:
            break
    return trace_states, decision_record


def _map_decision(value: str | None) -> str:
    return {
        "allow": "passed",
        "block": "blocked",
        "quarantine": "isolated",
        "error": "failed",
        "restrict": "checking",
        "escalate": "checking",
    }.get(str(value or "").lower(), "unknown")


def defence_status(*, fabric: dict[str, Any] | None = None,
                   runtime_state: dict[str, Any] | None = None,
                   telemetry_state: dict[str, Any] | None = None,
                   force_integrity_check: bool = False) -> dict[str, Any]:
    """Return last observed enforcement evidence plus a current signed-tree check."""
    integrity = _integrity_check(force=force_integrity_check)
    audit = _latest_audit()
    records = audit.get("records_data", [])
    trace, decision = _trace_map(records)
    components: dict[str, dict[str, Any]] = {}

    components["integrity"] = dict(integrity)
    components["ui"] = verify_ui_asset()
    for key, trace_key in (("barrier", "barrier"), ("l1", "layer1"), ("l2", "layer2"), ("l3", "layer3")):
        decision_value = trace.get(trace_key)
        if decision_value:
            components[key] = _state(
                _map_decision(decision_value),
                f"Last verified defence trace: {trace_key}:{decision_value}.",
                observed_at=audit.get("timestamp"),
            )
        else:
            components[key] = _state("unknown", "No verified event for this component is available in the latest audit.")

    isolation_value = trace.get("isolation")
    if isolation_value:
        components["iso"] = _state(
            _map_decision("quarantine" if isolation_value == "quarantined" else isolation_value),
            f"Last verified trace: isolation:{isolation_value}.",
            observed_at=audit.get("timestamp"),
        )
    elif decision is not None and isinstance(decision.get("fields"), dict) and decision["fields"].get("decision") == "allow":
        components["iso"] = _state("passed", "Last guarded request was allowed; no isolation was triggered for that request.", observed_at=audit.get("timestamp"))
    else:
        components["iso"] = _state("unknown", "No verified isolation decision is available in the latest audit.")

    event_names = [r.get("event") for r in records if isinstance(r, dict)]
    if any(name == "regenerated" for name in event_names):
        components["regen"] = _state("passed", "Verified recovery event recorded; the execution that performed recovery was blocked and requires restart.", observed_at=audit.get("timestamp"))
    elif any(name == "regeneration_failed" for name in event_names):
        components["regen"] = _state("failed", "Latest audit records a refused or failed recovery.", observed_at=audit.get("timestamp"))
    elif integrity["state"] == "passed":
        components["regen"] = _state("idle", "Signed baselines and current trees are clean; recovery is not currently required.", checked_at=integrity.get("checked_at"))
    elif integrity["state"] == "failed":
        components["regen"] = _state("failed", "Integrity did not pass; no automatic recovery was performed by the status endpoint.")
    else:
        components["regen"] = _state("unknown", "Recovery readiness is unknown until signed baselines exist and verify.")

    if audit.get("chainOk") is False:
        components["crypto"] = _state("failed", "Latest encrypted audit could not be authenticated or its hash chain failed.", observed_at=audit.get("timestamp"))
    elif integrity["state"] == "passed" and audit.get("chainOk") is True:
        components["crypto"] = _state("passed", "HMAC-SHA256 signed baselines and the AES-GCM encrypted audit/hash chain both verified.", observed_at=audit.get("timestamp"))
    elif integrity["state"] == "passed":
        try:
            if DEFENCE_ROOT.parent not in map(Path, sys.path):
                sys.path.insert(0, str(DEFENCE_ROOT.parent))
            from ai_cyber.crypto_integrity import aead_available
            encryption_available = aead_available()
        except Exception:
            encryption_available = False
        components["crypto"] = _state(
            "checking" if encryption_available else "failed",
            "HMAC-SHA256 signed baselines verify; AES-GCM is available, but no persisted encrypted audit has yet been verified."
            if encryption_available else
            "HMAC-SHA256 baseline integrity passed, but AES-GCM support is unavailable.",
        )
    elif integrity["state"] == "failed":
        components["crypto"] = _state("failed", "Cryptographic trust cannot be reported healthy while integrity verification fails.")
    else:
        components["crypto"] = _state("unknown", "Cryptographic readiness is unverified until signed baselines and key configuration are available.")

    last_success = (runtime_state or {}).get("last_success")
    if last_success is True:
        components["hydra"] = _state("passed", "Latest HYDRA execution in this UI process reported success.", phase=(runtime_state or {}).get("last_phase"))
    elif last_success is False:
        components["hydra"] = _state("failed", "Latest HYDRA execution in this UI process reported failure.", phase=(runtime_state or {}).get("last_phase"))
    else:
        finished = next((r for r in reversed(records) if isinstance(r, dict) and r.get("event") == "hydra_finished"), None)
        if finished and isinstance(finished.get("fields"), dict):
            exit_code = finished["fields"].get("exit_code")
            components["hydra"] = _state("passed" if exit_code == 0 else "failed",
                                          f"Latest guarded HYDRA process exit code: {exit_code}.",
                                          exit_code=exit_code, observed_at=audit.get("timestamp"))
        else:
            components["hydra"] = _state("idle", "HYDRA is wired but no execution result is currently available.")

    datasets = (fabric or {}).get("datasets", [])
    if fabric and fabric.get("ready") is True:
        count = int(fabric.get("records", 0))
        relations = int(fabric.get("relations", 0))
        components["fabric"] = _state(
            "passed" if count > 0 else "idle",
            f"SQLite/FTS5 knowledge fabric ready: {count} evidence records, {relations} relationships.",
            records=count, relations=relations,
        )
        components["rag"] = _state(
            "passed" if count > 0 else "idle",
            f"Deterministic lexical RAG store ready; {count} evidence records are indexed. Semantic embeddings are not claimed.",
            records=count,
        )
        dataset_events = [
            event for event in (telemetry_state or {}).get("events", [])
            if isinstance(event, dict) and event.get("operation") in {"dataset-ingest-manifest", "dataset-inspect-manifest"}
        ]
        latest_dataset = dataset_events[-1] if dataset_events else None
        if latest_dataset:
            event_status = str(latest_dataset.get("status", "INFO")).upper()
            dataset_state = "passed" if event_status == "PASS" else "failed" if event_status in {"FAIL", "ERROR"} else "checking"
            components["dataset"] = _state(
                dataset_state,
                f"Latest guarded dataset action {latest_dataset.get('operation')} reported {event_status}.",
                observed_at=latest_dataset.get("timestamp"),
            )
        elif int((fabric or {}).get("manifest_count", 0)) > 0:
            components["dataset"] = _state(
                "checking",
                f"{int(fabric.get('manifest_count', 0))} manifests discovered; their artifact hashes and counts have not been verified by this UI session.",
            )
        else:
            components["dataset"] = _state("unknown", "No supported dataset manifests were found.")
        threat_terms = ("cve", "nvd", "kev", "attack", "mitre", "cwe", "cpe", "epss", "sigma", "suricata", "zeek", "capec", "threat", "intel")
        threat_datasets = [
            item for item in datasets
            if isinstance(item, dict) and any(term in str(item.get("dataset", "")).lower() for term in threat_terms)
        ]
        threat_records = sum(int(item.get("records", 0)) for item in threat_datasets)
        components["intel"] = _state(
            "passed" if threat_records > 0 else "idle",
            f"Indexed security-intelligence evidence: {threat_records} records across {len(threat_datasets)} matching datasets.",
            records=threat_records, datasets=[str(item.get("dataset", "")) for item in threat_datasets[:30]],
        )
    else:
        components["fabric"] = _state("unknown", "Data Fabric status is unavailable.")
        components["rag"] = _state("unknown", "RAG retrieval store status is unavailable.")
        components["dataset"] = _state("unknown", "Dataset manifest status is unavailable.")
        components["intel"] = _state("unknown", "Threat-intelligence dataset status is unavailable.")

    if audit.get("chainOk") is True:
        components["audit"] = _state("passed", "The latest encrypted audit was decrypted and its hash chain verified.", records=int(audit.get("records", 0)), observed_at=audit.get("timestamp"))
    elif audit.get("chainOk") is False:
        components["audit"] = _state("failed", "The latest encrypted audit failed authentication or hash-chain verification.", observed_at=audit.get("timestamp"))
    else:
        components["audit"] = _state("unknown", "No persisted encrypted audit chain is available for verification.")

    project_parts = [HYDRA_ROOT / "hydra.py", HYDRA_ROOT / "knowledge.py", HYDRA_ROOT / "dataset_pipeline.py",
                     DEFENCE_ROOT / "barrier.py", DEFENCE_ROOT / "layer1.py", DEFENCE_ROOT / "layer2.py",
                     DEFENCE_ROOT / "layer3.py", DEFENCE_ROOT / "isolation.py", DEFENCE_ROOT / "crypto_integrity.py"]
    present = sum(p.is_file() for p in project_parts)
    project_ok = present == len(project_parts)
    if not project_ok:
        project_state = "failed"
        project_evidence = f"Required runtime components present: {present}/{len(project_parts)}."
    elif integrity["state"] == "failed" or any(components[k]["state"] == "failed" for k in ("barrier", "l1", "l2", "l3")):
        project_state = "failed"
        project_evidence = "At least one critical integrity/defence component has a failure state."
    elif components["ui"]["state"] != "passed":
        project_state = "failed"
        project_evidence = "The served UI asset failed its pinned SHA-256 check."
    elif integrity["state"] == "unknown":
        project_state = "checking"
        project_evidence = "Core files exist; signed integrity is not yet verified."
    else:
        project_state = "passed"
        project_evidence = "Required core files, pinned UI asset, and signed integrity currently verify."
    components["project"] = _state(project_state, project_evidence, files_present=present, files_required=len(project_parts))

    return {
        "source": "live",
        "timestamp": _now(),
        "components": components,
        "audit": {
            "available": audit.get("available", False),
            "encrypted": audit.get("encrypted", False),
            "chainOk": audit.get("chainOk"),
            "records": int(audit.get("records", 0)),
            "timestamp": audit.get("timestamp"),
            "evidence": audit.get("evidence"),
        },
        "last_decision": {
            "decision": (decision or {}).get("fields", {}).get("decision") if decision else None,
            "reason": (decision or {}).get("fields", {}).get("reason") if decision else None,
            "trace": (decision or {}).get("fields", {}).get("trace") if decision else [],
            "timestamp": (decision or {}).get("ts") if decision else None,
        },
    }


def _git_info() -> dict[str, Any]:
    def run(*args: str) -> str | None:
        try:
            result = subprocess.run(
                ["git", "-C", str(PROJECT_ROOT), *args],
                capture_output=True, text=True, timeout=2, check=True,
            )
            return result.stdout.strip()
        except Exception:
            return None

    branch = run("rev-parse", "--abbrev-ref", "HEAD")
    commit = run("rev-parse", "--short=12", "HEAD")
    dirty_output = run("status", "--porcelain")
    return {
        "branch": branch,
        "commit": commit,
        "working_tree": "clean" if dirty_output == "" else "modified" if dirty_output is not None else "unknown",
    }


def project_summary(*, runtime_state: dict[str, Any] | None = None,
                    telemetry_state: dict[str, Any] | None = None,
                    fabric: dict[str, Any] | None = None,
                    defence: dict[str, Any] | None = None) -> dict[str, Any]:
    """Build the whole-project panel using real repository/runtime counters only."""
    runtime_state = runtime_state or {}
    telemetry_state = telemetry_state or {}
    events = telemetry_state.get("events", [])
    run = telemetry_state.get("run", {})
    event_count = len(events) if isinstance(events, list) else 0
    root_files = [
        "CYBER_OS_defence.html", "src/ai_cyber_os/hydra.py", "src/ai_cyber_os/knowledge.py",
        "src/ai_cyber_os/dataset_pipeline.py", "src/ai_cyber_os/telemetry.py",
        "layered_defense/ai_cyber/barrier.py", "layered_defense/ai_cyber/layer1.py",
        "layered_defense/ai_cyber/layer2.py", "layered_defense/ai_cyber/layer3.py",
        "layered_defense/ai_cyber/isolation.py", "layered_defense/ai_cyber/regeneration.py",
        "layered_defense/ai_cyber/crypto_integrity.py",
    ]
    existing = [name for name in root_files if (PROJECT_ROOT / name).is_file()]
    total_py = 0
    try:
        for directory, names, filenames in os.walk(PROJECT_ROOT):
            names[:] = [name for name in names if name not in {".git", "__pycache__", ".venv", "node_modules", ".ai_cyber"}]
            total_py += sum(name.endswith(".py") for name in filenames)
    except OSError:
        pass
    phase_summary = runtime_state.get("last_summary")
    last_phase = runtime_state.get("last_phase")
    last_success = runtime_state.get("last_success")
    if last_success is True:
        hydra_state = "passed"
    elif last_success is False:
        hydra_state = "failed"
    elif run.get("active"):
        hydra_state = "checking"
    else:
        hydra_state = "idle"
    components = (defence or {}).get("components", {})
    integrity_state = components.get("integrity", {}).get("state", "unknown")
    ui_state = components.get("ui", {}).get("state", "unknown")
    layer_states = [components.get(key, {}).get("state", "unknown") for key in ("barrier", "l1", "l2", "l3")]
    critical_states = [ui_state, integrity_state, *layer_states]
    if len(existing) != len(root_files):
        project_state, project_evidence = "failed", "One or more required runtime source files are missing."
    elif any(value == "failed" for value in critical_states):
        project_state, project_evidence = "degraded", "A critical UI/integrity/defence component has a verified failure state."
    elif any(value in {"unknown", "checking"} for value in critical_states):
        project_state, project_evidence = "checking", "Core files exist, but not all key components have verified live evidence yet."
    else:
        project_state, project_evidence = "ready", "Core UI, signed integrity, and live defence evidence are available."
    runtime_label = str(runtime_state.get("runtime", "unknown")).lower()
    if runtime_label not in {"online", "degraded", "blocked", "starting", "unknown"}:
        runtime_label = "unknown"

    return {
        "timestamp": _now(),
        "app": {
            "state": runtime_label,
            "ui": "CYBER_OS_defence.html",
            "host_scope": "localhost-only",
            "uptime_seconds": round(time.monotonic() - _SERVICE_STARTED, 1),
        },
        "repository": _git_info(),
        "project": {
            "state": project_state,
            "evidence": project_evidence,
            "required_files_present": len(existing),
            "required_files_total": len(root_files),
            "python_files": total_py,
        },
        "hydra": {
            "state": hydra_state,
            "last_phase": last_phase,
            "last_success": last_success,
            "last_summary": phase_summary,
            "available_phases": 27,
        },
        "runtime": {
            "active": bool(run.get("active", False)),
            "status": run.get("status", "IDLE"),
            "operation": run.get("operation"),
            "phase": run.get("phase"),
            "event_count": event_count,
            "latest_event_id": telemetry_state.get("next_id", 0),
        },
        "data_fabric": {
            "ready": bool((fabric or {}).get("ready", False)),
            "records": int((fabric or {}).get("records", 0)),
            "relations": int((fabric or {}).get("relations", 0)),
            "datasets": len((fabric or {}).get("datasets", [])),
            "manifests": int((fabric or {}).get("manifest_count", 0)),
        },
        "defence": {
            "integrity": (defence or {}).get("components", {}).get("integrity", {}).get("state", "unknown"),
            "ui": (defence or {}).get("components", {}).get("ui", {}).get("state", "unknown"),
            "barrier": (defence or {}).get("components", {}).get("barrier", {}).get("state", "unknown"),
            "layers": [(defence or {}).get("components", {}).get(key, {}).get("state", "unknown") for key in ("l1", "l2", "l3")],
            "isolation": (defence or {}).get("components", {}).get("iso", {}).get("state", "unknown"),
            "regeneration": (defence or {}).get("components", {}).get("regen", {}).get("state", "unknown"),
            "cryptography": (defence or {}).get("components", {}).get("crypto", {}).get("state", "unknown"),
            "rag": (defence or {}).get("components", {}).get("rag", {}).get("state", "unknown"),
            "dataset": (defence or {}).get("components", {}).get("dataset", {}).get("state", "unknown"),
            "threat_intel": (defence or {}).get("components", {}).get("intel", {}).get("state", "unknown"),
            "audit": (defence or {}).get("components", {}).get("audit", {}).get("state", "unknown"),
        },
        "files": {"required": root_files, "present": existing},
    }
