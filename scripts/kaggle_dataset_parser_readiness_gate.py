#!/usr/bin/env python3
"""Real-artifact parser/readiness gate for the AI-CYBER dataset workspace.

This script inspects raw artifacts and manifests only. It never writes to the
Knowledge DB and never ingests records. The sole allowed dataset mutation is a
Git LFS pointer replacement after the downloaded bytes exactly match the pointer's
declared SHA-256 and size.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path
from typing import Any

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT / "src"))

from ai_cyber_os.dataset_readiness import readiness_report
from ai_cyber_os.threat_intel import parse_d3fend_jsonld, parse_mbc_stix, parse_suricata_rules


ATTACK_BASENAME = "enterprise-attack_v19.2_6cda5ad8462c.json"
EXPECTED_D3FEND_NODES = 7688
EXPECTED_MBC_BUNDLES = 1906
EXPECTED_SURICATA_ACTIVE = 52588
EXPECTED_SURICATA_DISABLED = 19500
# The approved first wave contains eleven independent datasets.
# NVD CVE feeds and the CVSS derivation stage are intentionally out of scope.
REQUIRED_DATASET_NAMES = (
    "capec", "cisa_kev", "cpe", "cwe", "epss", "mitre_attack",
    "mitre_d3fend", "mitre_mbc", "sigma", "suricata", "zeek_intel",
)
EXCLUDED_DATASET_NAMES = ("nvd_cve", "cvss")
EXPECTED_MBC_STIX_OBJECTS = 1905

ATTACK_RESTORE_URLS = (
    "https://raw.githubusercontent.com/mitre/cti/6cda5ad8462c/enterprise-attack/enterprise-attack.json",
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/v19.2/enterprise-attack/enterprise-attack-19.2.json",
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def lfs_pointer(path: Path) -> dict[str, Any] | None:
    try:
        with path.open("rb") as handle:
            head = handle.read(1024).decode("utf-8", errors="replace").lstrip()
    except OSError:
        return None
    if not head.startswith("version https://git-lfs.github.com/spec/v1"):
        return None
    digest_match = re.search(r"(?m)^oid sha256:([0-9a-f]{64})\s*$", head)
    size_match = re.search(r"(?m)^size (\d+)\s*$", head)
    return {
        "sha256": digest_match.group(1) if digest_match else None,
        "size": int(size_match.group(1)) if size_match else None,
        "pointer_text": path.read_text(encoding="utf-8", errors="replace"),
    }


def _matches_pointer(path: Path, expected: dict[str, Any]) -> bool:
    return (
        path.is_file()
        and expected.get("sha256") is not None
        and expected.get("size") is not None
        and path.stat().st_size == expected["size"]
        and sha256_file(path) == expected["sha256"]
    )


def restore_lfs_exact_match(path: Path, expected: dict[str, Any]) -> dict[str, Any]:
    """Attempt native git-lfs, then official versioned URLs; never accept a mismatch."""
    attempts: list[dict[str, Any]] = []

    git_roots: list[Path] = []
    for parent in (path.parent, *path.parents):
        if (parent / ".git").exists() and parent not in git_roots:
            git_roots.append(parent)
    # The Kaggle raw-artifact workspace may be separate from the repo checkout.
    # In that case, try the tracked copy in this checkout, then copy only if the
    # source bytes match the exact LFS pointer digest and size.
    if REPOSITORY_ROOT.is_dir() and REPOSITORY_ROOT not in git_roots:
        git_roots.append(REPOSITORY_ROOT)

    for git_root in git_roots:
        try:
            relative = path.relative_to(git_root)
        except ValueError:
            relative = Path("datasets") / "raw" / "mitre_attack" / path.name
        result = subprocess.run(
            ["git", "-C", str(git_root), "lfs", "pull", f"--include={relative.as_posix()}"],
            text=True, capture_output=True, timeout=180,
        )
        candidate = git_root / relative
        attempts.append({
            "method": "git-lfs",
            "repository": str(git_root),
            "artifact": str(candidate),
            "returncode": result.returncode,
            "output": (result.stderr or result.stdout)[-1200:],
        })
        if candidate.resolve() == path.resolve() and _matches_pointer(path, expected):
            return {"restored": True, "method": "git-lfs-exact-match", "attempts": attempts}
        if _matches_pointer(candidate, expected):
            fd, temp_name = tempfile.mkstemp(prefix=".attack-restore-", dir=str(path.parent))
            os.close(fd)
            temp_path = Path(temp_name)
            try:
                shutil.copyfile(candidate, temp_path)
                if _matches_pointer(temp_path, expected):
                    os.replace(temp_path, path)
                    return {"restored": True, "method": "git-lfs-checkout-copy-exact-match", "attempts": attempts}
            finally:
                temp_path.unlink(missing_ok=True)

    for url in ATTACK_RESTORE_URLS:
        temp_path: Path | None = None
        measured: dict[str, Any] = {"method": "official-url", "url": url}
        try:
            fd, temp_name = tempfile.mkstemp(prefix=".attack-restore-", dir=str(path.parent))
            os.close(fd)
            temp_path = Path(temp_name)
            digest = hashlib.sha256()
            size = 0
            with urllib.request.urlopen(url, timeout=60) as response, temp_path.open("wb") as output:
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    output.write(chunk)
                    digest.update(chunk)
                    size += len(chunk)
            observed_sha = digest.hexdigest()
            measured.update({"sha256": observed_sha, "size": size})
            exact = (
                expected.get("sha256") is not None
                and expected.get("size") is not None
                and observed_sha == expected["sha256"]
                and size == expected["size"]
            )
            measured["matches_original_lfs_object"] = exact
            attempts.append(measured)
            if exact:
                os.replace(temp_path, path)
                temp_path = None
                return {"restored": True, "method": "official-url-exact-match", "attempts": attempts}
        except Exception as exc:
            measured["error"] = f"{type(exc).__name__}: {exc}"
            attempts.append(measured)
        finally:
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)

    # Do not leave a partial or mismatched replacement in place.
    path.write_text(str(expected["pointer_text"]), encoding="utf-8")
    return {
        "restored": False,
        "method": "unresolved",
        "attempts": attempts,
        "evidence": "No downloaded object exactly matched the pointer's original SHA-256 and size; the pointer was preserved.",
    }


def find_raw_root(argument: str | None) -> Path | None:
    if argument:
        candidate = Path(argument).expanduser().resolve()
        return candidate if candidate.is_dir() else None
    candidates = (
        Path("/content/AI-CYBER-dataset-fix-verification/datasets/raw"),
        Path("/kaggle/working/AI-CYBER-dataset-fix-verification/datasets/raw"),
        Path.cwd() / "AI-CYBER-dataset-fix-verification" / "datasets" / "raw",
    )
    for candidate in candidates:
        if candidate.is_dir():
            return candidate.resolve()
    return None


def add_result(results: list[dict[str, Any]], name: str, status: str, evidence: str, **details: Any) -> None:
    results.append({"dataset": name, "status": status, "evidence": evidence, **details})


def locate_d3fend(root: Path) -> Path | None:
    matches = [
        p for p in root.rglob("*")
        if p.is_file() and "d3fend" in p.name.casefold()
        and p.suffix.casefold() in {".json", ".jsonld"}
        and p.name.casefold() != "example.json"
    ]
    if not matches:
        return None
    return sorted(matches, key=lambda p: (p.name.casefold() != "d3fend.json", len(str(p))))[0]


def locate_mbc_source(root: Path) -> Path | None:
    """Find the MBC repository archive first, or a previously extracted bundle directory."""
    archives = [
        p for p in root.rglob("*")
        if p.is_file() and "mbc" in str(p).casefold()
        and (p.name.casefold().endswith(".tar.gz") or p.suffix.casefold() in {".tgz", ".tar"})
    ]
    if archives:
        return sorted(archives, key=lambda p: (p.name.casefold().startswith("mbc-stix2.1"), str(p)), reverse=True)[0]

    candidates = [
        p for p in root.rglob("*")
        if p.is_dir() and "mbc" in p.name.casefold()
    ]
    ranked = []
    for directory in candidates:
        json_files = list(directory.rglob("*.json"))
        bundle_count = 0
        for file_path in json_files:
            try:
                if lfs_pointer(file_path):
                    continue
                payload = json.loads(file_path.read_text(encoding="utf-8"))
            except Exception:
                continue
            if (isinstance(payload, dict) and isinstance(payload.get("objects"), list)) or (
                isinstance(payload, list)
            ) or (
                isinstance(payload, dict) and payload.get("type") and payload.get("id") and payload.get("type") != "bundle"
            ):
                bundle_count += 1
        ranked.append((directory, bundle_count, len(json_files)))
    if not ranked:
        return None
    return max(ranked, key=lambda item: (item[1], item[2]))[0]


def locate_suricata_source(root: Path) -> Path | None:
    """Find the raw Suricata archive or its extracted .rules tree."""
    archives = [
        p for p in root.rglob("*")
        if p.is_file() and "suricata" in str(p).casefold()
        and (p.name.casefold().endswith(".tar.gz") or p.suffix.casefold() in {".tgz", ".tar"})
    ]
    if archives:
        return sorted(archives, key=lambda p: (p.name.casefold().startswith("emerging.rules_"), str(p)), reverse=True)[0]
    candidates = [
        p for p in root.rglob("*")
        if p.is_dir() and "suricata" in p.name.casefold()
        and any(child.is_file() for child in p.rglob("*.rules"))
    ]
    if candidates:
        return max(candidates, key=lambda p: sum(1 for _ in p.rglob("*.rules")))
    files = [
        p for p in root.rglob("*.rules")
        if p.is_file() and "suricata" in str(p).casefold()
        and "example" not in str(p).casefold()
    ]
    return sorted(files, key=lambda p: str(p))[0] if files else None


def _mbc_document_objects(payload: Any) -> list[dict[str, Any]]:
    """Return actual STIX objects represented by one MBC JSON source member."""
    if isinstance(payload, dict) and isinstance(payload.get("objects"), list):
        candidates = payload["objects"]
    elif isinstance(payload, list):
        candidates = payload
    elif isinstance(payload, dict) and payload.get("type") and payload.get("id") and payload.get("type") != "bundle":
        candidates = [payload]
    else:
        candidates = []
    return [
        item for item in candidates
        if isinstance(item, dict) and item.get("type") and item.get("id")
    ]


def inspect_attack(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {"dataset": "mitre-attack-enterprise", "status": "BLOCKED", "evidence": f"File missing: {path}"}

    expected = lfs_pointer(path)
    restore = None
    if expected:
        restore = restore_lfs_exact_match(path, expected)
        if not restore["restored"]:
            return {
                "dataset": "mitre-attack-enterprise",
                "status": "BLOCKED",
                "path": str(path),
                "evidence": restore["evidence"],
                "expected_sha256": expected.get("sha256"),
                "expected_size_bytes": expected.get("size"),
                "restore_attempts": restore["attempts"],
            }

    actual_sha = sha256_file(path)
    actual_size = path.stat().st_size
    try:
        with path.open("r", encoding="utf-8") as handle:
            raw = json.load(handle)
    except Exception as exc:
        return {
            "dataset": "mitre-attack-enterprise", "status": "FAIL", "path": str(path),
            "sha256": actual_sha, "size_bytes": actual_size,
            "evidence": f"Restored/readable bytes are not valid JSON: {type(exc).__name__}: {exc}",
        }

    objects = raw.get("objects") if isinstance(raw, dict) else None
    if not isinstance(objects, list) or not objects:
        return {
            "dataset": "mitre-attack-enterprise", "status": "FAIL", "path": str(path),
            "sha256": actual_sha, "size_bytes": actual_size,
            "evidence": "JSON is parseable but has no non-empty STIX objects list.",
        }
    if expected and (actual_sha != expected["sha256"] or actual_size != expected["size"]):
        return {
            "dataset": "mitre-attack-enterprise", "status": "FAIL", "path": str(path),
            "sha256": actual_sha, "size_bytes": actual_size,
            "evidence": "Restored file does not match the LFS pointer's declared SHA-256 and size.",
            "expected_sha256": expected["sha256"], "expected_size_bytes": expected["size"],
        }
    return {
        "dataset": "mitre-attack-enterprise",
        "status": "PASS",
        "path": str(path),
        "sha256": actual_sha,
        "size_bytes": actual_size,
        "stix_object_count": len(objects),
        "restored_from_lfs": bool(expected),
        "restore_method": (restore or {}).get("method", "already-real-file"),
        "evidence": "Valid JSON STIX bundle; byte size and SHA-256 measured"
                    + (" and matched the original LFS pointer." if expected else "."),
    }


def inspect_critical_sources(raw_root: Path) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []

    attack_paths = list(raw_root.rglob(ATTACK_BASENAME))
    attack_paths = [p for p in attack_paths if p.is_file()]
    if attack_paths:
        results.append(inspect_attack(sorted(attack_paths, key=lambda p: len(str(p)))[0]))
    else:
        add_result(results, "mitre-attack-enterprise", "BLOCKED",
                   f"Expected artifact was not found: {ATTACK_BASENAME}")

    d3fend_path = locate_d3fend(raw_root)
    if d3fend_path is None:
        add_result(results, "mitre-d3fend", "BLOCKED", "No D3FEND JSON/JSON-LD file found under raw root.")
    else:
        try:
            records = parse_d3fend_jsonld(d3fend_path, validation_status="readiness-only")
            count = len(records)
            add_result(
                results, "mitre-d3fend",
                "PASS" if count == EXPECTED_D3FEND_NODES else "FAIL",
                f"Parsed {count} graph nodes; expected {EXPECTED_D3FEND_NODES}.",
                path=str(d3fend_path), graph_node_count=count,
                sha256=sha256_file(d3fend_path), size_bytes=d3fend_path.stat().st_size,
            )
        except Exception as exc:
            add_result(results, "mitre-d3fend", "BLOCKED" if "lfs pointer" in str(exc).casefold() else "FAIL",
                       f"{type(exc).__name__}: {exc}", path=str(d3fend_path))

    mbc_dir = locate_mbc_source(raw_root)
    if mbc_dir is None:
        add_result(results, "mitre-mbc", "BLOCKED", "No MBC bundle directory found under raw root.")
    else:
        try:
            bundle_files = 0
            json_file_count = 0
            raw_stix_object_occurrences = 0
            source_stix_ids: set[str] = set()
            if mbc_dir.is_file():
                with tarfile.open(mbc_dir, "r:*") as archive:
                    members = [
                        item for item in archive.getmembers()
                        if item.isfile() and Path(item.name).suffix.casefold() == ".json"
                    ]
                    json_file_count = len(members)
                    for member in members:
                        handle = archive.extractfile(member)
                        if handle is None:
                            continue
                        raw_bytes = handle.read()
                        if raw_bytes.lstrip().startswith(b"version https://git-lfs.github.com/spec/v1"):
                            continue
                        try:
                            payload = json.loads(raw_bytes.decode("utf-8"))
                        except Exception:
                            continue
                        objects = _mbc_document_objects(payload)
                        if objects:
                            bundle_files += 1
                        raw_stix_object_occurrences += len(objects)
                        source_stix_ids.update(str(obj["id"]) for obj in objects)
            else:
                files = [p for p in mbc_dir.rglob("*.json") if p.is_file()]
                json_file_count = len(files)
                for file_path in files:
                    if lfs_pointer(file_path):
                        continue
                    payload = json.loads(file_path.read_text(encoding="utf-8"))
                    objects = _mbc_document_objects(payload)
                    if objects:
                        bundle_files += 1
                    raw_stix_object_occurrences += len(objects)
                    source_stix_ids.update(str(obj["id"]) for obj in objects)
            records = parse_mbc_stix(mbc_dir, validation_status="readiness-only")
            object_count = len(records)
            unique_id_count = len(source_stix_ids)
            duplicate_occurrences = raw_stix_object_occurrences - unique_id_count
            parser_ids_match = object_count == unique_id_count
            count_ok = (
                bundle_files == EXPECTED_MBC_BUNDLES
                and object_count == EXPECTED_MBC_STIX_OBJECTS
                and parser_ids_match
                and duplicate_occurrences >= 0
            )
            add_result(
                results, "mitre-mbc", "PASS" if count_ok else "FAIL",
                f"Found {bundle_files} STIX-bearing source JSON files among {json_file_count} JSON files; saw {raw_stix_object_occurrences} object occurrences and {object_count} unique STIX object IDs ({duplicate_occurrences} repeated occurrences). Expected {EXPECTED_MBC_BUNDLES} source files and {EXPECTED_MBC_STIX_OBJECTS} distinct objects.",
                path=str(mbc_dir), json_file_count=json_file_count,
                bundle_file_count=bundle_files,
                raw_stix_object_occurrences=raw_stix_object_occurrences,
                duplicate_stix_object_occurrences=duplicate_occurrences,
                unique_source_stix_id_count=unique_id_count,
                stix_object_count=object_count,
                parser_and_source_unique_ids_match=parser_ids_match,
                expected_stix_object_count=EXPECTED_MBC_STIX_OBJECTS,
            )
        except Exception as exc:
            add_result(results, "mitre-mbc", "BLOCKED" if "lfs pointer" in str(exc).casefold() else "FAIL",
                       f"{type(exc).__name__}: {exc}", path=str(mbc_dir))

    suricata_path = locate_suricata_source(raw_root)
    if suricata_path is None:
        add_result(results, "suricata-rules", "BLOCKED", "No Suricata .rules file/directory found under raw root.")
    else:
        try:
            records = parse_suricata_rules(suricata_path, validation_status="readiness-only")
            active = disabled = 0
            for record in records:
                metadata = json.loads(record["metadata_json"])
                if metadata.get("status") == "active":
                    active += 1
                elif metadata.get("status") == "disabled":
                    disabled += 1
            count_ok = active == EXPECTED_SURICATA_ACTIVE and disabled == EXPECTED_SURICATA_DISABLED
            add_result(
                results, "suricata-rules", "PASS" if count_ok else "FAIL",
                f"Classified {active} active and {disabled} disabled rules; expected {EXPECTED_SURICATA_ACTIVE} active and {EXPECTED_SURICATA_DISABLED} disabled.",
                path=str(suricata_path), active_rule_count=active,
                disabled_rule_count=disabled, total_rule_count=len(records),
            )
        except Exception as exc:
            add_result(results, "suricata-rules", "FAIL", f"{type(exc).__name__}: {exc}", path=str(suricata_path))

    example_candidates = [p for p in raw_root.rglob("example.json") if p.is_file()]
    manifest_root = raw_root.parent / "manifests"
    if manifest_root.is_dir():
        example_candidates.extend(p for p in manifest_root.rglob("example.json") if p.is_file())
    examples = sorted(set(example_candidates))
    add_result(
        results,
        "example.json-placeholder",
        "PASS",
        "Placeholder manifests/data are explicitly excluded from readiness counts and ingestion; they are never treated as real datasets."
        + (f" Found and excluded {len(examples)} file(s): " + ", ".join(str(p) for p in examples[:5]) if examples else " No example.json placeholder found."),
        excluded_paths=[str(p) for p in examples],
    )
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-root", default=None, help="Path to datasets/raw")
    parser.add_argument("--report", default="dataset_parser_readiness_report.json")
    args = parser.parse_args()

    raw_root = find_raw_root(args.raw_root)
    report: dict[str, Any] = {
        "report_version": "1.0",
        "raw_root": str(raw_root) if raw_root else None,
        "ingestion_performed": False,
        "permanent_database_created": False,
        "datasets": [],
        "manifest_readiness": None,
    }
    if raw_root is None:
        report.update({
            "overall": "BLOCKED",
            "evidence": "Raw dataset root not found. Supply --raw-root explicitly.",
        })
    else:
        report["datasets"] = inspect_critical_sources(raw_root)
        manifests_dir = raw_root.parent / "manifests"
        if manifests_dir.is_dir():
            manifest_summary = readiness_report(
                manifests_dir,
                required_datasets=REQUIRED_DATASET_NAMES,
                excluded_datasets=EXCLUDED_DATASET_NAMES,
            )
            available_files = []
            available_names = set()
            for manifest_path in sorted(manifests_dir.rglob("*.json")):
                if manifest_path.name.casefold() == "example.json":
                    continue
                try:
                    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
                    identity = str(payload.get("dataset") or manifest_path.stem) if isinstance(payload, dict) else manifest_path.stem
                except (OSError, json.JSONDecodeError):
                    available_files.append(manifest_path)  # Malformed in-scope manifests remain visible.
                    continue
                if identity.casefold() in EXCLUDED_DATASET_NAMES or manifest_path.stem.casefold() in EXCLUDED_DATASET_NAMES:
                    continue
                available_files.append(manifest_path)
                available_names.add(identity)
            manifest_summary["available_manifest_count"] = len(available_files)
            manifest_summary["available_dataset_count"] = len(available_names)
            manifest_summary["expected_dataset_count"] = len(REQUIRED_DATASET_NAMES)
            manifest_summary["missing_manifest_count"] = len(set(REQUIRED_DATASET_NAMES) - available_names)
            manifest_summary["expected_dataset_names"] = list(REQUIRED_DATASET_NAMES)
            if manifest_summary["missing_manifest_count"] and manifest_summary.get("overall") == "PASS":
                manifest_summary["overall"] = "BLOCKED"
                manifest_summary["evidence"] = (
                    f"Missing manifests for: {', '.join(sorted(set(REQUIRED_DATASET_NAMES) - available_names))}."
                )
            report["manifest_readiness"] = manifest_summary
            report["excluded_dataset_scope"] = {
                name: {"status": "EXCLUDED_BY_SCOPE", "required": False}
                for name in EXCLUDED_DATASET_NAMES
            }
        else:
            report["manifest_readiness"] = {
                "overall": "BLOCKED",
                "evidence": f"No manifests directory found at {manifests_dir}; the selected 11-source readiness gate cannot pass.",
                "count": 0,
            }

        critical_ok = all(
            row["status"] == "PASS"
            for row in report["datasets"]
            if row["dataset"] != "example.json-placeholder"
        )
        manifest_ok = report["manifest_readiness"].get("overall") == "PASS"
        report["overall"] = "PASS" if critical_ok and manifest_ok else (
            "FAIL" if any(row["status"] == "FAIL" for row in report["datasets"])
            or report["manifest_readiness"].get("overall") == "FAIL"
            else "BLOCKED"
        )
        report["evidence"] = (
            "Parser-specific checks and all eleven in-scope source manifests passed; NVD/CVSS were excluded and no data was ingested."
            if report["overall"] == "PASS"
            else "Readiness is not green. Review per-dataset evidence; do not start ingestion until every required dataset is PASS."
        )

    report_path = Path(args.report).expanduser().resolve()
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    print(json.dumps(report, indent=2, ensure_ascii=False, default=str))
    print(f"REPORT_FILE={report_path}")
    return 0 if report.get("overall") == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
