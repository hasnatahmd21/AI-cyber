#!/usr/bin/env python3
"""Acquire official NVD CVE 2.0 bulk feeds and verify readiness without DB ingestion.

Downloads yearly feeds plus the official recent/modified update feeds, checks each
compressed artifact against its NVD .meta file (uncompressed SHA-256/size and
compressed size), parses actual CVE IDs, and writes datasets/manifests/nvd_cve.json.
An optional --push commits the raw feed snapshot and manifest to the selected Git
branch using Git LFS. No Knowledge DB is created or touched.
"""
from __future__ import annotations

import argparse
import datetime as dt
import gzip
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT / "src"))

from ai_cyber_os.threat_intel import parse_nvd  # noqa: E402

SOURCE_URI = "https://nvd.nist.gov/vuln/data-feeds"
LICENSE_TEXT = "NVD data feed terms; preserve source attribution"
BASE_URL = "https://nvd.nist.gov/feeds/json/cve/2.0"
DEFAULT_BRANCH = "fix/dataset-parser-readiness"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_gzip_payload(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with gzip.open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def parse_meta(text: str) -> dict[str, str]:
    """Parse NVD .meta key/value lines without assuming key order."""
    result: dict[str, str] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()
        if key:
            result[key] = value
    required = {"sha256", "size", "gzSize"}
    missing = sorted(required - set(result))
    if missing:
        raise ValueError(f"NVD .meta is missing required fields: {', '.join(missing)}")
    digest = result["sha256"].lower()
    if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        raise ValueError("NVD .meta sha256 must be a 64-character hexadecimal digest")
    for field in ("size", "gzSize"):
        if not result[field].isdigit():
            raise ValueError(f"NVD .meta {field} must be a non-negative integer")
    return result


def download_to(url: str, target: Path, *, retries: int = 4, timeout: int = 180) -> None:
    """Download to a sibling .part file and atomically replace on success."""
    target.parent.mkdir(parents=True, exist_ok=True)
    last_error: Exception | None = None
    for attempt in range(1, retries + 1):
        part = target.with_name(target.name + ".part")
        part.unlink(missing_ok=True)
        request = urllib.request.Request(
            url,
            headers={
                "User-Agent": "AI-CYBER-NVD-readiness/1.0",
                "Accept-Encoding": "identity",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response, part.open("wb") as output:
                shutil.copyfileobj(response, output, length=1024 * 1024)
            if not part.is_file() or part.stat().st_size == 0:
                raise ValueError(f"empty response from {url}")
            part.replace(target)
            return
        except Exception as exc:
            last_error = exc
            part.unlink(missing_ok=True)
            print(f"DOWNLOAD RETRY {attempt}/{retries}: {url} ({type(exc).__name__}: {exc})", flush=True)
            if attempt < retries:
                time.sleep(min(2 ** (attempt - 1), 8))
    raise RuntimeError(f"download failed after {retries} attempts: {url}") from last_error


def verified_against_meta(feed_path: Path, meta: dict[str, str]) -> dict[str, Any]:
    """Verify raw gzip bytes, gzip integrity, uncompressed SHA-256 and size."""
    compressed_size = feed_path.stat().st_size
    expected_gz_size = int(meta["gzSize"])
    if compressed_size != expected_gz_size:
        raise ValueError(
            f"compressed size mismatch for {feed_path.name}: "
            f"expected {expected_gz_size}, got {compressed_size}"
        )
    uncompressed_sha256, uncompressed_size = sha256_gzip_payload(feed_path)
    expected_sha = meta["sha256"].lower()
    expected_size = int(meta["size"])
    if uncompressed_sha256 != expected_sha:
        raise ValueError(
            f"NVD uncompressed SHA-256 mismatch for {feed_path.name}: "
            f"expected {expected_sha}, got {uncompressed_sha256}"
        )
    if uncompressed_size != expected_size:
        raise ValueError(
            f"NVD uncompressed byte-size mismatch for {feed_path.name}: "
            f"expected {expected_size}, got {uncompressed_size}"
        )
    return {
        "compressed_size": compressed_size,
        "compressed_sha256": sha256_file(feed_path),
        "uncompressed_size": uncompressed_size,
        "uncompressed_sha256": uncompressed_sha256,
        "nvd_meta_sha256": expected_sha,
        "nvd_meta_last_modified": meta.get("lastModifiedDate", ""),
    }


def _meta_name(feed_name: str) -> str:
    suffix = ".json.gz"
    if not feed_name.endswith(suffix):
        raise ValueError(f"unexpected NVD feed filename: {feed_name}")
    return feed_name[:-len(suffix)] + ".meta"


def process_feed(root: Path, feed_name: str, *, dataset_version: str, project_root: Path) -> tuple[dict[str, Any], set[str]]:
    feed_path = root / feed_name
    meta_path = root / _meta_name(feed_name)
    feed_url = f"{BASE_URL}/{feed_name}"
    meta_url = f"{BASE_URL}/{meta_path.name}"

    # Read the current authoritative metadata first. Cached data is reused only
    # if it matches this current checksum/size contract exactly.
    download_to(meta_url, meta_path)
    meta_text = meta_path.read_text(encoding="utf-8")
    meta = parse_meta(meta_text)

    cached_ok = False
    cache_evidence: dict[str, Any] = {}
    if feed_path.is_file():
        try:
            cache_evidence = verified_against_meta(feed_path, meta)
            cached_ok = True
        except (OSError, ValueError, EOFError, gzip.BadGzipFile):
            cached_ok = False

    if not cached_ok:
        part = feed_path.with_name(feed_path.name + ".candidate")
        part.unlink(missing_ok=True)
        try:
            download_to(feed_url, part)
            cache_evidence = verified_against_meta(part, meta)
            part.replace(feed_path)
        finally:
            part.unlink(missing_ok=True)

    # Parsing checks JSON validity and NVD totalResults in addition to the .meta
    # content hash. This counts real CVE entries; it never counts the .meta file.
    records = parse_nvd(
        feed_path,
        dataset="nvd_cve",
        source="NIST National Vulnerability Database (NVD)",
        version=dataset_version,
        source_uri=SOURCE_URI,
        license=LICENSE_TEXT,
        validation_status="local-integrity-verified",
    )
    cve_ids = {str(record["record_id"]) for record in records}
    if len(cve_ids) != len(records):
        raise ValueError(f"duplicate CVE IDs inside one NVD feed: {feed_name}")

    artifact = {
        "path": feed_path.relative_to(project_root).as_posix(),
        "role": "data",
        "format": "NVD JSON 2.0 gzip",
        "count_kind": "nvd-feed",
        "record_count": len(records),
        "byte_size": cache_evidence["compressed_size"],
        "sha256": cache_evidence["compressed_sha256"],
        "uncompressed_byte_size": cache_evidence["uncompressed_size"],
        "uncompressed_sha256": cache_evidence["uncompressed_sha256"],
        "source_uri": feed_url,
        "version": dataset_version,
        "upstream_meta": {
            "path": meta_path.relative_to(project_root).as_posix(),
            "sha256": sha256_file(meta_path),
            "byte_size": meta_path.stat().st_size,
            "last_modified_date": meta.get("lastModifiedDate", ""),
            "declared_gzip_size": int(meta["gzSize"]),
            "declared_uncompressed_size": int(meta["size"]),
            "declared_uncompressed_sha256": meta["sha256"].lower(),
        },
        "cache_reused": cached_ok,
    }
    print(
        f"PASS {feed_name}: records={len(records)} compressed={artifact['byte_size']} "
        f"uncompressed={artifact['uncompressed_byte_size']} "
        f"sha256={artifact['sha256']}",
        flush=True,
    )
    return artifact, cve_ids


def build_manifest(root: Path, year_start: int, year_end: int, include_updates: bool, *, project_root: Path) -> dict[str, Any]:
    if year_start < 2002 or year_end < year_start:
        raise ValueError("NVD year range must start at or after 2002 and end >= start")
    root.mkdir(parents=True, exist_ok=True)
    feed_specs: list[tuple[str, str]] = [
        (f"nvdcve-2.0-{year}.json.gz", f"NVD-2.0-{year}")
        for year in range(year_start, year_end + 1)
    ]
    if include_updates:
        feed_specs.extend([
            ("nvdcve-2.0-recent.json.gz", "NVD-2.0-recent"),
            ("nvdcve-2.0-modified.json.gz", "NVD-2.0-modified"),
        ])

    artifacts: list[dict[str, Any]] = []
    seen_cve_ids: set[str] = set()
    feed_record_count = 0
    for filename, version in feed_specs:
        artifact, cve_ids = process_feed(root, filename, dataset_version=version, project_root=project_root)
        artifacts.append(artifact)
        feed_record_count += int(artifact["record_count"])
        seen_cve_ids.update(cve_ids)

    feed_hashes = "\n".join(item["sha256"] for item in artifacts)
    aggregate_sha = hashlib.sha256(feed_hashes.encode("utf-8")).hexdigest()
    today = dt.datetime.now(dt.timezone.utc).date().isoformat()
    return {
        "manifest_format": 1,
        "dataset": "nvd_cve",
        "version": f"NVD-2.0-snapshot-{today}",
        "source": "NIST National Vulnerability Database (NVD)",
        "source_uri": SOURCE_URI,
        "license": LICENSE_TEXT,
        "license_basis": "Official NVD data-feed provenance; retain NVD attribution",
        "local_path": "datasets/raw/nvd_cve",
        "artifact_set_sha256": aggregate_sha,
        "artifact_set_sha256_scheme": "SHA-256 of newline-joined per-artifact compressed SHA-256 digests in manifest order",
        "byte_size": sum(int(item["byte_size"]) for item in artifacts),
        "record_count": feed_record_count,
        "unique_cve_id_count": len(seen_cve_ids),
        "duplicate_feed_record_occurrences": feed_record_count - len(seen_cve_ids),
        "schema": {
            "format": "NVD JSON 2.0 compressed feeds",
            "parser_kind": "nvd",
            "count_semantics": (
                "record_count is the sum of parsed occurrences across all listed feeds; "
                "yearly feeds are authoritative snapshots and recent/modified feeds overlap them. "
                "unique_cve_id_count counts distinct CVE IDs across this feed set."
            ),
        },
        "ingestion_status": "not-started",
        "validation_status": "local-integrity-verified",
        "acquisition_method": "NVD official JSON 2.0 yearly feeds with optional recent/modified update feeds",
        "feed_range": {"year_start": year_start, "year_end": year_end, "includes_updates": include_updates},
        "artifacts": artifacts,
    }


def write_json_atomic(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".part")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
    temporary.replace(path)


def acquire_github_token() -> str:
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        return token.strip()
    try:
        from kaggle_secrets import UserSecretsClient
        return UserSecretsClient().get_secret("cyber repo").strip()
    except Exception as exc:
        raise RuntimeError(
            'GitHub push requested but no token is available. In Kaggle, configure secret "cyber repo".'
        ) from exc


def push_snapshot(checkout: Path, branch: str, manifest_path: Path, report_path: Path) -> None:
    checkout = checkout.resolve()
    if not (checkout / ".git").exists():
        raise RuntimeError("--push requires running inside a Git checkout")
    active = subprocess.run(
        ["git", "-C", str(checkout), "branch", "--show-current"],
        text=True, capture_output=True, check=True,
    ).stdout.strip()
    if active != branch:
        raise RuntimeError(f"current branch is {active!r}; refusing to push to {branch!r} from another branch")

    if not shutil.which("git-lfs"):
        raise RuntimeError("--push requires git-lfs for a persistent NVD feed snapshot")
    subprocess.run(["git", "-C", str(checkout), "lfs", "install", "--local"], check=True)
    subprocess.run(
        ["git", "-C", str(checkout), "lfs", "track", "datasets/raw/nvd_cve/*.json.gz"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(checkout), "add", "--", ".gitattributes", "datasets/raw/nvd_cve", str(manifest_path), str(report_path)],
        check=True,
    )
    status = subprocess.run(
        ["git", "-C", str(checkout), "diff", "--cached", "--quiet"],
        check=False,
    )
    if status.returncode == 0:
        print("No NVD snapshot changes to commit.")
        return
    subprocess.run(
        ["git", "-C", str(checkout), "config", "user.name", "AI-CYBER Dataset Runner"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(checkout), "config", "user.email", "ai-cyber-dataset-runner@users.noreply.github.com"],
        check=True,
    )
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    subprocess.run(
        ["git", "-C", str(checkout), "commit", "-m", f"data: verify NVD CVE feeds {stamp}"],
        check=True,
    )
    token = acquire_github_token()
    askpass_fd, askpass_name = tempfile.mkstemp(prefix="ai-cyber-askpass-")
    os.close(askpass_fd)
    askpass = Path(askpass_name)
    try:
        askpass.write_text("#!/bin/sh\nprintf '%s\\n' \"$GITHUB_TOKEN\"\n", encoding="utf-8")
        askpass.chmod(0o700)
        env = os.environ.copy()
        env["GITHUB_TOKEN"] = token
        env["GIT_ASKPASS"] = str(askpass)
        env["GIT_TERMINAL_PROMPT"] = "0"
        # No token is embedded in the remote URL or printed in process arguments.
        subprocess.run(
            ["git", "-C", str(checkout), "remote", "set-url", "origin",
             "https://x-access-token@github.com/hasnatahmd21/AI-cyber.git"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(checkout), "push", "origin", branch],
            check=True, env=env,
        )
    finally:
        askpass.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=REPOSITORY_ROOT)
    parser.add_argument("--raw-root", type=Path, default=None)
    parser.add_argument("--manifest", type=Path, default=None)
    parser.add_argument("--report", type=Path, default=None)
    parser.add_argument("--start-year", type=int, default=2002)
    parser.add_argument("--end-year", type=int, default=None)
    parser.add_argument("--skip-update-feeds", action="store_true")
    parser.add_argument("--push", action="store_true", help="Persist raw feeds and manifest to GitHub via Git LFS")
    parser.add_argument("--branch", default=os.environ.get("AI_CYBER_BRANCH", DEFAULT_BRANCH))
    args = parser.parse_args(argv)

    project_root = args.project_root.expanduser().resolve()
    raw_root = (args.raw_root or project_root / "datasets" / "raw" / "nvd_cve").expanduser().resolve()
    manifest_path = (args.manifest or project_root / "datasets" / "manifests" / "nvd_cve.json").expanduser().resolve()
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    report_path = (args.report or project_root / "datasets" / "acquisition_reports" / f"nvd-readiness-{stamp}.json").expanduser().resolve()
    year_end = args.end_year if args.end_year is not None else dt.datetime.now(dt.timezone.utc).year

    try:
        manifest = build_manifest(
            raw_root,
            args.start_year,
            year_end,
            include_updates=not args.skip_update_feeds,
            project_root=project_root,
        )
        write_json_atomic(manifest_path, manifest)
        report = {
            "overall": "SOURCE_INTEGRITY_PASS",
            "dataset": "nvd_cve",
            "raw_root": str(raw_root),
            "manifest_path": str(manifest_path),
            "manifest_sha256": sha256_file(manifest_path),
            "feed_count": len(manifest["artifacts"]),
            "feed_record_occurrences": manifest["record_count"],
            "unique_cve_id_count": manifest["unique_cve_id_count"],
            "duplicate_feed_record_occurrences": manifest["duplicate_feed_record_occurrences"],
            "ingestion_performed": False,
            "database_created": False,
            "feeds": manifest["artifacts"],
        }
        write_json_atomic(report_path, report)
        print(json.dumps({
            "source_integrity": "PASS",
            "manifest_path": str(manifest_path),
            "report_path": str(report_path),
            "feed_count": report["feed_count"],
            "feed_record_occurrences": report["feed_record_occurrences"],
            "unique_cve_id_count": report["unique_cve_id_count"],
            "duplicate_feed_record_occurrences": report["duplicate_feed_record_occurrences"],
            "ingestion_performed": False,
            "database_created": False,
        }, indent=2))
        if args.push:
            push_snapshot(project_root, args.branch, manifest_path, report_path)

        gate = project_root / "scripts" / "kaggle_dataset_parser_readiness_gate.py"
        if not gate.is_file():
            raise FileNotFoundError(f"readiness gate script is missing: {gate}")
        gate_report_path = project_root / "datasets" / "acquisition_reports" / f"parser-readiness-{stamp}.json"
        completed = subprocess.run(
            [
                sys.executable, str(gate),
                "--raw-root", str(raw_root.parent),
                "--report", str(gate_report_path),
            ],
            cwd=project_root,
            text=True,
            check=False,
        )
        print(f"PARSER_READINESS_REPORT={gate_report_path}")
        if completed.returncode != 0:
            print("NVD source acquisition succeeded, but the combined 12-source readiness gate is not PASS.")
            return 2
        print("OVERALL_READINESS=PASS (no Knowledge DB created; no ingestion performed)")
        return 0
    except Exception as exc:
        error_report = {
            "overall": "BLOCKED",
            "dataset": "nvd_cve",
            "error": f"{type(exc).__name__}: {exc}",
            "ingestion_performed": False,
            "database_created": False,
        }
        try:
            write_json_atomic(report_path, error_report)
        except Exception:
            pass
        print(json.dumps(error_report, indent=2))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
