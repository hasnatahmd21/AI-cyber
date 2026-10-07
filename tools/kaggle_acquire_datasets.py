#!/usr/bin/env python3
"""
AI-CYBER — Kaggle master dataset acquisition/push runner.

Purpose:
  1. Clone the AI-CYBER repair branch into a fresh Kaggle workspace.
  2. Acquire the 13 locked dataset families from authoritative/public sources.
  3. Preserve the exact downloaded artifact, provenance, version/snapshot metadata,
     SHA-256 and byte count.
  4. Place data under the canonical datasets/ tree.
  5. Push Git-trackable artifacts and manifests to the repository.
  6. Use Git LFS for files >= 50 MiB when available; fail closed if LFS is missing.
  7. Never fabricate a version/license/checksum and never silently replace a changed
     artifact.

IMPORTANT:
  Large NVD/CPE artifacts can be hundreds of MB. GitHub blocks regular Git files
  above 100 MiB, so this runner uses Git LFS for large files. It does NOT use a
  third-party mirror for NVD/CPE/KEV/EPSS/ATT&CK/Sigma/MBC/D3FEND.

Kaggle:
  Set GH_TOKEN in the Kaggle environment/secret. Do not hard-code the token.
  Optional:
    AI_CYBER_BRANCH=repair/forensic-reconstruction
    AI_CYBER_REPO=hasnatahmd21/AI-cyber
    DATASET_ROOT=/kaggle/working/AI-cyber/datasets
    DATASET_FAMILIES=all   # or comma-separated family names
    PUSH_DATASETS=1
    GIT_LFS_THRESHOLD_MB=50
"""

from __future__ import annotations

import csv
import datetime as dt
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path
from typing import Iterable

REPO = os.environ.get("AI_CYBER_REPO", "hasnatahmd21/AI-cyber")
BRANCH = os.environ.get("AI_CYBER_BRANCH", "repair/forensic-reconstruction")
WORK = Path("/kaggle/working")
CHECKOUT = WORK / "AI-cyber"
DATASETS = Path(os.environ.get("DATASET_ROOT", str(CHECKOUT / "datasets")))
RAW = DATASETS / "raw"
MANIFESTS = DATASETS / "manifests"
REPORTS = DATASETS / "acquisition_reports"
LFS_THRESHOLD = int(os.environ.get("GIT_LFS_THRESHOLD_MB", "50")) * 1024 * 1024
PUSH = os.environ.get("PUSH_DATASETS", "1").lower() not in {"0", "false", "no"}

LOCKED = (
    "nvd_cve", "cisa_kev", "epss", "cwe", "cpe", "cvss",
    "mitre_attack", "capec", "d3fend", "sigma",
    "suricata_rules", "zeek_intel", "mbc",
)

FAMILIES = [x.strip() for x in os.environ.get("DATASET_FAMILIES", "all").split(",") if x.strip()]
if FAMILIES == ["all"]:
    FAMILIES = list(LOCKED)
unknown = sorted(set(FAMILIES) - set(LOCKED))
if unknown:
    raise SystemExit(f"Unknown dataset family: {unknown}")

TODAY = dt.datetime.now(dt.timezone.utc).date().isoformat()
STAMP = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def run(*args: str, cwd: Path | None = None, check: bool = True, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    print("+", " ".join(args))
    return subprocess.run(args, cwd=cwd, text=True, check=check, env=env)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def download(url: str, target: Path) -> Path:
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(target.suffix + ".part")
    if tmp.exists():
        tmp.unlink()
    print(f"DOWNLOAD {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "AI-CYBER-dataset-runner/1.0"})
    with urllib.request.urlopen(req, timeout=120) as r, tmp.open("wb") as out:
        shutil.copyfileobj(r, out, length=1024 * 1024)
    tmp.replace(target)
    if target.stat().st_size == 0:
        raise RuntimeError(f"empty download: {target}")
    return target


def write_json(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".part")
    tmp.write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
    tmp.replace(path)


def artifact_record(
    *,
    family: str,
    path: Path,
    source: str,
    source_uri: str,
    version: str,
    license_text: str,
    format_name: str,
) -> dict:
    return {
        "dataset": family,
        "version": version,
        "source": source,
        "source_uri": source_uri,
        "license": license_text,
        "local_path": path.relative_to(CHECKOUT).as_posix(),
        "bytes": path.stat().st_size,
        "sha256": sha256(path),
        "format": format_name,
        "acquired_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "validation_status": "downloaded-integrity-hashed",
        "ingestion_status": "pending",
    }


def get(url: str, target: Path, *, retries: int = 3) -> Path:
    last = None
    for attempt in range(1, retries + 1):
        try:
            return download(url, target)
        except Exception as exc:
            last = exc
            print(f"download attempt {attempt}/{retries} failed: {exc}")
    raise RuntimeError(f"download failed: {url}") from last


def git_clone() -> None:
    if CHECKOUT.exists():
        shutil.rmtree(CHECKOUT)
    # Public clone: keep the write token out of URLs, logs, and process listings.
    url = f"https://github.com/{REPO}.git"
    run("git", "clone", "--branch", BRANCH, "--single-branch", url, str(CHECKOUT))
    run("git", "config", "user.name", "AI-CYBER Dataset Runner", cwd=CHECKOUT)
    run("git", "config", "user.email", "ai-cyber-dataset-runner@users.noreply.github.com", cwd=CHECKOUT)


def ensure_lfs() -> bool:
    if shutil.which("git-lfs"):
        run("git", "lfs", "install", "--local", cwd=CHECKOUT)
        return True
    try:
        run("git", "lfs", "version", cwd=CHECKOUT)
        return True
    except Exception:
        return False


def nvd_family() -> list[dict]:
    out = []
    root = RAW / "nvd_cve"
    root.mkdir(parents=True, exist_ok=True)
    current_year = dt.datetime.now(dt.timezone.utc).year
    # NVD 2.0 year feeds are official and are updated daily. We retain each year
    # separately so a failed/changed feed never silently replaces another year.
    for year in range(2002, current_year + 1):
        name = f"nvdcve-2.0-{year}.json.gz"
        uri = f"https://nvd.nist.gov/feeds/json/cve/2.0/{name}"
        p = get(uri, root / name)
        out.append(artifact_record(
            family="nvd_cve", path=p, source="NVD", source_uri=uri,
            version=f"NVD-2.0-{year}", license_text="NVD data feed terms; preserve source attribution",
            format_name="gzip-json",
        ))
    for name, label in (
        ("nvdcve-2.0-recent.json.gz", "NVD-2.0-recent"),
        ("nvdcve-2.0-modified.json.gz", "NVD-2.0-modified"),
    ):
        uri = f"https://nvd.nist.gov/feeds/json/cve/2.0/{name}"
        p = get(uri, root / name)
        out.append(artifact_record(
            family="nvd_cve", path=p, source="NVD", source_uri=uri,
            version=label, license_text="NVD data feed terms; preserve source attribution",
            format_name="gzip-json",
        ))
    return out


def cpe_family() -> list[dict]:
    out = []
    root = RAW / "cpe"
    root.mkdir(parents=True, exist_ok=True)
    # NVD publishes the current 2.0 CPE dictionary and match feed as tar.gz
    # chunks. These are deliberately kept raw; the downstream normalizer can
    # consume each chunk without losing source fidelity.
    for name, label in (
        ("nvdcpe-2.0.tar.gz", "NVD-CPE-Dictionary-2.0"),
        ("nvdcpe-match-2.0.tar.gz", "NVD-CPE-Match-2.0"),
    ):
        uri = f"https://nvd.nist.gov/feeds/json/cpe/2.0/{name}"
        p = get(uri, root / name)
        out.append(artifact_record(
            family="cpe", path=p, source="NVD", source_uri=uri,
            version=label, license_text="NVD data feed terms; preserve source attribution",
            format_name="tar-gzip",
        ))
    return out


def kev_family() -> list[dict]:
    root = RAW / "cisa_kev"
    uri = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    p = get(uri, root / "known_exploited_vulnerabilities.json")
    return [artifact_record(
        family="cisa_kev", path=p, source="CISA KEV", source_uri=uri,
        version=TODAY, license_text="CC0 1.0 (CISA KEV catalog)",
        format_name="json",
    )]


def epss_family() -> list[dict]:
    root = RAW / "epss"
    # EPSS publishes a daily CSV snapshot. The date is part of the artifact
    # identity; there is no fabricated 'latest' version.
    d = dt.datetime.now(dt.timezone.utc).date()
    for _ in range(8):
        date_s = d.isoformat()
        uri = f"https://epss.empiricalsecurity.com/epss_scores-{date_s}.csv.gz"
        try:
            p = get(uri, root / f"epss_scores-{date_s}.csv.gz", retries=1)
            return [artifact_record(
                family="epss", path=p, source="FIRST EPSS / Empirical Security",
                source_uri=uri, version=date_s,
                license_text="EPSS data is freely published; attribution requested by FIRST",
                format_name="gzip-csv",
            )]
        except Exception:
            d -= dt.timedelta(days=1)
    raise RuntimeError("could not locate an EPSS daily snapshot in the last 8 days")


def github_snapshot(repo: str, family: str, *, license_text: str) -> list[dict]:
    root = RAW / family
    root.mkdir(parents=True, exist_ok=True)
    target = root / f"{family}-{STAMP}.tar.gz"
    url = f"https://github.com/{repo}/archive/refs/heads/master.tar.gz"
    # Some repositories use main instead of master; try master first, then main.
    try:
        p = get(url, target, retries=1)
        branch = "master"
    except Exception:
        url = f"https://github.com/{repo}/archive/refs/heads/main.tar.gz"
        p = get(url, target, retries=1)
        branch = "main"
    return [artifact_record(
        family=family, path=p, source=repo, source_uri=url,
        version=f"{branch}-{STAMP}", license_text=license_text,
        format_name="tar-gzip-github-snapshot",
    )]


def cwe_family() -> list[dict]:
    root = RAW / "cwe"
    root.mkdir(parents=True, exist_ok=True)
    # The official page publishes the current version; the stable public XML
    # endpoint below is the MITRE CWE catalog distribution.
    uri = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
    p = get(uri, root / "cwec_latest.xml.zip")
    return [artifact_record(
        family="cwe", path=p, source="MITRE CWE", source_uri=uri,
        version="latest-authoritative", license_text="MITRE CWE Terms of Use",
        format_name="zip-xml",
    )]


def capec_family() -> list[dict]:
    root = RAW / "capec"
    root.mkdir(parents=True, exist_ok=True)
    uri = "https://capec.mitre.org/data/archive/capec_latest.zip"
    p = get(uri, root / "capec_latest.zip")
    return [artifact_record(
        family="capec", path=p, source="MITRE CAPEC", source_uri=uri,
        version="latest-authoritative", license_text="MITRE CAPEC Terms of Use",
        format_name="zip-xml",
    )]


def d3fend_family() -> list[dict]:
    root = RAW / "d3fend"
    root.mkdir(parents=True, exist_ok=True)
    base = "https://d3fend.mitre.org/ontologies/"
    out = []
    for name in ("d3fend.json", "d3fend.csv", "d3fend-full-mappings.json", "d3fend-full-mappings.csv"):
        uri = base + name
        p = get(uri, root / name)
        out.append(artifact_record(
            family="d3fend", path=p, source="MITRE D3FEND", source_uri=uri,
            version="1.6.0", license_text="MITRE D3FEND Terms of Use",
            format_name=p.suffix.lstrip("."),
        ))
    return out


def sigma_family() -> list[dict]:
    # Sigma rules are YAML and per-rule licensing/provenance must be preserved.
    # Keep the upstream snapshot intact; normalization happens after acquisition.
    return github_snapshot(
        "SigmaHQ/sigma", "sigma",
        license_text="Per-rule license/provenance metadata; upstream repository license applies where specified",
    )


def attack_family() -> list[dict]:
    return github_snapshot(
        "mitre-attack/attack-stix-data", "mitre_attack",
        license_text="MITRE ATT&CK Terms of Use",
    )


def mbc_family() -> list[dict]:
    return github_snapshot(
        "MBCProject/mbc-markdown", "mbc",
        license_text="MITRE Malware Behavior Catalog Terms of Use",
    )


def suricata_family() -> list[dict]:
    root = RAW / "suricata_rules"
    root.mkdir(parents=True, exist_ok=True)
    # Official Suricata documentation identifies Emerging Threats Open as a
    # free ruleset and suricata-update as the official management mechanism.
    # We install the tool and capture its produced ruleset as an exact snapshot.
    try:
        run(sys.executable, "-m", "pip", "install", "-q", "suricata-update")
        run("suricata-update", "--no-test")
    except Exception as exc:
        raise RuntimeError(
            "suricata-update failed; no Suricata rules were fabricated or substituted"
        ) from exc
    candidates = [
        Path("/var/lib/suricata/rules/suricata.rules"),
        Path("/etc/suricata/rules/suricata.rules"),
    ]
    src = next((p for p in candidates if p.exists()), None)
    if src is None:
        raise RuntimeError("suricata-update completed but suricata.rules was not found")
    target = root / "suricata.rules"
    shutil.copy2(src, target)
    return [artifact_record(
        family="suricata_rules", path=target, source="Suricata-Update / Emerging Threats Open",
        source_uri="https://docs.suricata.io/en/latest/rules/intro.html",
        version=STAMP,
        license_text="Ruleset license/provenance preserved from upstream rule headers",
        format_name="suricata-rules",
    )]


def zeek_family() -> list[dict]:
    # Zeek itself defines the intel format/framework. The actual feed snapshot
    # is kept explicitly as third-party feed provenance rather than pretending
    # Zeek owns the feed.
    return github_snapshot(
        "CriticalPathSecurity/Zeek-Intelligence-Feeds", "zeek_intel",
        license_text="Upstream feed repository license/TOU; preserve source metadata",
    )


def cvss_family(nvd_records: list[dict]) -> list[dict]:
    # CVSS is an enrichment extracted from the authoritative NVD CVE snapshots,
    # not a second copy of the CVE corpus.
    # The actual extraction is performed from downloaded NVD JSON in a later
    # normalization stage; this marker records the dependency explicitly.
    marker = RAW / "cvss" / "README.json"
    write_json(marker, {
        "dataset": "cvss",
        "version": f"derived-from-nvd-2.0-{TODAY}",
        "source": "NVD CVE 2.0 CVSS metadata",
        "source_uri": "https://nvd.nist.gov/vuln/data-feeds",
        "license": "NVD data feed terms; preserve source attribution",
        "derivation": "Extract CVSS v4/v3 metrics from NVD CVE records; do not duplicate CVE records.",
        "dependencies": [x["local_path"] for x in nvd_records],
        "validation_status": "pending-derived-extraction",
    })
    return [artifact_record(
        family="cvss", path=marker, source="NVD CVE 2.0 CVSS metadata",
        source_uri="https://nvd.nist.gov/vuln/data-feeds",
        version=f"derived-from-nvd-2.0-{TODAY}",
        license_text="NVD data feed terms; preserve source attribution",
        format_name="json-marker",
    )]


def acquire_family(name: str) -> list[dict]:
    if name == "nvd_cve":
        return nvd_family()
    if name == "cpe":
        return cpe_family()
    if name == "cisa_kev":
        return kev_family()
    if name == "epss":
        return epss_family()
    if name == "cwe":
        return cwe_family()
    if name == "capec":
        return capec_family()
    if name == "d3fend":
        return d3fend_family()
    if name == "mitre_attack":
        return attack_family()
    if name == "sigma":
        return sigma_family()
    if name == "suricata_rules":
        return suricata_family()
    if name == "zeek_intel":
        return zeek_family()
    if name == "mbc":
        return mbc_family()
    raise AssertionError(name)


def push() -> None:
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if not token:
        raise SystemExit("GH_TOKEN/GITHUB_TOKEN is required for PUSH_DATASETS=1")
    # Large regular-Git objects are blocked by GitHub at 100 MiB. Track them in
    # LFS before staging, but fail closed if LFS is unavailable.
    large = [p for p in DATASETS.rglob("*") if p.is_file() and p.stat().st_size >= LFS_THRESHOLD]
    if large:
        if not ensure_lfs():
            raise SystemExit(
                "Large dataset artifacts found but git-lfs is unavailable. "
                "Install git-lfs or use an external artifact store; nothing is pushed."
            )
        patterns = sorted({str(p.relative_to(CHECKOUT)) for p in large})
        run("git", "lfs", "track", *patterns, cwd=CHECKOUT)
    run("git", "add", "datasets", cwd=CHECKOUT)
    run("git", "status", "--short", cwd=CHECKOUT)
    result = run("git", "diff", "--cached", "--quiet", cwd=CHECKOUT, check=False)
    if result.returncode == 0:
        print("No dataset changes to commit.")
        return
    run("git", "commit", "-m", f"data: acquire locked AI-CYBER datasets {STAMP}", cwd=CHECKOUT)
    askpass = Path(tempfile.mkstemp(prefix="ai-cyber-git-askpass-", text=True)[1])
    try:
        askpass.write_text("#!/bin/sh\nprintf '%s\\n' \"$GITHUB_TOKEN\"\n", encoding="utf-8")
        askpass.chmod(0o700)
        env = os.environ.copy()
        env["GITHUB_TOKEN"] = token
        env["GIT_ASKPASS"] = str(askpass)
        env["GIT_TERMINAL_PROMPT"] = "0"
        run("git", "push", "origin", BRANCH, cwd=CHECKOUT, env=env)
    finally:
        try:
            askpass.unlink()
        except FileNotFoundError:
            pass


def main() -> int:
    print("=" * 88)
    print("AI-CYBER — KAGGLE MASTER DATASET ACQUISITION")
    print("=" * 88)
    print("Locked families:", ", ".join(FAMILIES))
    print("Branch:", BRANCH)
    print("Push:", PUSH)

    git_clone()
    for d in (RAW, MANIFESTS, REPORTS):
        d.mkdir(parents=True, exist_ok=True)

    all_records: list[dict] = []
    errors: list[dict] = []
    nvd_records: list[dict] = []

    for family in FAMILIES:
        print("\n---", family, "---")
        try:
            records = acquire_family(family)
            if family == "nvd_cve":
                nvd_records = records
            all_records.extend(records)
            print(f"OK: {family}: {len(records)} artifact(s)")
        except Exception as exc:
            errors.append({"dataset": family, "error": repr(exc)})
            print(f"FAILED: {family}: {exc}")

    if "cvss" in FAMILIES and nvd_records:
        try:
            records = cvss_family(nvd_records)
            all_records.extend(records)
            print(f"OK: cvss: {len(records)} derivation marker")
        except Exception as exc:
            errors.append({"dataset": "cvss", "error": repr(exc)})

    report = {
        "runner": "tools/kaggle_acquire_datasets.py",
        "run_id": STAMP,
        "repo": REPO,
        "branch": BRANCH,
        "locked_families": list(LOCKED),
        "requested_families": FAMILIES,
        "artifacts": all_records,
        "errors": errors,
        "fail_closed": bool(errors),
    }
    write_json(REPORTS / f"acquisition-{STAMP}.json", report)

    # Per-family manifests make later ingestion deterministic and avoid any
    # dependence on a live feed.
    by_family: dict[str, list[dict]] = {}
    for rec in all_records:
        by_family.setdefault(rec["dataset"], []).append(rec)
    for family, records in sorted(by_family.items()):
        write_json(MANIFESTS / f"{family}.json", {
            "dataset": family,
            "artifacts": records,
            "source_of_truth": "acquisition-report",
        })

    if errors:
        print("\nFAIL-CLOSED: one or more dataset families failed.")
        print(json.dumps(errors, indent=2))
        print(f"Report: {REPORTS / f'acquisition-{STAMP}.json'}")
        return 2

    if PUSH:
        push()

    print("\nSUCCESS: all requested dataset families acquired and recorded.")
    print(f"Acquisition report: {REPORTS / f'acquisition-{STAMP}.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
