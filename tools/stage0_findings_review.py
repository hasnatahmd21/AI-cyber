#!/usr/bin/env python3
"""Evidence-driven Part 3 triage for the AI-CYBER Stage 0 forensic audit."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from pathlib import Path, PurePosixPath
from typing import Any

AUDIT_SCHEMA = "ai-cyber.deep-forensic-audit.v1"
REVIEW_SCHEMA = "ai-cyber.stage0-findings-review.v1"
LEGACY_FILES = (
    "Assrf next .py", "HYDRA_FINAL_CLIENT_HANDOVER_FIXED.py",
    "HYDRA_MASTER_RECONSTRUCTED_v2.py", "HYDRA_patched-3.py",
    "IT_tech__MERGED_ALL_FIXES_APPLIED.py", "New tech .py",
)
CORE = "src/ai_cyber_os/hydra.py"
ARCH_MAP = "docs/ARCHITECTURE_STAGE_1.md"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_SNAPSHOT = re.compile(r"(?im)^\*\*Snapshot commit:\*\*\s*([0-9a-f]{40})\s*$")


class ReviewError(ValueError):
    """Untrusted, malformed, or mismatched evidence."""


def _path(value: Any) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise ReviewError(f"Invalid repository-relative path: {value!r}")
    p = PurePosixPath(value)
    if p.is_absolute() or any(x in {"", ".", ".."} for x in p.parts):
        raise ReviewError(f"Unsafe repository-relative path: {value!r}")
    return p.as_posix()


def _digest(root: Path, rel: str, category: str) -> tuple[str | None, int | None, str | None]:
    """Hash file bytes or symlink-target text without following symlinks."""
    p = root.joinpath(*PurePosixPath(rel).parts)
    try:
        if category == "symlink":
            if not p.is_symlink():
                return None, None, "expected symlink, found another file type"
            data = os.readlink(p).encode("utf-8", errors="surrogateescape")
            return hashlib.sha256(data).hexdigest(), len(data), None
        if p.is_symlink():
            return None, None, "unexpected symlink at regular-file path"
        if not p.is_file():
            return None, None, "missing or non-regular file"
        h, size = hashlib.sha256(), 0
        with p.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                h.update(chunk)
                size += len(chunk)
        return h.hexdigest(), size, None
    except OSError as exc:
        return None, None, f"{type(exc).__name__}: {exc}"


def _list(value: Any, label: str) -> list:
    if not isinstance(value, list):
        raise ReviewError(f"{label} must be a list")
    return value


def _count(record: dict, key: str) -> int:
    value = record.get(key, [])
    return len(value) if isinstance(value, list) else 0


def build_review(report: dict[str, Any], root: Path, expected_commit: str) -> dict[str, Any]:
    if not isinstance(report, dict) or report.get("schema") != AUDIT_SCHEMA:
        raise ReviewError(f"Expected schema {AUDIT_SCHEMA!r}")
    if not isinstance(expected_commit, str) or not _COMMIT.fullmatch(expected_commit):
        raise ReviewError("expected_commit must be a 40-character lowercase Git SHA")
    if report.get("commit_sha") != expected_commit:
        raise ReviewError(f"Audit commit mismatch: {report.get('commit_sha')!r} != {expected_commit!r}")
    summary, inventory = report.get("summary"), report.get("repository_inventory")
    if not isinstance(summary, dict) or not isinstance(inventory, dict):
        raise ReviewError("summary and repository_inventory must be objects")
    root = root.resolve()

    inv_by_path, integrity = {}, []
    for entry in _list(inventory.get("files"), "repository_inventory.files"):
        if not isinstance(entry, dict):
            raise ReviewError("Inventory entries must be objects")
        rel = _path(entry.get("path"))
        if rel in inv_by_path:
            raise ReviewError(f"Duplicate inventory path: {rel}")
        digest, size = entry.get("sha256"), entry.get("bytes")
        if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
            raise ReviewError(f"Invalid SHA-256 for {rel}")
        if not isinstance(size, int) or size < 0:
            raise ReviewError(f"Invalid byte size for {rel}")
        inv_by_path[rel] = entry
        got_hash, got_size, error = _digest(root, rel, str(entry.get("category", "")))
        integrity.append({
            "path": rel, "expected_sha256": digest, "actual_sha256": got_hash,
            "expected_bytes": size, "actual_bytes": got_size,
            "matches": error is None and got_hash == digest and got_size == size, "error": error,
        })

    records = {}
    for entry in _list(report.get("files"), "files"):
        if not isinstance(entry, dict):
            raise ReviewError("Python AST records must be objects")
        rel = _path(entry.get("path"))
        if rel in records:
            raise ReviewError(f"Duplicate AST record: {rel}")
        records[rel] = entry

    findings = []

    def add(fid, severity, status, title, evidence, action):
        findings.append({"id": fid, "severity": severity, "status": status,
                         "title": title, "evidence": evidence, "required_action": action})

    mismatches = [x for x in integrity if not x["matches"]]
    if mismatches:
        add("ST0-P3-001", "high", "BLOCKED", "Checkout differs from audit inventory",
            {"mismatch_count": len(mismatches), "paths": [x["path"] for x in mismatches[:100]]},
            "Regenerate the report from this exact commit and repeat evidence-integrity checks.")
    missing = [p for p in LEGACY_FILES if p not in records or p not in inv_by_path]
    if missing:
        add("ST0-P3-002", "high", "BLOCKED", "Legacy-source evidence is incomplete", {"missing_paths": missing},
            "Preserve and inventory all six legacy sources; do not rewrite them in Stage 0.")
    core = records.get(CORE)
    if core is None or not core.get("syntax_ok", False):
        add("ST0-P3-003", "high", "BLOCKED", "Canonical HYDRA core is missing or has a syntax error",
            {"path": CORE, "present": core is not None, "syntax_error": core.get("syntax_error") if core else None},
            "Reconcile and verify canonical source in its owning implementation stage.")

    syntax_errors, nonlegacy_errors = [], []
    for rel, item in sorted(records.items()):
        if item.get("syntax_ok") is True:
            continue
        err = item.get("syntax_error") if isinstance(item.get("syntax_error"), dict) else {}
        ev = {"path": rel, "line": err.get("line"), "column": err.get("column"),
              "message": err.get("message"), "classification": item.get("classification")}
        syntax_errors.append(ev)
        legacy = item.get("classification") == "legacy_forensic_candidate"
        if not legacy:
            nonlegacy_errors.append(ev)
        add(f"ST0-SYNTAX-{ 'LEGACY' if legacy else 'BLOCK' }-{len(syntax_errors):03d}",
            "medium" if legacy else "high", "REVIEW_REQUIRED" if legacy else "BLOCKED",
            "Preserved legacy source syntax error" if legacy else "Non-legacy Python syntax error", ev,
            "Preserve original bytes and track parser evidence." if legacy else
            "Investigate this syntax failure, then rerun current-commit verification.")

    declared_legacy = set(summary.get("legacy_forensic_files_present", [])) if isinstance(summary.get("legacy_forensic_files_present"), list) else set()
    legacy_rows = []
    for rel in LEGACY_FILES:
        item, inv = records.get(rel, {}), inv_by_path.get(rel, {})
        syntax = item.get("syntax_ok")
        state = "MISSING_EVIDENCE" if rel not in records or rel not in inv_by_path else (
            "PRESERVED_SYNTAX_ERROR" if syntax is False else "REVIEW_REQUIRED")
        legacy_rows.append({
            "path": rel, "present_in_summary": rel in declared_legacy, "bytes": inv.get("bytes"),
            "sha256": inv.get("sha256"), "line_count": item.get("lines"),
            "syntax_ok": syntax if isinstance(syntax, bool) else None, "syntax_error": item.get("syntax_error"),
            "symbol_count": _count(item, "symbols"), "callsite_count": _count(item, "calls"),
            "import_count": _count(item, "imports"), "main_guard_count": _count(item, "main_guards"),
            "duplicate_scoped_symbol_count": _count(item, "duplicate_scoped_symbols"),
            "side_effect_signal_count": _count(item, "side_effect_signals"),
            "unused_import_candidate_count": _count(item, "unused_import_candidates"),
            "stub_candidate_count": _count(item, "stub_candidates"),
            "unreachable_statement_candidate_count": _count(item, "unreachable_statement_candidates"),
            "todo_marker_count": _count(item, "todo_markers"), "state": state,
        })

    duplicates = report.get("cross_file_duplicate_symbols", {})
    if not isinstance(duplicates, dict):
        raise ReviewError("cross_file_duplicate_symbols must be an object")
    security = report.get("security_review", {})
    rule_counts = security.get("rule_counts", {}) if isinstance(security, dict) else {}
    if not isinstance(rule_counts, dict):
        rule_counts = {}
    candidates = {
        key: summary.get(key, 0) for key in (
            "cross_file_duplicate_symbol_keys", "files_with_duplicate_scoped_symbols",
            "side_effect_signal_count", "broad_exception_count", "stub_candidate_count",
            "unreachable_statement_candidate_count", "unused_import_candidate_count",
            "import_resolution_finding_count", "todo_marker_count",
        )
    }
    candidates["security_review_rule_counts"] = dict(sorted(
        (str(k), v) for k, v in rule_counts.items() if isinstance(v, int) and not isinstance(v, bool)))
    candidates["duplicate_name_examples"] = sorted(duplicates)[:30]
    if any(isinstance(candidates.get(k), int) and candidates[k] > 0 for k in (
        "cross_file_duplicate_symbol_keys", "files_with_duplicate_scoped_symbols",
        "side_effect_signal_count", "broad_exception_count", "stub_candidate_count",
        "unreachable_statement_candidate_count", "unused_import_candidate_count",
        "import_resolution_finding_count", "todo_marker_count",
    )):
        add("ST0-P3-CANDIDATES", "medium", "REVIEW_REQUIRED",
            "Static candidates require source-context review", candidates,
            "Review source ranges, callers, effects, contracts and tests; counts alone do not establish defects.")

    entries, entry_files = report.get("entrypoints", {}), report.get("entrypoint_files", {})
    if not isinstance(entries, dict) or not isinstance(entry_files, dict):
        raise ReviewError("entrypoints and entrypoint_files must be objects")
    canonical = {
        "core_path": CORE, "core_present": core is not None,
        "core_syntax_ok": core.get("syntax_ok") if core else None,
        "core_sha256": core.get("sha256") if core else None,
        "core_bytes": core.get("bytes") if core else None,
        "core_symbol_count": _count(core or {}, "symbols"), "core_callsite_count": _count(core or {}, "calls"),
        "static_runtime_reachable_files": summary.get("static_runtime_reachable_files"),
        "entrypoint_file_count": summary.get("entrypoint_file_count"), "entrypoints": entries,
        "entrypoint_file_evidence": {p: entry_files[p] for p in sorted(entry_files) if isinstance(entry_files[p], dict)},
        "limitation": "Static reachability is approximate; dynamic calls and dispatch may not be resolved.",
    }

    arch_sha, arch_status = None, "MISSING"
    arch_path = root / ARCH_MAP
    if arch_path.is_file() and not arch_path.is_symlink():
        match = _SNAPSHOT.search(arch_path.read_text(encoding="utf-8", errors="replace"))
        if match:
            arch_sha = match.group(1)
            arch_status = "CURRENT_SNAPSHOT" if arch_sha == expected_commit else "STALE_SNAPSHOT"
        else:
            arch_status = "SNAPSHOT_SHA_NOT_DECLARED"
    if arch_status != "CURRENT_SNAPSHOT":
        add("ST0-P3-005", "medium", "REVIEW_REQUIRED", "Stage 1 map is not tied to audited commit",
            {"path": ARCH_MAP, "declared_snapshot_sha": arch_sha,
             "audited_commit_sha": expected_commit, "map_status": arch_status},
            "Cross-check architecture claims against the current evidence and refresh source anchors after review.")

    blockers = sum(x["status"] == "BLOCKED" for x in findings)
    review_count = sum(x["status"] == "REVIEW_REQUIRED" for x in findings)
    return {
        "schema": REVIEW_SCHEMA, "audit_commit_sha": expected_commit, "reviewed_commit_sha": expected_commit,
        "status": "BLOCKED" if blockers else "REVIEW_REQUIRED", "automated_green_claim": False,
        "decision_note": "This triage ledger is not a product-security verdict. Stage 0 remains open until review actions are resolved or explicitly documented as blocked.",
        "summary": {
            "repository_inventory_file_count": len(inv_by_path), "inventory_integrity_mismatch_count": len(mismatches),
            "python_file_count": summary.get("python_file_count", len(records)),
            "syntax_error_file_count": len(syntax_errors), "blocking_nonlegacy_syntax_error_count": len(nonlegacy_errors),
            "cross_file_duplicate_symbol_keys": summary.get("cross_file_duplicate_symbol_keys", 0),
            "files_with_duplicate_scoped_symbols": summary.get("files_with_duplicate_scoped_symbols", 0),
            "side_effect_signal_count": summary.get("side_effect_signal_count", 0),
            "legacy_expected_count": len(LEGACY_FILES),
            "legacy_evidence_count": sum(p in records and p in inv_by_path for p in LEGACY_FILES),
            "canonical_core_present": core is not None,
            "canonical_core_syntax_ok": core.get("syntax_ok") if core else None,
            "architecture_map_status": arch_status, "architecture_map_snapshot_sha": arch_sha,
            "blocker_count": blockers, "review_required_count": review_count, "static_candidates": candidates,
        },
        "canonical_reconciliation": canonical, "legacy_sources": legacy_rows,
        "syntax_errors": syntax_errors, "inventory_integrity": integrity, "findings": findings,
        "required_review_actions": [
            "Review syntax, duplicates, import resolution, stubs, side effects and apparent unreachable statements against source ranges.",
            "Reconcile canonical CLI/UI routes against direct imports and call edges; mark dynamic dispatch UNKNOWN.",
            "Cross-check the Stage 1 architecture map against this exact audit commit.",
            "Preserve all six legacy sources and record a disposition for each.",
            "Retain exact-SHA artifacts; never treat static counts as a security verdict.",
        ],
    }


def render_markdown(review: dict[str, Any]) -> str:
    s, core = review["summary"], review["canonical_reconciliation"]
    out = [
        "# AI-CYBER Stage 0 — Part 3 Findings Review", "",
        f"**Audited commit:** {review['audit_commit_sha']}", f"**Decision:** {review['status']}",
        "**Automated green claim:** No", "", review["decision_note"], "",
        "## Gate summary", "", "| Check | Result |", "|---|---:|",
        f"| Inventory files / mismatches | {s['repository_inventory_file_count']} / {s['inventory_integrity_mismatch_count']} |",
        f"| Python syntax errors / non-legacy blockers | {s['syntax_error_file_count']} / {s['blocking_nonlegacy_syntax_error_count']} |",
        f"| Cross-file duplicate-name keys (candidates) | {s['cross_file_duplicate_symbol_keys']} |",
        f"| Same-scope duplicate files (candidates) | {s['files_with_duplicate_scoped_symbols']} |",
        f"| Security-sensitive API signals (review only) | {s['side_effect_signal_count']} |",
        f"| Legacy sources with AST + inventory evidence | {s['legacy_evidence_count']} / {s['legacy_expected_count']} |",
        f"| Architecture map snapshot | {s['architecture_map_status']} |",
        f"| Blocking / review-required findings | {s['blocker_count']} / {s['review_required_count']} |", "",
        "## Canonical runtime reconciliation", "",
        f"- Core path: {core['core_path']}",
        f"- Core present / syntax OK: {core['core_present']} / {core['core_syntax_ok']}",
        f"- Core SHA-256: {core['core_sha256'] or 'MISSING'}",
        f"- Core symbols / callsites: {core['core_symbol_count']} / {core['core_callsite_count']}",
        f"- Approximate reachable files / entry-point files: {core['static_runtime_reachable_files']} / {core['entrypoint_file_count']}",
        "", "Entry-point evidence is detailed in the JSON artifact. Static reachability is approximate.", "",
        "## Preserved legacy source ledger", "",
        "| Source | Bytes | SHA-256 | Syntax | Symbols | Callsites | Duplicate scopes | Risk signals | State |",
        "|---|---:|---|---|---:|---:|---:|---:|---|",
    ]
    for item in review["legacy_sources"]:
        syntax = "OK" if item["syntax_ok"] is True else "ERROR" if item["syntax_ok"] is False else "UNKNOWN"
        out.append(
            f"| {item['path']} | {item['bytes'] if item['bytes'] is not None else '—'} | "
            f"{item['sha256'] or 'MISSING'} | {syntax} | {item['symbol_count']} | {item['callsite_count']} | "
            f"{item['duplicate_scoped_symbol_count']} | {item['side_effect_signal_count']} | {item['state']} |")
    out += ["", "## Findings requiring attention", ""]
    for item in review["findings"]:
        out += [f"### {item['id']} — {item['title']}",
                f"- Severity/status: {item['severity']} / {item['status']}",
                f"- Evidence: {json.dumps(item['evidence'], sort_keys=True, ensure_ascii=False)}",
                f"- Required action: {item['required_action']}", ""]
    out += ["", "## Required review actions", ""]
    out.extend(f"{i}. {action}" for i, action in enumerate(review["required_review_actions"], 1))
    out += ["", "> Static findings are investigation leads, not confirmed vulnerabilities or dead code. "
            "This ledger does not prove live SSRF prevention, network isolation, signed artifact trust, deception, or self-recovery.", ""]
    return "\n".join(out)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("audit_json", type=Path)
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--markdown-out", type=Path)
    args = parser.parse_args()
    try:
        report = json.loads(args.audit_json.read_text(encoding="utf-8"))
        review = build_review(report, args.root, args.expected_commit)
    except (OSError, json.JSONDecodeError, ReviewError) as exc:
        parser.error(str(exc))
    payload = json.dumps(review, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    markdown = render_markdown(review)
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(payload, encoding="utf-8")
    if args.markdown_out:
        args.markdown_out.parent.mkdir(parents=True, exist_ok=True)
        args.markdown_out.write_text(markdown, encoding="utf-8")
    if not args.json_out and not args.markdown_out:
        print(markdown)
    else:
        print(json.dumps({"status": review["status"], "summary": review["summary"]}, indent=2, sort_keys=True))
    return 1 if review["status"] == "BLOCKED" else 0


if __name__ == "__main__":
    raise SystemExit(main())
