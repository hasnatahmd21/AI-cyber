"""Canonical dataset manifest validation, provenance, SQLite ingestion and integrity checks."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Callable, Iterable, Iterator, Mapping

SCHEMA = "ai-cyber.dataset-manifest.v2"
LEGACY_SCHEMA = "ai-cyber.dataset-manifest.v1"
DEFAULT_MAX_ARTIFACT_BYTES = 128 * 1024 * 1024
DEFAULT_MAX_RECORDS = 1_000_000
SUPPORTED_FORMATS = {"json", "jsonl", "ndjson"}
JSON_COLLECTION_KEYS = ("records", "data", "items", "examples", "rows", "entries")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class DatasetPipelineError(ValueError):
    """Base class for deterministic dataset-pipeline failures."""


class ManifestValidationError(DatasetPipelineError):
    """Raised when a manifest or referenced artifact violates the contract."""


class DatasetIntegrityError(DatasetPipelineError):
    """Raised when canonical storage no longer matches its source dataset."""


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _strict_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ManifestValidationError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ManifestValidationError(f"non-standard JSON constant is not allowed: {value}")


def _strict_json_loads(text: str, context: str) -> Any:
    try:
        return json.loads(
            text,
            object_pairs_hook=_strict_pairs,
            parse_constant=_reject_constant,
        )
    except ManifestValidationError:
        raise
    except json.JSONDecodeError as exc:
        raise ManifestValidationError(f"invalid JSON in {context}: {exc}") from exc


def sha256_file(path: Path) -> str:
    """Return SHA-256 without loading the whole file."""
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _validate_root(root: Path) -> Path:
    root = Path(root).expanduser().resolve()
    if not root.is_dir():
        raise ManifestValidationError(f"dataset root is not a directory: {root}")
    return root


def _safe_relative_file(root: Path, relative_path: str, *, kind: str = "artifact") -> Path:
    if not isinstance(relative_path, str) or not relative_path:
        raise ManifestValidationError(f"{kind} path must be a non-empty string")
    if "\x00" in relative_path:
        raise ManifestValidationError(f"{kind} path contains NUL byte")
    if "\\" in relative_path:
        raise ManifestValidationError(f"{kind} path must use portable '/' separators")

    posix = PurePosixPath(relative_path)
    windows = PureWindowsPath(relative_path)
    if posix.is_absolute() or windows.is_absolute() or windows.drive:
        raise ManifestValidationError(f"{kind} path must be relative: {relative_path!r}")
    if any(part in {".", "..", ""} for part in posix.parts):
        raise ManifestValidationError(
            f"{kind} path must be canonical and cannot contain '.' or '..': {relative_path!r}"
        )
    if posix.as_posix() != relative_path:
        raise ManifestValidationError(f"{kind} path is not canonical: {relative_path!r}")

    candidate = root
    for part in posix.parts:
        candidate /= part
        if candidate.is_symlink():
            raise ManifestValidationError(f"{kind} path traverses a symlink: {relative_path!r}")

    resolved = candidate.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ManifestValidationError(
            f"{kind} path escapes dataset root: {relative_path!r}"
        ) from exc
    if not resolved.is_file():
        raise FileNotFoundError(resolved)
    return resolved


def _validate_identifier(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER_RE.fullmatch(value):
        raise ManifestValidationError(f"{field} must match {_IDENTIFIER_RE.pattern!r}")
    return value


def _validate_provenance(value: Any, field: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ManifestValidationError(f"{field} must be an object")
    try:
        _canonical_json(value)
    except (TypeError, ValueError) as exc:
        raise ManifestValidationError(f"{field} contains non-JSON values") from exc
    return dict(value)


def _load_manifest(manifest_path: Path) -> tuple[dict[str, Any], str]:
    try:
        raw = manifest_path.read_bytes()
    except OSError as exc:
        raise ManifestValidationError(f"cannot read manifest: {manifest_path}") from exc
    if len(raw) > 4 * 1024 * 1024:
        raise ManifestValidationError("manifest exceeds 4 MiB safety limit")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ManifestValidationError("manifest must be valid UTF-8") from exc
    value = _strict_json_loads(text, str(manifest_path))
    if not isinstance(value, dict):
        raise ManifestValidationError("manifest root must be a JSON object")
    return value, hashlib.sha256(raw).hexdigest()


def _extract_json_records(value: Any, context: str) -> Iterable[dict[str, Any]]:
    if isinstance(value, list):
        rows = value
    elif isinstance(value, dict):
        candidates = [key for key in JSON_COLLECTION_KEYS if isinstance(value.get(key), list)]
        if len(candidates) > 1:
            raise ManifestValidationError(
                f"{context} contains multiple record collections: {', '.join(candidates)}"
            )
        rows = value[candidates[0]] if candidates else [value]
    else:
        raise ManifestValidationError(f"{context} root must be an object or list")

    for index, row in enumerate(rows, 1):
        if not isinstance(row, dict):
            raise ManifestValidationError(f"{context} record {index} is not a JSON object")
        yield row


def _record_id(row: Mapping[str, Any], artifact_path: str, ordinal: int) -> str:
    explicit = next((row[key] for key in ("record_id", "id", "uid") if key in row), None)
    if explicit is None:
        return f"{artifact_path}:{ordinal}"
    if isinstance(explicit, bool) or not isinstance(explicit, (str, int)):
        raise ManifestValidationError(
            f"{artifact_path}:{ordinal} has an invalid record identifier"
        )
    normalized = str(explicit).strip()
    return _validate_identifier(
        normalized,
        f"{artifact_path}:{ordinal} record_id",
    )


def _iter_jsonl_records(
    path: Path,
    raw_hash: Any,
    max_records: int,
) -> Iterator[tuple[int, dict[str, Any]]]:
    count = 0
    with path.open("rb") as handle:
        for line_no, raw_line in enumerate(handle, 1):
            raw_hash.update(raw_line)
            if not raw_line.strip():
                continue
            count += 1
            if count > max_records:
                raise ManifestValidationError(f"{path} exceeds record safety limit")
            try:
                text = raw_line.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ManifestValidationError(f"{path}:{line_no} is not valid UTF-8") from exc
            value = _strict_json_loads(text, f"{path}:{line_no}")
            if not isinstance(value, dict):
                raise ManifestValidationError(f"{path}:{line_no} is not a JSON object")
            yield line_no, value


def _iter_json_records(
    path: Path,
    max_records: int,
) -> Iterator[tuple[int, dict[str, Any]]]:
    raw = path.read_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ManifestValidationError(f"{path} is not valid UTF-8") from exc
    value = _strict_json_loads(text, str(path))
    for index, row in enumerate(_extract_json_records(value, str(path)), 1):
        if index > max_records:
            raise ManifestValidationError(f"{path} exceeds record safety limit")
        yield index, row


def _validate_artifact_contract(
    artifact: Mapping[str, Any],
    root: Path,
    *,
    max_artifact_bytes: int,
    max_records: int,
) -> tuple[str, Path, str, int, dict[str, Any]]:
    if not isinstance(artifact, dict):
        raise ManifestValidationError("each manifest artifact must be an object")
    rel = artifact.get("path")
    if not isinstance(rel, str):
        raise ManifestValidationError("artifact.path must be a string")
    path = _safe_relative_file(root, rel)

    fmt = artifact.get("format")
    if not isinstance(fmt, str) or fmt not in SUPPORTED_FORMATS:
        raise ManifestValidationError(
            f"{rel}: unsupported format {fmt!r}; expected {sorted(SUPPORTED_FORMATS)}"
        )
    expected_suffix = ".json" if fmt == "json" else f".{fmt}"
    if path.suffix.lower() != expected_suffix:
        raise ManifestValidationError(
            f"{rel}: format {fmt!r} does not match filename suffix {path.suffix!r}"
        )

    count = artifact.get("records")
    if isinstance(count, bool) or not isinstance(count, int) or not 0 <= count <= max_records:
        raise ManifestValidationError(
            f"{rel}: records must be an integer in [0, {max_records}]"
        )

    digest = artifact.get("sha256")
    if not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest):
        raise ManifestValidationError(
            f"{rel}: sha256 must be 64 lowercase hexadecimal characters"
        )

    size = path.stat().st_size
    if size > max_artifact_bytes:
        raise ManifestValidationError(
            f"{rel}: artifact size {size} exceeds configured limit {max_artifact_bytes}"
        )

    provenance = _validate_provenance(artifact.get("provenance"), f"{rel}.provenance")
    return rel, path, fmt, count, {"sha256": digest, "provenance": provenance}


def _scan_artifact(
    rel: str,
    path: Path,
    fmt: str,
    expected_count: int,
    expected_sha256: str,
    *,
    max_artifact_bytes: int,
    max_records: int,
    row_consumer: Callable[[str, str, str], None] | None = None,
) -> tuple[int, str]:
    size = path.stat().st_size
    if size > max_artifact_bytes:
        raise ManifestValidationError(
            f"{rel}: artifact size {size} exceeds configured limit {max_artifact_bytes}"
        )

    raw_hash = hashlib.sha256()
    seen_ids: set[str] = set()

    if fmt in {"jsonl", "ndjson"}:
        iterator = _iter_jsonl_records(path, raw_hash, max_records)
    else:
        raw = path.read_bytes()
        raw_hash.update(raw)
        iterator = _iter_json_records(path, max_records)

    count = 0
    for ordinal, row in iterator:
        count += 1
        rid = _record_id(row, rel, ordinal)
        if rid in seen_ids:
            raise ManifestValidationError(f"{rel}: duplicate record_id {rid!r}")
        seen_ids.add(rid)
        payload = _canonical_json(row)
        payload_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        if row_consumer is not None:
            row_consumer(rid, payload, payload_hash)

    actual_sha256 = raw_hash.hexdigest()
    if actual_sha256 != expected_sha256:
        raise ManifestValidationError(
            f"SHA256 mismatch for {rel}: manifest={expected_sha256} actual={actual_sha256}"
        )
    if count != expected_count:
        raise ManifestValidationError(
            f"record count mismatch for {rel}: manifest={expected_count} actual={count}"
        )
    return count, actual_sha256


def count_records(path: Path, *, max_records: int = DEFAULT_MAX_RECORDS) -> int:
    """Count validated object records in a supported dataset file."""
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(path)
    if path.stat().st_size > DEFAULT_MAX_ARTIFACT_BYTES:
        raise ManifestValidationError("artifact exceeds default safety limit")
    suffix = path.suffix.lower()
    if suffix == ".json":
        return sum(1 for _ in _iter_json_records(path, max_records))
    if suffix in {".jsonl", ".ndjson"}:
        digest = hashlib.sha256()
        return sum(1 for _ in _iter_jsonl_records(path, digest, max_records))
    raise ManifestValidationError(f"unsupported dataset format: {path.suffix}")


def iter_records(
    path: Path,
    *,
    max_records: int = DEFAULT_MAX_RECORDS,
) -> Iterator[dict[str, Any]]:
    """Yield validated object records from a supported dataset file."""
    path = Path(path)
    suffix = path.suffix.lower()
    if suffix == ".json":
        for _, row in _iter_json_records(path, max_records):
            yield row
        return
    if suffix in {".jsonl", ".ndjson"}:
        digest = hashlib.sha256()
        for _, row in _iter_jsonl_records(path, digest, max_records):
            yield row
        return
    raise ManifestValidationError(f"unsupported dataset format: {path.suffix}")


def validate_manifest(
    manifest: dict[str, Any],
    root: Path,
    *,
    max_artifact_bytes: int = DEFAULT_MAX_ARTIFACT_BYTES,
    max_records: int = DEFAULT_MAX_RECORDS,
) -> dict[str, Any]:
    """Validate manifest structure and every referenced artifact."""
    if not isinstance(manifest, dict):
        raise ManifestValidationError("manifest must be a JSON object")
    if max_artifact_bytes <= 0 or max_records <= 0:
        raise ManifestValidationError("safety limits must be positive")
    root = _validate_root(root)

    schema = manifest.get("schema")
    if schema not in {SCHEMA, LEGACY_SCHEMA}:
        raise ManifestValidationError(f"unsupported dataset manifest schema: {schema!r}")
    dataset_id = _validate_identifier(manifest.get("dataset_id"), "dataset_id")
    version = _validate_identifier(manifest.get("version"), "version")
    created_by = manifest.get("created_by")
    if created_by is not None and not isinstance(created_by, str):
        raise ManifestValidationError("created_by must be a string when supplied")
    manifest_provenance = _validate_provenance(
        manifest.get("provenance"),
        "manifest.provenance",
    )

    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise ManifestValidationError("manifest.artifacts must be a non-empty list")

    seen_paths: set[str] = set()
    checked: list[dict[str, Any]] = []
    total_records = 0

    for artifact in artifacts:
        rel, path, fmt, expected_count, meta = _validate_artifact_contract(
            artifact,
            root,
            max_artifact_bytes=max_artifact_bytes,
            max_records=max_records,
        )
        if rel in seen_paths:
            raise ManifestValidationError(f"duplicate artifact path: {rel}")
        seen_paths.add(rel)

        count, digest = _scan_artifact(
            rel,
            path,
            fmt,
            expected_count,
            meta["sha256"],
            max_artifact_bytes=max_artifact_bytes,
            max_records=max_records,
        )
        total_records += count
        if total_records > max_records:
            raise ManifestValidationError(
                f"dataset exceeds configured total record limit {max_records}"
            )
        checked.append(
            {
                "path": rel,
                "format": fmt,
                "sha256": digest,
                "records": count,
                "provenance": meta["provenance"],
            }
        )

    return {
        "schema": schema,
        "dataset_id": dataset_id,
        "version": version,
        "artifact_count": len(checked),
        "record_count": total_records,
        "artifacts": checked,
        "provenance": manifest_provenance,
    }


def _table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}


def _ensure_column(
    conn: sqlite3.Connection,
    table: str,
    column: str,
    definition: str,
) -> None:
    if column not in _table_columns(conn, table):
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def init_store(db_path: Path) -> None:
    """Create or migrate the local SQLite dataset store."""
    db_path = Path(db_path).expanduser()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS dataset_schema_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS dataset_catalog (
                dataset_id TEXT PRIMARY KEY,
                version TEXT NOT NULL,
                manifest_path TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS artifacts (
                dataset_id TEXT NOT NULL,
                artifact_path TEXT NOT NULL,
                format TEXT NOT NULL,
                record_count INTEGER NOT NULL,
                sha256 TEXT NOT NULL,
                PRIMARY KEY(dataset_id, artifact_path)
            );
            CREATE TABLE IF NOT EXISTS provenance (
                dataset_id TEXT NOT NULL,
                artifact_path TEXT,
                source TEXT,
                version TEXT,
                origin TEXT,
                acquired_at TEXT
            );
            CREATE TABLE IF NOT EXISTS records (
                dataset_id TEXT NOT NULL,
                artifact_path TEXT NOT NULL,
                record_id TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                PRIMARY KEY(dataset_id, artifact_path, record_id)
            );
            CREATE INDEX IF NOT EXISTS idx_records_dataset_artifact
                ON records(dataset_id, artifact_path);
            CREATE INDEX IF NOT EXISTS idx_provenance_dataset_artifact
                ON provenance(dataset_id, artifact_path);
            """
        )
        _ensure_column(conn, "dataset_catalog", "manifest_sha256", "TEXT")
        _ensure_column(conn, "dataset_catalog", "artifact_count", "INTEGER")
        _ensure_column(conn, "dataset_catalog", "record_count", "INTEGER")
        _ensure_column(conn, "dataset_catalog", "provenance_json", "TEXT")
        _ensure_column(conn, "dataset_catalog", "updated_at", "TEXT")
        _ensure_column(conn, "artifacts", "provenance_json", "TEXT")
        _ensure_column(conn, "provenance", "license", "TEXT")
        _ensure_column(conn, "records", "payload_sha256", "TEXT")
        conn.execute(
            """
            INSERT INTO dataset_schema_meta(key,value) VALUES('schema',?)
            ON CONFLICT(key) DO UPDATE SET value=excluded.value
            """,
            (SCHEMA,),
        )


def _source_provenance(
    manifest_provenance: Mapping[str, Any],
    artifact_provenance: Mapping[str, Any],
) -> dict[str, Any]:
    merged = dict(manifest_provenance)
    merged.update(artifact_provenance)
    return merged


def _manifest_relative_path(manifest_path: Path, root: Path) -> str:
    original = Path(manifest_path).expanduser()
    if original.is_symlink():
        raise ManifestValidationError("manifest symlinks are not allowed")
    resolved = original.resolve()
    try:
        relative = resolved.relative_to(root)
    except ValueError as exc:
        raise ManifestValidationError("manifest must live inside dataset root") from exc
    return relative.as_posix()


def ingest_manifest(
    manifest_path: Path,
    root: Path,
    db_path: Path,
    *,
    max_artifact_bytes: int = DEFAULT_MAX_ARTIFACT_BYTES,
    max_records: int = DEFAULT_MAX_RECORDS,
) -> dict[str, Any]:
    """Validate, ingest and atomically reconcile one dataset."""
    root = _validate_root(root)
    manifest_path = Path(manifest_path).expanduser()
    if manifest_path.is_symlink():
        raise ManifestValidationError("manifest symlinks are not allowed")
    manifest_relative = _manifest_relative_path(manifest_path, root)
    manifest_path = _safe_relative_file(root, manifest_relative, kind="manifest")
    manifest, manifest_sha256 = _load_manifest(manifest_path)

    validated = validate_manifest(
        manifest,
        root,
        max_artifact_bytes=max_artifact_bytes,
        max_records=max_records,
    )
    init_store(Path(db_path))

    dataset_id = validated["dataset_id"]
    now = datetime.now(timezone.utc).isoformat()
    current_paths = {item["path"] for item in validated["artifacts"]}

    with sqlite3.connect(db_path) as conn:
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        conn.execute("BEGIN IMMEDIATE")

        stale_paths = {
            row[0]
            for row in conn.execute(
                "SELECT artifact_path FROM artifacts WHERE dataset_id=?",
                (dataset_id,),
            ).fetchall()
        } - current_paths
        for stale in stale_paths:
            conn.execute(
                "DELETE FROM records WHERE dataset_id=? AND artifact_path=?",
                (dataset_id, stale),
            )
            conn.execute(
                "DELETE FROM provenance WHERE dataset_id=? AND artifact_path=?",
                (dataset_id, stale),
            )
            conn.execute(
                "DELETE FROM artifacts WHERE dataset_id=? AND artifact_path=?",
                (dataset_id, stale),
            )

        conn.execute(
            """
            INSERT INTO dataset_catalog(
                dataset_id,version,manifest_path,created_at,
                manifest_sha256,artifact_count,record_count,provenance_json,updated_at
            )
            VALUES(?,?,?,?,?,?,?,?,?)
            ON CONFLICT(dataset_id) DO UPDATE SET
                version=excluded.version,
                manifest_path=excluded.manifest_path,
                manifest_sha256=excluded.manifest_sha256,
                artifact_count=excluded.artifact_count,
                record_count=excluded.record_count,
                provenance_json=excluded.provenance_json,
                updated_at=excluded.updated_at
            """,
            (
                dataset_id,
                validated["version"],
                manifest_relative,
                now,
                manifest_sha256,
                validated["artifact_count"],
                validated["record_count"],
                _canonical_json(validated["provenance"]),
                now,
            ),
        )

        actual_total = 0
        for artifact in validated["artifacts"]:
            rel = artifact["path"]
            fmt = artifact["format"]
            path = _safe_relative_file(root, rel)
            provenance = _source_provenance(
                validated["provenance"],
                artifact.get("provenance", {}),
            )
            conn.execute(
                """
                INSERT INTO artifacts(
                    dataset_id,artifact_path,format,record_count,sha256,provenance_json
                )
                VALUES(?,?,?,?,?,?)
                ON CONFLICT(dataset_id,artifact_path) DO UPDATE SET
                    format=excluded.format,
                    record_count=excluded.record_count,
                    sha256=excluded.sha256,
                    provenance_json=excluded.provenance_json
                """,
                (
                    dataset_id,
                    rel,
                    fmt,
                    artifact["records"],
                    artifact["sha256"],
                    _canonical_json(provenance),
                ),
            )
            conn.execute(
                "DELETE FROM provenance WHERE dataset_id=? AND artifact_path=?",
                (dataset_id, rel),
            )
            conn.execute(
                """
                INSERT INTO provenance(
                    dataset_id,artifact_path,source,version,origin,acquired_at,license
                )
                VALUES(?,?,?,?,?,?,?)
                """,
                (
                    dataset_id,
                    rel,
                    provenance.get("source"),
                    provenance.get("version"),
                    provenance.get("origin"),
                    provenance.get("acquired_at"),
                    provenance.get("license"),
                ),
            )
            conn.execute(
                "DELETE FROM records WHERE dataset_id=? AND artifact_path=?",
                (dataset_id, rel),
            )

            count, digest = _scan_artifact(
                rel,
                path,
                fmt,
                artifact["records"],
                artifact["sha256"],
                max_artifact_bytes=max_artifact_bytes,
                max_records=max_records,
                row_consumer=lambda rid, payload, payload_hash: conn.execute(
                    """
                    INSERT INTO records(
                        dataset_id,artifact_path,record_id,payload_json,payload_sha256
                    )
                    VALUES(?,?,?,?,?)
                    """,
                    (dataset_id, rel, rid, payload, payload_hash),
                ),
            )
            actual_total += count
            if digest != artifact["sha256"]:
                raise DatasetIntegrityError(f"{rel}: second-pass SHA256 mismatch")

        stored_artifact_count = conn.execute(
            "SELECT count(*) FROM artifacts WHERE dataset_id=?",
            (dataset_id,),
        ).fetchone()[0]
        stored_record_count = conn.execute(
            "SELECT count(*) FROM records WHERE dataset_id=?",
            (dataset_id,),
        ).fetchone()[0]
        if actual_total != validated["record_count"]:
            raise DatasetIntegrityError(
                f"transactional total record mismatch: expected {validated['record_count']} actual {actual_total}"
            )
        if stored_artifact_count != validated["artifact_count"]:
            raise DatasetIntegrityError("stored artifact count does not match manifest")
        if stored_record_count != validated["record_count"]:
            raise DatasetIntegrityError("stored record count does not match manifest")

        final_manifest_sha256 = sha256_file(manifest_path)
        if final_manifest_sha256 != manifest_sha256:
            raise DatasetIntegrityError(
                "manifest changed during ingestion; transaction rolled back"
            )

        conn.commit()

    return {
        **validated,
        "manifest_sha256": manifest_sha256,
        "manifest_path": manifest_relative,
        "verified": True,
    }


def _compare_record(
    conn: sqlite3.Connection,
    dataset_id: str,
    artifact_path: str,
    record_id: str,
    payload: str,
    payload_hash: str,
    errors: list[str],
) -> None:
    row = conn.execute(
        """
        SELECT payload_json,payload_sha256
        FROM records
        WHERE dataset_id=? AND artifact_path=? AND record_id=?
        """,
        (dataset_id, artifact_path, record_id),
    ).fetchone()
    if row is None:
        errors.append(f"{dataset_id}/{artifact_path}/{record_id}: missing stored record")
        return
    if row[0] != payload or row[1] != payload_hash:
        errors.append(f"{dataset_id}/{artifact_path}/{record_id}: stored payload mismatch")


def verify_store(
    db_path: Path,
    root: Path,
    *,
    dataset_id: str | None = None,
    max_artifact_bytes: int = DEFAULT_MAX_ARTIFACT_BYTES,
    max_records: int = DEFAULT_MAX_RECORDS,
) -> dict[str, Any]:
    """Verify canonical SQLite data against its source manifests and artifacts."""
    root = _validate_root(root)
    if dataset_id is not None:
        dataset_id = _validate_identifier(dataset_id, "dataset_id")
    init_store(Path(db_path))

    errors: list[str] = []
    checked_datasets = checked_artifacts = checked_records = 0

    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        catalogs = (
            conn.execute(
                "SELECT * FROM dataset_catalog WHERE dataset_id=?",
                (dataset_id,),
            ).fetchall()
            if dataset_id
            else conn.execute("SELECT * FROM dataset_catalog ORDER BY dataset_id").fetchall()
        )

        for catalog in catalogs:
            checked_datasets += 1
            ds = catalog["dataset_id"]
            try:
                manifest_path = _safe_relative_file(
                    root,
                    catalog["manifest_path"],
                    kind="stored manifest",
                )
                manifest, manifest_sha = _load_manifest(manifest_path)
                validation = validate_manifest(
                    manifest,
                    root,
                    max_artifact_bytes=max_artifact_bytes,
                    max_records=max_records,
                )
                expected_artifacts = {item["path"]: item for item in validation["artifacts"]}
                expected_paths = set(expected_artifacts)
                if catalog["manifest_sha256"] and catalog["manifest_sha256"] != manifest_sha:
                    errors.append(f"{ds}: manifest SHA256 mismatch")
                if catalog["provenance_json"]:
                    try:
                        if json.loads(catalog["provenance_json"]) != validation["provenance"]:
                            errors.append(f"{ds}: stored manifest provenance mismatch")
                    except (TypeError, json.JSONDecodeError):
                        errors.append(f"{ds}: stored manifest provenance is invalid JSON")
                if catalog["version"] != validation["version"]:
                    errors.append(f"{ds}: catalog version mismatch")
                if int(catalog["artifact_count"] or -1) != validation["artifact_count"]:
                    errors.append(f"{ds}: catalog artifact count mismatch")
                if int(catalog["record_count"] or -1) != validation["record_count"]:
                    errors.append(f"{ds}: catalog record count mismatch")
            except (OSError, DatasetPipelineError) as exc:
                errors.append(f"{ds}: manifest verification failed: {exc}")
                continue

            artifacts = conn.execute(
                "SELECT * FROM artifacts WHERE dataset_id=? ORDER BY artifact_path",
                (ds,),
            ).fetchall()
            stored_paths = {row["artifact_path"] for row in artifacts}
            if stored_paths != expected_paths:
                errors.append(f"{ds}: stored artifact identity set mismatch")

            for artifact in artifacts:
                checked_artifacts += 1
                rel = artifact["artifact_path"]
                try:
                    safe_path = _safe_relative_file(root, rel)
                    expected_artifact = expected_artifacts.get(rel)
                    if expected_artifact is None:
                        errors.append(f"{ds}/{rel}: artifact is not present in manifest")
                    else:
                        expected_provenance = _source_provenance(
                            validation["provenance"],
                            expected_artifact.get("provenance", {}),
                        )
                        try:
                            stored_provenance = json.loads(artifact["provenance_json"] or "{}")
                        except (TypeError, json.JSONDecodeError):
                            stored_provenance = None
                        if stored_provenance != expected_provenance:
                            errors.append(f"{ds}/{rel}: stored provenance mismatch")
                    count, digest = _scan_artifact(
                        rel,
                        safe_path,
                        artifact["format"],
                        int(artifact["record_count"]),
                        artifact["sha256"],
                        max_artifact_bytes=max_artifact_bytes,
                        max_records=max_records,
                        row_consumer=lambda rid, payload, payload_hash: _compare_record(
                            conn,
                            ds,
                            rel,
                            rid,
                            payload,
                            payload_hash,
                            errors,
                        ),
                    )
                    if digest != artifact["sha256"]:
                        errors.append(f"{ds}/{rel}: artifact SHA256 mismatch")
                    if count != int(artifact["record_count"]):
                        errors.append(f"{ds}/{rel}: artifact record count mismatch")
                except (OSError, DatasetPipelineError) as exc:
                    errors.append(f"{ds}/{rel}: source verification failed: {exc}")
                    continue

                db_count = conn.execute(
                    "SELECT count(*) FROM records WHERE dataset_id=? AND artifact_path=?",
                    (ds, rel),
                ).fetchone()[0]
                if db_count != int(artifact["record_count"]):
                    errors.append(
                        f"{ds}/{rel}: stored record count {db_count} != artifact count {artifact['record_count']}"
                    )
                checked_records += count

    return {
        "ok": not errors,
        "dataset_count": checked_datasets,
        "artifact_count": checked_artifacts,
        "record_count": checked_records,
        "errors": errors,
    }


def ingest_and_verify(
    manifest_path: str | Path,
    root: str | Path,
    db_path: str | Path,
) -> dict[str, Any]:
    """Backward-compatible convenience wrapper with a post-ingest integrity gate."""
    result = ingest_manifest(Path(manifest_path), Path(root), Path(db_path))
    verification = verify_store(
        Path(db_path),
        Path(root),
        dataset_id=result["dataset_id"],
    )
    if not verification["ok"]:
        raise DatasetIntegrityError("; ".join(verification["errors"]))
    return result


def verify_ingested_dataset(
    db_path: str | Path,
    root: str | Path,
    dataset_id: str,
) -> dict[str, Any]:
    return verify_store(Path(db_path), Path(root), dataset_id=dataset_id)


def _main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate, ingest and verify an AI-CYBER dataset manifest"
    )
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--root", required=True)
    parser.add_argument("--db", required=True)
    parser.add_argument(
        "--max-artifact-bytes",
        type=int,
        default=DEFAULT_MAX_ARTIFACT_BYTES,
    )
    parser.add_argument(
        "--max-records",
        type=int,
        default=DEFAULT_MAX_RECORDS,
    )
    args = parser.parse_args()
    if args.max_artifact_bytes <= 0 or args.max_records <= 0:
        parser.error("safety limits must be positive")
    try:
        result = ingest_and_verify(args.manifest, args.root, args.db)
    except (OSError, DatasetPipelineError, sqlite3.Error) as exc:
        print(
            json.dumps({"ok": False, "error": str(exc)}, indent=2),
            file=sys.stderr,
        )
        return 2
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
