"""Canonical 13-family security knowledge structure.

This layer normalizes heterogeneous cyber records into deterministic families,
typed identifiers, severity metadata, and explicit evidence references. It does
not resolve cross-record graphs; that belongs to the relationship layer (#4).
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

SCHEMA_VERSION = "security_families.v1"

FAMILIES = (
    "vulnerability",
    "weakness",
    "threat",
    "attack",
    "exploit",
    "malware",
    "identity_access",
    "network_security",
    "application_security",
    "cloud_security",
    "detection_monitoring",
    "incident_response",
    "defense_remediation",
)

FAMILY_DESCRIPTIONS = {
    "vulnerability": "Specific security flaws and affected components.",
    "weakness": "General weakness classes such as CWE concepts.",
    "threat": "Threat actors, campaigns, objectives, and threat intelligence.",
    "attack": "Attack techniques, tactics, procedures, and behaviors.",
    "exploit": "Exploit artifacts, exploitability evidence, and proof references.",
    "malware": "Malware families, capabilities, and malicious artifacts.",
    "identity_access": "Identity, authentication, authorization, and access control.",
    "network_security": "Network protocols, services, segmentation, and network controls.",
    "application_security": "Application and software security concepts outside a single CVE.",
    "cloud_security": "Cloud, container, orchestration, and hosted-service security.",
    "detection_monitoring": "Detection logic, telemetry, indicators, and monitoring evidence.",
    "incident_response": "Incident handling, investigation, containment, and recovery.",
    "defense_remediation": "Mitigations, patches, hardening, and defensive guidance.",
}

_IDENTIFIER_PATTERNS = {
    "cve": re.compile(r"^CVE-\d{4}-\d{4,}$", re.I),
    "cwe": re.compile(r"^CWE-\d+$", re.I),
    "capec": re.compile(r"^CAPEC-\d+$", re.I),
    "attack": re.compile(r"^(?:T|TA)\d{4}(?:\.\d{3})?$", re.I),
}


class SecurityFamilyError(ValueError):
    """Raised when a security-family record violates the canonical contract."""


def _text(value: Any, field: str, *, required: bool = False, max_len: int = 2048) -> str | None:
    if value is None:
        if required:
            raise SecurityFamilyError(f"{field} is required")
        return None
    if not isinstance(value, str):
        raise SecurityFamilyError(f"{field} must be a string")
    value = value.strip()
    if required and not value:
        raise SecurityFamilyError(f"{field} is required")
    if len(value) > max_len:
        raise SecurityFamilyError(f"{field} exceeds maximum length {max_len}")
    return value or None


def _identifier(value: Any, field: str, pattern: re.Pattern[str]) -> str | None:
    value = _text(value, field)
    if value is None:
        return None
    if not pattern.fullmatch(value):
        raise SecurityFamilyError(f"{field} has invalid format: {value}")
    return value.upper()


def _finite_number(value: Any, field: str, minimum: float, maximum: float) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise SecurityFamilyError(f"{field} must be numeric")
    value = float(value)
    if value != value or value in (float("inf"), float("-inf")):
        raise SecurityFamilyError(f"{field} must be finite")
    if not minimum <= value <= maximum:
        raise SecurityFamilyError(f"{field} must be between {minimum} and {maximum}")
    return value


def _string_list(value: Any, field: str, *, max_items: int = 64) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, (list, tuple)):
        raise SecurityFamilyError(f"{field} must be a list")
    if len(value) > max_items:
        raise SecurityFamilyError(f"{field} exceeds maximum item count {max_items}")
    result = []
    for item in value:
        text = _text(item, field, required=True, max_len=512)
        result.append(text)
    if len(set(result)) != len(result):
        raise SecurityFamilyError(f"{field} contains duplicates")
    return tuple(result)


def _canonical_json(value: Mapping[str, Any]) -> str:
    return json.dumps(dict(value), ensure_ascii=False, sort_keys=True, separators=(",", ":"))


@dataclass(frozen=True)
class SecurityKnowledgeRecord:
    record_id: str
    family: str
    title: str
    description: str | None = None
    cve_id: str | None = None
    cwe_ids: tuple[str, ...] = ()
    capec_ids: tuple[str, ...] = ()
    attack_ids: tuple[str, ...] = ()
    cvss_score: float | None = None
    cvss_vector: str | None = None
    severity: str | None = None
    evidence_refs: tuple[str, ...] = ()
    related_record_ids: tuple[str, ...] = ()
    source_dataset: str | None = None
    source_artifact: str | None = None
    source_version: str | None = None

    def __post_init__(self) -> None:
        rid = _text(self.record_id, "record_id", required=True, max_len=256)
        family = _text(self.family, "family", required=True, max_len=64)
        title = _text(self.title, "title", required=True, max_len=512)
        if family not in FAMILIES:
            raise SecurityFamilyError(f"unsupported family: {family}")
        object.__setattr__(self, "record_id", rid)
        object.__setattr__(self, "family", family)
        object.__setattr__(self, "title", title)
        object.__setattr__(self, "description", _text(self.description, "description", max_len=20000))
        object.__setattr__(self, "cve_id", _identifier(self.cve_id, "cve_id", _IDENTIFIER_PATTERNS["cve"]))
        cwe_ids = tuple(_identifier(x, "cwe_id", _IDENTIFIER_PATTERNS["cwe"]) for x in self.cwe_ids)
        capec_ids = tuple(_identifier(x, "capec_id", _IDENTIFIER_PATTERNS["capec"]) for x in self.capec_ids)
        attack_ids = tuple(_identifier(x, "attack_id", _IDENTIFIER_PATTERNS["attack"]) for x in self.attack_ids)
        for field, values in (("cwe_ids", cwe_ids), ("capec_ids", capec_ids), ("attack_ids", attack_ids)):
            if len(set(values)) != len(values):
                raise SecurityFamilyError(f"{field} contains duplicates")
        object.__setattr__(self, "cwe_ids", cwe_ids)
        object.__setattr__(self, "capec_ids", capec_ids)
        object.__setattr__(self, "attack_ids", attack_ids)
        object.__setattr__(self, "cvss_score", _finite_number(self.cvss_score, "cvss_score", 0.0, 10.0))
        object.__setattr__(self, "cvss_vector", _text(self.cvss_vector, "cvss_vector", max_len=1024))
        object.__setattr__(self, "severity", _text(self.severity, "severity", max_len=32))
        object.__setattr__(self, "evidence_refs", _string_list(self.evidence_refs, "evidence_refs"))
        object.__setattr__(self, "related_record_ids", _string_list(self.related_record_ids, "related_record_ids"))
        object.__setattr__(self, "source_dataset", _text(self.source_dataset, "source_dataset", max_len=256))
        object.__setattr__(self, "source_artifact", _text(self.source_artifact, "source_artifact", max_len=1024))
        object.__setattr__(self, "source_version", _text(self.source_version, "source_version", max_len=256))

    @property
    def canonical_payload(self) -> dict[str, Any]:
        return {
            "record_id": self.record_id,
            "family": self.family,
            "title": self.title,
            "description": self.description,
            "cve_id": self.cve_id,
            "cwe_ids": list(self.cwe_ids),
            "capec_ids": list(self.capec_ids),
            "attack_ids": list(self.attack_ids),
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "severity": self.severity,
            "evidence_refs": list(self.evidence_refs),
            "related_record_ids": list(self.related_record_ids),
            "source_dataset": self.source_dataset,
            "source_artifact": self.source_artifact,
            "source_version": self.source_version,
        }

    @property
    def content_hash(self) -> str:
        return hashlib.sha256(
            _canonical_json(self.canonical_payload).encode("utf-8")
        ).hexdigest()


def normalize_record(payload: Mapping[str, Any], *, default_family: str | None = None) -> SecurityKnowledgeRecord:
    if not isinstance(payload, Mapping):
        raise SecurityFamilyError("security record must be an object")
    family = payload.get("family") or default_family
    if not isinstance(family, str):
        raise SecurityFamilyError("family is required")
    return SecurityKnowledgeRecord(
        record_id=payload.get("record_id"),
        family=family.strip().lower(),
        title=payload.get("title"),
        description=payload.get("description"),
        cve_id=payload.get("cve_id") or payload.get("cve"),
        cwe_ids=payload.get("cwe_ids") or ([payload["cwe"]] if payload.get("cwe") else []),
        capec_ids=payload.get("capec_ids") or ([payload["capec"]] if payload.get("capec") else []),
        attack_ids=payload.get("attack_ids") or payload.get("mitre_attack_ids") or [],
        cvss_score=payload.get("cvss_score") if payload.get("cvss_score") is not None else payload.get("cvss"),
        cvss_vector=payload.get("cvss_vector"),
        severity=payload.get("severity"),
        evidence_refs=payload.get("evidence_refs") or [],
        related_record_ids=payload.get("related_record_ids") or [],
        source_dataset=payload.get("source_dataset") or payload.get("dataset_id"),
        source_artifact=payload.get("source_artifact") or payload.get("artifact_path"),
        source_version=payload.get("source_version") or payload.get("version"),
    )


class SecurityFamilyStore:
    """SQLite catalog for canonical 13-family records.

    Relationship targets are retained as explicit IDs, but graph resolution is
    deliberately deferred to the #4 Cross-Dataset Relationship Layer.
    """

    SCHEMA_VERSION = SCHEMA_VERSION

    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init()

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.db_path, timeout=10)
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA busy_timeout=5000")
        return db

    def _init(self) -> None:
        with self._connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS security_families(
                    family TEXT PRIMARY KEY,
                    description TEXT NOT NULL,
                    schema_version TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS security_records(
                    record_id TEXT PRIMARY KEY,
                    family TEXT NOT NULL REFERENCES security_families(family),
                    title TEXT NOT NULL,
                    description TEXT,
                    cve_id TEXT,
                    cwe_ids_json TEXT NOT NULL,
                    capec_ids_json TEXT NOT NULL,
                    attack_ids_json TEXT NOT NULL,
                    cvss_score REAL,
                    cvss_vector TEXT,
                    severity TEXT,
                    evidence_refs_json TEXT NOT NULL,
                    related_record_ids_json TEXT NOT NULL,
                    source_dataset TEXT,
                    source_artifact TEXT,
                    source_version TEXT,
                    content_hash TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_security_records_family
                    ON security_records(family);
                CREATE INDEX IF NOT EXISTS idx_security_records_cve
                    ON security_records(cve_id);
                """
            )
            db.executemany(
                "INSERT OR REPLACE INTO security_families(family,description,schema_version) VALUES (?,?,?)",
                [(f, FAMILY_DESCRIPTIONS[f], SCHEMA_VERSION) for f in FAMILIES],
            )
            db.execute(
                "CREATE TABLE IF NOT EXISTS security_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)"
            )
            db.execute(
                "INSERT OR REPLACE INTO security_meta(key,value) VALUES ('schema_version',?)",
                (SCHEMA_VERSION,),
            )

    def upsert(self, record: SecurityKnowledgeRecord) -> None:
        payload = record.canonical_payload
        with self._connect() as db:
            db.execute(
                """
                INSERT INTO security_records(
                    record_id,family,title,description,cve_id,cwe_ids_json,capec_ids_json,
                    attack_ids_json,cvss_score,cvss_vector,severity,evidence_refs_json,
                    related_record_ids_json,source_dataset,source_artifact,source_version,
                    content_hash,payload_json
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(record_id) DO UPDATE SET
                    family=excluded.family,title=excluded.title,description=excluded.description,
                    cve_id=excluded.cve_id,cwe_ids_json=excluded.cwe_ids_json,
                    capec_ids_json=excluded.capec_ids_json,attack_ids_json=excluded.attack_ids_json,
                    cvss_score=excluded.cvss_score,cvss_vector=excluded.cvss_vector,
                    severity=excluded.severity,evidence_refs_json=excluded.evidence_refs_json,
                    related_record_ids_json=excluded.related_record_ids_json,
                    source_dataset=excluded.source_dataset,source_artifact=excluded.source_artifact,
                    source_version=excluded.source_version,content_hash=excluded.content_hash,
                    payload_json=excluded.payload_json
                """,
                (
                    record.record_id, record.family, record.title, record.description,
                    record.cve_id, json.dumps(list(record.cwe_ids)),
                    json.dumps(list(record.capec_ids)), json.dumps(list(record.attack_ids)),
                    record.cvss_score, record.cvss_vector, record.severity,
                    json.dumps(list(record.evidence_refs)), json.dumps(list(record.related_record_ids)),
                    record.source_dataset, record.source_artifact, record.source_version,
                    record.content_hash, _canonical_json(payload),
                ),
            )

    def get(self, record_id: str) -> SecurityKnowledgeRecord | None:
        with self._connect() as db:
            row = db.execute(
                "SELECT payload_json FROM security_records WHERE record_id=?", (record_id,)
            ).fetchone()
        if not row:
            return None
        return normalize_record(json.loads(row[0]))

    def list_family(self, family: str, limit: int = 100) -> list[SecurityKnowledgeRecord]:
        if family not in FAMILIES:
            raise SecurityFamilyError(f"unsupported family: {family}")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise SecurityFamilyError("limit must be an integer between 1 and 1000")
        with self._connect() as db:
            rows = db.execute(
                "SELECT payload_json FROM security_records WHERE family=? ORDER BY record_id LIMIT ?",
                (family, limit),
            ).fetchall()
        return [normalize_record(json.loads(row[0])) for row in rows]

    def verify_integrity(self) -> dict[str, Any]:
        errors: list[str] = []
        with self._connect() as db:
            families = {r[0] for r in db.execute("SELECT family FROM security_families")}
            if families != set(FAMILIES):
                errors.append("family catalog mismatch")
            rows = db.execute(
                "SELECT record_id,payload_json,content_hash FROM security_records ORDER BY record_id"
            ).fetchall()
        for record_id, payload_json, stored_hash in rows:
            try:
                record = normalize_record(json.loads(payload_json))
                if record.record_id != record_id:
                    errors.append(f"{record_id}: record_id mismatch")
                if record.content_hash != stored_hash:
                    errors.append(f"{record_id}: content hash mismatch")
            except (json.JSONDecodeError, SecurityFamilyError) as exc:
                errors.append(f"{record_id}: invalid stored record: {exc}")
        return {
            "ok": not errors,
            "schema_version": SCHEMA_VERSION,
            "family_count": len(FAMILIES),
            "record_count": len(rows),
            "errors": errors,
        }

    def count(self, family: str | None = None) -> int:
        with self._connect() as db:
            if family is None:
                return db.execute("SELECT count(*) FROM security_records").fetchone()[0]
            if family not in FAMILIES:
                raise SecurityFamilyError(f"unsupported family: {family}")
            return db.execute(
                "SELECT count(*) FROM security_records WHERE family=?", (family,)
            ).fetchone()[0]


def family_catalog() -> list[dict[str, str]]:
    return [{"family": f, "description": FAMILY_DESCRIPTIONS[f]} for f in FAMILIES]
