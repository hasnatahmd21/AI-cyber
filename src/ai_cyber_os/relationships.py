"""Deterministic cross-dataset relationship graph for canonical security knowledge.

This layer resolves explicit relationships between canonical security-family records
and materializes typed graph edges without inventing facts. Identifiers, evidence
references, and severity labels are represented as first-class graph nodes so
records from different datasets can converge on shared knowledge anchors.

The layer is local-first SQLite and deliberately performs no network access,
LLM inference, command execution, or external verification.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

from .security_families import FAMILIES, SCHEMA_VERSION as FAMILY_SCHEMA_VERSION
from .security_families import SecurityFamilyError, SecurityKnowledgeRecord, normalize_record

SCHEMA_VERSION = "cross_dataset_relationships.v1"
NODE_TYPES = ("record", "identifier", "evidence", "severity")
RELATION_TYPES = (
    "identified_as",
    "maps_to_weakness",
    "maps_to_attack",
    "maps_to_attack_pattern",
    "references_vulnerability",
    "same_vulnerability",
    "same_entity",
    "has_severity",
    "supported_by",
    "related_to",
)
DECLARATION_STATUSES = ("pending", "resolved", "orphan", "ambiguous")
_IDENTIFIER_KINDS = ("cve", "cwe", "capec", "attack")
_IDENTIFIER_PREFIXES = {
    "cve": "cve:",
    "cwe": "cwe:",
    "capec": "capec:",
    "attack": "attack:",
}
MAX_TRAVERSE_DEPTH = 8
MAX_TRAVERSE_NODES = 5000
MAX_DIRECT_LINK_TARGETS = 16


class RelationshipError(ValueError):
    """Raised when a relationship-layer contract is violated."""


def _text(value: Any, field: str, *, required: bool = False, max_len: int = 4096) -> str | None:
    if value is None:
        if required:
            raise RelationshipError(f"{field} is required")
        return None
    if not isinstance(value, str):
        raise RelationshipError(f"{field} must be a string")
    value = value.strip()
    if required and not value:
        raise RelationshipError(f"{field} is required")
    if "\x00" in value:
        raise RelationshipError(f"{field} contains NUL byte")
    if len(value) > max_len:
        raise RelationshipError(f"{field} exceeds maximum length {max_len}")
    return value or None


def _choice(value: Any, field: str, allowed: tuple[str, ...]) -> str:
    value = _text(value, field, required=True, max_len=128)
    if value not in allowed:
        raise RelationshipError(f"unsupported {field}: {value}")
    return value


def _string_list(value: Any, field: str, *, max_items: int = 64) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, (list, tuple)):
        raise RelationshipError(f"{field} must be a list")
    if len(value) > max_items:
        raise RelationshipError(f"{field} exceeds maximum item count {max_items}")
    result: list[str] = []
    for item in value:
        text = _text(item, field, required=True, max_len=4096)
        assert text is not None
        result.append(text)
    if len(set(result)) != len(result):
        raise RelationshipError(f"{field} contains duplicates")
    return tuple(result)


def _canonical_json(value: Mapping[str, Any]) -> str:
    try:
        return json.dumps(
            dict(value),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise RelationshipError("payload contains non-JSON values") from exc


def _digest(payload_json: str) -> str:
    return hashlib.sha256(payload_json.encode("utf-8")).hexdigest()


def node_id_for_record(dataset_id: str, artifact_path: str, record_id: str) -> str:
    dataset_id = _text(dataset_id, "dataset_id", required=True, max_len=256)
    artifact_path = _text(artifact_path, "artifact_path", required=True, max_len=1024)
    record_id = _text(record_id, "record_id", required=True, max_len=256)
    assert dataset_id and artifact_path and record_id
    raw = "\x00".join((dataset_id, artifact_path, record_id)).encode("utf-8")
    return "record:" + hashlib.sha256(raw).hexdigest()


def node_id_for_identifier(identifier_type: str, identifier_value: str) -> str:
    identifier_type = _choice(identifier_type, "identifier_type", _IDENTIFIER_KINDS)
    identifier_value = _text(identifier_value, "identifier_value", required=True, max_len=256)
    assert identifier_value is not None
    return _IDENTIFIER_PREFIXES[identifier_type] + identifier_value.upper()


def node_id_for_evidence(reference: str) -> str:
    reference = _text(reference, "evidence_ref", required=True, max_len=4096)
    assert reference is not None
    return "evidence:" + hashlib.sha256(reference.encode("utf-8")).hexdigest()


def node_id_for_severity(severity: str) -> str:
    severity = _text(severity, "severity", required=True, max_len=64)
    assert severity is not None
    return "severity:" + severity.upper()


def _record_family(record: SecurityKnowledgeRecord) -> str:
    if record.family not in FAMILIES:
        raise RelationshipError(f"unsupported record family: {record.family}")
    return record.family


@dataclass(frozen=True)
class GraphNode:
    node_id: str
    node_type: str
    label: str
    dataset_id: str | None = None
    artifact_path: str | None = None
    record_id: str | None = None
    family: str | None = None
    identifier_type: str | None = None
    identifier_value: str | None = None
    payload: Mapping[str, Any] | None = None

    def __post_init__(self) -> None:
        node_id = _text(self.node_id, "node_id", required=True, max_len=512)
        node_type = _choice(self.node_type, "node_type", NODE_TYPES)
        label = _text(self.label, "label", required=True, max_len=4096)
        assert node_id and label
        object.__setattr__(self, "node_id", node_id)
        object.__setattr__(self, "node_type", node_type)
        object.__setattr__(self, "label", label)

        for field, max_len in (
            ("dataset_id", 256),
            ("artifact_path", 1024),
            ("record_id", 256),
            ("family", 64),
            ("identifier_type", 64),
            ("identifier_value", 256),
        ):
            value = _text(getattr(self, field), field, max_len=max_len)
            object.__setattr__(self, field, value)

        if self.family is not None and self.family not in FAMILIES:
            raise RelationshipError(f"unsupported family: {self.family}")

        if node_type == "record":
            if not all((self.dataset_id, self.artifact_path, self.record_id)):
                raise RelationshipError("record nodes require dataset_id, artifact_path and record_id")
        elif node_type == "identifier":
            if self.identifier_type not in _IDENTIFIER_KINDS or not self.identifier_value:
                raise RelationshipError("identifier nodes require a valid identifier type and value")
        elif node_type in {"evidence", "severity"}:
            if self.dataset_id or self.artifact_path or self.record_id:
                raise RelationshipError(f"{node_type} nodes cannot carry record provenance")

        payload = dict(self.payload or {})
        payload_json = _canonical_json(payload)
        object.__setattr__(self, "payload", payload)

    @property
    def canonical_payload(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "node_type": self.node_type,
            "label": self.label,
            "dataset_id": self.dataset_id,
            "artifact_path": self.artifact_path,
            "record_id": self.record_id,
            "family": self.family,
            "identifier_type": self.identifier_type,
            "identifier_value": self.identifier_value,
            "payload": dict(self.payload or {}),
        }

    @property
    def content_hash(self) -> str:
        payload_json = _canonical_json(self.canonical_payload)
        return _digest(payload_json)


@dataclass(frozen=True)
class GraphEdge:
    source_node_id: str
    target_node_id: str
    relation: str
    evidence_refs: tuple[str, ...] = ()
    source_dataset: str | None = None
    source_artifact: str | None = None

    def __post_init__(self) -> None:
        source = _text(self.source_node_id, "source_node_id", required=True, max_len=512)
        target = _text(self.target_node_id, "target_node_id", required=True, max_len=512)
        relation = _choice(self.relation, "relation", RELATION_TYPES)
        assert source and target
        if source == target:
            raise RelationshipError("self relationships are not allowed")
        object.__setattr__(self, "source_node_id", source)
        object.__setattr__(self, "target_node_id", target)
        object.__setattr__(self, "relation", relation)
        object.__setattr__(self, "evidence_refs", _string_list(self.evidence_refs, "evidence_refs"))
        object.__setattr__(self, "source_dataset", _text(self.source_dataset, "source_dataset", max_len=256))
        object.__setattr__(self, "source_artifact", _text(self.source_artifact, "source_artifact", max_len=1024))

    @property
    def canonical_payload(self) -> dict[str, Any]:
        return {
            "source_node_id": self.source_node_id,
            "target_node_id": self.target_node_id,
            "relation": self.relation,
            "evidence_refs": list(self.evidence_refs),
            "source_dataset": self.source_dataset,
            "source_artifact": self.source_artifact,
        }

    @property
    def edge_id(self) -> str:
        return "edge:" + _digest(_canonical_json(self.canonical_payload))


class CrossDatasetRelationshipStore:
    """SQLite-backed deterministic relationship graph."""

    SCHEMA_VERSION = SCHEMA_VERSION

    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init()

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.db_path, timeout=10)
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA busy_timeout=5000")
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        return db

    def _init(self) -> None:
        with self._connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS relationship_meta(
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS relationship_nodes(
                    node_id TEXT PRIMARY KEY,
                    node_type TEXT NOT NULL,
                    label TEXT NOT NULL,
                    dataset_id TEXT,
                    artifact_path TEXT,
                    record_id TEXT,
                    family TEXT,
                    identifier_type TEXT,
                    identifier_value TEXT,
                    payload_json TEXT NOT NULL,
                    content_hash TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_relationship_nodes_record
                    ON relationship_nodes(node_type, record_id);
                CREATE INDEX IF NOT EXISTS idx_relationship_nodes_family
                    ON relationship_nodes(family);
                CREATE INDEX IF NOT EXISTS idx_relationship_nodes_identifier
                    ON relationship_nodes(identifier_type, identifier_value);

                CREATE TABLE IF NOT EXISTS relationship_edges(
                    edge_id TEXT PRIMARY KEY,
                    source_node_id TEXT NOT NULL
                        REFERENCES relationship_nodes(node_id) ON DELETE CASCADE,
                    target_node_id TEXT NOT NULL
                        REFERENCES relationship_nodes(node_id) ON DELETE CASCADE,
                    relation TEXT NOT NULL,
                    evidence_refs_json TEXT NOT NULL,
                    source_dataset TEXT,
                    source_artifact TEXT,
                    content_hash TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_relationship_edges_source
                    ON relationship_edges(source_node_id);
                CREATE INDEX IF NOT EXISTS idx_relationship_edges_target
                    ON relationship_edges(target_node_id);
                CREATE INDEX IF NOT EXISTS idx_relationship_edges_relation
                    ON relationship_edges(relation);

                CREATE TABLE IF NOT EXISTS relationship_declarations(
                    declaration_id TEXT PRIMARY KEY,
                    source_node_id TEXT NOT NULL
                        REFERENCES relationship_nodes(node_id) ON DELETE CASCADE,
                    raw_target TEXT NOT NULL,
                    relation TEXT NOT NULL,
                    status TEXT NOT NULL,
                    target_node_id TEXT,
                    candidates_json TEXT NOT NULL,
                    content_hash TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_relationship_declarations_source
                    ON relationship_declarations(source_node_id);
                CREATE INDEX IF NOT EXISTS idx_relationship_declarations_status
                    ON relationship_declarations(status);
                """
            )
            db.execute(
                "INSERT OR REPLACE INTO relationship_meta(key,value) VALUES('schema_version',?)",
                (SCHEMA_VERSION,),
            )
            db.execute(
                "INSERT OR REPLACE INTO relationship_meta(key,value) VALUES('family_schema_version',?)",
                (FAMILY_SCHEMA_VERSION,),
            )

    @staticmethod
    def _node_from_row(row: sqlite3.Row) -> GraphNode:
        return GraphNode(
            node_id=row["node_id"],
            node_type=row["node_type"],
            label=row["label"],
            dataset_id=row["dataset_id"],
            artifact_path=row["artifact_path"],
            record_id=row["record_id"],
            family=row["family"],
            identifier_type=row["identifier_type"],
            identifier_value=row["identifier_value"],
            payload=json.loads(row["payload_json"]),
        )

    @staticmethod
    def _edge_from_row(row: sqlite3.Row) -> GraphEdge:
        return GraphEdge(
            source_node_id=row["source_node_id"],
            target_node_id=row["target_node_id"],
            relation=row["relation"],
            evidence_refs=tuple(json.loads(row["evidence_refs_json"])),
            source_dataset=row["source_dataset"],
            source_artifact=row["source_artifact"],
        )

    def _upsert_node_conn(self, db: sqlite3.Connection, node: GraphNode) -> None:
        payload_json = _canonical_json(node.canonical_payload)
        db.execute(
            """
            INSERT INTO relationship_nodes(
                node_id,node_type,label,dataset_id,artifact_path,record_id,family,
                identifier_type,identifier_value,payload_json,content_hash
            )
            VALUES(?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(node_id) DO UPDATE SET
                node_type=excluded.node_type,
                label=excluded.label,
                dataset_id=excluded.dataset_id,
                artifact_path=excluded.artifact_path,
                record_id=excluded.record_id,
                family=excluded.family,
                identifier_type=excluded.identifier_type,
                identifier_value=excluded.identifier_value,
                payload_json=excluded.payload_json,
                content_hash=excluded.content_hash
            """,
            (
                node.node_id,
                node.node_type,
                node.label,
                node.dataset_id,
                node.artifact_path,
                node.record_id,
                node.family,
                node.identifier_type,
                node.identifier_value,
                payload_json,
                node.content_hash,
            ),
        )

    def _add_edge_conn(self, db: sqlite3.Connection, edge: GraphEdge) -> None:
        source_exists = db.execute(
            "SELECT 1 FROM relationship_nodes WHERE node_id=?",
            (edge.source_node_id,),
        ).fetchone()
        target_exists = db.execute(
            "SELECT 1 FROM relationship_nodes WHERE node_id=?",
            (edge.target_node_id,),
        ).fetchone()
        if source_exists is None or target_exists is None:
            raise RelationshipError("relationship endpoints must exist before the edge is added")
        payload_json = _canonical_json(edge.canonical_payload)
        db.execute(
            """
            INSERT INTO relationship_edges(
                edge_id,source_node_id,target_node_id,relation,evidence_refs_json,
                source_dataset,source_artifact,content_hash
            )
            VALUES(?,?,?,?,?,?,?,?)
            ON CONFLICT(edge_id) DO UPDATE SET
                source_node_id=excluded.source_node_id,
                target_node_id=excluded.target_node_id,
                relation=excluded.relation,
                evidence_refs_json=excluded.evidence_refs_json,
                source_dataset=excluded.source_dataset,
                source_artifact=excluded.source_artifact,
                content_hash=excluded.content_hash
            """,
            (
                edge.edge_id,
                edge.source_node_id,
                edge.target_node_id,
                edge.relation,
                json.dumps(list(edge.evidence_refs), ensure_ascii=False, sort_keys=True),
                edge.source_dataset,
                edge.source_artifact,
                _digest(payload_json),
            ),
        )

    def upsert_node(self, node: GraphNode) -> None:
        with self._connect() as db:
            self._upsert_node_conn(db, node)

    def add_edge(self, edge: GraphEdge) -> None:
        with self._connect() as db:
            self._add_edge_conn(db, edge)

    def get_node(self, node_id: str) -> GraphNode | None:
        node_id = _text(node_id, "node_id", required=True, max_len=512)
        assert node_id is not None
        with self._connect() as db:
            db.row_factory = sqlite3.Row
            row = db.execute(
                "SELECT * FROM relationship_nodes WHERE node_id=?",
                (node_id,),
            ).fetchone()
        return self._node_from_row(row) if row else None

    def get_edges(
        self,
        node_id: str,
        *,
        relation: str | None = None,
        direction: str = "both",
    ) -> list[GraphEdge]:
        node_id = _text(node_id, "node_id", required=True, max_len=512)
        assert node_id is not None
        direction = _choice(direction, "direction", ("outgoing", "incoming", "both"))
        if relation is not None:
            relation = _choice(relation, "relation", RELATION_TYPES)
        with self._connect() as db:
            db.row_factory = sqlite3.Row
            if direction == "outgoing":
                sql = "SELECT * FROM relationship_edges WHERE source_node_id=?"
                params: tuple[Any, ...] = (node_id,)
            elif direction == "incoming":
                sql = "SELECT * FROM relationship_edges WHERE target_node_id=?"
                params = (node_id,)
            else:
                sql = (
                    "SELECT * FROM relationship_edges "
                    "WHERE source_node_id=? OR target_node_id=?"
                )
                params = (node_id, node_id)
            if relation is not None:
                sql += " AND relation=?"
                params += (relation,)
            sql += " ORDER BY edge_id"
            return [self._edge_from_row(row) for row in db.execute(sql, params).fetchall()]

    def _record_node(self, record: SecurityKnowledgeRecord) -> GraphNode:
        dataset_id = _text(record.source_dataset, "record.source_dataset", required=True, max_len=256)
        artifact_path = _text(record.source_artifact, "record.source_artifact", required=True, max_len=1024)
        assert dataset_id and artifact_path
        return GraphNode(
            node_id=node_id_for_record(dataset_id, artifact_path, record.record_id),
            node_type="record",
            label=record.title,
            dataset_id=dataset_id,
            artifact_path=artifact_path,
            record_id=record.record_id,
            family=_record_family(record),
            payload=record.canonical_payload,
        )

    @staticmethod
    def _identifier_pairs(record: SecurityKnowledgeRecord) -> list[tuple[str, str]]:
        pairs: list[tuple[str, str]] = []
        if record.cve_id:
            pairs.append(("cve", record.cve_id))
        pairs.extend(("cwe", value) for value in record.cwe_ids)
        pairs.extend(("capec", value) for value in record.capec_ids)
        pairs.extend(("attack", value) for value in record.attack_ids)
        return pairs

    def _materialize_record_anchors_conn(
        self,
        db: sqlite3.Connection,
        record: SecurityKnowledgeRecord,
        record_node: GraphNode,
    ) -> None:
        for identifier_type, identifier_value in self._identifier_pairs(record):
            identifier_id = node_id_for_identifier(identifier_type, identifier_value)
            identifier_node = GraphNode(
                node_id=identifier_id,
                node_type="identifier",
                label=identifier_value.upper(),
                identifier_type=identifier_type,
                identifier_value=identifier_value.upper(),
                payload={
                    "identifier_type": identifier_type,
                    "identifier_value": identifier_value.upper(),
                },
            )
            self._upsert_node_conn(db, identifier_node)
            self._add_edge_conn(
                db,
                GraphEdge(
                    source_node_id=record_node.node_id,
                    target_node_id=identifier_node.node_id,
                    relation="identified_as",
                    source_dataset=record_node.dataset_id,
                    source_artifact=record_node.artifact_path,
                ),
            )

        for evidence_ref in record.evidence_refs:
            evidence_id = node_id_for_evidence(evidence_ref)
            evidence_node = GraphNode(
                node_id=evidence_id,
                node_type="evidence",
                label=evidence_ref,
                payload={"reference": evidence_ref},
            )
            self._upsert_node_conn(db, evidence_node)
            self._add_edge_conn(
                db,
                GraphEdge(
                    source_node_id=record_node.node_id,
                    target_node_id=evidence_node.node_id,
                    relation="supported_by",
                    evidence_refs=(evidence_ref,),
                    source_dataset=record_node.dataset_id,
                    source_artifact=record_node.artifact_path,
                ),
            )

        if record.severity:
            severity_id = node_id_for_severity(record.severity)
            severity_node = GraphNode(
                node_id=severity_id,
                node_type="severity",
                label=record.severity.upper(),
                payload={"severity": record.severity.upper()},
            )
            self._upsert_node_conn(db, severity_node)
            self._add_edge_conn(
                db,
                GraphEdge(
                    source_node_id=record_node.node_id,
                    target_node_id=severity_node.node_id,
                    relation="has_severity",
                    source_dataset=record_node.dataset_id,
                    source_artifact=record_node.artifact_path,
                ),
            )

        for raw_target in record.related_record_ids:
            relation = "related_to"
            declaration_payload = {
                "source_node_id": record_node.node_id,
                "raw_target": raw_target,
                "relation": relation,
            }
            declaration_id = "decl:" + _digest(_canonical_json(declaration_payload))
            declaration_hash = _digest(_canonical_json(declaration_payload))
            db.execute(
                """
                INSERT INTO relationship_declarations(
                    declaration_id,source_node_id,raw_target,relation,status,
                    target_node_id,candidates_json,content_hash
                )
                VALUES(?,?,?,?,?,?,?,?)
                ON CONFLICT(declaration_id) DO UPDATE SET
                    source_node_id=excluded.source_node_id,
                    raw_target=excluded.raw_target,
                    relation=excluded.relation,
                    status=excluded.status,
                    target_node_id=excluded.target_node_id,
                    candidates_json=excluded.candidates_json,
                    content_hash=excluded.content_hash
                """,
                (
                    declaration_id,
                    record_node.node_id,
                    raw_target,
                    relation,
                    "pending",
                    None,
                    "[]",
                    declaration_hash,
                ),
            )

    def ingest_records(self, records: Iterable[SecurityKnowledgeRecord]) -> dict[str, int]:
        """Atomically ingest canonical records and materialize explicit graph anchors."""
        normalized = list(records)
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                for record in normalized:
                    if not isinstance(record, SecurityKnowledgeRecord):
                        raise RelationshipError("ingest_records accepts SecurityKnowledgeRecord objects")
                    record_node = self._record_node(record)
                    self._upsert_node_conn(db, record_node)
                    self._materialize_record_anchors_conn(db, record, record_node)
                db.commit()
            except Exception:
                db.rollback()
                raise
        return {
            "records": len(normalized),
            "identifiers": self.count(node_type="identifier"),
            "evidence": self.count(node_type="evidence"),
            "severities": self.count(node_type="severity"),
        }

    def ingest_family_store(self, family_store_db: str | Path) -> dict[str, int]:
        """Import all canonical security-family records from a #3 SQLite store."""
        family_store_db = Path(family_store_db)
        if not family_store_db.is_file():
            raise FileNotFoundError(family_store_db)

        records: list[SecurityKnowledgeRecord] = []
        with sqlite3.connect(family_store_db) as db:
            columns = {
                row[1]
                for row in db.execute("PRAGMA table_info(security_records)").fetchall()
            }
            required_columns = {"record_id", "payload_json", "content_hash"}
            if not required_columns.issubset(columns):
                raise RelationshipError("family store does not match the #3 security record contract")
            rows = db.execute(
                "SELECT record_id,payload_json,content_hash FROM security_records ORDER BY record_id"
            ).fetchall()

        for record_id, payload_json, stored_hash in rows:
            try:
                payload = json.loads(payload_json)
                record = normalize_record(payload)
            except (json.JSONDecodeError, SecurityFamilyError) as exc:
                raise RelationshipError(
                    f"invalid canonical security record {record_id}: {exc}"
                ) from exc
            if record.content_hash != stored_hash:
                raise RelationshipError(f"security family store hash mismatch for {record_id}")
            records.append(record)

        return self.ingest_records(records)

    @staticmethod
    def _parse_scoped_record_ref(raw_target: str) -> tuple[str, str, str] | None:
        if raw_target.count("#") != 1:
            return None
        scope, record_id = raw_target.split("#", 1)
        parts = scope.split("/", 1)
        if len(parts) != 2 or not parts[0] or not parts[1] or not record_id:
            return None
        return parts[0], parts[1], record_id

    def resolve_declared_links(self) -> dict[str, int]:
        """Resolve #3 related_record_ids against unique record identity.

        Plain record IDs resolve only when globally unique. A scoped reference
        uses the canonical \`dataset_id/artifact_path#record_id\` form.
        Ambiguous or missing targets are retained as explicit states; no guessed
        edge is created.
        """
        counts = {"resolved": 0, "orphan": 0, "ambiguous": 0, "pending": 0}
        with self._connect() as db:
            db.row_factory = sqlite3.Row
            declarations = db.execute(
                "SELECT * FROM relationship_declarations ORDER BY declaration_id"
            ).fetchall()

            for declaration in declarations:
                raw = declaration["raw_target"]
                candidates: list[str]
                scoped = self._parse_scoped_record_ref(raw)
                if scoped:
                    dataset_id, artifact_path, record_id = scoped
                    rows = db.execute(
                        """
                        SELECT node_id
                        FROM relationship_nodes
                        WHERE node_type='record'
                          AND dataset_id=?
                          AND artifact_path=?
                          AND record_id=?
                        ORDER BY node_id
                        """,
                        (dataset_id, artifact_path, record_id),
                    ).fetchall()
                    candidates = [row[0] for row in rows]
                else:
                    rows = db.execute(
                        """
                        SELECT node_id
                        FROM relationship_nodes
                        WHERE node_type='record' AND record_id=?
                        ORDER BY node_id
                        """,
                        (raw,),
                    ).fetchall()
                    candidates = [row[0] for row in rows]

                if len(candidates) == 1:
                    status = "resolved"
                    target = candidates[0]
                elif not candidates:
                    status = "orphan"
                    target = None
                else:
                    status = "ambiguous"
                    target = None

                payload = {
                    "source_node_id": declaration["source_node_id"],
                    "raw_target": raw,
                    "relation": declaration["relation"],
                    "status": status,
                    "target_node_id": target,
                    "candidates": candidates,
                }
                content_hash = _digest(_canonical_json(payload))
                db.execute(
                    """
                    UPDATE relationship_declarations
                    SET status=?,target_node_id=?,candidates_json=?,content_hash=?
                    WHERE declaration_id=?
                    """,
                    (
                        status,
                        target,
                        json.dumps(candidates, ensure_ascii=False, sort_keys=True),
                        content_hash,
                        declaration["declaration_id"],
                    ),
                )
                if target:
                    self._add_edge_conn(
                        db,
                        GraphEdge(
                            source_node_id=declaration["source_node_id"],
                            target_node_id=target,
                            relation=declaration["relation"],
                        ),
                    )
                counts[status] += 1

            counts["pending"] = sum(
                1
                for row in db.execute(
                    "SELECT status FROM relationship_declarations"
                ).fetchall()
                if row[0] == "pending"
            )
        return counts

    def resolve_typed_relationships(self) -> dict[str, int]:
        """Resolve deterministic identifier-to-family relationships.

        A typed edge is added only when a declared identifier points to a
        candidate family set within a bounded deterministic fan-out. Ambiguous
        or overlarge target sets are left represented through the shared
        identifier node instead of guessed direct links.
        """
        created = 0
        skipped_ambiguous = 0
        with self._connect() as db:
            db.row_factory = sqlite3.Row
            records = db.execute(
                """
                SELECT node_id,family,dataset_id,artifact_path,payload_json
                FROM relationship_nodes
                WHERE node_type='record'
                ORDER BY node_id
                """
            ).fetchall()

            for row in records:
                record = normalize_record(json.loads(row["payload_json"])["payload"])
                source_id = row["node_id"]

                targets_by_relation: list[tuple[str, str, tuple[str, ...]]] = []

                if record.cwe_ids:
                    targets_by_relation.append(
                        ("maps_to_weakness", "cwe", record.cwe_ids)
                    )
                if record.capec_ids:
                    targets_by_relation.append(
                        ("maps_to_attack_pattern", "capec", record.capec_ids)
                    )
                if record.attack_ids:
                    targets_by_relation.append(
                        ("maps_to_attack", "attack", record.attack_ids)
                    )

                for relation, identifier_type, values in targets_by_relation:
                    for value in values:
                        identifier_id = node_id_for_identifier(identifier_type, value)
                        rows2 = db.execute(
                            """
                            SELECT n.node_id,n.family
                            FROM relationship_edges e
                            JOIN relationship_nodes n ON n.node_id=e.source_node_id
                            WHERE e.target_node_id=?
                              AND e.relation='identified_as'
                              AND n.node_type='record'
                            ORDER BY n.node_id
                            """,
                            (identifier_id,),
                        ).fetchall()
                        expected_family = {
                            "maps_to_weakness": "weakness",
                            "maps_to_attack_pattern": "attack",
                            "maps_to_attack": "attack",
                        }[relation]
                        candidates = [
                            item["node_id"]
                            for item in rows2
                            if item["family"] == expected_family and item["node_id"] != source_id
                        ]
                        if 0 < len(candidates) <= MAX_DIRECT_LINK_TARGETS:
                            for target_id in candidates:
                                edge = GraphEdge(
                                    source_node_id=source_id,
                                    target_node_id=target_id,
                                    relation=relation,
                                    source_dataset=row["dataset_id"],
                                    source_artifact=row["artifact_path"],
                                )
                                self._add_edge_conn(db, edge)
                                created += 1
                        elif len(candidates) > MAX_DIRECT_LINK_TARGETS:
                            skipped_ambiguous += 1

                if record.cve_id:
                    identifier_id = node_id_for_identifier("cve", record.cve_id)
                    rows2 = db.execute(
                        """
                        SELECT n.node_id,n.family
                        FROM relationship_edges e
                        JOIN relationship_nodes n ON n.node_id=e.source_node_id
                        WHERE e.target_node_id=?
                          AND e.relation='identified_as'
                          AND n.node_type='record'
                        ORDER BY n.node_id
                        """,
                        (identifier_id,),
                    ).fetchall()
                    candidates = [
                        item["node_id"]
                        for item in rows2
                        if item["family"] == "vulnerability" and item["node_id"] != source_id
                    ]
                    if record.family != "vulnerability" and len(candidates) == 1:
                        self._add_edge_conn(
                            db,
                            GraphEdge(
                                source_node_id=source_id,
                                target_node_id=candidates[0],
                                relation="references_vulnerability",
                                source_dataset=row["dataset_id"],
                                source_artifact=row["artifact_path"],
                            ),
                        )
                        created += 1
                    elif record.family == "vulnerability" and 0 < len(candidates) <= MAX_DIRECT_LINK_TARGETS:
                        # Symmetric identity relation uses a canonical endpoint
                        # order so duplicated dataset copies do not produce two
                        # independent edge identities.
                        for target_id in candidates:
                            left, right = sorted((source_id, target_id))
                            edge = GraphEdge(
                                source_node_id=left,
                                target_node_id=right,
                                relation="same_vulnerability",
                            )
                            before = self.edge_count(edge.edge_id)
                            self._add_edge_conn(db, edge)
                            if before == 0:
                                created += 1
                    elif len(candidates) > MAX_DIRECT_LINK_TARGETS:
                        skipped_ambiguous += 1

            db.execute(
                "INSERT OR REPLACE INTO relationship_meta(key,value) VALUES('last_typed_resolution_count',?)",
                (str(created),),
            )
            db.execute(
                "INSERT OR REPLACE INTO relationship_meta(key,value) VALUES('last_typed_resolution_ambiguous',?)",
                (str(skipped_ambiguous),),
            )
        return {"created": created, "skipped_ambiguous": skipped_ambiguous}

    def traverse(
        self,
        start_node_id: str,
        *,
        max_depth: int = 3,
        relation: str | None = None,
        direction: str = "both",
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Deterministically breadth-first traverse a connected knowledge graph."""
        start_node_id = _text(start_node_id, "start_node_id", required=True, max_len=512)
        assert start_node_id is not None
        if isinstance(max_depth, bool) or not isinstance(max_depth, int) or not 0 <= max_depth <= MAX_TRAVERSE_DEPTH:
            raise RelationshipError(
                f"max_depth must be an integer between 0 and {MAX_TRAVERSE_DEPTH}"
            )
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_TRAVERSE_NODES:
            raise RelationshipError(
                f"limit must be an integer between 1 and {MAX_TRAVERSE_NODES}"
            )
        direction = _choice(direction, "direction", ("outgoing", "incoming", "both"))
        if relation is not None:
            relation = _choice(relation, "relation", RELATION_TYPES)

        if self.get_node(start_node_id) is None:
            raise RelationshipError(f"unknown start node: {start_node_id}")

        results = [{
            "node_id": start_node_id,
            "depth": 0,
            "via_relation": None,
            "from_node_id": None,
            "edge_direction": None,
        }]
        visited = {start_node_id}
        queue: deque[tuple[str, int]] = deque([(start_node_id, 0)])

        while queue and len(results) < limit:
            current, depth = queue.popleft()
            if depth >= max_depth:
                continue
            edges = self.get_edges(current, relation=relation, direction=direction)
            for edge in edges:
                if direction == "outgoing":
                    neighbor = edge.target_node_id
                    edge_direction = "outgoing"
                elif direction == "incoming":
                    neighbor = edge.source_node_id
                    edge_direction = "incoming"
                else:
                    if edge.source_node_id == current:
                        neighbor = edge.target_node_id
                        edge_direction = "outgoing"
                    else:
                        neighbor = edge.source_node_id
                        edge_direction = "incoming"

                if neighbor in visited:
                    continue
                visited.add(neighbor)
                results.append(
                    {
                        "node_id": neighbor,
                        "depth": depth + 1,
                        "via_relation": edge.relation,
                        "from_node_id": current,
                        "edge_direction": edge_direction,
                    }
                )
                if len(results) >= limit:
                    break
                queue.append((neighbor, depth + 1))

        return results

    def connected_records(
        self,
        start_node_id: str,
        *,
        max_depth: int = 3,
        limit: int = 100,
    ) -> list[GraphNode]:
        traversal = self.traverse(
            start_node_id,
            max_depth=max_depth,
            direction="both",
            limit=limit * 4,
        )
        nodes: list[GraphNode] = []
        for item in traversal:
            node = self.get_node(item["node_id"])
            if node and node.node_type == "record":
                nodes.append(node)
                if len(nodes) >= limit:
                    break
        return nodes

    def list_orphans(self) -> list[dict[str, Any]]:
        with self._connect() as db:
            db.row_factory = sqlite3.Row
            rows = db.execute(
                """
                SELECT declaration_id,source_node_id,raw_target,relation,candidates_json
                FROM relationship_declarations
                WHERE status='orphan'
                ORDER BY declaration_id
                """
            ).fetchall()
        return [
            {
                "declaration_id": row["declaration_id"],
                "source_node_id": row["source_node_id"],
                "raw_target": row["raw_target"],
                "relation": row["relation"],
                "candidates": json.loads(row["candidates_json"]),
            }
            for row in rows
        ]

    def list_ambiguous(self) -> list[dict[str, Any]]:
        with self._connect() as db:
            db.row_factory = sqlite3.Row
            rows = db.execute(
                """
                SELECT declaration_id,source_node_id,raw_target,relation,candidates_json
                FROM relationship_declarations
                WHERE status='ambiguous'
                ORDER BY declaration_id
                """
            ).fetchall()
        return [
            {
                "declaration_id": row["declaration_id"],
                "source_node_id": row["source_node_id"],
                "raw_target": row["raw_target"],
                "relation": row["relation"],
                "candidates": json.loads(row["candidates_json"]),
            }
            for row in rows
        ]

    def edge_count(self, edge_id: str | None = None) -> int:
        with self._connect() as db:
            if edge_id is None:
                return db.execute("SELECT COUNT(*) FROM relationship_edges").fetchone()[0]
            return db.execute(
                "SELECT COUNT(*) FROM relationship_edges WHERE edge_id=?",
                (edge_id,),
            ).fetchone()[0]

    def count(self, *, node_type: str | None = None, relation: str | None = None) -> int:
        if node_type is not None:
            node_type = _choice(node_type, "node_type", NODE_TYPES)
        if relation is not None:
            relation = _choice(relation, "relation", RELATION_TYPES)
        with self._connect() as db:
            if node_type is not None:
                return db.execute(
                    "SELECT COUNT(*) FROM relationship_nodes WHERE node_type=?",
                    (node_type,),
                ).fetchone()[0]
            if relation is not None:
                return db.execute(
                    "SELECT COUNT(*) FROM relationship_edges WHERE relation=?",
                    (relation,),
                ).fetchone()[0]
            return db.execute("SELECT COUNT(*) FROM relationship_nodes").fetchone()[0]

    def cross_dataset_edge_count(self) -> int:
        with self._connect() as db:
            return db.execute(
                """
                SELECT COUNT(*)
                FROM relationship_edges e
                JOIN relationship_nodes s ON s.node_id=e.source_node_id
                JOIN relationship_nodes t ON t.node_id=e.target_node_id
                WHERE s.node_type='record'
                  AND t.node_type='record'
                  AND s.dataset_id IS NOT NULL
                  AND t.dataset_id IS NOT NULL
                  AND s.dataset_id <> t.dataset_id
                """
            ).fetchone()[0]

    def verify_integrity(self) -> dict[str, Any]:
        errors: list[str] = []
        with self._connect() as db:
            db.row_factory = sqlite3.Row
            node_rows = db.execute(
                "SELECT * FROM relationship_nodes ORDER BY node_id"
            ).fetchall()
            edge_rows = db.execute(
                "SELECT * FROM relationship_edges ORDER BY edge_id"
            ).fetchall()
            declaration_rows = db.execute(
                "SELECT * FROM relationship_declarations ORDER BY declaration_id"
            ).fetchall()
            schema = db.execute(
                "SELECT value FROM relationship_meta WHERE key='schema_version'"
            ).fetchone()
            family_schema = db.execute(
                "SELECT value FROM relationship_meta WHERE key='family_schema_version'"
            ).fetchone()

        if not schema or schema[0] != SCHEMA_VERSION:
            errors.append("schema version mismatch")
        if not family_schema or family_schema[0] != FAMILY_SCHEMA_VERSION:
            errors.append("family schema version mismatch")

        for row in node_rows:
            try:
                payload = json.loads(row["payload_json"])
                node = self._node_from_row(row)
                if node.canonical_payload != payload:
                    errors.append(f"{row['node_id']}: canonical node payload mismatch")
                if node.content_hash != row["content_hash"]:
                    errors.append(f"{row['node_id']}: content hash mismatch")
                if node.node_type == "record":
                    record_payload = payload.get("payload")
                    record = normalize_record(record_payload)
                    if record.content_hash != row["content_hash"]:
                        errors.append(f"{row['node_id']}: canonical security record hash mismatch")
            except (json.JSONDecodeError, RelationshipError, SecurityFamilyError, TypeError) as exc:
                errors.append(f"{row['node_id']}: invalid node: {exc}")

        node_ids = {row["node_id"] for row in node_rows}
        for row in edge_rows:
            try:
                if row["source_node_id"] not in node_ids or row["target_node_id"] not in node_ids:
                    errors.append(f"{row['edge_id']}: orphan edge endpoint")
                if row["source_node_id"] == row["target_node_id"]:
                    errors.append(f"{row['edge_id']}: self relationship")
                edge = self._edge_from_row(row)
                if edge.edge_id != row["edge_id"]:
                    errors.append(f"{row['edge_id']}: edge hash mismatch")
            except (json.JSONDecodeError, RelationshipError, TypeError) as exc:
                errors.append(f"{row['edge_id']}: invalid edge: {exc}")

        for row in declaration_rows:
            try:
                candidates = json.loads(row["candidates_json"])
                if not isinstance(candidates, list) or any(not isinstance(x, str) for x in candidates):
                    raise RelationshipError("candidates_json must be a string list")
                status = _choice(row["status"], "status", DECLARATION_STATUSES)
                target = row["target_node_id"]
                if status == "resolved":
                    if len(candidates) != 1 or target != candidates[0] or target not in node_ids:
                        errors.append(f"{row['declaration_id']}: invalid resolved declaration")
                elif status == "orphan":
                    if candidates or target is not None:
                        errors.append(f"{row['declaration_id']}: invalid orphan declaration")
                elif status == "ambiguous":
                    if len(candidates) < 2 or target is not None:
                        errors.append(f"{row['declaration_id']}: invalid ambiguous declaration")
                elif status == "pending":
                    if candidates or target is not None:
                        errors.append(f"{row['declaration_id']}: invalid pending declaration")

                payload = {
                    "source_node_id": row["source_node_id"],
                    "raw_target": row["raw_target"],
                    "relation": row["relation"],
                    "status": status,
                    "target_node_id": target,
                    "candidates": candidates,
                }
                if _digest(_canonical_json(payload)) != row["content_hash"]:
                    errors.append(f"{row['declaration_id']}: declaration hash mismatch")
            except (json.JSONDecodeError, RelationshipError, TypeError) as exc:
                errors.append(f"{row['declaration_id']}: invalid declaration: {exc}")

        orphan_declarations = sum(1 for row in declaration_rows if row["status"] == "orphan")
        ambiguous_declarations = sum(1 for row in declaration_rows if row["status"] == "ambiguous")
        pending_declarations = sum(1 for row in declaration_rows if row["status"] == "pending")

        return {
            "ok": not errors,
            "schema_version": SCHEMA_VERSION,
            "node_count": len(node_rows),
            "edge_count": len(edge_rows),
            "record_nodes": sum(row["node_type"] == "record" for row in node_rows),
            "identifier_nodes": sum(row["node_type"] == "identifier" for row in node_rows),
            "evidence_nodes": sum(row["node_type"] == "evidence" for row in node_rows),
            "severity_nodes": sum(row["node_type"] == "severity" for row in node_rows),
            "cross_dataset_edges": self.cross_dataset_edge_count(),
            "orphan_declarations": orphan_declarations,
            "ambiguous_declarations": ambiguous_declarations,
            "pending_declarations": pending_declarations,
            "errors": errors,
        }

    def health(self) -> dict[str, Any]:
        integrity = self.verify_integrity()
        return {
            "ok": integrity["ok"],
            "schema_version": SCHEMA_VERSION,
            "nodes": integrity["node_count"],
            "edges": integrity["edge_count"],
            "cross_dataset_edges": integrity["cross_dataset_edges"],
            "orphans": integrity["orphan_declarations"],
            "ambiguous": integrity["ambiguous_declarations"],
            "pending": integrity["pending_declarations"],
            "integrity": integrity,
        }
