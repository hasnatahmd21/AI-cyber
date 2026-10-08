from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from ai_cyber_os.relationships import (
    RELATION_TYPES,
    CrossDatasetRelationshipStore,
    GraphEdge,
    GraphNode,
    RelationshipError,
    node_id_for_identifier,
    node_id_for_record,
    node_id_for_severity,
)
from ai_cyber_os.security_families import SecurityFamilyStore, normalize_record


def _record(record_id: str, family: str, dataset: str, artifact: str, **overrides):
    value = {
        "record_id": record_id,
        "family": family,
        "title": f"{family} {record_id}",
        "description": "Deterministic relationship test record.",
        "cve_id": "CVE-2026-12345" if family == "vulnerability" else None,
        "cwe_ids": ["CWE-79"] if family in {"vulnerability", "weakness"} else [],
        "capec_ids": [],
        "attack_ids": [],
        "cvss_score": 8.8 if family == "vulnerability" else None,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" if family == "vulnerability" else None,
        "severity": "HIGH" if family == "vulnerability" else None,
        "evidence_refs": [f"{dataset}:{artifact}:evidence-1"],
        "related_record_ids": [],
        "source_dataset": dataset,
        "source_artifact": artifact,
        "source_version": "1.0",
    }
    value.update(overrides)
    return normalize_record(value)


def test_relationship_contract_is_typed_and_deterministic():
    assert "maps_to_weakness" in RELATION_TYPES
    assert "supported_by" in RELATION_TYPES

    a = node_id_for_record("nvd", "cve.jsonl", "CVE-2026-12345")
    b = node_id_for_record("nvd", "cve.jsonl", "CVE-2026-12345")
    assert a == b
    assert a.startswith("record:")

    assert node_id_for_identifier("cve", "cve-2026-12345") == "cve:CVE-2026-12345"
    assert node_id_for_severity("high") == "severity:HIGH"


def test_identifier_hubs_join_records_across_datasets(tmp_path: Path):
    store = CrossDatasetRelationshipStore(tmp_path / "graph.sqlite")
    vuln_a = _record("vuln-a", "vulnerability", "nvd", "cve.jsonl")
    vuln_b = _record("vuln-b", "vulnerability", "vendor-feed", "issues.json")
    store.ingest_records([vuln_a, vuln_b])

    cve_node = store.get_node("cve:CVE-2026-12345")
    assert cve_node is not None
    assert store.count(node_type="record") == 2
    assert store.count(node_type="identifier") == 2  # CVE + CWE
    assert len(store.get_edges(cve_node.node_id, direction="incoming")) == 2


def test_typed_links_connect_vulnerability_weakness_and_attack(tmp_path: Path):
    store = CrossDatasetRelationshipStore(tmp_path / "graph.sqlite")
    vuln = _record("vuln-a", "vulnerability", "nvd", "cve.jsonl")
    weakness = _record("weakness-a", "weakness", "cwe", "cwe.jsonl")
    attack = _record(
        "attack-a",
        "attack",
        "attack-db",
        "attack.json",
        cve_id=None,
        cwe_ids=[],
        attack_ids=["T1059"],
    )
    technique_source = _record(
        "detector-a",
        "detection_monitoring",
        "detections",
        "rules.jsonl",
        cve_id=None,
        cwe_ids=[],
        attack_ids=["T1059"],
    )

    store.ingest_records([vuln, weakness, attack, technique_source])
    result = store.resolve_typed_relationships()
    assert result["created"] >= 2

    vuln_node = node_id_for_record("nvd", "cve.jsonl", "vuln-a")
    weakness_node = node_id_for_record("cwe", "cwe.jsonl", "weakness-a")
    assert any(
        edge.relation == "maps_to_weakness" and edge.target_node_id == weakness_node
        for edge in store.get_edges(vuln_node, direction="outgoing")
    )

    attack_node = node_id_for_record("attack-db", "attack.json", "attack-a")
    assert any(
        edge.relation == "maps_to_attack" and edge.target_node_id == attack_node
        for edge in store.get_edges(
            node_id_for_record("detections", "rules.jsonl", "detector-a"),
            direction="outgoing",
        )
    )


def test_cross_dataset_same_cve_relation_is_materialized_once(tmp_path: Path):
    store = CrossDatasetRelationshipStore(tmp_path / "graph.sqlite")
    vuln_a = _record("vuln-a", "vulnerability", "nvd", "cve.jsonl")
    vuln_b = _record("vuln-b", "vulnerability", "vendor", "issues.json")
    store.ingest_records([vuln_a, vuln_b])

    result = store.resolve_typed_relationships()
    assert result["created"] == 1
    assert store.count(relation="same_vulnerability") == 1
    assert store.cross_dataset_edge_count() == 1

    store.resolve_typed_relationships()
    assert store.count(relation="same_vulnerability") == 1


def test_declared_related_links_resolve_and_preserve_orphans(tmp_path: Path):
    store = CrossDatasetRelationshipStore(tmp_path / "graph.sqlite")
    source = _record(
        "source",
        "vulnerability",
        "nvd",
        "source.jsonl",
        related_record_ids=["weakness-target", "missing-target"],
    )
    target = _record("weakness-target", "weakness", "cwe", "cwe.jsonl", cve_id=None, cvss_score=None)
    store.ingest_records([source, target])

    result = store.resolve_declared_links()
    assert result["resolved"] == 1
    assert result["orphan"] == 1
    assert len(store.list_orphans()) == 1
    assert store.count(relation="related_to") == 1

    source_node = node_id_for_record("nvd", "source.jsonl", "source")
    target_node = node_id_for_record("cwe", "cwe.jsonl", "weakness-target")
    assert any(
        edge.relation == "related_to" and edge.target_node_id == target_node
        for edge in store.get_edges(source_node, direction="outgoing")
    )


def test_scoped_declared_link_resolves_across_duplicate_record_ids(tmp_path: Path):
    store = CrossDatasetRelationshipStore(tmp_path / "graph.sqlite")
    first = _record("same-id", "weakness", "ds-a", "a.jsonl", cve_id=None, cwe_ids=[])
    second = _record("same-id", "weakness", "ds-b", "b.jsonl", cve_id=None, cwe_ids=[])
    source = _record(
        "source",
        "vulnerability",
        "nvd",
        "source.jsonl",
        related_record_ids=["ds-b/b.jsonl#same-id"],
    )
    store.ingest_records([first, second, source])

    result = store.resolve_declared_links()
    assert result["resolved"] == 1
    assert result["ambiguous"] == 0


def test_plain_declared_link_becomes_ambiguous_without_guessing(tmp_path: Path):
    store = CrossDatasetRelationshipStore(tmp_path / "graph.sqlite")
    first = _record("same-id", "weakness", "ds-a", "a.jsonl", cve_id=None, cwe_ids=[])
    second = _record("same-id", "weakness", "ds-b", "b.jsonl", cve_id=None, cwe_ids=[])
    source = _record(
        "source",
        "vulnerability",
        "nvd",
        "source.jsonl",
        related_record_ids=["same-id"],
    )
    store.ingest_records([first, second, source])

    result = store.resolve_declared_links()
    assert result["ambiguous"] == 1
    assert store.list_ambiguous()[0]["candidates"] == sorted(
        [
            node_id_for_record("ds-a", "a.jsonl", "same-id"),
            node_id_for_record("ds-b", "b.jsonl", "same-id"),
        ]
    )
    assert store.count(relation="related_to") == 0


def test_traversal_is_bounded_and_deterministic(tmp_path: Path):
    store = CrossDatasetRelationshipStore(tmp_path / "graph.sqlite")
    vuln = _record("vuln", "vulnerability", "nvd", "cve.jsonl")
    weakness = _record("weakness", "weakness", "cwe", "cwe.jsonl")
    store.ingest_records([vuln, weakness])
    store.resolve_typed_relationships()

    start = node_id_for_record("nvd", "cve.jsonl", "vuln")
    first = store.traverse(start, max_depth=3, limit=20)
    second = store.traverse(start, max_depth=3, limit=20)
    assert first == second
    assert first[0]["node_id"] == start
    assert len(first) <= 20
    assert all(item["depth"] <= 3 for item in first)

    records = store.connected_records(start, max_depth=3)
    assert {node.record_id for node in records} >= {"vuln", "weakness"}


def test_atomic_ingest_rolls_back_invalid_record(tmp_path: Path):
    store = CrossDatasetRelationshipStore(tmp_path / "graph.sqlite")
    good = _record("good", "vulnerability", "nvd", "a.jsonl")
    bad = _record("bad", "vulnerability", "nvd", "b.jsonl", related_record_ids=["bad"])
    with pytest.raises(RelationshipError):
        store.ingest_records([good, object()])  # type: ignore[arg-type]
    assert store.count() == 0

    # A valid batch is accepted afterward.
    store.ingest_records([good, bad])
    assert store.count(node_type="record") == 2


def test_foreign_key_endpoints_and_self_relationships_are_rejected(tmp_path: Path):
    store = CrossDatasetRelationshipStore(tmp_path / "graph.sqlite")
    node = GraphNode(
        node_id="record:manual",
        node_type="record",
        label="manual",
        dataset_id="ds",
        artifact_path="a.jsonl",
        record_id="r1",
        family="vulnerability",
        payload={"x": 1},
    )
    store.upsert_node(node)

    with pytest.raises(RelationshipError):
        store.add_edge(
            GraphEdge(
                source_node_id=node.node_id,
                target_node_id=node.node_id,
                relation="related_to",
            )
        )
    with pytest.raises(RelationshipError):
        store.add_edge(
            GraphEdge(
                source_node_id=node.node_id,
                target_node_id="record:missing",
                relation="related_to",
            )
        )


def test_sql_payload_is_data_not_executable_sql(tmp_path: Path):
    store = CrossDatasetRelationshipStore(tmp_path / "graph.sqlite")
    record = _record(
        "payload",
        "vulnerability",
        "nvd",
        "cve.jsonl",
        description='x"}; DROP TABLE relationship_nodes; --',
        evidence_refs=["evidence'}; DROP TABLE relationship_nodes; --"],
    )
    store.ingest_records([record])
    assert store.count(node_type="record") == 1
    assert store.count(node_type="evidence") == 1


def test_family_store_import_requires_integrity_and_provenance(tmp_path: Path):
    family_db = tmp_path / "families.sqlite"
    family_store = SecurityFamilyStore(family_db)
    good = _record("v1", "vulnerability", "nvd", "cve.jsonl")
    family_store.upsert(good)

    graph = CrossDatasetRelationshipStore(tmp_path / "graph.sqlite")
    result = graph.ingest_family_store(family_db)
    assert result["records"] == 1
    assert graph.count(node_type="record") == 1
    integrity = graph.verify_integrity()
    assert integrity["ok"] is True, integrity

    with sqlite3.connect(family_db) as db:
        db.execute(
            "UPDATE security_records SET content_hash=? WHERE record_id=?",
            ("0" * 64, good.record_id),
        )

    with pytest.raises(RelationshipError, match="hash mismatch"):
        CrossDatasetRelationshipStore(tmp_path / "graph2.sqlite").ingest_family_store(family_db)


def test_graph_tampering_is_detected(tmp_path: Path):
    store = CrossDatasetRelationshipStore(tmp_path / "graph.sqlite")
    record = _record("v1", "vulnerability", "nvd", "cve.jsonl")
    store.ingest_records([record])
    with sqlite3.connect(store.db_path) as db:
        db.execute(
            "UPDATE relationship_nodes SET label=? WHERE node_id=?",
            ("tampered", node_id_for_record("nvd", "cve.jsonl", "v1")),
        )
    result = store.verify_integrity()
    assert result["ok"] is False
    assert any("canonical node payload mismatch" in error for error in result["errors"])


def test_integrity_reports_pending_and_resolves_later(tmp_path: Path):
    store = CrossDatasetRelationshipStore(tmp_path / "graph.sqlite")
    source = _record(
        "source",
        "vulnerability",
        "nvd",
        "source.jsonl",
        related_record_ids=["target"],
    )
    store.ingest_records([source])
    result = store.verify_integrity()
    assert result["ok"] is True, result
    assert result["pending_declarations"] == 1

    target = _record("target", "weakness", "cwe", "cwe.jsonl", cve_id=None, cwe_ids=[])
    store.ingest_records([target])
    resolved = store.resolve_declared_links()
    assert resolved["resolved"] == 1
    assert store.verify_integrity()["ok"] is True
