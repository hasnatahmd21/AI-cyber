from __future__ import annotations
import sqlite3
from pathlib import Path
import pytest
from ai_cyber_os.backend import BackendIntegrationError, BackendLimits, KnowledgeRAGBackend
from ai_cyber_os.security_families import SecurityFamilyStore, normalize_record

def rec(record_id, family, dataset, artifact, **extra):
    p = {
        "record_id": record_id, "family": family, "title": f"{family}:{record_id}",
        "description": "Backend integration test evidence.",
        "cve_id": "CVE-2026-22222" if family == "vulnerability" else None,
        "cwe_ids": ["CWE-79"] if family in {"vulnerability", "weakness"} else [],
        "capec_ids": [], "attack_ids": [],
        "cvss_score": 8.8 if family == "vulnerability" else None,
        "cvss_vector": None, "severity": "HIGH" if family == "vulnerability" else None,
        "evidence_refs": [f"{dataset}:{artifact}:evidence"], "related_record_ids": [],
        "source_dataset": dataset, "source_artifact": artifact, "source_version": "1.0",
    }
    p.update(extra)
    return normalize_record(p)

def test_ingest_and_connected_query(tmp_path: Path):
    b = KnowledgeRAGBackend(tmp_path/"knowledge.sqlite", tmp_path/"relationships.sqlite")
    b.ingest_records([rec("v1","vulnerability","nvd","cve.jsonl"), rec("w1","weakness","cwe","cwe.jsonl")])
    packet = b.query("CVE-2026-22222", graph_depth=2)
    assert packet["lexical_hits"]
    assert any(h["record_id"] == "w1" and h["retrieval_source"] == "graph" for h in packet["hits"])
    assert any(x["via_relation"] == "maps_to_weakness" for x in packet["graph_relationships"])
    assert packet["citations"]

def test_ambiguous_declared_link_never_becomes_graph_evidence(tmp_path: Path):
    b = KnowledgeRAGBackend(tmp_path/"k.sqlite", tmp_path/"g.sqlite")
    b.ingest_records([
        rec("same","weakness","ds-a","a.jsonl",cve_id=None,cwe_ids=[]),
        rec("same","weakness","ds-b","b.jsonl",cve_id=None,cwe_ids=[]),
        rec("source","vulnerability","nvd","source.jsonl",related_record_ids=["same"]),
    ])
    packet = b.query("source", graph_depth=3)
    assert not any(x["via_relation"] == "related_to" for x in packet["graph_relationships"])

def test_verified_family_store_import(tmp_path: Path):
    family_db = tmp_path/"families.sqlite"
    families = SecurityFamilyStore(family_db)
    families.upsert(rec("v1","vulnerability","nvd","cve.jsonl"))
    b = KnowledgeRAGBackend(tmp_path/"k.sqlite", tmp_path/"g.sqlite")
    result = b.ingest_family_store(family_db)
    assert result["source_integrity"]["ok"] is True
    assert b.knowledge.count() == 1
    assert b.relationships.count(node_type="record") == 1

def test_missing_identity_rejected_before_mutation(tmp_path: Path):
    b = KnowledgeRAGBackend(tmp_path/"k.sqlite", tmp_path/"g.sqlite")
    good = rec("v1","vulnerability","nvd","cve.jsonl")
    bad = type(good)(**{**good.canonical_payload,"source_dataset":None,"source_artifact":None})
    with pytest.raises(BackendIntegrationError, match="source_dataset"):
        b.ingest_records([bad])
    assert b.knowledge.count() == 0
    assert b.relationships.count(node_type="record") == 0

def test_tampered_family_source_rejected(tmp_path: Path):
    family_db = tmp_path/"families.sqlite"
    families = SecurityFamilyStore(family_db)
    good = rec("v1","vulnerability","nvd","cve.jsonl")
    families.upsert(good)
    with sqlite3.connect(family_db) as db:
        db.execute("UPDATE security_records SET content_hash=?",("0"*64,))
    b = KnowledgeRAGBackend(tmp_path/"k.sqlite", tmp_path/"g.sqlite")
    with pytest.raises(BackendIntegrationError, match="integrity"):
        b.ingest_family_store(family_db)
    assert b.knowledge.count() == 0
    assert b.relationships.count() == 0

def test_limits_and_health(tmp_path: Path):
    with pytest.raises(BackendIntegrationError): BackendLimits(max_graph_depth=9)
    with pytest.raises(BackendIntegrationError): BackendLimits(max_context_chars=255)
    b = KnowledgeRAGBackend(tmp_path/"k.sqlite", tmp_path/"g.sqlite")
    b.ingest_records([rec("v1","vulnerability","nvd","cve.jsonl")])
    h = b.health()
    assert h["ok"] is True and h["record_count_aligned"] is True
