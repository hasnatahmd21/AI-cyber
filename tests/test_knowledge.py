from pathlib import Path
import sqlite3
import pytest

from ai_cyber_os.dataset_pipeline import ingest_and_verify
from ai_cyber_os.knowledge import KnowledgeStore

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "docs/datasets/manifest.json"


def _load_store(tmp_path: Path) -> KnowledgeStore:
    dataset_db = tmp_path / "dataset.sqlite"
    knowledge_db = tmp_path / "knowledge.sqlite"
    result = ingest_and_verify(MANIFEST, ROOT, dataset_db)
    assert result["record_count"] == 2
    store = KnowledgeStore(knowledge_db)
    assert store.ingest_dataset_store(dataset_db) == 2
    return store


def test_dataset_to_rag_retrieval_is_traceable(tmp_path):
    store = _load_store(tmp_path)
    hits = store.retrieve("cyber observation", top_k=5)

    assert len(hits) == 2
    assert [hit["rank"] for hit in hits] == [1, 2]
    assert all(hit["payload"] for hit in hits)
    assert all(hit["source"] == "internal-smoke-fixture" for hit in hits)
    assert all(hit["record_id"].startswith("fixture-") for hit in hits)
    assert all(hit["snippet"] for hit in hits)
    assert all("relevance" in hit for hit in hits)


def test_malicious_fts_syntax_is_treated_as_text(tmp_path):
    store = _load_store(tmp_path)
    queries = [
        "cyber OR observation",
        'cyber") NEAR observation',
        '"""',
        "CVE-2026-0001; OR NOT *",
    ]
    for query in queries:
        store.search(query, limit=5)


def test_strict_then_recall_fallback(tmp_path):
    store = KnowledgeStore(tmp_path / "knowledge.sqlite")
    store.upsert_record(
        dataset_id="ds",
        artifact_path="a.jsonl",
        record_id="1",
        payload={"title": "credential theft", "body": "endpoint evidence"},
        source="unit",
        version="1",
    )

    assert store.search("credential theft", limit=5)[0]["record_id"] == "1"
    fallback = store.search("credential missing", limit=5)
    assert fallback and fallback[0]["record_id"] == "1"


def test_filters_are_deterministic(tmp_path):
    store = KnowledgeStore(tmp_path / "knowledge.sqlite")
    store.upsert_record(
        dataset_id="a",
        artifact_path="one.jsonl",
        record_id="1",
        payload={"value": "same finding"},
        source="source-a",
        version="1",
    )
    store.upsert_record(
        dataset_id="b",
        artifact_path="two.jsonl",
        record_id="2",
        payload={"value": "same finding"},
        source="source-b",
        version="2",
    )

    assert [x["dataset_id"] for x in store.search("same finding", dataset_id="b")] == ["b"]
    assert [x["record_id"] for x in store.search("same finding", source="source-a")] == ["1"]
    assert [x["record_id"] for x in store.search("same finding", version="2")] == ["2"]


def test_upsert_is_idempotent_and_integrity_is_checkable(tmp_path):
    store = KnowledgeStore(tmp_path / "knowledge.sqlite")
    payload1 = {"kind": "finding", "value": "initial"}
    payload2 = {"kind": "finding", "value": "updated"}

    store.upsert_record(
        dataset_id="ds",
        artifact_path="a.jsonl",
        record_id="1",
        payload=payload1,
        source="unit",
        version="1",
    )
    store.upsert_record(
        dataset_id="ds",
        artifact_path="a.jsonl",
        record_id="1",
        payload=payload2,
        source="unit",
        version="2",
    )

    assert store.count() == 1
    hit = store.search("updated", limit=1)[0]
    assert hit["version"] == "2"
    assert store.search("initial", limit=1) == []
    assert store.verify_integrity()["ok"] is True


def test_rebuild_index_restores_search(tmp_path):
    store = _load_store(tmp_path)
    with sqlite3.connect(store.db_path) as db:
        db.execute("DELETE FROM knowledge_fts")
        db.commit()

    assert store.verify_integrity()["ok"] is False
    assert store.rebuild_index() == 2
    assert store.verify_integrity()["ok"] is True
    assert len(store.search("cyber observation")) == 2


def test_context_packet_is_bounded_and_citable(tmp_path):
    store = _load_store(tmp_path)
    packet = store.retrieve_context(
        "cyber observation",
        top_k=5,
        max_chars=256,
    )

    assert packet["query"] == "cyber observation"
    assert packet["hits"]
    assert packet["citations"]
    assert packet["included"] >= 1
    assert packet["truncated"] is True
    assert len(packet["context"]) <= 256
    assert packet["citations"][0]["record_id"].startswith("fixture-")


def test_empty_and_invalid_limits_are_handled(tmp_path):
    store = KnowledgeStore(tmp_path / "knowledge.sqlite")
    assert store.search("   ") == []
    with pytest.raises(ValueError):
        store.search("anything", limit=0)
    with pytest.raises(TypeError):
        store.search("anything", limit=True)


def test_health_reports_operational_state(tmp_path):
    store = _load_store(tmp_path)
    health = store.health()
    assert health["ok"] is True
    assert health["fts5"] is True
    assert health["documents"] == 2
    assert health["datasets"] == 1
    assert health["integrity"]["bad_hashes"] == 0
