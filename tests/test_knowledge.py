from pathlib import Path
from ai_cyber_os.dataset_pipeline import ingest_and_verify
from ai_cyber_os.knowledge import KnowledgeStore

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "docs/datasets/manifest.json"

def test_dataset_to_knowledge_retrieval(tmp_path):
    dataset_db = tmp_path / "dataset.sqlite"
    knowledge_db = tmp_path / "knowledge.sqlite"
    result = ingest_and_verify(MANIFEST, ROOT, dataset_db)
    assert result["record_count"] == 2
    store = KnowledgeStore(knowledge_db)
    assert store.ingest_dataset_store(dataset_db) == 2
    hits = store.search("cyber observation", limit=5)
    assert len(hits) >= 2
    assert all("payload" in hit and hit["source"] for hit in hits)

def test_empty_query_is_safe(tmp_path):
    store = KnowledgeStore(tmp_path / "knowledge.sqlite")
    assert store.search("   ") == []
