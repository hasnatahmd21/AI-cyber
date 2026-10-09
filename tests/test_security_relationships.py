import sqlite3
from pathlib import Path

from ai_cyber_os.knowledge import ingest_file
from ai_cyber_os.security_relationships import extract_security_relations


def test_extracts_typed_identifiers_across_security_families():
    text = (
        "CVE-2026-1234 CWE-79 T1059 "
        "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:* "
        "CAPEC-66 D3FEND-DA B0001 "
        "123e4567-e89b-12d3-a456-426614174000 "
        "alert tcp any any -> any any (sid:2026001;)"
    )
    relations = set(extract_security_relations(text))
    assert ("cve", "CVE-2026-1234") in relations
    assert ("cwe", "CWE-79") in relations
    assert ("attack", "T1059") in relations
    assert ("cpe", "CPE:2.3:A:VENDOR:PRODUCT:1.0:*:*:*:*:*:*:*") in relations
    assert ("capec", "CAPEC-66") in relations
    assert ("d3fend", "D3FEND-DA") in relations
    assert ("mbc", "B0001") in relations
    assert ("sigma", "123E4567-E89B-12D3-A456-426614174000") in relations
    assert ("suricata_sid", "2026001") in relations


def test_relation_extraction_is_deterministic_and_deduplicated():
    text = "CVE-2026-1234 appears twice: CVE-2026-1234 and T1059 T1059"
    assert extract_security_relations(text) == sorted(set(extract_security_relations(text)))


def test_knowledge_ingestion_persists_cross_dataset_relationships(tmp_path: Path):
    data = tmp_path / "crosswalk.jsonl"
    data.write_text(
        '{"id":"crosswalk-1","content":"CVE-2026-1234 CWE-79 T1059 CAPEC-66 D3FEND-DA B0001 sid:2026001;"}\n',
        encoding="utf-8",
    )
    db_path = tmp_path / "knowledge.db"
    result = ingest_file(data, db_path=db_path, dataset="security-crosswalk")
    assert result["success"] is True

    conn = sqlite3.connect(db_path)
    try:
        actual = set(conn.execute(
            "SELECT relation_type, target_id FROM knowledge_relations WHERE record_id=?",
            ("crosswalk-1",),
        ).fetchall())
    finally:
        conn.close()

    assert {
        ("cve", "CVE-2026-1234"),
        ("cwe", "CWE-79"),
        ("attack", "T1059"),
        ("capec", "CAPEC-66"),
        ("d3fend", "D3FEND-DA"),
        ("mbc", "B0001"),
        ("suricata_sid", "2026001"),
    } <= actual
